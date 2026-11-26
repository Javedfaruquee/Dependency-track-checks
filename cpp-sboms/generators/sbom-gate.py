#!/usr/bin/env python3
"""sbom-gate.py 1.1 - CI release gate for a CycloneDX SBOM.

Fails the job (exit 1) unless:
  1. the SBOM is CycloneDX 1.6 and lists at least one component;
  2. sbomqs scores every REQUIRED BSI TR-03183-2 v2.1 field at --min-bsi (default 10)
     and the NTIA 2026 minimum elements at --min-ntia (default 10);
  3. the SBOM covers what the build actually shipped:
       --link-txt  CMake link line (build/CMakeFiles/<target>.dir/link.txt): every library
                   from the build tree must be a component (matched on bsi:component:filename)
       --rootfs    unpacked firmware root: every ELF file must be claimed by a component
                   (path-in-image property)
  4. every third-party component has a usable CPE 2.3: a product, a real version (not * or -),
     and the component's version (a distro suffix such as 1.33.1-r0 or 2.39-0ubuntu8.9 is fine).
     Dependency-Track checks C/C++ components against NVD by CPE only, so a component without
     one is never checked. Third-party = supplier differs from the SBOM's manufacturer/supplier
     (or from every --own-supplier). A wildcard vendor (cpe:2.3:a:*:name:...) passes with a warning.
     --cpe-exceptions FILE allows named components without a CPE, each with a reason:
       {"exceptions": [{"name": "tinyxml-fork", "version": "*", "reason": "internal fork, no NVD entry"}]}

usage: sbom-gate.py --sbom SBOM --sbomqs PATH [--link-txt FILE] [--rootfs DIR]
                    [--cpe-exceptions FILE] [--own-supplier NAME ...]
                    [--min-bsi 10] [--min-ntia 10] [--report gate-report.json]
System libraries on the link line (absolute paths outside the build tree, -lname) are
reported as warnings: they come from the target platform and are outside the SBOM's scope.
"""
import argparse, json, os, re, shlex, subprocess, sys

ap = argparse.ArgumentParser()
ap.add_argument("--sbom", required=True)
ap.add_argument("--sbomqs", required=True, help="path to sbomqs v2.1.3 or newer")
ap.add_argument("--link-txt")
ap.add_argument("--rootfs")
ap.add_argument("--min-bsi", type=float, default=10.0)
ap.add_argument("--min-ntia", type=float, default=10.0)
ap.add_argument("--cpe-exceptions", help="JSON file of third-party components allowed without a CPE, each with a reason")
ap.add_argument("--own-supplier", action="append", default=[],
                help="supplier name of our own components (repeatable; default: the SBOM's manufacturer and supplier)")
ap.add_argument("--report")
a = ap.parse_args()

fails, warns, info = [], [], {}
doc = json.load(open(a.sbom))
comps = doc.get("components", [])
info["components"] = len(comps)
if doc.get("bomFormat") != "CycloneDX" or doc.get("specVersion") != "1.6":
    fails.append(f"not CycloneDX 1.6 (got {doc.get('bomFormat')} {doc.get('specVersion')})")
if not comps:
    fails.append("SBOM lists no components")

def props(c, name):
    return [p["value"] for p in c.get("properties", []) if p.get("name") == name]
all_comps = comps + ([doc["metadata"]["component"]] if doc.get("metadata", {}).get("component") else [])

# ---- 2. sbomqs scores ----
def sbomqs(flag):
    p = subprocess.run([a.sbomqs, "compliance", flag, "-j", a.sbom], capture_output=True, text=True)
    try:
        return json.loads(p.stdout)
    except ValueError:
        fails.append(f"sbomqs {flag} gave no JSON: {(p.stderr or p.stdout).strip()[:200]}")
        return None
bsi = sbomqs("--bsi")
if bsi:
    s = bsi["summary"]["required_elements_score"]; info["bsi_v2_1_required"] = round(s, 2)
    if s + 1e-9 < a.min_bsi:
        missing = sorted({f'{x["section_id"]} {x["section_data_field"]} ({x["element_id"]})'
                          for x in bsi["sections"] if x.get("required") and x["score"] < 10})
        fails.append(f"BSI TR-03183-2 v2.1 required fields score {s:.2f} < {a.min_bsi}: " + "; ".join(missing[:15]))
ntia = sbomqs("--ntia")
if ntia:
    s = ntia["summary"]["total_score"]; info["ntia_2026"] = round(s, 2)
    if s + 1e-9 < a.min_ntia:
        missing = sorted({f'{x["section_data_field"]} ({x["element_id"]})' for x in ntia["sections"]
                          if x.get("required") and x["score"] < 10})
        fails.append(f"NTIA 2026 score {s:.2f} < {a.min_ntia}: " + "; ".join(missing[:15]))

# ---- 3a. CMake link line ----
if a.link_txt:
    names = {f for c in all_comps for f in props(c, "bsi:component:filename")}
    toks = shlex.split(open(a.link_txt).read())
    out = toks[toks.index("-o") + 1] if "-o" in toks else None
    libs = [t for t in toks if t != out and (t.endswith(".a") or ".so" in os.path.basename(t)
            or t.endswith(".lib") or t.endswith(".dylib"))]
    info["link_line_libraries"] = len(libs)
    for t in libs:
        if os.path.isabs(t) and not t.startswith(os.path.dirname(os.path.abspath(a.link_txt)).split("/CMakeFiles")[0]):
            warns.append(f"system library on link line (platform, not in SBOM scope): {t}")
        elif os.path.basename(t) not in names:
            fails.append(f"library on the link line is not in the SBOM: {t}")
    for t in toks:
        if t.startswith("-l"):
            warns.append(f"system library on link line (platform, not in SBOM scope): {t}")

# ---- 3b. firmware root ----
if a.rootfs:
    claimed = {p for c in all_comps for p in props(c, "path-in-image")}
    elves = []
    for dp, dn, fn in os.walk(a.rootfs):
        for f in fn:
            p = os.path.join(dp, f)
            if os.path.islink(p) or not os.path.isfile(p): continue
            with open(p, "rb") as fh:
                if fh.read(4) == b"\x7fELF": elves.append("/" + os.path.relpath(p, a.rootfs).replace(os.sep, "/"))
    info["elf_files"] = len(elves)
    for e in sorted(elves):
        if e not in claimed: fails.append(f"ELF file in the image is not claimed by any SBOM component: {e}")
    for c in sorted(claimed - set(elves)):
        warns.append(f"SBOM claims {c}, which is not an ELF file in the image")

# ---- 4. identifiers for vulnerability matching ----
def bare_version(v):
    v = re.sub(r"^\d+:", "", str(v or ""))          # Debian epoch
    return v[1:] if re.match(r"^[vV]\d", v) else v  # tag-style v1.2.11

def cpe_problem(c):
    """Returns (failure or None, warning or None)."""
    cpe = c.get("cpe")
    if not cpe:
        return "no CPE, so Dependency-Track never checks it against NVD", None
    f = re.split(r"(?<!\\):", cpe)
    if len(f) != 13 or f[0] != "cpe" or f[1] != "2.3" or f[2] not in ("a", "o", "h"):
        return f"CPE is not in CPE 2.3 format: {cpe}", None
    vendor, product, ver = f[3], f[4], f[5].replace("\\", "")
    if product in ("*", "-", ""):
        return f"CPE has no product: {cpe}", None
    if ver in ("*", "-", ""):
        return f"CPE has no version, so it would match every version's CVEs: {cpe}", None
    have = bare_version(c.get("version"))
    if not (have == ver or (have.startswith(ver) and not have[len(ver)].isalnum())):
        return f"CPE version {ver} differs from the component version {c.get('version')}: {cpe}", None
    if vendor in ("-", ""):
        return f"CPE has no vendor: {cpe}", None
    if vendor == "*":
        return None, f"CPE has a wildcard vendor and matches every vendor's '{product}'; fine only for distinctive names: {cpe}"
    return None, None

md = doc.get("metadata", {})
own = {n.strip().lower() for n in a.own_supplier} or \
      {((x or {}).get("name") or "").strip().lower()
       for x in (md.get("manufacturer"), md.get("supplier"), (md.get("component") or {}).get("supplier"))} - {""}
exc = {}
if a.cpe_exceptions:
    for e in json.load(open(a.cpe_exceptions)).get("exceptions", []):
        name, why = (e.get("name") or "").strip(), (e.get("reason") or "").strip()
        if not name or not why:
            fails.append(f"CPE exception without a name or a reason: {json.dumps(e)}"); continue
        exc[(name.lower(), str(e.get("version", "*")))] = why
CHECKED = {"library", "framework", "application", "operating-system", "firmware", "device-driver", "platform"}
third, excepted, used = 0, 0, set()
for c in comps:
    if c.get("type") not in CHECKED:
        continue
    if ((c.get("supplier") or {}).get("name") or "").strip().lower() in own:
        continue
    third += 1
    label = f'{c.get("name")} {c.get("version")}'
    fail, warn = cpe_problem(c)
    if warn:
        warns.append(f"{label}: {warn}")
    if not fail:
        continue
    key = next((k for k in ((str(c.get("name")).lower(), str(c.get("version"))), (str(c.get("name")).lower(), "*"))
                if k in exc), None)
    if key:
        used.add(key); excepted += 1
        warns.append(f"{label}: {fail}. Allowed by exception: {exc[key]}")
    else:
        fails.append(f"third-party component {label}: {fail}")
for k in sorted(set(exc) - used):
    warns.append(f"CPE exception for {k[0]} {k[1]} is not needed: no such component, or it has a usable CPE")
info["third_party_components"] = third
if exc:
    info["cpe_exceptions_used"] = excepted

res = {"sbom": a.sbom, "result": "FAIL" if fails else "PASS", "info": info, "failures": fails, "warnings": warns}
if a.report: json.dump(res, open(a.report, "w"), indent=2)
print(f"SBOM gate: {res['result']}  {json.dumps(info)}")
for f in fails: print("  FAIL:", f)
for w in warns: print("  warn:", w)
sys.exit(1 if fails else 0)
