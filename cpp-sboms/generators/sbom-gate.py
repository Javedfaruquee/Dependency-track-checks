#!/usr/bin/env python3
"""sbom-gate.py 1.0 - CI release gate for a CycloneDX SBOM.

Fails the job (exit 1) unless:
  1. the SBOM is CycloneDX 1.6 and lists at least one component;
  2. sbomqs scores every REQUIRED BSI TR-03183-2 v2.1 field at --min-bsi (default 10)
     and the NTIA 2026 minimum elements at --min-ntia (default 10);
  3. the SBOM covers what the build actually shipped:
       --link-txt  CMake link line (build/CMakeFiles/<target>.dir/link.txt): every library
                   from the build tree must be a component (matched on bsi:component:filename)
       --rootfs    unpacked firmware root: every ELF file must be claimed by a component
                   (path-in-image property)

usage: sbom-gate.py --sbom SBOM --sbomqs PATH [--link-txt FILE] [--rootfs DIR]
                    [--min-bsi 10] [--min-ntia 10] [--report gate-report.json]
System libraries on the link line (absolute paths outside the build tree, -lname) are
reported as warnings: they come from the target platform and are outside the SBOM's scope.
"""
import argparse, json, os, shlex, subprocess, sys

ap = argparse.ArgumentParser()
ap.add_argument("--sbom", required=True)
ap.add_argument("--sbomqs", required=True, help="path to sbomqs v2.1.3 or newer")
ap.add_argument("--link-txt")
ap.add_argument("--rootfs")
ap.add_argument("--min-bsi", type=float, default=10.0)
ap.add_argument("--min-ntia", type=float, default=10.0)
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

res = {"sbom": a.sbom, "result": "FAIL" if fails else "PASS", "info": info, "failures": fails, "warnings": warns}
if a.report: json.dump(res, open(a.report, "w"), indent=2)
print(f"SBOM gate: {res['result']}  {json.dumps(info)}")
for f in fails: print("  FAIL:", f)
for w in warns: print("  warn:", w)
sys.exit(1 if fails else 0)
