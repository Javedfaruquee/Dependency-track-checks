#!/usr/bin/env python3
"""compare-findings.py 1.0 - score any SBOM tool's results against the known contents of the samples.

usage: compare-findings.py --expected expected-components.json --product "<key>" \
         --findings <export> [--findings <export> ...] [--reference cpp-sboms-dt-results.json --reference-project <name>]

--findings accepts:
  * CycloneDX JSON with a "vulnerabilities" array (VEX/VDR export from Dependency-Track, Manifest, Sonar, ...)
  * CycloneDX JSON without vulnerabilities (then only component coverage is scored)
  * cpp-sboms-dt-results.json from cpp-sboms-dt-test.ps1 (pick the project with --project)
  * CSV with a component/package column, a version column and a CVE/vulnerability column
--reference gives the CVE set to compare against (by default: Dependency-Track on the build-derived SBOM).
CVE IDs are compared after alias resolution (GHSA/OSV IDs count only through their CVE alias).
"""
import argparse, csv, json, re, sys
from collections import defaultdict

ALIASES = {"libexpat": {"expat", "libexpat"}, "nlohmann-json": {"nlohmann-json", "nlohmann_json", "json-for-modern-cpp", "nlohmann"},
           "cjson": {"cjson"}, "zlib": {"zlib"}, "openssl": {"openssl", "libcrypto", "libssl"},
           "glibc": {"glibc", "libc", "libc6", "gnu c library"}, "busybox": {"busybox"}, "fmt": {"fmt", "libfmt"}}
CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)

def canon(name, purl="", cpe=""):
    s = " ".join([name or "", purl or "", cpe or ""]).lower()
    for k, al in ALIASES.items():
        for a in al:
            if re.search(r"(^|[^a-z0-9])" + re.escape(a) + r"([^a-z0-9]|$)", s): return k
    return None

def from_cdx(d):
    """-> components {canon: version}, findings {canon: set(ids)}"""
    comps, refmap, finds = {}, {}, defaultdict(set)
    for c in d.get("components", []) + ([d["metadata"]["component"]] if d.get("metadata", {}).get("component") else []):
        k = canon(c.get("name"), c.get("purl"), c.get("cpe"))
        if k: comps[k] = c.get("version"); refmap[c.get("bom-ref")] = k
    for v in d.get("vulnerabilities", []):
        ids = set(CVE.findall(v.get("id", "") + " " + json.dumps(v.get("references", [])) + " " + json.dumps(v.get("aliases", []))))
        if not ids: ids = {v.get("id")}
        for a in v.get("affects", []):
            k = refmap.get(a.get("ref"))
            if k: finds[k] |= {i.upper() for i in ids}
    return comps, finds

def from_dt_results(d, project):
    p = d["projects"].get(project)
    if not p: sys.exit(f"project {project} not in results; have: {', '.join(d['projects'])}")
    comps, finds = {}, defaultdict(set)
    for c in p.get("componentList", []):
        k = canon(c.get("name"), c.get("purl"), c.get("cpe"))
        if k: comps[k] = c.get("version")
    for f in p.get("findingList", []):
        n, _, ver = f["component"].rpartition("@"); k = canon(n)
        if not k: continue
        ids = {i.upper() for i in CVE.findall(" ".join([f.get("id") or ""] + list(f.get("aliases") or [])))} or {f.get("id")}
        finds[k] |= ids
    return comps, finds

def from_csv(path):
    rows = list(csv.DictReader(open(path, newline="", encoding="utf-8-sig")))
    if not rows: return {}, {}
    cols = {c.lower(): c for c in rows[0]}
    pick = lambda *keys: next((cols[c] for c in cols if any(k in c for k in keys)), None)
    cn, cv, ci = pick("component", "package", "name"), pick("version"), pick("cve", "vulnerab", "advisory", "id")
    print(f"  CSV columns used: component={cn} version={cv} id={ci}", file=sys.stderr)
    comps, finds = {}, defaultdict(set)
    for r in rows:
        k = canon(r.get(cn, ""))
        if not k: continue
        comps[k] = r.get(cv)
        ids = {i.upper() for i in CVE.findall(r.get(ci, "") or "")}
        finds[k] |= ids
    return comps, finds

def load(path, project=None):
    if path.lower().endswith(".csv"): return from_csv(path)
    d = json.load(open(path, encoding="utf-8-sig"))
    if "projects" in d and "bomFormat" not in d: return from_dt_results(d, project)
    return from_cdx(d)

ap = argparse.ArgumentParser()
ap.add_argument("--expected", required=True); ap.add_argument("--product", required=True)
ap.add_argument("--findings", action="append", required=True); ap.add_argument("--project")
ap.add_argument("--reference"); ap.add_argument("--reference-project")
ap.add_argument("--out")
a = ap.parse_args()
exp = json.load(open(a.expected))["products"][a.product]["components"]
comps, finds = {}, defaultdict(set)
for f in a.findings:
    c, fi = load(f, a.project); comps.update(c)
    for k, v in fi.items(): finds[k] |= v
ref = defaultdict(set)
if a.reference:
    _, r = load(a.reference, a.reference_project)
    for k, v in r.items(): ref[k] |= v
rows, tot = [], defaultdict(int)
for e in exp:
    k = canon(e["name"], e.get("purl"), e.get("cpe"))
    got = finds.get(k, set()); cves = {i for i in got if i and i.startswith("CVE-")}
    rcves = {i for i in ref.get(k, set()) if i and i.startswith("CVE-")}
    row = {"component": f'{e["name"]} {e["version"]}', "listed": k in comps, "version_ok": str(comps.get(k) or "") == e["version"] or str(comps.get(k) or "").startswith(e["version"] + "-"),
           "cves": len(cves), "reference_cves": len(rcves), "missed_vs_reference": sorted(rcves - cves), "extra_vs_reference": sorted(cves - rcves)}
    rows.append(row)
    tot["listed"] += row["listed"]; tot["cves"] += len(cves); tot["ref"] += len(rcves); tot["shared"] += len(cves & rcves)
print(f"{'component':24} {'listed':7} {'version':8} {'CVEs':>5} {'ref':>5} {'missed':>7}")
for r in rows:
    print(f"{r['component']:24} {'yes' if r['listed'] else 'NO':7} {'ok' if r['version_ok'] else '-':8} {r['cves']:>5} {r['reference_cves']:>5} {len(r['missed_vs_reference']):>7}")
summary = {"components_listed": f"{tot['listed']}/{len(exp)}", "cves": tot["cves"], "reference_cves": tot["ref"],
           "reference_cves_found": tot["shared"]}
print("summary:", json.dumps(summary))
if a.out: json.dump({"product": a.product, "summary": summary, "rows": rows}, open(a.out, "w"), indent=2)
