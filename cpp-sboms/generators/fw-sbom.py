#!/usr/bin/env python3
"""fw-sbom.py 0.4 - firmware SBOM from the build manifest, checked against the built rootfs.

usage: fw-sbom.py <build-manifest.json> <fw-dir> <src-dir> <out.cdx.json>
  fw-dir  holds rootfs/, rootfs.squashfs, the image file and app/ (product source)
  src-dir holds the third-party source trees named in the manifest ("src")
Every manifest entry must point at a file that exists in the rootfs, and where a
version_string is given it must appear in that binary; otherwise the script exits 1.
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tr03183 import component, bom, artifact_url

man_p, fw, srcdir, out = sys.argv[1:5]
m = json.load(open(man_p))
rootfs = os.path.join(fw, "rootfs")
problems, comps = [], []

def git_remote(path):
    try:
        import subprocess
        return subprocess.check_output(["git", "-C", path, "remote", "get-url", "origin"], text=True,
                                       stderr=subprocess.DEVNULL).strip()
    except Exception:
        return None

for e in m["components"]:
    f = os.path.join(rootfs, e["file"])
    if not os.path.isfile(f):
        problems.append(f"{e['ref']}: {e['file']} not in rootfs"); continue
    vs = e.get("version_string")
    if vs and vs.encode() not in open(f, "rb").read():
        problems.append(f"{e['ref']}: '{vs}' not found in {e['file']}")
    src = None
    if e.get("src") == "@app": src = os.path.join(fw, "app")
    elif e.get("src"): src = os.path.join(srcdir, e["src"])
    src_url = e.get("source_url") or (git_remote(src) if src else None)
    artifact = os.path.join(fw, e["build_artifact"]) if e.get("build_artifact") else f
    props = [{"name": "path-in-image", "value": "/" + e["file"]},
             {"name": "linkage", "value": e["linkage"]}]
    for extra in e.get("also", []):
        props.append({"name": "path-in-image", "value": "/" + extra})
    if e.get("build_artifact"):
        props.append({"name": "hash-subject", "value": f"build artifact {os.path.basename(artifact)} linked into /{e['file']}"})
    c = component("application" if e["linkage"] == "application" else "library", e["ref"], e["name"], e["version"],
                  e["supplier"], e["supplier_url"], e["license"], artifact, os.path.basename(artifact), "executable",
                  purl=e.get("purl"), cpe=e.get("cpe"), source_url=src_url, source_path=src,
                  download_url=e.get("download_url"), extra_props=props,
                  artifact_url=artifact_url(m["product"]["name"], m["product"]["version"], os.path.basename(artifact)),
                  security_txt=e.get("security_txt"))
    comps.append(c)

o = m["os"]
os_c = component("operating-system", f"{o['name']}@{o['version']}", o["name"], o["version"], m["product"]["supplier"],
                 m["product"]["supplier_url"], m["product"]["license"], os.path.join(fw, o["image"]), o["image"],
                 "non-executable", purl=f"pkg:generic/example/{o['name']}@{o['version']}",
                 source_url=o.get("source_url"), archive="archive", structured="structured",
                 artifact_url=artifact_url(m["product"]["name"], m["product"]["version"], o["image"]))
p = m["product"]
root = component("firmware", f"{p['name']}@{p['version']}", p["name"], p["version"], p["supplier"], p["supplier_url"],
                 p["license"], os.path.join(fw, p["image"]), p["image"], "non-executable",
                 purl=f"pkg:generic/example/{p['name']}@{p['version']}",
                 cpe=f"cpe:2.3:o:example:{p['name']}:{p['version']}:*:*:*:*:*:*:*",
                 source_url=p["source_url"], source_path=os.path.join(fw, "app"),
                 archive="archive", structured="structured",
                 artifact_url=artifact_url(p["name"], p["version"], p["image"]), security_txt=p.get("security_txt"),
                 extra_props=[{"name": "build-id", "value": p["build"]}])
refs = [c["bom-ref"] for c in comps]
deps = [{"ref": root["bom-ref"], "dependsOn": [os_c["bom-ref"]]},
        {"ref": os_c["bom-ref"], "dependsOn": refs}]
for e in m["components"]:
    deps.append({"ref": e["ref"], "dependsOn": e.get("uses", [])})
doc = bom(root, comps + [os_c], "fw-sbom.py 0.4", deps)
doc["metadata"]["manufacturer"]["name"] = doc["metadata"]["supplier"]["name"] = p["supplier"]
json.dump(doc, open(out, "w"), indent=2)
print(f"{p['name']} {p['version']}: {len(comps) + 1} components")
for x in problems: print("PROBLEM:", x, file=sys.stderr)
sys.exit(1 if problems else 0)
