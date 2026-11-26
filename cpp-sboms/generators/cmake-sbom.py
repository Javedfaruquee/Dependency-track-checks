#!/usr/bin/env python3
"""Build a BSI TR-03183-2 style CycloneDX 1.6 SBOM for a CMake-only C++ product.
Reads FetchContent checkouts in <build>/_deps (git tag and remote) and the declared manifest
third_party/MANIFEST.json for vendored code; checks declared versions against the source;
adds CPEs, PURLs, licences, suppliers and SHA-512 hashes of built artefacts and sources.
Usage: cmake-sbom.py <source-dir> <build-dir> <product-binary> <out.json>   (exit 1 on mismatches)"""
import json, os, re, subprocess, sys, glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tr03183 import component, bom, artifact_url
src, build, binary, out = sys.argv[1:5]
KNOWN = {  # FetchContent name -> identifiers; extend centrally per organisation
 "fmt": dict(name="fmt", supplier="fmtlib", url="https://fmt.dev", lic="MIT", cpe="cpe:2.3:a:fmt:fmt:{v}:*:*:*:*:*:*:*", art="_deps/fmt-build/libfmt.a"),
 "nlohmann_json": dict(name="nlohmann-json", supplier="Niels Lohmann", url="https://json.nlohmann.me", lic="MIT", cpe="cpe:2.3:a:json-for-modern-cpp_project:json-for-modern-cpp:{v}:*:*:*:*:*:*:*", art="_deps/nlohmann_json-src/single_include/nlohmann/json.hpp"),
 "expat": dict(name="libexpat", supplier="The Expat project", url="https://libexpat.github.io", lic="MIT", cpe="cpe:2.3:a:libexpat_project:libexpat:{v}:*:*:*:*:*:*:*", art="_deps/expat-build/libexpat.a"),
}
git = lambda d, *a: subprocess.run(["git", "-C", d, *a], capture_output=True, text=True).stdout.strip()
def ver(tag):
    m = re.search(r"(\d+)[._](\d+)(?:[._](\d+))?", tag); return ".".join(x for x in m.groups() if x) if m else tag
p = re.search(r"project\(\s*([\w.-]+)\s+VERSION\s+([\d.]+)", open(os.path.join(src, "CMakeLists.txt")).read())
AU = lambda f: artifact_url(p.group(1), p.group(2), os.path.basename(f))
comps, problems = [], []
for d in sorted(glob.glob(os.path.join(build, "_deps", "*-src"))):
    key = os.path.basename(d)[:-4]; k = KNOWN.get(key)
    if not k: problems.append(f"FetchContent dependency '{key}' has no identifier mapping"); continue
    tag = git(d, "describe", "--tags", "--exact-match") or git(d, "describe", "--tags"); url = git(d, "remote", "get-url", "origin")
    v = ver(tag); repo = re.sub(r"^https://github.com/|\.git$", "", url); art = os.path.join(build, k["art"])
    comps.append(component("library", f"{k['name']}@{v}", k["name"], v, k["supplier"], k["url"], k["lic"], art,
        os.path.basename(art), "non-executable" if art.endswith(".hpp") else "executable",
        purl=f"pkg:github/{repo.lower()}@{tag}", cpe=k["cpe"].format(v=v), source_url=url, source_path=d,
        download_url=f"https://github.com/{repo}/archive/refs/tags/{tag}.tar.gz", artifact_url=AU(art), extra_props=[{"name": "origin", "value": "CMake FetchContent"}]))
for m in json.load(open(os.path.join(src, "third_party", "MANIFEST.json")))["components"]:
    vc = m.get("version_check")
    if vc:
        g = re.search(vc["regex"], open(os.path.join(src, vc["file"]), errors="replace").read())
        found = ".".join(g.groups()) if g else None
        if found != m["version"]: problems.append(f"{m['name']}: manifest says {m['version']}, source says {found}")
    art = os.path.join(src, m["artifact"]); repo_url = m["purl"].split("@")[0].replace("pkg:github/", "https://github.com/")
    comps.append(component("library", f"{m['name']}@{m['version']}", m["name"], m["version"], m["supplier"], m["supplier_url"], m["license"],
        art, os.path.basename(art), "executable", purl=m["purl"], cpe=m["cpe"], source_url=repo_url,
        source_path=os.path.join(src, m["path"]), download_url=m.get("download_url"), artifact_url=AU(art),
        extra_props=[{"name": "origin", "value": "vendored (declared manifest)"}]))
root = component("application", f"{p.group(1)}@{p.group(2)}", p.group(1), p.group(2), "Example Product Team",
    "https://example.com/security", "LicenseRef-Proprietary", binary, os.path.basename(binary), "executable",
    purl=f"pkg:generic/example/{p.group(1)}@{p.group(2)}", cpe=f"cpe:2.3:a:example:{p.group(1)}:{p.group(2)}:*:*:*:*:*:*:*",
    source_url=os.environ.get("SOURCE_URL", f"https://git.example.com/{p.group(1)}"), source_path=src,
    artifact_url=AU(binary),
    security_txt="https://example.com/.well-known/security.txt",
    extra_props=[{"name": "scope-note", "value": "C/C++ runtime (libstdc++, glibc) is provided by the target OS, not shipped"}])
json.dump(bom(root, comps, "cmake-sbom.py 0.4"), open(out, "w"), indent=1)
print(f"{p.group(1)} {p.group(2)}: {len(comps)} components"); [print("WARNING:", x) for x in problems]
sys.exit(1 if problems else 0)
