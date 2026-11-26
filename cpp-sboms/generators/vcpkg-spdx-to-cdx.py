#!/usr/bin/env python3
"""vcpkg-spdx-to-cdx.py 1.0 - turn vcpkg's per-port SPDX files into ONE CycloneDX 1.6 SBOM for Dependency-Track.

Dependency-Track accepts only CycloneDX. Generic converters (CycloneDX CLI, syft convert) lose either the
package URL or the hashes, turn every file into a component and keep vcpkg's port-version suffix
("1.3.2#3"), so nothing matches. This script reads the vcpkg SPDX directly and keeps one component per port:
  * version without the "#port-version" suffix
  * purl: pkg:conan/<recipe>@<version> when a ConanCenter recipe is known (OSS Index matches it),
    otherwise pkg:github/<owner>/<repo>@<tag> from the source download location; vcpkg purl kept as property
  * CPE from the KNOWN map (NVD matching), licence from the port, SHA-512 of the source archive
usage: vcpkg-spdx-to-cdx.py --product NAME --version VER --out sbom.cdx.json <installed>/<triplet>/share/*/vcpkg.spdx.json
"""
import argparse, datetime, json, re, sys, uuid

KNOWN = {  # vcpkg port -> identifiers; extend centrally (same idea as cmake-sbom.py)
    "zlib": {"conan": "zlib", "cpe": "cpe:2.3:a:zlib:zlib:{v}:*:*:*:*:*:*:*", "supplier": "Jean-loup Gailly and Mark Adler"},
    "cjson": {"conan": "cjson", "cpe": "cpe:2.3:a:cjson_project:cjson:{v}:*:*:*:*:*:*:*", "supplier": "Dave Gamble"},
    "expat": {"conan": "expat", "cpe": "cpe:2.3:a:libexpat_project:libexpat:{v}:*:*:*:*:*:*:*", "supplier": "The Expat project"},
    "openssl": {"conan": "openssl", "cpe": "cpe:2.3:a:openssl:openssl:{v}:*:*:*:*:*:*:*", "supplier": "OpenSSL Software Foundation"},
    "fmt": {"conan": "fmt", "cpe": "cpe:2.3:a:fmt:fmt:{v}:*:*:*:*:*:*:*", "supplier": "fmtlib"},
    "nlohmann-json": {"conan": "nlohmann_json", "cpe": "cpe:2.3:a:json-for-modern-cpp_project:json-for-modern-cpp:{v}:*:*:*:*:*:*:*", "supplier": "Niels Lohmann"},
    "curl": {"conan": "libcurl", "cpe": "cpe:2.3:a:haxx:curl:{v}:*:*:*:*:*:*:*", "supplier": "Daniel Stenberg"},
    "libpng": {"conan": "libpng", "cpe": "cpe:2.3:a:libpng:libpng:{v}:*:*:*:*:*:*:*", "supplier": "libpng project"},
    "sqlite3": {"conan": "sqlite3", "cpe": "cpe:2.3:a:sqlite:sqlite:{v}:*:*:*:*:*:*:*", "supplier": "SQLite"},
}

ap = argparse.ArgumentParser()
ap.add_argument("--product", required=True); ap.add_argument("--version", required=True)
ap.add_argument("--supplier", default="Example Product Team"); ap.add_argument("--out", required=True)
ap.add_argument("--purl-style", choices=["conan", "github"], default="conan")
ap.add_argument("spdx", nargs="+")
a = ap.parse_args()

comps, warn = [], []
for f in a.spdx:
    d = json.load(open(f, encoding="utf-8-sig"))
    if not str(d.get("spdxVersion", "")).startswith("SPDX-2"):
        sys.exit(f"{f}: not SPDX 2.x JSON")
    pk = {p["SPDXID"]: p for p in d.get("packages", [])}
    port = pk.get("SPDXRef-port")
    if not port:
        warn.append(f"{f}: no SPDXRef-port package (not a vcpkg SPDX file?)"); continue
    name = port["name"]; ver = str(port.get("versionInfo", "")).split("#")[0]
    vpurl = next((e["referenceLocator"] for e in port.get("externalRefs", []) if e.get("referenceType") == "purl"), None)
    binary = pk.get("SPDXRef-binary", {})
    src = [p for k, p in pk.items() if k.startswith("SPDXRef-resource")]
    k = KNOWN.get(name)
    c = {"type": "library", "bom-ref": f"{name}@{ver}", "name": name, "version": ver}
    gh = None
    for s in src:
        m = re.match(r"git\+https://github\.com/([^/]+)/([^@#]+)@(.+)", s.get("downloadLocation", ""))
        if m: gh = (m.group(1), m.group(2), m.group(3))
    if a.purl_style == "conan" and k and k.get("conan"):
        c["purl"] = f"pkg:conan/{k['conan']}@{ver}"
    elif gh:
        c["purl"] = f"pkg:github/{gh[0].lower()}/{gh[1].lower()}@{gh[2]}"
    elif vpurl:
        c["purl"] = vpurl.split("?")[0]
    if k:
        c["cpe"] = k["cpe"].format(v=ver)
        c["supplier"] = {"name": k["supplier"]}
    else:
        warn.append(f"{name}: no KNOWN mapping - no CPE, so NVD cannot match it; add it to KNOWN")
    lic = port.get("licenseConcluded")
    if lic and lic not in ("NOASSERTION", "NONE"):
        c["licenses"] = [{"expression": lic}] if (" OR " in lic or " AND " in lic or " WITH " in lic) else [{"license": {"id": lic, "acknowledgement": "concluded"}}]
    refs = []
    if port.get("homepage"): refs.append({"type": "website", "url": port["homepage"]})
    for s in src:
        h = [{"alg": "SHA-512", "content": x["checksumValue"]} for x in s.get("checksums", []) if x.get("algorithm") == "SHA512"]
        loc = s.get("downloadLocation", "")
        url = f"https://github.com/{gh[0]}/{gh[1]}/archive/{gh[2]}.tar.gz" if gh and loc.startswith("git+https://github.com") else loc.replace("git+", "")
        r = {"type": "source-distribution", "url": url}
        if h: r["hashes"] = h
        refs.append(r)
    if refs: c["externalReferences"] = refs
    props = [{"name": "origin", "value": "vcpkg"}]
    if vpurl: props.append({"name": "vcpkg:purl", "value": vpurl})
    if binary.get("versionInfo"): props.append({"name": "vcpkg:abi", "value": binary["versionInfo"]})
    if "#" in str(port.get("versionInfo", "")): props.append({"name": "vcpkg:port-version", "value": str(port["versionInfo"]).split("#", 1)[1]})
    c["properties"] = props
    comps.append(c)

root = {"type": "application", "bom-ref": f"{a.product}@{a.version}", "name": a.product, "version": a.version,
        "supplier": {"name": a.supplier}}
bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
       "metadata": {"timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "lifecycles": [{"phase": "build"}],
                    "tools": {"components": [{"type": "application", "name": "vcpkg-spdx-to-cdx.py", "version": "1.0"}]},
                    "component": root},
       "components": comps,
       # vcpkg writes one SPDX file per port without the graph between ports: list them flat and say so
       "dependencies": [{"ref": root["bom-ref"], "dependsOn": [c["bom-ref"] for c in comps]}] + [{"ref": c["bom-ref"], "dependsOn": []} for c in comps],
       "compositions": [{"aggregate": "incomplete", "assemblies": [root["bom-ref"]]}]}
json.dump(bom, open(a.out, "w"), indent=1)
print(f"{a.out}: {len(comps)} components")
for w in warn: print("WARNING:", w, file=sys.stderr)
