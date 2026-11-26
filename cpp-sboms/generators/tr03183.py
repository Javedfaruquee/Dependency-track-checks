"""Shared helpers: put CycloneDX 1.6 fields where BSI TR-03183-2 checks expect them."""
import hashlib, os, subprocess, tarfile, io
def sha512_file(p):
    h = hashlib.sha512()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()
def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()
def file_hashes(p):
    """SHA-512 as TR-03183-2 v2 requires, plus SHA-256 for tools that still check v1.1."""
    return [{"alg": "SHA-512", "content": sha512_file(p)}, {"alg": "SHA-256", "content": sha256_file(p)}]
def sha512_tree(path):
    """Deterministic SHA-512 over a source tree (sorted relative paths + contents), ignoring .git."""
    h = hashlib.sha512()
    for dp, dn, fn in os.walk(path):
        dn[:] = sorted(d for d in dn if d != ".git")
        for f in sorted(fn):
            p = os.path.join(dp, f); rel = os.path.relpath(p, path)
            h.update(rel.encode()); h.update(b"\0")
            if os.path.isfile(p) and not os.path.islink(p): h.update(open(p, "rb").read())
    return h.hexdigest()
def licenses(spdx):
    lic = {"id": spdx} if not spdx.startswith("LicenseRef-") else {"name": spdx}
    return [{"license": dict(lic, acknowledgement="declared")}, {"license": dict(lic, acknowledgement="concluded")}]
def component(ctype, ref, name, version, supplier, supplier_url, license_spdx, artifact, filename, executable,
              purl=None, cpe=None, source_url=None, source_path=None, download_url=None, archive="no archive",
              structured="no structured", extra_props=(), artifact_url=None, security_txt=None):
    """artifact_url: where the deployable file we hashed is stored (our artifact repository), so the
    'distribution' reference and its SHA-512 describe the same file. download_url: the upstream source
    release archive, recorded as 'source-distribution' (not hashed here). The source hash is a
    SHA-512 over the checked-out tree (sorted paths + contents), attached to the 'vcs' reference."""
    c = {"type": ctype, "bom-ref": ref, "name": name, "version": version,
         "supplier": {"name": supplier, "url": [supplier_url]}, "manufacturer": {"name": supplier, "url": [supplier_url]},
         "licenses": licenses(license_spdx),
         "hashes": file_hashes(artifact)}
    if purl: c["purl"] = purl
    if cpe: c["cpe"] = cpe
    ext = []
    if artifact_url:
        ext.append({"type": "distribution", "url": artifact_url, "hashes": file_hashes(artifact)})
    if download_url:
        ext.append({"type": "source-distribution", "url": download_url, "comment": "upstream source release"})
    if source_url:
        v = {"type": "vcs", "url": source_url}
        if source_path:
            v["hashes"] = [{"alg": "SHA-512", "content": sha512_tree(source_path)}]
            v["comment"] = "hash = SHA-512 over the checked-out source tree (sorted paths + contents, .git excluded)"
        ext.append(v)
    if security_txt:
        ext.append({"type": "rfc-9116", "url": security_txt})
    c["externalReferences"] = ext
    c["properties"] = [{"name": "bsi:component:filename", "value": filename},
                       {"name": "bsi:component:executable", "value": executable},
                       {"name": "bsi:component:archive", "value": archive},
                       {"name": "bsi:component:structured", "value": structured}] + list(extra_props)
    return c
ARTIFACT_BASE = os.environ.get("ARTIFACT_BASE_URL", "https://artifacts.example.com/artifactory/releases")
def artifact_url(product, version, filename):
    return f"{ARTIFACT_BASE}/{product}/{version}/{filename}"
def bom(root, comps, tool, deps=None, aggregate="complete"):
    import uuid, datetime
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
      "metadata": {"timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lifecycles": [{"phase": "build"}],
        "tools": {"components": [{"type": "application", "name": tool.rsplit(" ", 1)[0], "version": tool.rsplit(" ", 1)[-1]}]},
        "authors": [{"name": "Product Security", "email": "psirt@example.com"}],
        "manufacturer": {"name": "Example Product Team", "url": ["https://example.com"]},
        "supplier": {"name": "Example Product Team", "url": ["https://example.com"]},
        "component": root},
      "components": comps,
      "dependencies": deps or ([{"ref": root["bom-ref"], "dependsOn": [c["bom-ref"] for c in comps]}] +
                               [{"ref": c["bom-ref"], "dependsOn": []} for c in comps]),
      # TR-03183-2 v2.1 5.2.2: say explicitly whether the enumeration is complete
      "compositions": [{"aggregate": aggregate,
                        "assemblies": [root["bom-ref"]] + [c["bom-ref"] for c in comps],
                        "dependencies": [root["bom-ref"]] + [c["bom-ref"] for c in comps]}]}
