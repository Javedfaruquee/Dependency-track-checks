#!/usr/bin/env python3
"""openvex-to-cdx-vex.py 1.0 - turn OpenVEX (for example from Yocto's sbom-cve-check --export-type openvex)
into a CycloneDX 1.6 VEX that Dependency-Track can import (PUT/POST /api/v1/vex).

Dependency-Track applies a VEX only to findings it already has. It finds the vulnerability by id and
source (source.name "NVD" avoids ambiguity) and the component by the bom-ref in affects[].ref, which must
point at a component in this VEX whose identity (purl, CPE or name+version) matches the project.
States resolved, not_affected and false_positive suppress the finding.

usage: openvex-to-cdx-vex.py --sbom <the product SBOM> --openvex <file> --out <vex.cdx.json>
Products in OpenVEX are matched to SBOM components by purl, CPE, or "name@version".
"""
import argparse, datetime, json, sys, uuid

STATUS = {"not_affected": "not_affected", "fixed": "resolved", "affected": "exploitable",
          "under_investigation": "in_triage"}
JUSTIFICATION = {  # OpenVEX -> CycloneDX (closest meaning)
    "component_not_present": "code_not_present",
    "vulnerable_code_not_present": "code_not_present",
    "vulnerable_code_not_in_execute_path": "code_not_reachable",
    "vulnerable_code_cannot_be_controlled_by_adversary": "requires_environment",
    "inline_mitigations_already_exist": "protected_by_mitigating_control",
}

ap = argparse.ArgumentParser()
ap.add_argument("--sbom", required=True); ap.add_argument("--openvex", required=True); ap.add_argument("--out", required=True)
ap.add_argument("--source", default="NVD", help="vulnerability source name for CVE ids (default NVD)")
a = ap.parse_args()
sbom = json.load(open(a.sbom)); ov = json.load(open(a.openvex))
idx = {}
for c in sbom.get("components", []):
    for key in (c.get("purl"), c.get("cpe"), f'{c.get("name")}@{c.get("version")}', c.get("bom-ref")):
        if key: idx[key.lower()] = c
used, vulns, unmatched = {}, [], []
for st in ov.get("statements", []):
    vid = (st.get("vulnerability") or {}).get("name") or (st.get("vulnerability") or {}).get("@id")
    status = STATUS.get(st.get("status"))
    if not vid or not status:
        continue
    refs = []
    for p in st.get("products", []):
        ids = [p.get("@id")] + list((p.get("identifiers") or {}).values()) + [s.get("@id") for s in p.get("subcomponents", [])]
        comp = next((idx[i.lower()] for i in ids if i and i.lower() in idx), None)
        if comp is None:
            unmatched.append(f"{vid}: {ids[0]}"); continue
        used[comp["bom-ref"]] = comp; refs.append({"ref": comp["bom-ref"]})
    if not refs:
        continue
    an = {"state": status}
    if status == "not_affected" and st.get("justification") in JUSTIFICATION:
        an["justification"] = JUSTIFICATION[st["justification"]]
    detail = " ".join(x for x in (st.get("impact_statement"), st.get("status_notes"), st.get("action_statement")) if x)
    if detail: an["detail"] = detail
    if status == "resolved": an["response"] = ["update"]
    v = {"id": vid, "analysis": an, "affects": refs}
    if vid.upper().startswith("CVE-"): v["source"] = {"name": a.source}
    vulns.append(v)
root = sbom.get("metadata", {}).get("component", {})
vex = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
       "metadata": {"timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "component": {k: root[k] for k in ("type", "bom-ref", "name", "version") if k in root},
                    "tools": {"components": [{"type": "application", "name": "openvex-to-cdx-vex.py", "version": "1.0"}]}},
       "components": [{k: c[k] for k in ("type", "bom-ref", "name", "version", "purl", "cpe") if k in c} for c in used.values()],
       "vulnerabilities": vulns}
json.dump(vex, open(a.out, "w"), indent=1)
print(f"{a.out}: {len(vulns)} vulnerability statements for {len(used)} components")
for u in unmatched: print("NOT IN SBOM:", u, file=sys.stderr)
