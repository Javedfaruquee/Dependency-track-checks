#!/usr/bin/env python3
"""openvex-to-cdx-vex.py 1.1 - turn OpenVEX (for example from Yocto's sbom-cve-check --export-type openvex)
into a CycloneDX 1.6 VEX that Dependency-Track can import (PUT/POST /api/v1/vex).

Dependency-Track applies a VEX only to vulnerabilities it knows and components it can match. It finds the
vulnerability by id and source (source.name "NVD" avoids ambiguity) and the component by the bom-ref in
affects[].ref, which points at a component in this VEX whose identity (purl, CPE or name+version) matches
the project. A ref to the root component (metadata.component) applies to every component of the project
that has the finding. States resolved, not_affected and false_positive suppress the finding.
Upload the result with ci/dt-vex-upload.py, which waits for the analysis and checks every statement.

Products: each product, its "identifiers" (purl, cpe23, cpe22) and its subcomponents are matched against
the SBOM (components at any depth, and the root). sbom-cve-check writes one product per identifier of the
same component; a statement is matched when any of its products matches, and identifiers that match nothing
(for example a second CPE from CVE_PRODUCT) are listed as warnings. A product with subcomponents means the
subcomponents, but only when the product is this SBOM's root (or names no identifier): subcomponents of
another product are never applied here. Repeated statements for the same vulnerability and component: the latest timestamp wins
(then document order), as OpenVEX intends.

The converter refuses (exit 3, nothing written) when:
  - no product of a statement is in the SBOM (--allow-unmatched writes the rest anyway);
  - a not_affected statement lacks a justification or an impact statement (VEX policy);
  - an affected statement lacks an action statement (OpenVEX requires one);
  - a statement has an unknown status, or no usable vulnerability id.
The OpenVEX author and timestamps are kept: metadata.authors, and analysis.firstIssued / lastUpdated.

usage: openvex-to-cdx-vex.py --sbom <the product SBOM> --openvex <file> --out <vex.cdx.json> [--allow-unmatched]
"""
import argparse, datetime, json, re, sys, uuid

VERSION = "1.1"
STATUS = {"not_affected": "not_affected", "fixed": "resolved", "affected": "exploitable",
          "under_investigation": "in_triage"}
JUSTIFICATION = {  # OpenVEX -> CycloneDX (closest meaning)
    "component_not_present": "code_not_present",
    "vulnerable_code_not_present": "code_not_present",
    "vulnerable_code_not_in_execute_path": "code_not_reachable",
    "vulnerable_code_cannot_be_controlled_by_adversary": "requires_environment",
    "inline_mitigations_already_exist": "protected_by_mitigating_control",
}
VULN_ID = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|[A-Z][A-Z0-9]*-[A-Za-z0-9.:_-]+)$", re.I)


def iso(ts):
    """Normalise an RFC 3339 timestamp to CycloneDX date-time (UTC, seconds)."""
    if not ts:
        return None
    t = datetime.datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", str(ts).replace("Z", "+00:00")))
    if t.tzinfo is None:
        t = t.replace(tzinfo=datetime.timezone.utc)
    return t.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def vuln_id(v):
    """OpenVEX vulnerability.name is the id; @id is an IRI whose last segment may be the id."""
    name = (v.get("name") or "").strip()
    if not name and v.get("@id"):
        last = str(v["@id"]).rstrip("/").rsplit("/", 1)[-1]
        name = last if VULN_ID.match(last) else ""
    if not name or not VULN_ID.match(name):
        return None
    return name.upper() if name[:4].upper() == "CVE-" else name


def index_sbom(sbom):
    """Map identifiers to SBOM components (any depth) and to the root. Gives components without bom-ref one."""
    idx, n = {}, 0
    root = (sbom.get("metadata") or {}).get("component") or {}

    def keys(c):
        return [k for k in (c.get("purl"), c.get("cpe"), f'{c.get("name")}@{c.get("version")}', c.get("bom-ref")) if k]

    def walk(cs):
        nonlocal n
        for c in cs or []:
            if not c.get("bom-ref"):
                n += 1
                c = dict(c, **{"bom-ref": f"vex-component-{n}"})
            for k in keys(c):
                idx.setdefault(k.lower(), ("component", c))
            walk(c.get("components"))
    walk(sbom.get("components"))
    if root:
        r = dict(root) if root.get("bom-ref") else dict(root, **{"bom-ref": "vex-root"})
        for k in keys(r):
            idx.setdefault(k.lower(), ("root", r))
    return idx, root


def product_ids(p):
    ids = [p.get("@id")] + list((p.get("identifiers") or {}).values())
    return [i for i in ids if i]


def convert(sbom, ov, source="NVD"):
    """Returns (vex, problems, unmatched, warnings)."""
    idx, root = index_sbom(sbom)
    problems, unmatched, warnings = [], [], []
    doc_ts = iso(ov.get("timestamp"))
    upd_ts = iso(ov.get("last_updated")) or doc_ts
    latest = {}   # (vuln id, bom-ref) -> (timestamp, order, analysis, target)
    for n, st in enumerate(ov.get("statements", []), 1):
        vid = vuln_id(st.get("vulnerability") or {})
        where = f"statement {n} ({vid or (st.get('vulnerability') or {}).get('name') or 'no vulnerability'})"
        if not vid:
            problems.append(f"{where}: no usable vulnerability id (vulnerability.name)"); continue
        status = STATUS.get(st.get("status"))
        if not status:
            problems.append(f"{where}: unknown status {st.get('status')!r}"); continue
        if status == "not_affected":
            if st.get("justification") not in JUSTIFICATION:
                problems.append(f"{where}: not_affected needs one of the OpenVEX justifications "
                                f"({', '.join(JUSTIFICATION)}), got {st.get('justification')!r}")
            if not (st.get("impact_statement") or "").strip():
                problems.append(f"{where}: not_affected needs an impact_statement saying why (VEX policy)")
        if status == "exploitable" and not (st.get("action_statement") or "").strip():
            problems.append(f"{where}: affected needs an action_statement (OpenVEX)")
        targets, missed = {}, []
        for p in st.get("products", []):
            subs = p.get("subcomponents") or []
            if subs and product_ids(p):
                # subcomponents count only inside THIS product: a statement about another product
                # must not touch our components just because they share a library
                own = next((idx[i.lower()] for i in product_ids(p) if i.lower() in idx), None)
                if own is None or own[0] != "root":
                    missed.append(f"{product_ids(p)[0]} (not this product)")
                    continue
            if subs:
                for s in subs:
                    hit = next((idx[i.lower()] for i in product_ids(s) if i.lower() in idx), None)
                    if hit:
                        targets[hit[1]["bom-ref"]] = hit
                    else:
                        missed.append(next(iter(product_ids(s)), "?"))
                continue
            hit = next((idx[i.lower()] for i in product_ids(p) if i.lower() in idx), None)
            if hit:
                targets[hit[1]["bom-ref"]] = hit
            else:
                missed.append(next(iter(product_ids(p)), "?"))
        if not targets:
            unmatched.append(f"{where}: none of {', '.join(missed) or 'its products'} is in the SBOM"); continue
        if missed:
            warnings.append(f"{where}: ignored identifiers not in the SBOM: {', '.join(missed)}")
        an = {"state": status}
        if status == "not_affected" and st.get("justification") in JUSTIFICATION:
            an["justification"] = JUSTIFICATION[st["justification"]]
        detail = " ".join(x for x in (st.get("impact_statement"), st.get("status_notes"), st.get("action_statement")) if x)
        if detail:
            an["detail"] = detail
        if status == "resolved":
            an["response"] = ["update"]
        first = iso(st.get("timestamp")) or doc_ts
        last = iso(st.get("last_updated")) or iso(st.get("timestamp")) or upd_ts
        if first:
            an["firstIssued"] = first
        if last:
            an["lastUpdated"] = last
        for ref, hit in targets.items():
            key = (vid, ref)
            rank = (last or "", n)
            if key not in latest or rank >= latest[key][0]:
                if key in latest:
                    warnings.append(f"{where}: replaces an earlier statement for {vid} on {ref}")
                latest[key] = (rank, an, hit)
    # group (vuln, analysis) -> refs, keeping the order of first appearance
    groups, used = {}, {}
    for (vid, ref), (_, an, hit) in latest.items():
        gk = (vid, json.dumps(an, sort_keys=True))
        groups.setdefault(gk, {"id": vid, "analysis": an, "affects": []})["affects"].append({"ref": ref})
        if hit[0] == "component":
            used[ref] = hit[1]
    vulns = []
    for g in groups.values():
        if g["id"].upper().startswith("CVE-"):
            g["source"] = {"name": source}
        vulns.append({k: g[k] for k in ("id", "source", "analysis", "affects") if k in g})
    root_ref = None
    for (_, ref), (_, _, hit) in latest.items():
        if hit[0] == "root":
            root_ref = ref
    meta_comp = {k: root[k] for k in ("type", "bom-ref", "name", "version", "purl", "cpe") if k in root}
    if root_ref and "bom-ref" not in meta_comp:
        meta_comp["bom-ref"] = root_ref
    meta = {"timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": meta_comp,
            "tools": {"components": [{"type": "application", "name": "openvex-to-cdx-vex.py", "version": VERSION}]}}
    if ov.get("author"):
        meta["authors"] = [{"name": ov["author"]}]
    props = [{"name": "openvex:id", "value": ov["@id"]}] if ov.get("@id") else []
    if ov.get("version") is not None:
        props.append({"name": "openvex:version", "value": str(ov["version"])})
    if props:
        meta["properties"] = props
    vex = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
           "metadata": meta,
           "components": [{k: c[k] for k in ("type", "bom-ref", "group", "name", "version", "purl", "cpe") if k in c}
                          for c in used.values()],
           "vulnerabilities": vulns}
    return vex, problems, unmatched, warnings


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--sbom", required=True)
    ap.add_argument("--openvex", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--source", default="NVD", help="vulnerability source name for CVE ids (default NVD)")
    ap.add_argument("--allow-unmatched", action="store_true",
                    help="write the VEX even if some statements match nothing in the SBOM (they are listed and dropped)")
    a = ap.parse_args(argv)
    sbom = json.load(open(a.sbom, encoding="utf-8"))
    ov = json.load(open(a.openvex, encoding="utf-8"))
    vex, problems, unmatched, warnings = convert(sbom, ov, a.source)
    for w in warnings:
        print("warning:", w, file=sys.stderr)
    for p in problems:
        print("POLICY:", p, file=sys.stderr)
    for u in unmatched:
        print("NOT IN SBOM:", u, file=sys.stderr)
    if problems or (unmatched and not a.allow_unmatched) or not vex["vulnerabilities"]:
        print(f"{a.out}: not written ({len(problems)} policy problems, {len(unmatched)} statements not in the SBOM"
              + (", no statements left" if not vex["vulnerabilities"] else "") + ")", file=sys.stderr)
        return 3
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(vex, f, indent=1)
    n = sum(len(v["affects"]) for v in vex["vulnerabilities"])
    print(f"{a.out}: {n} statements on {len(vex['components'])} components"
          + (f"; {len(unmatched)} statements not in the SBOM dropped" if unmatched else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
