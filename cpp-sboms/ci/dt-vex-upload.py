#!/usr/bin/env python3
"""dt-vex-upload.py 1.0 - upload a CycloneDX VEX to Dependency-Track 5 and prove what it did.

Why: Dependency-Track imports VEX asynchronously and reports nothing back. In 5.2.1
(CycloneDXVexImporter) it skips the whole VEX when the project has no findings yet, which is the case
right after a BOM upload while the analysis is still running, and it skips any statement whose
vulnerability it does not know. The upload "succeeds" either way.

What this tool does:
  1. With --bom-token: waits until the BOM upload and the vulnerability analysis it triggers are finished
     (GET /api/v1/event/token/{token}; DT labels the analysis run with the same token).
  2. Matches every statement's component to the project the way DT does (purl, purl coordinates, CPE,
     or group+name+version). A component the project lacks fails the run before anything is uploaded.
  3. If the project has no findings, DT would ignore the VEX: nothing is uploaded, statements are
     reported PENDING_NO_FINDINGS.
  4. Uploads the VEX (PUT /api/v1/vex) and waits for its import token.
  5. Checks the analysis DT now holds for every statement and component (GET /api/v1/analysis): state,
     suppression, and justification, response and details where the VEX gives them.

Result per statement and component:
  APPLIED              analysis set, and DT has the finding
  STORED               analysis set ahead of a finding (applies when a finding appears later)
  OPEN_UNDER_ALIAS     analysis stored, but the component's finding is another record of the same issue
                       (another source, or an alias), which stays open: add a statement for that id
                       (a warning; --pending-from does not re-apply it)
  PENDING_UNKNOWN_VULN DT does not know the vulnerability yet: re-run later with --pending-from
  PENDING_NO_FINDINGS  the project had no findings, so DT would skip the VEX: re-run later
  NO_COMPONENT         the VEX names a component the project does not have              -> failure
  AMBIGUOUS_VULN       no source given and the id exists in several sources; DT skips it  -> failure
  NOT_APPLIED          DT holds no analysis, or a different one                         -> failure
A VEX without statements fails as well.

Re-runs: DT overwrites the analysis whenever an uploaded statement differs, so re-uploading a whole VEX
undoes later manual triage. A daily job should re-apply only what was pending:
  dt-vex-upload.py ... --pending-from yesterday-report.json --report today-report.json

Exit codes: 0 ok (pending statements are listed), 1 a statement failed, 2 DT or usage error,
4 pending statements and --fail-on-pending.

usage: dt-vex-upload.py --url https://dt.example.com --vex product.vex.cdx.json
                        (--project-uuid UUID | --project-name NAME --project-version VERSION)
                        [--bom-token TOKEN] [--wait 900] [--report vex-report.json] [--fail-on-pending]
                        [--verify-only] [--pending-from REPORT] [--allow-http]
http:// is accepted only for localhost; --allow-http for anything else (e.g. a container name in a test stack).
Auth: DT_API_KEY (X-Api-Key) or DT_BEARER (Authorization: Bearer). The key needs VIEW_PORTFOLIO,
VIEW_VULNERABILITY and VULNERABILITY_ANALYSIS_UPDATE (or VULNERABILITY_ANALYSIS); BOM_UPLOAD and
PROJECT_CREATION_UPLOAD for the BOM upload before it. Only the Python standard library is used.
"""
import argparse, base64, json, os, sys, tempfile, time, urllib.error, urllib.parse, urllib.request

VERSION = "1.0"
STATE = {"not_affected": "NOT_AFFECTED", "resolved": "RESOLVED", "exploitable": "EXPLOITABLE",
         "in_triage": "IN_TRIAGE", "false_positive": "FALSE_POSITIVE"}
SUPPRESSING = {"NOT_AFFECTED", "RESOLVED", "FALSE_POSITIVE"}
DT_SOURCES = ["NVD", "GITHUB", "OSV", "OSSINDEX", "SNYK", "VULNDB", "JVN", "CX", "INTERNAL", "UNKNOWN"]  # Vulnerability.Source
FAILING = {"NO_COMPONENT", "NOT_APPLIED", "AMBIGUOUS_VULN"}
PENDING = {"PENDING_UNKNOWN_VULN", "PENDING_NO_FINDINGS"}   # re-applied by --pending-from
WARNING = {"OPEN_UNDER_ALIAS"}                              # needs a new statement, not a re-run


class DtError(Exception):
    pass


def q(s):
    return urllib.parse.quote(str(s), safe="")


class Dt:
    def __init__(self, url, api_key=None, bearer=None, timeout=60, allow_http=False):
        self.url = url.rstrip("/")
        u = urllib.parse.urlparse(self.url)
        host = u.hostname or ""
        local = host in ("localhost", "127.0.0.1", "::1")
        if u.scheme != "https" and not (u.scheme == "http" and (local or allow_http)):
            raise DtError(f"refusing {u.scheme}:// for {host}: use https, or --allow-http")
        self.h = {"Accept": "application/json"}
        if api_key:
            self.h["X-Api-Key"] = api_key
        elif bearer:
            self.h["Authorization"] = f"Bearer {bearer}"
        else:
            raise DtError("set DT_API_KEY or DT_BEARER")
        self.timeout = timeout
        self.calls = []

    def call(self, method, path, body=None, ok404=False):
        data = None
        headers = dict(self.h)
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        self.calls.append(f"{method} {path.split('?')[0]}")
        for attempt in range(4):
            req = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    raw = r.read()
                    return (json.loads(raw) if raw else None), dict(r.headers)
            except urllib.error.HTTPError as e:
                if e.code == 404 and ok404:
                    return None, {}
                if e.code in (429, 502, 503, 504) and attempt < 3:
                    time.sleep(2 ** attempt); continue
                hint = " (the API key lacks a permission; see the usage text)" if e.code == 403 else ""
                raise DtError(f"{method} {path.split('?')[0]}: HTTP {e.code}{hint} {e.read()[:300]!r}")
            except urllib.error.URLError as e:
                if attempt < 3:
                    time.sleep(2 ** attempt); continue
                raise DtError(f"{method} {path.split('?')[0]}: {e.reason}")

    def paged(self, path, key, size=100):
        """v1 lists honour pageSize only together with pageNumber (Alpine ApiFilter). Dedupe by key."""
        out, seen, sep = [], set(), "&" if "?" in path else "?"
        for page in range(1, 10000):
            items, _ = self.call("GET", f"{path}{sep}pageSize={size}&pageNumber={page}")
            items = items or []
            new = 0
            for x in items:
                k = key(x)
                if k not in seen:
                    seen.add(k); out.append(x); new += 1
            if len(items) < size or new == 0:
                break
        return out

    def wait_token(self, token, max_sec, what):
        deadline, delay = time.time() + max_sec, 2
        while True:
            r, _ = self.call("GET", f"/api/v1/event/token/{q(token)}")
            if not r.get("processing"):
                status = r.get("status")
                if status == "COMPLETED":
                    return status
                if status == "FAILED":
                    raise DtError(f"{what} failed in Dependency-Track (token {token})")
                raise DtError(f"{what}: Dependency-Track knows no run for token {token}")
            if time.time() > deadline:
                raise DtError(f"{what} still processing after {max_sec} s (token {token})")
            time.sleep(delay)
            delay = min(delay * 2, 15)


def purl_coordinates(purl):
    return purl.split("#", 1)[0].split("?", 1)[0] if purl else None


def identity_matches(spec, comp):
    """The OR of identities DT uses in ComponentQueryManager.buildComponentIdentityQuery."""
    if spec.get("purl"):
        if comp.get("purl") == spec["purl"]:
            return True
        if purl_coordinates(comp.get("purl")) == purl_coordinates(spec["purl"]):
            return True
    if spec.get("cpe") and comp.get("cpe") == spec["cpe"]:
        return True
    return (comp.get("group") or None) == (spec.get("group") or None) and \
           (comp.get("name") or None) == (spec.get("name") or None) and \
           (comp.get("version") or None) == (spec.get("version") or None)


def statements(vex):
    comps = {}
    def walk(cs):
        for c in cs or []:
            if c.get("bom-ref"):
                comps.setdefault(c["bom-ref"], c)
            walk(c.get("components"))
    walk(vex.get("components"))
    meta = (vex.get("metadata") or {}).get("component") or {}
    out = []
    for v in vex.get("vulnerabilities", []):
        an = v.get("analysis") or {}
        responses = an.get("response") or []
        for a in v.get("affects", []):
            ref = a.get("ref")
            scoped = ref is not None and (ref == meta.get("bom-ref") or str(ref).startswith("urn:cdx:"))
            out.append({"vulnId": v.get("id"), "source": (v.get("source") or {}).get("name"), "ref": ref,
                        "projectScoped": scoped, "component": comps.get(ref),
                        "expectedState": STATE.get(an.get("state")),
                        "expectedJustification": an["justification"].upper() if an.get("justification") else None,
                        "expectedResponse": responses[-1].upper() if responses else None,
                        "expectedDetails": an.get("detail")})
    return out


def st_public(s):
    c = s["component"] or {}
    return {"vulnId": s["vulnId"], "source": s["source"], "ref": s["ref"], "expectedState": s["expectedState"],
            "vexComponent": c.get("purl") or c.get("cpe") or (f"{c.get('name')}@{c.get('version')}" if c else s["ref"])}


def filter_pending(vex, report_path, tmpdir):
    """A copy of the VEX holding only the (vulnerability, ref) pairs that a previous report left pending."""
    rep = json.load(open(report_path, encoding="utf-8"))
    pend = {(r["vulnId"], r["ref"]) for r in rep.get("results", []) if r.get("result") in PENDING}
    vulns = []
    for v in vex.get("vulnerabilities", []):
        aff = [a for a in v.get("affects", []) if (v.get("id"), a.get("ref")) in pend]
        if aff:
            vulns.append(dict(v, affects=aff))
    out = dict(vex, vulnerabilities=vulns)
    p = os.path.join(tmpdir, "pending.vex.cdx.json")
    with open(p, "w", encoding="utf-8") as f:
        json.dump(out, f)
    return out, p


def resolve_vuln(dt, s, cache):
    """Like CycloneDXVexImporter.resolveVulnerability: source+id first, then the id alone if unique."""
    key = (s["source"], s["vulnId"])
    if key in cache:
        return cache[key]
    found = None
    tried = None
    if s["source"] and s["source"].upper() in DT_SOURCES:
        tried = s["source"]
        v, _ = dt.call("GET", f"/api/v1/vulnerability/source/{q(s['source'])}/vuln/{q(s['vulnId'])}", ok404=True)
        found = ("ok", v) if v else None
    if found is None:
        hits = []
        for src in DT_SOURCES:
            if src == tried:          # skip only the exact string already asked for
                continue
            v, _ = dt.call("GET", f"/api/v1/vulnerability/source/{src}/vuln/{q(s['vulnId'])}", ok404=True)
            if v:
                hits.append(v)
        found = ("ok", hits[0]) if len(hits) == 1 else (("ambiguous", None) if hits else ("unknown", None))
    cache[key] = found
    return found


def aliases_of(f):
    ids = {f["vulnerability"].get("vulnId")}
    for a in f["vulnerability"].get("aliases") or []:
        ids.update(x for x in a.values() if isinstance(x, str))
    return ids


def run(a, dt):
    vex = json.load(open(a.vex, encoding="utf-8"))
    vex_path = a.vex
    tmpdir = tempfile.mkdtemp(prefix="dt-vex-")
    if a.pending_from:
        vex, vex_path = filter_pending(vex, a.pending_from, tmpdir)
    sts = statements(vex)
    report = {"tool": f"dt-vex-upload.py {VERSION}", "vex": os.path.basename(a.vex), "statements": len(sts),
              "steps": [], "results": []}
    if not sts:
        if a.pending_from:
            report["steps"].append("nothing pending in the previous report")
            return report
        raise DtError("the VEX holds no statements (vulnerabilities[].affects[])")
    if a.project_uuid:
        puuid = a.project_uuid
    else:
        qs = urllib.parse.urlencode({"name": a.project_name, "version": a.project_version})
        project, _ = dt.call("GET", f"/api/v1/project/lookup?{qs}", ok404=True)
        if not project:
            raise DtError(f"project {a.project_name} {a.project_version} not found")
        puuid = project["uuid"]
    report["project"] = puuid

    if a.bom_token:
        report["steps"].append(f"BOM upload and analysis finished: {dt.wait_token(a.bom_token, a.wait, 'BOM upload and analysis')}")

    # sortName adds the id as tie-breaker (ComponentQueryManager), so OFFSET paging cannot skip equal rows
    comps = dt.paged(f"/api/v1/component/project/{q(puuid)}?sortName=name&sortOrder=asc", key=lambda c: c["uuid"])
    targets = {}
    for i, s in enumerate(sts):
        if s["projectScoped"]:
            targets[i] = None                 # resolved after the import, from the findings
        else:
            targets[i] = [c for c in comps if s["component"] and identity_matches(s["component"], c)]
    missing = [i for i, t in targets.items() if t == []]
    if missing:
        report["results"] = [dict(st_public(sts[i]), result="NO_COMPONENT") for i in missing]
        report["steps"].append("the VEX names components this project does not have; nothing was uploaded")
        return report

    fkey = lambda f: (f["component"]["uuid"], f["vulnerability"]["uuid"])
    findings = dt.paged(f"/api/v1/finding/project/{q(puuid)}?suppressed=true", key=fkey)
    report["findingsBefore"] = len(findings)
    if not findings:
        report["steps"].append("project has no findings; Dependency-Track would ignore the VEX, so it was not uploaded")
        report["results"] = [dict(st_public(s), result="PENDING_NO_FINDINGS") for s in sts]
        return report

    if not a.verify_only:
        body = {"project": puuid, "vex": base64.b64encode(open(vex_path, "rb").read()).decode()}
        r, _ = dt.call("PUT", "/api/v1/vex", body)
        token = (r or {}).get("token")
        if not token:
            raise DtError(f"VEX upload returned no token: {r}")
        report["steps"].append(f"VEX import finished: {dt.wait_token(token, a.wait, 'VEX import')}")
        findings = dt.paged(f"/api/v1/finding/project/{q(puuid)}?suppressed=true", key=fkey)

    have = {fkey(f) for f in findings}
    by_comp = {}
    for f in findings:
        by_comp.setdefault(f["component"]["uuid"], []).append(f)
    cache = {}
    for i, s in enumerate(sts):
        base = st_public(s)
        kind, v = resolve_vuln(dt, s, cache)
        if kind == "unknown":
            report["results"].append(dict(base, result="PENDING_UNKNOWN_VULN")); continue
        if kind == "ambiguous":
            report["results"].append(dict(base, result="AMBIGUOUS_VULN")); continue
        vu = v["uuid"]
        tg = targets[i] if targets[i] is not None else [c for c in comps if (c["uuid"], vu) in have]
        if not tg:
            report["results"].append(dict(base, result="PENDING_NO_FINDINGS")); continue
        for c in tg:
            qs = urllib.parse.urlencode({"project": puuid, "component": c["uuid"], "vulnerability": vu})
            an, _ = dt.call("GET", f"/api/v1/analysis?{qs}", ok404=True)
            an = an or {}
            got = {"state": an.get("analysisState"), "suppressed": bool(an.get("isSuppressed")),
                   "justification": an.get("analysisJustification"), "response": an.get("analysisResponse"),
                   "details": an.get("analysisDetails")}
            diffs = []
            if got["state"] != s["expectedState"]:
                diffs.append(f"state {got['state']}")
            if got["suppressed"] != (s["expectedState"] in SUPPRESSING):
                diffs.append(f"suppressed {got['suppressed']}")
            for k, e in (("justification", s["expectedJustification"]), ("response", s["expectedResponse"]),
                         ("details", s["expectedDetails"])):
                if e is not None and got[k] != e:
                    diffs.append(f"{k} {got[k]!r}")
            res = {"componentUuid": c["uuid"], "componentName": f"{c.get('name')}@{c.get('version')}",
                   "gotState": got["state"], "suppressed": got["suppressed"]}
            if diffs:
                res.update(result="NOT_APPLIED", differences=diffs)
            elif (c["uuid"], vu) in have:
                res["result"] = "APPLIED"
            else:
                other = [f for f in by_comp.get(c["uuid"], []) if s["vulnId"] in aliases_of(f)]
                if other:
                    res.update(result="OPEN_UNDER_ALIAS", openFinding=f"{other[0]['vulnerability'].get('source')}:"
                                                                      f"{other[0]['vulnerability'].get('vulnId')}")
                else:
                    res["result"] = "STORED"
            report["results"].append(dict(base, **res))
    return report


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--vex", required=True)
    ap.add_argument("--project-uuid")
    ap.add_argument("--project-name")
    ap.add_argument("--project-version")
    ap.add_argument("--bom-token", help="token returned by the BOM upload; waits for its analysis first")
    ap.add_argument("--wait", type=int, default=900, help="seconds to wait for each token (default 900)")
    ap.add_argument("--report", help="write the per-statement result as JSON")
    ap.add_argument("--fail-on-pending", action="store_true")
    ap.add_argument("--verify-only", action="store_true", help="check what DT holds, without uploading")
    ap.add_argument("--pending-from", help="re-apply only the statements this earlier report left pending")
    ap.add_argument("--allow-http", action="store_true", help="allow http:// to a non-local server")
    a = ap.parse_args(argv)
    if not a.project_uuid and not (a.project_name and a.project_version):
        ap.error("give --project-uuid, or --project-name and --project-version")
    try:
        dt = Dt(a.url, os.environ.get("DT_API_KEY"), os.environ.get("DT_BEARER"), allow_http=a.allow_http)
        report = run(a, dt)
    except (DtError, OSError, ValueError, KeyError) as e:
        print(f"VEX upload: ERROR {e}", file=sys.stderr)
        return 2
    counts = {}
    for r in report["results"]:
        counts[r["result"]] = counts.get(r["result"], 0) + 1
    report["counts"] = counts
    failed = sum(v for k, v in counts.items() if k in FAILING)
    pending = sum(v for k, v in counts.items() if k in PENDING | WARNING)
    report["result"] = "FAIL" if failed else ("PENDING" if pending else "PASS")
    if a.report:
        with open(a.report, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
    for st in report["steps"]:
        print("  " + st)
    print(f"VEX upload: {report['result']}  {json.dumps(counts)}")
    for r in report["results"]:
        if r["result"] in FAILING | PENDING | WARNING:
            extra = ""
            if r.get("differences"):
                extra = f" (DT holds {', '.join(r['differences'])})"
            elif r.get("openFinding"):
                extra = f" (open as {r['openFinding']})"
            print(f"  {r['result']}: {r['vulnId']} on {r.get('componentName') or r['vexComponent']}{extra}")
    if failed:
        return 1
    if pending and a.fail_on_pending:
        return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
