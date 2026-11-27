#!/usr/bin/env python3
"""Tests for gap 1 (a VEX upload can be lost silently): openvex-to-cdx-vex.py 1.1 and ci/dt-vex-upload.py,
against tests/mock_dt.py (a stand-in for the Dependency-Track 5.2.1 API).

usage: python3 tests/test_vex_gap1.py        (from cpp-sboms/; no network, standard library only)
"""
import base64, json, os, subprocess, sys, tempfile, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import mock_dt  # noqa: E402

CONV = os.path.join(ROOT, "generators", "openvex-to-cdx-vex.py")
TOOL = os.path.join(ROOT, "ci", "dt-vex-upload.py")
SBOM = os.path.join(ROOT, "sboms", "fw-build-manifest.cdx.json")
OPENVEX = os.path.join(ROOT, "vex", "test-gap1.openvex.json")
TMP = tempfile.mkdtemp(prefix="vexgap1-")
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))


def run(cmd, env=None):
    p = subprocess.run([sys.executable, "-I"] + cmd, capture_output=True, text=True,
                       env=dict(os.environ, **(env or {})))
    return p.returncode, p.stdout, p.stderr


def new_dt(**delays):
    st = mock_dt.State(**delays)
    st.add_vuln("CVE-2022-37434", affects=[("zlib", "1.2.11")])
    st.add_vuln("CVE-2018-25032", affects=[("zlib", "1.2.11")])
    st.add_vuln("CVE-2019-11834", affects=[("cjson", "1.7.10")])
    st.add_vuln("CVE-2021-3711", affects=[("openssl", "1.1.1k")])
    st.add_vuln("CVE-2021-44228", affects=[("log4j-core", "2.14.1")])   # known to DT, not in this product
    srv, url = mock_dt.serve(st)
    return st, srv, url


def api(url, method, path, body=None, key=mock_dt.API_KEY):
    req = urllib.request.Request(url + path, method=method, data=json.dumps(body).encode() if body else None,
                                 headers={"X-Api-Key": key, "Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read() or b"null")


def upload_bom(url, name, version="1"):
    bom = base64.b64encode(open(SBOM, "rb").read()).decode()
    return api(url, "PUT", "/api/v1/bom", {"projectName": name, "projectVersion": version, "autoCreate": True, "bom": bom})["token"]


def wait(url, token):
    for _ in range(100):
        if not api(url, "GET", f"/api/v1/event/token/{token}")["processing"]:
            return
        time.sleep(0.2)


# ---------------- converter ----------------
vex = os.path.join(TMP, "gap1.vex.cdx.json")
code, out, err = run([CONV, "--sbom", SBOM, "--openvex", OPENVEX, "--out", vex])
check("converter: test OpenVEX converts", code == 0 and os.path.exists(vex), err)
doc = json.load(open(vex))
check("converter: 5 statements, 3 components", len(doc["vulnerabilities"]) == 5 and len(doc["components"]) == 3)
check("converter: author kept", doc["metadata"].get("authors", [{}])[0].get("name", "").startswith("TEST fixture"))
check("converter: firstIssued/lastUpdated kept",
      all(v["analysis"].get("firstIssued") == "2026-11-26T20:00:00Z" and v["analysis"].get("lastUpdated") for v in doc["vulnerabilities"]))
check("converter: source NVD on CVEs", all(v.get("source", {}).get("name") == "NVD" for v in doc["vulnerabilities"]))


def bad_openvex(mut, name):
    ov = json.load(open(OPENVEX))
    mut(ov)
    p = os.path.join(TMP, name + ".openvex.json")
    json.dump(ov, open(p, "w"))
    o = os.path.join(TMP, name + ".vex.cdx.json")
    c, _, e = run([CONV, "--sbom", SBOM, "--openvex", p, "--out", o])
    return c, os.path.exists(o), e, p, o


c, wrote, e, p, o = bad_openvex(lambda ov: ov["statements"][0]["products"].__setitem__(0, {"@id": "pkg:github/acme/nothere@1.0"}), "unmatched")
check("converter: product not in SBOM -> exit 3, nothing written", c == 3 and not wrote and "NOT IN SBOM" in e, e)
c2, _, _ = run([CONV, "--sbom", SBOM, "--openvex", p, "--out", o, "--allow-unmatched"])
check("converter: --allow-unmatched writes the rest", c2 == 0 and len(json.load(open(o))["vulnerabilities"]) == 4)
c, wrote, e, *_ = bad_openvex(lambda ov: ov["statements"][1].pop("justification"), "nojust")
check("converter: not_affected without justification -> exit 3", c == 3 and not wrote and "justification" in e, e)
c, wrote, e, *_ = bad_openvex(lambda ov: ov["statements"][1].pop("impact_statement"), "noimpact")
check("converter: not_affected without impact statement -> exit 3", c == 3 and not wrote and "impact_statement" in e, e)
c, wrote, e, *_ = bad_openvex(lambda ov: ov["statements"][0].__setitem__("status", "patched"), "badstatus")
check("converter: unknown status -> exit 3", c == 3 and not wrote and "unknown status" in e, e)
c, wrote, e, *_ = bad_openvex(lambda ov: ov["statements"][0].update(status="affected"), "noaction")
check("converter: affected without action statement -> exit 3", c == 3 and not wrote and "action_statement" in e, e)


def conv(ov, name, sbom=SBOM):
    p = os.path.join(TMP, name + ".openvex.json"); json.dump(ov, open(p, "w"))
    o = os.path.join(TMP, name + ".vex.cdx.json")
    c, out, e = run([CONV, "--sbom", sbom, "--openvex", p, "--out", o])
    return c, (json.load(open(o)) if c == 0 else None), e, o


def refs(doc, vid):
    return sorted(a["ref"] for v in doc["vulnerabilities"] if v["id"] == vid for a in v["affects"])


CDXCLI = os.environ.get("CDXCLI")
def valid(path):
    if not CDXCLI:
        return True
    p = subprocess.run([CDXCLI, "validate", "--input-file", path, "--input-format", "json", "--input-version", "v1_6",
                        "--fail-on-errors"], capture_output=True, text=True)
    return p.returncode == 0

# sbom-cve-check writes one product per identifier (CPE and purl) of the same component, and one per CPE
sbomcc = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://openvex.dev/docs/public/vex-abc",
          "author": "SBOM CVE Checker Generator", "timestamp": "2026-11-26T20:00:00+00:00", "version": 1,
          "statements": [
              {"vulnerability": {"name": "CVE-2022-37434", "@id": "https://nvd.nist.gov/vuln/detail/CVE-2022-37434"},
               "products": [{"identifiers": {"cpe23": "cpe:2.3:a:zlib:zlib:1.2.11:*:*:*:*:*:*:*"}},
                            {"identifiers": {"purl": "pkg:github/madler/zlib@v1.2.11"}}],
               "status": "fixed", "timestamp": "2026-11-26T20:00:00.123456789+00:00", "status_notes": "Fixed by: CVE-2022-37434.patch"},
              {"vulnerability": {"name": "CVE-2021-3711"},
               "products": [{"identifiers": {"cpe23": "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"}},
                            {"identifiers": {"cpe23": "cpe:2.3:a:openssl_project:openssl:1.1.1k:*:*:*:*:*:*:*"}}],
               "status": "fixed", "timestamp": "2026-11-26T20:00:00+00:00"}]}
c, d, e, o = conv(sbomcc, "sbomcc")
check("converter: sbom-cve-check shape converts (CPE+purl products, extra CPE ignored with a warning)",
      c == 0 and refs(d, "CVE-2022-37434") == ["zlib@1.2.11"] and len(refs(d, "CVE-2021-3711")) == 1
      and "ignored identifiers" in e, e)
check("converter: sbom-cve-check output is valid CycloneDX 1.6 (no duplicate affects)", c == 0 and valid(o))

sub = {"@context": "https://openvex.dev/ns/v0.2.0", "author": "t", "timestamp": "2026-11-26T20:00:00Z", "statements": [
    {"vulnerability": {"name": "CVE-2022-37434"}, "status": "fixed",
     "products": [{"@id": "pkg:generic/example/sensorhub-fw@3.1.0",
                   "subcomponents": [{"@id": "pkg:github/madler/zlib@v1.2.11"}, {"@id": "pkg:github/openssl/openssl@OpenSSL_1_1_1k"}]}]}]}
c, d, e, o = conv(sub, "subcomponents")
check("converter: every subcomponent is mapped", c == 0 and len(refs(d, "CVE-2022-37434")) == 2, (c, e))

rootp = {"@context": "https://openvex.dev/ns/v0.2.0", "author": "t", "timestamp": "2026-11-26T20:00:00Z", "statements": [
    {"vulnerability": {"name": "CVE-2022-37434"}, "status": "fixed", "products": [{"@id": "pkg:generic/example/sensorhub-fw@3.1.0"}]}]}
other = {"@context": "https://openvex.dev/ns/v0.2.0", "author": "t", "timestamp": "2026-11-26T20:00:00Z", "statements": [
    {"vulnerability": {"name": "CVE-2022-37434"}, "status": "not_affected", "justification": "component_not_present",
     "impact_statement": "about another product", "products": [{"@id": "pkg:generic/example/other-product@9.9",
                                                                "subcomponents": [{"@id": "pkg:github/madler/zlib@v1.2.11"}]}]}]}
c, d, e, o = conv(other, "other-product")
check("converter: subcomponents of ANOTHER product are never applied here -> exit 3", c == 3 and d is None and "not this product" in e, (c, e))
c, d, e, o = conv(rootp, "root")
root_ref = json.load(open(SBOM))["metadata"]["component"]["bom-ref"]
check("converter: the product itself (the root) maps to metadata.component (project-scoped in DT)",
      c == 0 and refs(d, "CVE-2022-37434") == [root_ref] and d["metadata"]["component"]["bom-ref"] == root_ref and valid(o), (c, e))

hist = {"@context": "https://openvex.dev/ns/v0.2.0", "author": "t", "timestamp": "2026-11-01T00:00:00Z", "statements": [
    {"vulnerability": {"name": "CVE-2021-3711"}, "products": [{"@id": "pkg:github/openssl/openssl@OpenSSL_1_1_1k"}],
     "status": "not_affected", "justification": "vulnerable_code_not_present", "impact_statement": "SM2 not built",
     "timestamp": "2026-11-20T00:00:00Z"},
    {"vulnerability": {"name": "CVE-2021-3711"}, "products": [{"@id": "pkg:github/openssl/openssl@OpenSSL_1_1_1k"}],
     "status": "under_investigation", "timestamp": "2026-11-01T00:00:00Z"}]}
c, d, e, o = conv(hist, "history")
st_ = [v["analysis"]["state"] for v in d["vulnerabilities"]] if d else []
check("converter: repeated statements -> the latest timestamp wins", c == 0 and st_ == ["not_affected"], (st_, e))

ids = {"@context": "https://openvex.dev/ns/v0.2.0", "author": "t", "timestamp": "2026-11-26T20:00:00Z", "statements": [
    {"vulnerability": {"name": "cve-2022-37434"}, "status": "fixed", "products": [{"@id": "pkg:github/madler/zlib@v1.2.11"}]},
    {"vulnerability": {"@id": "https://nvd.nist.gov/vuln/detail/CVE-2023-45853"}, "status": "fixed", "products": [{"@id": "pkg:github/madler/zlib@v1.2.11"}]}]}
c, d, e, o = conv(ids, "ids")
check("converter: lower-case CVE upper-cased; id taken from an @id IRI",
      c == 0 and {v["id"] for v in d["vulnerabilities"]} == {"CVE-2022-37434", "CVE-2023-45853"}, (c, e))
ids["statements"][1]["vulnerability"] = {"@id": "https://example.com/advisories/42"}
c, d, e, o = conv(ids, "ids-bad")
check("converter: no usable vulnerability id -> exit 3", c == 3 and "vulnerability id" in e, e)

nested = json.load(open(SBOM))
z = next(x for x in nested["components"] if x["name"] == "zlib")
nested["components"] = [x for x in nested["components"] if x["name"] != "zlib"]
zc = dict(z); zc.pop("bom-ref")
nested["components"][0]["components"] = [zc]
np_ = os.path.join(TMP, "nested.cdx.json"); json.dump(nested, open(np_, "w"))
c, d, e, o = conv({"@context": "https://openvex.dev/ns/v0.2.0", "author": "t", "timestamp": "2026-11-26T20:00:00Z", "statements": [
    {"vulnerability": {"name": "CVE-2022-37434"}, "status": "fixed", "products": [{"@id": "pkg:github/madler/zlib@v1.2.11"}]}]},
    "nested", sbom=np_)
check("converter: nested SBOM component without bom-ref is found", c == 0 and len(refs(d, "CVE-2022-37434")) == 1 and valid(o), (c, e))

# ---------------- the problem: VEX sent right after the BOM is lost ----------------
st, srv, url = new_dt()
tok = upload_bom(url, "race-old-way")
pr = api(url, "GET", "/api/v1/project/lookup?name=race-old-way&version=1")
api(url, "PUT", "/api/v1/vex", {"project": pr["uuid"], "vex": base64.b64encode(open(vex, "rb").read()).decode()})
wait(url, tok); time.sleep(0.6); st.tick()
s = api(url, "GET", "/mock/state")
check("problem reproduced: VEX right after the BOM is skipped (no findings yet), and the upload reports success",
      s["analyses"] == 0 and "VEX skipped: project has no findings" in s["log"], s)

# ---------------- the fix ----------------
env = {"DT_API_KEY": mock_dt.API_KEY}
tok = upload_bom(url, "fw", "3.1.0")
rep = os.path.join(TMP, "report.json")
code, out, err = run([TOOL, "--url", url, "--vex", vex, "--project-name", "fw", "--project-version", "3.1.0",
                      "--bom-token", tok, "--report", rep, "--wait", "60"], env)
r = json.load(open(rep)) if os.path.exists(rep) else {}
res = {x["vulnId"]: x["result"] for x in r.get("results", [])}
check("tool: waits for analysis, then all statements are accounted for (exit 0)", code == 0, out + err)
check("tool: found CVEs are APPLIED", all(res.get(i) == "APPLIED" for i in ("CVE-2022-37434", "CVE-2019-11834", "CVE-2021-3711")), res)
check("tool: known CVE without a finding is STORED", res.get("CVE-2021-44228") == "STORED", res)
check("tool: unknown CVE is PENDING_UNKNOWN_VULN", res.get("CVE-2099-99999") == "PENDING_UNKNOWN_VULN", res)
check("tool: overall result PENDING, listed on stdout", r.get("result") == "PENDING" and "PENDING_UNKNOWN_VULN: CVE-2099-99999" in out, out)
states = {x["vulnId"]: (x.get("gotState"), x.get("suppressed")) for x in r.get("results", [])}
check("tool: states and suppression as expected",
      states.get("CVE-2022-37434") == ("RESOLVED", True) and states.get("CVE-2019-11834") == ("NOT_AFFECTED", True)
      and states.get("CVE-2021-3711") == ("IN_TRIAGE", False), states)
code, out, _ = run([TOOL, "--url", url, "--vex", vex, "--project-name", "fw", "--project-version", "3.1.0",
                    "--fail-on-pending", "--verify-only"], env)
check("tool: --fail-on-pending exits 4", code == 4, out)

# a statement DT does not apply (simulated DT bug) must fail
st.drop_vuln_ids.add("CVE-2019-11834")
tok = upload_bom(url, "fw-bug", "1")
code, out, _ = run([TOOL, "--url", url, "--vex", vex, "--project-name", "fw-bug", "--project-version", "1",
                    "--bom-token", tok, "--wait", "60"], env)
check("tool: statement DT did not apply -> NOT_APPLIED, exit 1", code == 1 and "NOT_APPLIED: CVE-2019-11834" in out, out)
st.drop_vuln_ids.clear()

# a VEX that names a component the project lacks must fail
bad = json.load(open(vex))
bad["components"][0]["purl"] = "pkg:github/acme/other@1.0"; bad["components"][0]["name"] = "other"
bad["components"][0].pop("cpe", None)
badp = os.path.join(TMP, "nocomp.vex.cdx.json"); json.dump(bad, open(badp, "w"))
code, out, _ = run([TOOL, "--url", url, "--vex", badp, "--project-name", "fw", "--project-version", "3.1.0", "--verify-only"], env)
check("tool: component not in the project -> NO_COMPONENT, exit 1", code == 1 and "NO_COMPONENT" in out, out)

# a project with no findings: DT would ignore the VEX, so the tool does not upload and says so
st2, srv2, url2 = new_dt()
st2.rules = []
tok = upload_bom(url2, "clean", "1")
before = api(url2, "GET", "/mock/state")["vexUploads"]
code, out, _ = run([TOOL, "--url", url2, "--vex", vex, "--project-name", "clean", "--project-version", "1",
                    "--bom-token", tok, "--wait", "60"], env)
after = api(url2, "GET", "/mock/state")["vexUploads"]
check("tool: project without findings -> PENDING_NO_FINDINGS, no upload", code == 0 and after == before and "PENDING_NO_FINDINGS" in out, out)

# auth and errors
code, out, err = run([TOOL, "--url", url, "--vex", vex, "--project-name", "fw", "--project-version", "3.1.0"], {"DT_API_KEY": "wrong"})
check("tool: wrong API key -> exit 2", code == 2 and "401" in err, err)
code, out, err = run([TOOL, "--url", url, "--vex", vex, "--project-name", "nope", "--project-version", "1"], env)
check("tool: unknown project -> exit 2", code == 2 and "not found" in err, err)

# paging: more than 100 components and findings
big = json.load(open(SBOM))
for i in range(130):
    big["components"].append({"type": "library", "bom-ref": f"x{i}", "name": "zlib", "version": "1.2.11",
                              "purl": f"pkg:generic/zlib-copy-{i}@1.2.11"})
bigp = os.path.join(TMP, "big.cdx.json"); json.dump(big, open(bigp, "w"))
SBOM_SAVE, SBOM = SBOM, bigp
tok = upload_bom(url, "fw-big", "1")
SBOM = SBOM_SAVE
code, out, _ = run([TOOL, "--url", url, "--vex", vex, "--project-name", "fw-big", "--project-version", "1",
                    "--bom-token", tok, "--report", rep, "--wait", "60"], env)
r = json.load(open(rep))
n_zlib = sum(1 for x in r["results"] if x["vulnId"] == "CVE-2022-37434" and x["result"] == "APPLIED")
# DT matches by purl OR CPE OR group+name+version, so the VEX applies to all 131 zlib 1.2.11 components
check("tool: pages past 100 findings and components (all 131 zlib 1.2.11 matched, as DT matches name+version)",
      code == 0 and r["findingsBefore"] > 100 and n_zlib == 131, (code, r.get("findingsBefore"), n_zlib))

# ---------------- review findings ----------------
# an older analysis with the same state but other details must not count as applied
st.drop_vuln_ids.add("CVE-2022-37434")
tok = upload_bom(url, "fw-stale", "1"); wait(url, tok); time.sleep(0.2); st.tick()
p = st.project("fw-stale", "1")
z = next(c for c in p["components"].values() if c["name"] == "zlib")
vz = st.vulns[("NVD", "CVE-2022-37434")]["uuid"]
p["analyses"][(z["uuid"], vz)] = {"analysisState": "RESOLVED", "isSuppressed": True, "analysisJustification": "NOT_SET",
                                  "analysisResponse": "UPDATE", "analysisDetails": "an older note"}
code, out, _ = run([TOOL, "--url", url, "--vex", vex, "--project-name", "fw-stale", "--project-version", "1"], env)
check("tool: stale analysis with the same state but other details -> NOT_APPLIED", code == 1 and "NOT_APPLIED: CVE-2022-37434" in out and "details" in out, out)
st.drop_vuln_ids.clear()

# a VEX for another product must fail even when the project has no findings
st3, srv3, url3 = new_dt(); st3.rules = []
tok = upload_bom(url3, "clean2", "1")
code, out, _ = run([TOOL, "--url", url3, "--vex", badp, "--project-name", "clean2", "--project-version", "1", "--bom-token", tok, "--wait", "60"], env)
check("tool: wrong-product VEX on a project without findings -> NO_COMPONENT, exit 1", code == 1 and "NO_COMPONENT" in out, out)

empty = dict(json.load(open(vex)), vulnerabilities=[]); ep = os.path.join(TMP, "empty.vex.cdx.json"); json.dump(empty, open(ep, "w"))
code, out, err = run([TOOL, "--url", url, "--vex", ep, "--project-name", "fw", "--project-version", "3.1.0"], env)
check("tool: VEX without statements -> error", code == 2 and "no statements" in err, err)

# DT falls back to the id alone when source+id is unknown; so must the check
st4, srv4, url4 = new_dt()
st4.add_vuln("OSV-2099-1", source="OSV", affects=[("zlib", "1.2.11")])
st4.add_vuln("GHSA-aaaa-bbbb-cccc", source="GITHUB", affects=[("cjson", "1.7.10")], aliases=[{"cveId": "CVE-2099-0002"}])
st4.add_vuln("CVE-2099-0002", source="NVD")                     # known, but cJSON's finding is the GHSA record
tok = upload_bom(url4, "fw4", "1")
v4 = json.load(open(vex))
zref = next(c["bom-ref"] for c in v4["components"] if c["name"] == "zlib")
cref = next(c["bom-ref"] for c in v4["components"] if c["name"] == "cjson")
v4["vulnerabilities"] = [
    {"id": "OSV-2099-1", "source": {"name": "NVD"}, "analysis": {"state": "resolved"}, "affects": [{"ref": zref}]},
    {"id": "CVE-2099-0002", "source": {"name": "NVD"}, "analysis": {"state": "not_affected", "justification": "code_not_present",
     "detail": "x"}, "affects": [{"ref": cref}]}]
p4 = os.path.join(TMP, "fallback.vex.cdx.json"); json.dump(v4, open(p4, "w"))
code, out, _ = run([TOOL, "--url", url4, "--vex", p4, "--project-name", "fw4", "--project-version", "1",
                    "--bom-token", tok, "--report", rep, "--wait", "60"], env)
res = {x["vulnId"]: x["result"] for x in json.load(open(rep))["results"]}
check("tool: source fallback like DT (id known only under OSV) -> APPLIED", res.get("OSV-2099-1") == "APPLIED", (res, out))
check("tool: finding open under another record (GHSA alias) -> OPEN_UNDER_ALIAS", res.get("CVE-2099-0002") == "OPEN_UNDER_ALIAS", (res, out))

# daily re-run: only the pending statements are uploaded
tok = upload_bom(url, "fw-pend", "1")
rep1 = os.path.join(TMP, "rep1.json"); rep2 = os.path.join(TMP, "rep2.json")
run([TOOL, "--url", url, "--vex", vex, "--project-name", "fw-pend", "--project-version", "1", "--bom-token", tok,
     "--report", rep1, "--wait", "60"], env)
st.add_vuln("CVE-2099-99999", affects=[("zlib", "1.2.11")])     # the CVE becomes known, and a later analysis finds it
pp = st.project("fw-pend", "1"); z = next(c for c in pp["components"].values() if c["name"] == "zlib")
pp["findings"].add((z["uuid"], st.vulns[("NVD", "CVE-2099-99999")]["uuid"]))
cj = next(c for c in pp["components"].values() if c["name"] == "cjson")
v11834 = st.vulns[("NVD", "CVE-2019-11834")]["uuid"]
pp["analyses"][(cj["uuid"], v11834)]["analysisState"] = "EXPLOITABLE"   # a human re-triaged it after the VEX
pp["analyses"][(cj["uuid"], v11834)]["isSuppressed"] = False
code, out, _ = run([TOOL, "--url", url, "--vex", vex, "--project-name", "fw-pend", "--project-version", "1",
                    "--pending-from", rep1, "--report", rep2, "--wait", "60"], env)
r2 = json.load(open(rep2))
check("tool: --pending-from uploads only the pending statement, which is now APPLIED",
      code == 0 and len(st.last_vex["vulnerabilities"]) == 1 and r2["counts"] == {"APPLIED": 1}, (code, r2.get("counts"), out))
check("tool: --pending-from leaves the human re-triage alone",
      pp["analyses"][(cj["uuid"], v11834)]["analysisState"] == "EXPLOITABLE")

code, out, err = run([TOOL, "--url", "http://dt.example.com", "--vex", vex, "--project-uuid", "x"], env)
check("tool: refuses http:// to a remote server", code == 2 and "refusing http" in err, err)
code, out, err = run([TOOL, "--url", "http://dtrack:8080", "--vex", vex, "--project-uuid", "x"], env)
check("tool: refuses http:// to a dot-less LAN name without --allow-http", code == 2 and "refusing http" in err, err)

# a statement on the product itself (the SBOM root) applies to every component with the finding, as in DT
tok = upload_bom(url, "fw-root", "1")
rootvex = os.path.join(TMP, "root.vex.cdx.json")
run([CONV, "--sbom", SBOM, "--openvex", os.path.join(TMP, "root.openvex.json"), "--out", rootvex])
code, out, _ = run([TOOL, "--url", url, "--vex", rootvex, "--project-name", "fw-root", "--project-version", "1",
                    "--bom-token", tok, "--report", rep, "--wait", "60"], env)
rr = json.load(open(rep))["results"]
check("tool: project-scoped statement (root ref) is applied to the component with the finding",
      code == 0 and [(x["componentName"], x["result"]) for x in rr] == [("zlib@1.2.11", "APPLIED")], (code, rr, out))

# a hand-written lower-case source: DT falls back to the id and finds the NVD record; so must the check
lc = json.load(open(vex)); lc["vulnerabilities"] = [dict(lc["vulnerabilities"][0], source={"name": "nvd"})]
lcp = os.path.join(TMP, "lc.vex.cdx.json"); json.dump(lc, open(lcp, "w"))
code, out, _ = run([TOOL, "--url", url, "--vex", lcp, "--project-name", "fw", "--project-version", "3.1.0", "--verify-only"], env)
check("tool: lower-case source 'nvd' resolves like DT", code == 0 and "PENDING_UNKNOWN_VULN" not in out, out)

# OPEN_UNDER_ALIAS is a warning: --pending-from does not re-apply it every day
rep4 = os.path.join(TMP, "rep4.json")
run([TOOL, "--url", url4, "--vex", p4, "--project-name", "fw4", "--project-version", "1", "--verify-only", "--report", rep4], env)
before = st4.vex_uploads
code, out, _ = run([TOOL, "--url", url4, "--vex", p4, "--project-name", "fw4", "--project-version", "1", "--pending-from", rep4], env)
check("tool: --pending-from does not re-upload OPEN_UNDER_ALIAS statements", code == 0 and st4.vex_uploads == before and "nothing pending" in out, out)
code, out, err = run([TOOL, "--url", url, "--vex", vex, "--project-name", "fw", "--project-version", "3.1.0",
                      "--bom-token", "00000000-0000-0000-0000-000000000000", "--wait", "5"], env)
check("tool: unknown BOM token -> error, not a silent pass", code == 2 and "knows no run" in err, err)

failed = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(failed)} of {len(results)} checks passed")
sys.exit(1 if failed else 0)
