#!/usr/bin/env python3
"""Tests for gap 2 (vulnerability data can stop silently): ci/dt-health-check.py against tests/mock_dt.py
(Dependency-Track 5.2.1 extensions, mirror runs, analyzers and their reconciliation) and a fake NVD feed
adapter (/health, /candidates/sample).

usage: python3 tests/test_health_gap2.py        (from cpp-sboms/; no network, standard library only)
"""
import base64, json, os, subprocess, sys, tempfile, threading, time, urllib.parse, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import mock_dt  # noqa: E402

TOOL = os.path.join(ROOT, "ci", "dt-health-check.py")
CONFIG = os.path.join(ROOT, "ci", "health", "dt-health.json")
CANARY = os.path.join(ROOT, "ci", "health", "dt-health-canary.cdx.json")
TMP = tempfile.mkdtemp(prefix="healthgap2-")
LEAST = {"VIEW_PORTFOLIO", "VIEW_VULNERABILITY", "SYSTEM_CONFIGURATION_READ", "BOM_UPLOAD", "PROJECT_CREATION_UPLOAD"}
results = []


def check(name, cond, detail=""):
    results.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{str(detail)[:700]}]" if detail and not cond else ""))


class FakeAdapter:
    def __init__(self):
        self.code, self.problems, self.warnings, self.sample, self.queries = 200, [], [], [], []
        self.candidates = 62000
        self.trivy_updated, self.trivy_code, self.health_body = time.strftime("%Y-%m-%dT%H:%M:%S.123456Z", time.gmtime(time.time() - 3 * 3600)), 200, None
        ad = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def reply(self, code, body):
                raw = json.dumps(body).encode()
                self.send_response(code); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

            def do_GET(self):
                if self.headers.get("X-Api-Key") or self.headers.get("Authorization"):
                    return self.reply(400, {"error": "the DT key must not be sent to the adapter or Trivy"})
                u = urllib.parse.urlparse(self.path)
                if u.path == "/version":   # the Trivy server
                    if ad.trivy_code != 200:
                        return self.reply(ad.trivy_code, {})
                    return self.reply(200, {"Version": "0.76.2", "VulnerabilityDB": {"Version": 2, "UpdatedAt": ad.trivy_updated}})
                if u.path == "/health" and ad.health_body is not None:
                    return self.reply(ad.code, ad.health_body)
                if u.path == "/health":
                    return self.reply(ad.code, {"status": "ok" if ad.code == 200 else "degraded", "problems": ad.problems,
                                                "warnings": ad.warnings, "nist": {"age_hours": 0.5},
                                                "vulncheck": {"age_hours": 3, "candidates": ad.candidates, "records": 424000,
                                                              "vc_has_cpes": 379000}})
                if u.path == "/candidates/sample":
                    ad.queries.append(urllib.parse.parse_qs(u.query))
                    return self.reply(200, {"candidates": 62000, "eligible": len(ad.sample),
                                            "sample": [{"id": i, "cpe_products": ["x:y"]} for i in ad.sample]})
                self.reply(404, {})
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"


def ago(hours):
    return int((time.time() - hours * 3600) * 1000)


def new_stack(perms=None):
    st = mock_dt.State(import_delay=0.2, analysis_delay=0.4, vex_delay=0.1)
    ad = FakeAdapter()
    st.add_extension("vuln-data-source", "nvd", testable=True, config={"cveFeedsUrl": ad.url + "/feeds"})
    st.add_extension("vuln-data-source", "osv", config={"ecosystems": ["NuGet"]})
    st.add_extension("vuln-data-source", "github", enabled=False)
    st.add_extension("vuln-data-source", "jvn", enabled=False, testable=True)
    st.add_extension("kev-data-source", "cisa")
    st.add_extension("kev-data-source", "enisa")
    st.add_extension("kev-data-source", "vulncheck", enabled=False)
    st.add_extension("vuln-analyzer", "internal")
    st.add_extension("vuln-analyzer", "oss-index", testable=True, config={"apiToken": "OSSINDEX_API_TOKEN"},
                     test=[{"name": "connection", "status": "PASSED"}, {"name": "authentication", "status": "PASSED"}])
    st.add_extension("vuln-analyzer", "trivy", config={"apiUrl": ad.url, "apiToken": "TRIVY_API_TOKEN"})
    st.add_extension("vuln-analyzer", "snyk", enabled=False)
    for k in [("vuln-data-source", "nvd"), ("vuln-data-source", "osv"), ("kev-data-source", "cisa"), ("kev-data-source", "enisa")]:
        st.mirror_runs[k] = {"status": "COMPLETED", "started_at": ago(2.1), "completed_at": ago(2)}
    st.add_rule("CVE-2022-37434", "NVD", "internal", cpe="cpe:2.3:a:zlib:zlib:1.2.11:*:*:*:*:*:*:*")
    st.add_rule("CVE-2018-25032", "NVD", "internal", cpe="cpe:2.3:a:zlib:zlib:1.2.11:*:*:*:*:*:*:*")
    st.add_rule("CVE-2019-11834", "NVD", "internal", cpe="cpe:2.3:a:cjson_project:cjson:1.7.10:*:*:*:*:*:*:*")
    for cid in ("CVE-2018-25032", "CVE-2022-37434", "CVE-2023-45853", "CVE-2026-22184"):
        st.add_rule(cid, "NVD", "oss-index", purl="pkg:conan/zlib@1.2.11")
    st.add_rule("CVE-2022-37434", "NVD", "trivy", purl="pkg:conan/zlib@1.2.11")   # shown as oss-index (first)
    st.add_rule("GHSA-7jgj-8wvc-jh57", "GITHUB", "internal", purl="pkg:nuget/System.Net.Http@4.3.0")
    st.add_rule("CVE-2018-8292", "NVD", "trivy", purl="pkg:nuget/system.net.http@4.3.0")
    ad.sample = [f"CVE-2026-{9000 + i}" for i in range(10)]
    for cid in ad.sample:
        st.add_vuln(cid, "NVD", cpes=[f"cpe:2.3:a:v:p{cid[-1]}:1:*:*:*:*:*:*:*"])
    st.notification_rules = [{"uuid": "r1", "name": "Mirror failures to platform", "enabled": True, "scope": "SYSTEM",
                              "notificationLevel": "ERROR", "notifyOn": ["DATASOURCE_MIRRORING"],
                              "publisher": {"name": "Outbound Webhook", "extensionName": "webhook"}}]
    st.perms = perms
    srv, url = mock_dt.serve(st)
    cfg = json.load(open(CONFIG, encoding="utf-8"))
    cfg["nvd_feeds_url"] = ad.url + "/feeds"
    cfg["canary"]["sbom"] = CANARY
    cpath = os.path.join(TMP, f"cfg-{id(st)}.json")
    json.dump(cfg, open(cpath, "w"), indent=1)
    return st, ad, url, cpath, cfg


def run_tool(url, cpath, *extra, key=mock_dt.API_KEY, bearer=None):
    rpt = os.path.join(TMP, f"r-{time.time_ns()}.json")
    env = {k: v for k, v in os.environ.items() if k not in ("DT_API_KEY", "DT_BEARER")}
    env.update({"DT_BEARER": bearer} if bearer else {"DT_API_KEY": key})
    p = subprocess.run([sys.executable, "-I", TOOL, "--url", url, "--config", cpath, "--report", rpt, "--wait", "60",
                        *extra], capture_output=True, text=True, env=env, timeout=300)
    rep = json.load(open(rpt)) if os.path.exists(rpt) else {}
    return p.returncode, rep, p.stdout + p.stderr


def find(rep, area=None, name=None, status=None):
    return [c for c in rep.get("checks", []) if (area is None or c["area"] == area) and (name is None or c["name"] == name)
            and (status is None or c["status"] == status)]


def expectations_ok(rep):
    return [c for c in find(rep, "canary", status="ok") if c["name"] != "analysis-latency"]


def problems(rep):
    return [f"{c['area']}/{c['name']}: {c['detail']}" for c in find(rep, status="problem")]


# ---------------------------------------------------------------- healthy, least privilege
st, ad, url, cpath, cfg = new_stack(perms=LEAST | {"SYSTEM_CONFIGURATION_UPDATE"})
code, rep, out = run_tool(url, cpath, "--test-extensions", "--state", os.path.join(TMP, "state.json"))
check("healthy stack: exit 0, PASS", code == 0 and rep.get("result") == "PASS", problems(rep) or out)
check("... 5 canary expectations ok, and the analysis latency", len(expectations_ok(rep)) == 5
      and find(rep, "canary", "analysis-latency", "ok"), find(rep, "canary"))
check("... 4 mirror runs ok, disabled sources not checked", len(find(rep, "mirror", status="ok")) == 4
      and not find(rep, "mirror", "vuln-data-source/github"), find(rep, "mirror"))
check("... live tests ran for nvd and oss-index only (enabled and testable)",
      sorted(c["name"] for c in find(rep, "test")) == ["vuln-analyzer/oss-index", "vuln-data-source/nvd"], find(rep, "test"))
check("... VulnCheck sample: 10 of 10 in DT", "10 of 10" in (find(rep, "vulncheck", "in-dt", "ok") or [{"detail": ""}])[0]["detail"],
      find(rep, "vulncheck"))
sb = int(ad.queries[-1]["served_before"][0]) if ad.queries else 0
check("... sample asked for CVEs served 6 h before the NVD run started",
      abs(sb - (st.mirror_runs[("vuln-data-source", "nvd")]["started_at"] - 6 * 3600 * 1000)) < 1000, ad.queries)
p = next(iter(st.projects.values()))
check("... canary project created with its tag", p["name"] == "dt-health-canary" and "dt-health-canary" in p.get("tags", ()), p)
g1 = {c["group"] for c in p["components"].values()}
code2, rep2, _ = run_tool(url, cpath, "--state", os.path.join(TMP, "state.json"))
g2 = {c["group"] for c in p["components"].values()}
check("rotation: the second run re-creates the 4 components in the other group",
      g1 == {"dt-health-canary-a"} and g2 == {"dt-health-canary-b"} and len(p["components"]) == 4 and code2 == 0,
      (g1, g2, len(p["components"]), problems(rep2)))
code, rep, out = run_tool(url, cpath, "--test-extensions", key="wrong-key")
check("wrong API key: exit 2 (cannot check), not PASS", code in (1, 2) and rep.get("result") != "PASS", out[-300:])
code, rep, out = run_tool("http://127.0.0.1:9", cpath)
check("DT unreachable: exit 2", code == 2 and rep.get("result") == "ERROR", out[-300:])

# ---------------------------------------------------------------- least privilege without UPDATE
st, ad, url, cpath, cfg = new_stack(perms=LEAST)
code, rep, out = run_tool(url, cpath)
check("least-privilege key (5 permissions): PASS without --test-extensions", code == 0, problems(rep) or out)
code, rep, out = run_tool(url, cpath, "--test-extensions")
check("... --test-extensions without SYSTEM_CONFIGURATION_UPDATE: a problem that names the permission",
      code == 1 and any("SYSTEM_CONFIGURATION_UPDATE" in c["detail"] for c in find(rep, "test", status="problem")), problems(rep))
st.perms = LEAST - {"SYSTEM_CONFIGURATION_READ"}
code, rep, out = run_tool(url, cpath)
check("... key without SYSTEM_CONFIGURATION_READ: problems, not a silent pass",
      code == 1 and any("permission" in x for x in problems(rep)), problems(rep))
st.perms = LEAST

# ---------------------------------------------------------------- mirror runs
st.mirror_runs[("vuln-data-source", "nvd")] = {"status": "FAILED", "started_at": ago(3), "completed_at": ago(2.9),
                                               "failure_reason": "Connection refused: nvdpp:8080"}
st.mirror_runs[("vuln-data-source", "osv")] = {"status": "COMPLETED", "started_at": ago(40.2), "completed_at": ago(40)}
st.mirror_runs[("kev-data-source", "cisa")] = None
st.mirror_runs[("kev-data-source", "enisa")] = {"status": "RUNNING", "started_at": ago(2)}
code, rep, out = run_tool(url, cpath, "--no-canary")
pr = " | ".join(problems(rep))
check("NVD mirror FAILED: problem with DT's reason", code == 1 and "FAILED" in pr and "Connection refused" in pr, pr)
check("OSV mirror 40 h old: problem (limit 30 h)", "completed 40.0 h ago (limit 30 h)" in pr, pr)
check("CISA KEV never mirrored: problem", "kev-data-source/cisa: no mirror run recorded" in pr, pr)
check("ENISA KEV running for 2 h: a warning, not a problem",
      find(rep, "mirror", "kev-data-source/enisa", "warning") and "enisa" not in pr, find(rep, "mirror"))
check("... the VulnCheck sample is skipped (no completed NVD run)", find(rep, "vulncheck", "in-dt", "warning"), find(rep, "vulncheck"))
st.mirror_runs[("kev-data-source", "enisa")] = {"status": "RUNNING", "started_at": ago(50)}
code, rep, out = run_tool(url, cpath, "--no-canary")
check("ENISA KEV running for 50 h: problem (stuck)", "RUNNING for 50.0 h" in " | ".join(problems(rep)), problems(rep))
for k in [("vuln-data-source", "nvd"), ("vuln-data-source", "osv"), ("kev-data-source", "cisa"), ("kev-data-source", "enisa")]:
    st.mirror_runs[k] = {"status": "COMPLETED", "started_at": ago(2.1), "completed_at": ago(2)}
code, rep, out = run_tool(url, cpath, "--no-canary", "--max-age-hours", "1")
check("--max-age-hours 1 with runs 2 h old: 4 mirror problems", len(find(rep, "mirror", status="problem")) == 4, find(rep, "mirror"))

# ---------------------------------------------------------------- configuration
st.extensions["vuln-data-source"]["nvd"]["config"]["cveFeedsUrl"] = "https://nvd.nist.gov/feeds"
code, rep, out = run_tool(url, cpath, "--no-canary")
pr = " | ".join(problems(rep))
check("NVD source switched back to NIST: problem (VulnCheck CPEs and aliases no longer reach DT)",
      code == 1 and "cveFeedsUrl is https://nvd.nist.gov/feeds" in pr, pr)
check("... and the adapter is reported missing (required)", "no NVD feed adapter" in pr, pr)
st.extensions["vuln-data-source"]["nvd"]["config"]["cveFeedsUrl"] = ad.url + "/feeds"
st.extensions["vuln-analyzer"]["trivy"]["config"]["enabled"] = False
code, rep, out = run_tool(url, cpath)
pr = " | ".join(problems(rep))
check("required analyzer trivy disabled: problem, and its canary expectation is skipped",
      code == 1 and "vuln-analyzer/trivy: required, but disabled" in pr and find(rep, "canary", "trivy", "skipped"), pr)
st.extensions["vuln-analyzer"]["trivy"]["config"]["enabled"] = True

# ---------------------------------------------------------------- analyzers that fail quietly
code, rep, out = run_tool(url, cpath)
check("baseline before the analyzer faults: PASS", code == 0, problems(rep))
st.failing = {"trivy"}
code, rep, out = run_tool(url, cpath)
check("trivy fails (server down): the trivy expectation fails, the others pass",
      code == 1 and [c["name"] for c in find(rep, "canary", status="problem")] == ["trivy"], find(rep, "canary"))
st.failing = {"internal"}
code, rep, out = run_tool(url, cpath)
check("internal analyzer fails: nvd-cpe, nvd-alias and osv expectations fail (fresh components)",
      code == 1 and sorted(c["name"] for c in find(rep, "canary", status="problem")) == ["nvd-alias", "nvd-cpe", "osv"],
      find(rep, "canary"))
st.failing = set()
cfg_nr = dict(cfg, canary=dict(cfg["canary"], rotate=False))
cnr = os.path.join(TMP, "cfg-norotate.json"); json.dump(cfg_nr, open(cnr, "w"))
run_tool(url, cnr)
st.failing = {"internal"}
code, rep, out = run_tool(url, cnr)
check("without rotation the same failure is hidden by the old findings (why rotate is the default)",
      code == 0 and not find(rep, "canary", status="problem"), find(rep, "canary"))
st.failing = set()
st.extensions["vuln-analyzer"]["oss-index"]["test"] = [{"name": "connection", "status": "PASSED"},
                                                      {"name": "authentication", "status": "FAILED",
                                                       "message": "Authentication failed with status 401"}]
st.perms = LEAST | {"SYSTEM_CONFIGURATION_UPDATE"}
code, rep, out = run_tool(url, cpath, "--test-extensions")
check("OSS Index token revoked (cached results still give findings): the live test reports it",
      code == 1 and any("authentication FAILED: Authentication failed with status 401" in c["detail"]
                        for c in find(rep, "test", "vuln-analyzer/oss-index", "problem"))
      and not find(rep, "canary", status="problem"), problems(rep))
st.extensions["vuln-analyzer"]["oss-index"]["test"] = [{"name": "connection", "status": "PASSED"}]
st.perms = LEAST

# ---------------------------------------------------------------- adapter
ad.code, ad.problems = 503, ["VulnCheck rejected the token: HTTPError: HTTP Error 401"]
code, rep, out = run_tool(url, cpath, "--no-canary")
check("adapter /health 503: its problems are reported", code == 1 and
      any("401" in c["detail"] for c in find(rep, "adapter", "health", "problem")), problems(rep))
ad.code, ad.problems, ad.warnings = 200, [], ["the last refresh from NIST failed: 503"]
code, rep, out = run_tool(url, cpath, "--no-canary")
check("adapter warnings stay warnings: PASS", code == 0 and find(rep, "adapter", "health", "warning"), problems(rep))
ad.warnings = []
ad.srv.shutdown(); ad.srv.server_close()
code, rep, out = run_tool(url, cpath, "--no-canary")
check("adapter stopped: problem", code == 1 and any("does not answer" in c["detail"] for c in find(rep, "adapter")), problems(rep))

# ---------------------------------------------------------------- VulnCheck CPEs in DT
st, ad, url, cpath, cfg = new_stack(perms=LEAST)
for cid in ad.sample[:3]:
    st.vulns[("NVD", cid)].pop("affectedComponents")
code, rep, out = run_tool(url, cpath, "--no-canary")
check("3 of 10 sampled enriched CVEs without CPEs in DT: problem (70% < 90%)",
      code == 1 and "7 of 10" in " ".join(c["detail"] for c in find(rep, "vulncheck", "in-dt", "problem")), find(rep, "vulncheck"))
st.vulns[("NVD", ad.sample[0])]["affectedComponents"] = [{"identityType": "CPE", "identity": "cpe:2.3:a:v:p:1"}]
st.vulns[("NVD", ad.sample[1])]["affectedComponents"] = [{"identityType": "CPE", "identity": "cpe:2.3:a:v:p:1"}]
code, rep, out = run_tool(url, cpath, "--no-canary")
check("... 9 of 10: ok (min_ratio 0.9)", code == 0 and find(rep, "vulncheck", "in-dt", "ok"), find(rep, "vulncheck"))
del st.vulns[("NVD", ad.sample[2])]
st.vulns[("NVD", ad.sample[3])]["affectedComponents"] = []
code, rep, out = run_tool(url, cpath, "--no-canary")
d = " ".join(c["detail"] for c in find(rep, "vulncheck"))
check("... CVE unknown to DT and CVE with no CPE are named", "(not in DT)" in d and "(no CPE in DT)" in d, d)

# ---------------------------------------------------------------- DT's own alerts
st, ad, url, cpath, cfg = new_stack(perms=LEAST)
code, rep, out = run_tool(url, cpath, "--no-canary")
check("alerts: an enabled SYSTEM rule for DATASOURCE_MIRRORING: ok", code == 0 and find(rep, "alerts", "DATASOURCE_MIRRORING", "ok"),
      find(rep, "alerts"))
st.notification_rules[0]["enabled"] = False
code, rep, out = run_tool(url, cpath, "--no-canary")
check("... rule disabled: problem (DT would not report failed mirrors itself)",
      code == 1 and find(rep, "alerts", "DATASOURCE_MIRRORING", "problem"), find(rep, "alerts"))
st.notification_rules[0].update(enabled=True, scope="PORTFOLIO")
code, rep, out = run_tool(url, cpath, "--no-canary")
check("... rule with PORTFOLIO scope: problem", code == 1 and find(rep, "alerts", "DATASOURCE_MIRRORING", "problem"), find(rep, "alerts"))
st.notification_rules[0]["scope"] = "SYSTEM"
st.notification_rules.append({"uuid": "r2", "name": "Analyzer errors to Slack", "enabled": True, "scope": "SYSTEM",
                              "notificationLevel": "ERROR", "notifyOn": ["ANALYZER"],
                              "publisher": {"name": "Slack", "extensionName": "slack"}})
code, rep, out = run_tool(url, cpath, "--no-canary")
check("scale: ANALYZER sent to Slack (one per project): a warning, still PASS",
      code == 0 and find(rep, "alerts", "rule Analyzer errors to Slack", "warning"), find(rep, "alerts"))
st.notification_rules[1]["publisher"] = {"name": "Outbound Webhook", "extensionName": "webhook"}
code, rep, out = run_tool(url, cpath, "--no-canary")
check("... ANALYZER sent to a webhook (a receiver that can group): no warning", code == 0 and not find(rep, "alerts", status="warning"),
      find(rep, "alerts"))
st.perms = LEAST - {"SYSTEM_CONFIGURATION_READ"}
code, rep, out = run_tool(url, cpath, "--no-canary")
check("... rules unreadable without SYSTEM_CONFIGURATION_READ: problem", find(rep, "alerts", "rules", "problem"), find(rep, "alerts"))
st.perms = LEAST

# ---------------------------------------------------------------- scale
st, ad, url, cpath, cfg = new_stack(perms=LEAST)
run_tool(url, cpath)                       # creates the canary project


def grow(n0, n):                           # a big portfolio: projects with 20 components and findings each
    for i in range(n0, n0 + n):
        pp = st.project(f"product-{i}", "1", create=True)
        pp["lastBomImport"] = pp["lastVulnerabilityAnalysis"] = int((time.time() - 3 * 3600) * 1000)
        for j in range(20):
            cu = f"p{i}-c{j}"
            pp["components"][cu] = {"uuid": cu, "_id": 0, "group": None, "name": f"lib{j}", "version": "1", "purl": None, "cpe": None}
            pp["findings"].add((cu, "v"))


grow(0, 5000)
code, rep_5k, out = run_tool(url, cpath)
grow(5000, 5000)
code2, rep_10k, out = run_tool(url, cpath)
c5, c10 = rep_5k.get("apiCallsExcludingPolls"), rep_10k.get("apiCallsExcludingPolls")
check("scale: DT API calls do not grow with the portfolio (5,000 -> 10,000 projects, 200,000 components)",
      code == 0 and code2 == 0 and c5 and c10 == c5, (c5, c10, problems(rep_5k), problems(rep_10k)))
check("... and stay within a budget of 80 calls per run (token polls apart)", c10 and c10 <= 80, c10)
st.d_analysis = 45                         # DT's analysis is behind (a burst of uploads ahead of the canary)
code, rep, out = run_tool(url, cpath, "--wait", "20")
lat = find(rep, "canary", "analysis-latency", "problem")
check("analysis behind (canary not analysed within the limit): its own problem, no analyzer blamed",
      code == 1 and lat and "still running" in lat[0]["detail"] and len(find(rep, "canary", status="problem")) == 1
      and not [c for c in find(rep, "canary") if c["name"] not in ("analysis-latency",)], find(rep, "canary"))
check("... token polls are counted apart and bounded (at most 6 + wait/30)",
      rep.get("tokenPolls") and rep["tokenPolls"] <= 6 + 20 / 30 + 1 and rep["apiCallsExcludingPolls"] == rep["apiCalls"] - rep["tokenPolls"],
      {k: rep.get(k) for k in ("apiCalls", "tokenPolls", "apiCallsExcludingPolls")})
time.sleep(30)                             # let that slow analysis finish before the next run
st.d_analysis = 0.4
cfg_w = dict(cfg, canary=dict(cfg["canary"], warn_analysis_minutes=0.001))
cw = os.path.join(TMP, "cfg-warn.json"); json.dump(cfg_w, open(cw, "w"))
code, rep, out = run_tool(url, cw)
check("... slower than warn_analysis_minutes: a warning, still PASS", code == 0 and find(rep, "canary", "analysis-latency", "warning"),
      find(rep, "canary"))

# ---------------------------------------------------------------- review findings: stuck runs, portfolio, Trivy DB, edge answers
st, ad, url, cpath, cfg = new_stack(perms=LEAST)
sf = os.path.join(TMP, "stuck-state.json")
st.mirror_runs[("vuln-data-source", "osv")] = {"status": "PENDING"}      # created, never started: no started_at
code, rep, out = run_tool(url, cpath, "--no-canary")
check("PENDING run without --state: a warning that asks for --state", code == 0 and
      "keep --state" in find(rep, "mirror", "vuln-data-source/osv", "warning")[0]["detail"], find(rep, "mirror", "vuln-data-source/osv"))
code, rep, out = run_tool(url, cpath, "--no-canary", "--state", sf)
check("... first seen with --state: still a warning", code == 0 and find(rep, "mirror", "vuln-data-source/osv", "warning"), find(rep, "mirror"))
stt = json.load(open(sf)); stt["nonterminal"]["vuln-data-source/osv"]["first_seen"] -= 40 * 3600; json.dump(stt, open(sf, "w"))
code, rep, out = run_tool(url, cpath, "--no-canary", "--state", sf)
check("... the same PENDING run seen for 40 h: problem (the source is frozen)", code == 1 and
      "frozen" in " ".join(c["detail"] for c in find(rep, "mirror", "vuln-data-source/osv", "problem")), find(rep, "mirror"))
st.mirror_runs[("vuln-data-source", "osv")] = {"status": "COMPLETED", "started_at": ago(1.1), "completed_at": ago(1)}
code, rep, out = run_tool(url, cpath, "--no-canary", "--state", sf)
check("... finished: ok, and forgotten in the state", code == 0 and "vuln-data-source/osv" not in json.load(open(sf)).get("nonterminal", {}),
      json.load(open(sf)))

for i in range(30):
    pp = st.project(f"old-product-{i}", "1", create=True)
    pp["components"]["c"] = {"uuid": f"o{i}", "_id": 0, "group": None, "name": "x", "version": "1", "purl": None, "cpe": None}
    pp["lastBomImport"] = ago(100); pp["lastVulnerabilityAnalysis"] = ago(60 if i < 12 else 2)
code, rep, out = run_tool(url, cpath, "--no-canary")
pa = find(rep, "portfolio", "re-analysis")
check("portfolio re-analysis: 12 of 30 projects analysed 60 h ago (40% > 10%): problem naming them",
      code == 1 and pa and pa[0]["status"] == "problem" and "old-product" in pa[0]["detail"], pa)
for i in range(12):
    st.project(f"old-product-{i}", "1")["lastVulnerabilityAnalysis"] = ago(2)
code, rep, out = run_tool(url, cpath, "--no-canary")
check("... all analysed recently: ok", code == 0 and find(rep, "portfolio", "re-analysis", "ok"), find(rep, "portfolio"))

ad.trivy_updated = time.strftime("%Y-%m-%dT%H:%M:%S.1Z", time.gmtime(time.time() - 72 * 3600))
code, rep, out = run_tool(url, cpath, "--no-canary")
check("Trivy DB 72 h old: problem (Trivy findings going stale)", code == 1 and find(rep, "trivy", "db", "problem"), find(rep, "trivy"))
ad.trivy_code = 404
code, rep, out = run_tool(url, cpath, "--no-canary")
check("... Trivy gives no DB metadata: a warning only", code == 0 and find(rep, "trivy", "db", "warning"), find(rep, "trivy"))
ad.trivy_code = 200; ad.trivy_updated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600))
code, rep, out = run_tool(url, cpath, "--no-canary")
check("... fresh DB: ok", code == 0 and find(rep, "trivy", "db", "ok"), find(rep, "trivy"))

ad.code, ad.health_body = 503, {"message": "Service Unavailable"}         # e.g. a proxy in front of the adapter
code, rep, out = run_tool(url, cpath, "--no-canary")
check("adapter 503 without a health report: problem, not a silent pass", code == 1 and
      any("without reasons" in c["detail"] for c in find(rep, "adapter", "health", "problem")), problems(rep))
ad.code, ad.health_body = 200, {"status": "ok", "problems": [], "warnings": []}   # 200 without nist/vulncheck
code, rep, out = run_tool(url, cpath, "--no-canary")
check("... adapter 200 without details: no crash", code == 0 and rep.get("result") == "PASS", out[-300:])
ad.health_body = None

st.failing = {"internal", "oss-index", "trivy"}                           # every analyzer fails: DT's token ends FAILED
code, rep, out = run_tool(url, cpath)
check("every analyzer fails (token FAILED): a canary problem, never a pass",
      code == 1 and any("FAILED" in c["detail"] for c in find(rep, "canary", status="problem")), find(rep, "canary"))
st.failing = set()
st.perms = LEAST | {"SYSTEM_CONFIGURATION_UPDATE"}
st.secrets = {"OSSINDEX_API_TOKEN"}
st.extensions["vuln-analyzer"]["oss-index"]["config"]["apiToken"] = "NO_SUCH_SECRET"
code, rep, out = run_tool(url, cpath, "--no-canary", "--test-extensions")
check("live test refused by DT (400: unresolvable secret): a problem, not ok",
      code == 1 and find(rep, "test", "vuln-analyzer/oss-index", "problem"), find(rep, "test"))
st.extensions["vuln-analyzer"]["oss-index"]["config"]["apiToken"] = "OSSINDEX_API_TOKEN"
st.secrets = None
st.perms = LEAST
code, rep, out = run_tool(url, cpath, "--no-canary", bearer=mock_dt.BEARER)
check("DT_BEARER instead of DT_API_KEY works, and the bearer is not sent to the adapter or Trivy", code == 0, problems(rep) or out[-300:])


class Redirect(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        self.send_response(302); self.send_header("Location", ad.url + self.path); self.send_header("Content-Length", "0"); self.end_headers()


rsrv = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
threading.Thread(target=rsrv.serve_forever, daemon=True).start()
code, rep, out = run_tool(f"http://127.0.0.1:{rsrv.server_address[1]}", cpath, "--no-canary")
check("a redirect from DT is not followed (the key would go along): exit 2", code == 2 and "not followed" in out, out[-300:])

# ---------------------------------------------------------------- round 2: portfolio on DT's real fields, headers, survivors
st, ad, url, cpath, cfg = new_stack(perms=LEAST)
for i in range(120):                       # the 20 oldest BOM imports were re-analysed; 100 newer imports never were
    pp = st.project(f"svc-{i:03d}", "1", create=True)
    pp["components"]["c"] = {"uuid": f"s{i}", "_id": 0, "group": None, "name": "x", "version": "1", "purl": None, "cpe": None}
    pp["lastBomImport"] = ago(500 - i)
    pp["lastVulnerabilityAnalysis"] = ago(2) if i < 20 else None
code, rep, out = run_tool(url, cpath, "--no-canary")
pa = (find(rep, "portfolio", "re-analysis") or [{}])[0]
check("portfolio: never-analysed projects beyond the first page are found (total read, random pages)",
      code == 1 and pa.get("status") == "problem" and "never" in pa.get("detail", ""), pa)
st.lower_headers = True                    # Envoy / Istio send header names in lower case
code, rep, out = run_tool(url, cpath, "--no-canary")
pa = (find(rep, "portfolio", "re-analysis") or [{}])[0]
check("... also when the proxy sends x-total-count in lower case", code == 1 and pa.get("status") == "problem"
      and "of 120 active" in pa.get("detail", ""), pa)
st.lower_headers = False
for i in range(20, 120):
    st.project(f"svc-{i:03d}", "1")["lastVulnerabilityAnalysis"] = ago(3)
for i in range(30):                        # just uploaded, first analysis still running: not stale
    pp = st.project(f"new-{i}", "1", create=True)
    pp["components"]["c"] = {"uuid": f"n{i}", "_id": 0, "group": None, "name": "x", "version": "1", "purl": None, "cpe": None}
    pp["lastBomImport"] = ago(0.2)
for i in range(30):                        # collection projects are never analysed themselves; oldest imports first
    cp_ = st.project(f"collection-{i}", "1", create=True)
    cp_["collectionLogic"] = "AGGREGATE_DIRECT_CHILDREN"; cp_["lastBomImport"] = ago(1000 + i)
    cp_["components"]["c"] = {"uuid": f"col{i}", "_id": 0, "group": None, "name": "x", "version": "1", "purl": None, "cpe": None}
code, rep, out = run_tool(url, cpath, "--no-canary")
pa = (find(rep, "portfolio", "re-analysis") or [{}])[0]
check("... just-uploaded and collection projects are not counted as stale", code == 0 and pa.get("status") == "ok", pa)
for pp in [x for x in st.projects.values() if x["name"].startswith(("new-", "collection", "svc-"))]:
    st.projects.pop(pp["uuid"])

sf2 = os.path.join(TMP, "sig-state.json")
st.mirror_runs[("vuln-data-source", "osv")] = {"status": "PENDING"}
run_tool(url, cpath, "--no-canary", "--state", sf2)
stt = json.load(open(sf2)); stt["nonterminal"]["vuln-data-source/osv"]["first_seen"] -= 40 * 3600; json.dump(stt, open(sf2, "w"))
st.mirror_runs[("vuln-data-source", "osv")] = {"status": "RUNNING", "started_at": ago(0.1)}   # a new run started
code, rep, out = run_tool(url, cpath, "--no-canary", "--state", sf2)
check("stuck-run state: a new run (other status and start) starts the clock again: a warning, not a problem",
      code == 0 and find(rep, "mirror", "vuln-data-source/osv", "warning"), find(rep, "mirror", "vuln-data-source/osv"))
st.mirror_runs[("vuln-data-source", "osv")] = {"status": "COMPLETED", "started_at": ago(1.1), "completed_at": ago(1)}

ad.sample = []
code, rep, out = run_tool(url, cpath, "--no-canary")
check("an empty VulnCheck sample is a warning (nothing to compare), not ok", code == 0 and find(rep, "vulncheck", "in-dt", "warning"),
      find(rep, "vulncheck"))
ad.sample = [f"CVE-2026-{9000 + i}" for i in range(10)]
sf3 = os.path.join(TMP, "cand-state.json")
run_tool(url, cpath, "--no-canary", "--state", sf3)
ad.candidates = 31000
code, rep, out = run_tool(url, cpath, "--no-canary", "--state", sf3)
check("trend: the adapter's enriched CVEs halve: a warning", find(rep, "trend", "adapter/vulncheck_candidates", "warning"), find(rep, "trend"))
ad.candidates = 62000
st.notification_rules[0]["filterExpression"] = "subject.name == 'nothing'"
code, rep, out = run_tool(url, cpath, "--no-canary")
check("alerts: the only mirror rule has a filter expression: a warning to check it", find(rep, "alerts", "DATASOURCE_MIRRORING", "warning"),
      find(rep, "alerts"))
st.notification_rules[0].pop("filterExpression")

st.d_analysis = 6                          # a second scheduler starts a run while this one waits for the analysis
def rival():
    time.sleep(2)
    bom = json.load(open(CANARY))
    for c in bom["components"]:
        c["group"] = "dt-health-canary-x"
    req = urllib.request.Request(url + "/api/v1/bom", method="PUT", headers={"X-Api-Key": mock_dt.API_KEY, "Content-Type": "application/json"},
                                 data=json.dumps({"projectName": "dt-health-canary", "projectVersion": "1",
                                                  "bom": base64.b64encode(json.dumps(bom).encode()).decode()}).encode())
    urllib.request.urlopen(req).read()
threading.Thread(target=rival, daemon=True).start()
code, rep, out = run_tool(url, cpath)
check("overlapping runs: the canary replaced by another run is a warning naming it, not 4 missing components",
      find(rep, "canary", "concurrent", "warning") and not find(rep, "canary", status="problem"), find(rep, "canary"))
st.d_analysis = 0.4

# ---------------------------------------------------------------- trend
st, ad, url, cpath, cfg = new_stack(perms=LEAST)
state = os.path.join(TMP, "trend.json")
code, rep, out = run_tool(url, cpath, "--state", state)
m1 = json.load(open(state))["metrics"]
st.rules2 = [r for r in st.rules2 if not (r[1] == "oss-index" and r[0][1] != "CVE-2018-25032")]
code, rep, out = run_tool(url, cpath, "--state", state)
check("trend: OSS Index canary findings 4 -> 1: warning, still PASS",
      m1.get("canary/oss-index") == 4 and code == 0 and find(rep, "trend", "canary/oss-index", "warning"), (m1, find(rep, "trend")))
check("... adapter VulnCheck counts are tracked", "adapter/vulncheck_records" in m1, m1)

ok = sum(1 for _, c in results if c)
print(f"\n{ok} of {len(results)} checks passed")
sys.exit(0 if ok == len(results) else 1)
