#!/usr/bin/env python3
"""Health and drop-guard test for the NVD feed adapter 2.1 and later, with a fake NIST and a fake VulnCheck API.

Each step injects one fault and checks that GET /health turns 503 with the right reason, that the data
already served stays as it was (Dependency-Track keeps getting the previous feeds), and that /health is
200 again once the fault is gone. Version 2 answered "ok" in every one of these cases.

usage: test_health.py <adapter.py>
"""
import datetime as dt, hashlib, io, json, os, shutil, subprocess, sys, tempfile, threading, time, urllib.error
import urllib.request, zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_adapter import DT, Nist, cve, free_port  # noqa: E402

GOOD = "good-token"


def ts(hours_ago):
    t = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours_ago)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}"


class FakeNist(Nist):
    """Nist feed server that can fail: fail = None | 404 | 503 (all files), fail_only = {name: code};
    delay = seconds before every answer."""
    fail = None
    fail_only = {}
    fail_paths = {}   # substring of the path -> status, e.g. {"modified.json.gz": 503}
    delay = 0

    def serve(self):
        root, nist = self.root, self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def do_GET(self):
                if nist.delay:
                    time.sleep(nist.delay)
                code = nist.fail or next((c for n, c in nist.fail_only.items() if f"nvdcve-2.0-{n}." in self.path), None) \
                    or next((c for sub, c in nist.fail_paths.items() if sub in self.path), None)
                if code:
                    self.send_response(code); self.send_header("Content-Length", "0"); self.end_headers(); return
                p = os.path.join(root, os.path.basename(self.path))
                if not os.path.exists(p):
                    self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers(); return
                b = open(p, "rb").read()
                self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        port = free_port(); srv = ThreadingHTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{port}"


class FakeVulnCheck:
    """/v3/backup/nist-nvd2 (Bearer token) and the backup download."""
    def __init__(self, root):
        self.root, self.token, self.downloads, self.meta_calls, self.entry, self.n = root, GOOD, 0, 0, None, 0
        self.dl_fail = None   # status for the backup download (a presigned URL that has expired)
        os.makedirs(root, exist_ok=True)

    def publish(self, records):
        self.n += 1
        name = f"nist-nvd2-{self.n}.zip"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("nvd.json", json.dumps(records))
        data = buf.getvalue()
        open(os.path.join(self.root, name), "wb").write(data)
        self.entry = {"filename": name, "sha256": hashlib.sha256(data).hexdigest(), "date_added": ts(0) + "Z",
                      "url": f"{self.url}/dl/{name}"}

    def serve(self):
        vc = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def reply(self, code, body, ctype="application/json"):
                self.send_response(code); self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

            def do_GET(self):
                if self.path.startswith("/v3/backup/"):
                    vc.meta_calls += 1
                    if self.headers.get("Authorization") != f"Bearer {vc.token}":
                        return self.reply(401, b'{"error":"invalid token"}')
                    return self.reply(200, json.dumps({"data": [vc.entry]}).encode())
                if self.path.startswith("/dl/") and vc.dl_fail:
                    return self.reply(vc.dl_fail, b"<Error><Code>SignatureDoesNotMatch</Code><AWSAccessKeyId>AKIAEXAMPLE</AWSAccessKeyId>"
                                                  b"<StringToSign>secret-ish</StringToSign></Error>", "application/xml")
                if self.path.startswith("/dl/"):
                    vc.downloads += 1
                    return self.reply(200, open(os.path.join(vc.root, os.path.basename(self.path)), "rb").read(),
                                      "application/zip")
                self.reply(404, b"{}")
        port = free_port(); srv = ThreadingHTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{port}"
        return self.url


def vc_record(cid, pub, vc_cpe=None, nist_cpe=None):
    r = {"id": cid, "published": pub, "lastModified": pub, "vulnStatus": "Analyzed",
         "descriptions": [{"lang": "en", "value": cid}]}
    if nist_cpe:
        r["configurations"] = cve(cid, pub, [(nist_cpe, {})])["cve"]["configurations"]
    if vc_cpe:
        r["vcConfigurations"] = cve(cid, pub, [(vc_cpe, {})])["cve"]["configurations"]
    return r


class Adapter:
    def __init__(self, script, cache, env):
        self.script, self.cache, self.env, self.p, self.port = script, cache, env, None, free_port()

    def start(self, **extra):
        env = dict(os.environ, CACHE_DIR=self.cache, PORT=str(self.port), FIRST_YEAR="2019", FEED_MAX_AGE_MIN="600",
                   CPE_ALIASES_FILE=os.path.join(self.cache, "no-aliases.json"))
        env.update(self.env); env.update(extra)
        self.log = open(os.path.join(self.cache, "adapter.log"), "a")
        self.p = subprocess.Popen([sys.executable, "-I", self.script], env=env, stdout=self.log, stderr=subprocess.STDOUT)
        for _ in range(200):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{self.port}/healthz", timeout=2); break
            except Exception:
                time.sleep(0.1)
        self.wait()
        return self

    def get(self, path, timeout=60):
        try:
            r = urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=timeout)
            raw = r.read() or b"null"
            try:
                return r.status, json.loads(raw)
            except ValueError:
                return r.status, raw.decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            raw = e.read() or b"null"
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, raw.decode("utf-8", "replace")

    def wait(self):
        for _ in range(600):
            _, s = self.get("/stats")
            if s.get("phase") in ("ready", "error") and not self.get("/health")[1]["building"]:
                return
            time.sleep(0.1)
        raise RuntimeError("adapter not ready")

    def rebuild(self, q="", wait=True, headers=None):
        """Plain refresh by GET; forcing or accepting needs POST with the header (CSRF guard)."""
        url = f"http://127.0.0.1:{self.port}/rebuild?wait={int(wait)}{q}"
        if not q and headers is None:
            return self.get(f"/rebuild?wait={int(wait)}", timeout=120)
        req = urllib.request.Request(url, method="POST", data=b"", headers={"X-NVDPP-Rebuild": "1"} if headers is None else headers)
        try:
            with urllib.request.urlopen(req, timeout=300) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def health(self):
        return self.get("/health")

    def stop(self):
        if self.p:
            self.p.terminate(); self.p.wait(10); self.log.close(); self.p = None


def run(script):
    tmp = tempfile.mkdtemp(prefix="nvdpp-health-")
    res, notes = {}, []
    nist = FakeNist(os.path.join(tmp, "nist")); vc = FakeVulnCheck(os.path.join(tmp, "vc"))
    # NIST: ten 2026 CVEs, the newest change an hour ago; three of them have no CPEs at NIST
    for i in range(10):
        cpes = None if i < 3 else [(f"cpe:2.3:a:vendor{i}:prod{i}:1.0:*:*:*:*:*:*:*", {})]
        nist.put(cve(f"CVE-2026-{1000 + i}", ts(30 - i), cpes))
    nist.publish(); nist_url = nist.serve(); vc_url = vc.serve()
    recs = [vc_record(f"CVE-2026-{1000 + i}", ts(30 - i), vc_cpe=f"cpe:2.3:a:zlib:zlib:1.2.{i}:*:*:*:*:*:*:*")
            for i in range(3)]
    recs += [vc_record(f"CVE-2025-{2000 + i}", ts(400), vc_cpe=f"cpe:2.3:a:v{i}:p{i}:1:*:*:*:*:*:*:*",
                       nist_cpe=f"cpe:2.3:a:v{i}:p{i}:1:*:*:*:*:*:*:*") for i in range(97)]
    vc.publish(recs)
    cache = os.path.join(tmp, "cache"); os.makedirs(cache)
    a = Adapter(script, cache, {"NIST_FEEDS_URL": nist_url, "VULNCHECK_API_URL": vc_url, "VULNCHECK_TOKEN": GOOD})
    d = DT(f"http://127.0.0.1:{a.port}/feeds")

    def check(label, cond, extra=""):
        res[label] = bool(cond)
        if not cond:
            notes.append(f"{label}: {extra}")

    def problems():
        return " | ".join(a.health()[1]["problems"])

    try:
        a.start()
        code, h = a.health()
        check("1 healthy start: /health 200", code == 200 and h["status"] == "ok", json.dumps(h)[:600])
        check("1 ... 3 VulnCheck candidates, one download", h["vulncheck"]["candidates"] == 3 and vc.downloads == 1,
              f"{h['vulncheck']} downloads={vc.downloads}")
        ok, _ = d.sync()
        check("1 ... DT mirror gets the feeds", ok and "CVE-2026-1000" in d.matches("zlib", "zlib", "1.2.0"), d.error)

        _, smp = a.get(f"/candidates/sample?n=2&served_before={int(time.time() * 1000) + 3600000}")
        _, none = a.get("/candidates/sample?served_before=0")
        _, recent = a.get(f"/candidates/sample?served_before={int(time.time() * 1000) - 3600000}")
        check("2 /candidates/sample filters on when the adapter first served a CVE (minutes ago), not its lastModified (a day old)",
              recent["eligible"] == 0 and smp["sample"][0].get("served_at"), json.dumps([recent, smp])[:300])
        first = {x["id"]: x["served_at"] for x in smp["sample"]}
        a.rebuild("&all=1")
        _, again = a.get(f"/candidates/sample?n=2&served_before={int(time.time() * 1000) + 3600000}")
        check("2 served_at stays the first publication time across rebuilds", first and
              all(first.get(x["id"]) in (None, x["served_at"]) for x in again["sample"]), (first, again["sample"]))
        check("2 /candidates/sample: 2 of 3 eligible, none before 1970",
              smp["eligible"] == 3 and len(smp["sample"]) == 2 and none["eligible"] == 0
              and smp["sample"][0]["cpe_products"] == ["zlib:zlib"], json.dumps([smp, none])[:400])

        # fault: VulnCheck rejects the token
        vc.token = "rotated"
        a.rebuild("&vc=1")
        code, h = a.health()
        check("3 token rejected: /health 503 at once", code == 503 and "401" in problems(), json.dumps(h)[:600])
        check("3 ... previous candidates still served", a.get("/stats")[1]["vulncheck"]["candidates"] == 3
              and a.get("/stats")[1]["vulncheck"]["status"] == "stale", json.dumps(a.get("/stats")[1]["vulncheck"])[:300])
        a.stop(); a.start()
        check("3 ... still 503 after a restart", a.health()[0] == 503, problems())
        vc.token = GOOD
        a.stop(); a.start()
        check("3b token fine again: 200", a.health()[0] == 200, problems())
        vc.token = "mistyped"   # a restart with a rejected token while the cache is fresh, no /rebuild call
        calls = vc.meta_calls
        a.stop(); a.start()
        check("3b restart with a rejected token (fresh cache, no /rebuild): 503 from the startup check",
              a.health()[0] == 503 and "401" in problems() and vc.meta_calls > calls, problems())
        code, body = a.get("/rebuild?vc=1&wait=0")
        check("3c CSRF guard: GET /rebuild?vc=1 is refused (405)", code == 405, (code, body))
        code2, _ = a.rebuild("&vc=1", wait=False, headers={})
        code3, _ = a.rebuild("&vc=1", wait=False, headers={"X-NVDPP-Rebuild": "1", "Host": "attacker.example:8090"})
        check("3c ... POST without the header: 405; POST from another Host (DNS rebinding): 403", code2 == 405 and code3 == 403,
              (code2, code3))
        vc.token = GOOD   # the operator fixes the token
        before = vc.downloads
        a.stop(); a.start()
        code, h = a.health()
        check("4 token fixed: /health 200 again, without a new download", code == 200 and vc.downloads == before,
              f"{problems()} downloads {before}->{vc.downloads}")

        nist.delay = 0.3                      # a slow NIST: the next plain refresh takes a few seconds
        before = vc.downloads
        a.rebuild(wait=False)                 # a build is running ...
        time.sleep(0.5)
        code, body = a.rebuild("&vc=1")       # ... and a forced VulnCheck reload is requested meanwhile
        nist.delay = 0
        check("4b /rebuild?vc=1 during a running build is queued and done, not dropped",
              code == 200 and vc.downloads == before + 1, f"{code} downloads {before}->{vc.downloads}")
        nist.delay = 0.3
        before = vc.downloads
        b2019 = a.get("/stats")[1]["feeds"]["2019"]["built_at"]
        a.rebuild(wait=False); time.sleep(0.5)
        a.rebuild("&vc=1", wait=False)        # two requests queued behind the running build ...
        code, body = a.rebuild("&all=1")      # ... must both be done in the next pass (flags merged)
        nist.delay = 0
        check("4c two queued requests (vc=1, then all=1) are merged, not overwritten",
              vc.downloads == before + 1 and a.get("/stats")[1]["feeds"]["2019"]["built_at"] != b2019,
              f"downloads {before}->{vc.downloads}, 2019 built {b2019} -> {a.get('/stats')[1]['feeds']['2019']['built_at']}")

        # fault: a truncated VulnCheck backup (half the records)
        vc.publish(recs[:2] + recs[3:51])
        a.rebuild("&vc=1")
        code, h = a.health()
        check("5 VulnCheck backup half the size: 503, previous data kept",
              code == 503 and "fewer" in problems() and h["vulncheck"]["candidates"] == 3, json.dumps(h)[:600])
        a.rebuild()   # the hourly refresh (cache fresh) must not clear a drop-guard stop
        check("5 ... an ordinary refresh does not clear it", a.health()[0] == 503, problems())
        before = vc.downloads
        a.rebuild("&vc=1&accept_vc_drop=1")
        code, h = a.health()
        check("6 accepted: 200, the kept backup reused (no download), 2 candidates",
              code == 200 and vc.downloads == before and h["vulncheck"]["candidates"] == 2,
              f"{json.dumps(h)[:500]} downloads {before}->{vc.downloads}")

        # fault: VulnCheck CPEs vanish from half the records (records unchanged)
        accepted = recs[:2] + recs[3:51]       # the state accepted in step 6: 50 records, 2 candidates
        half = [dict(r) for r in accepted]
        for r in half[30:]:
            r.pop("vcConfigurations", None)
        vc.publish(half)
        a.rebuild("&vc=1")
        check("6b fewer CVEs with VulnCheck CPEs (records unchanged): 503, previous data kept",
              a.health()[0] == 503 and "vc_has_cpes" in problems() and a.health()[1]["vulncheck"]["candidates"] == 2, problems())
        # fault: a format change - VulnCheck's CPEs now arrive in "configurations", so nothing looks enriched
        moved = [dict(r) for r in accepted]
        moved[0]["configurations"] = moved[0]["vcConfigurations"]   # 1 of 2 enriched CVEs gone: 50% > 10%
        vc.publish(moved)
        a.rebuild("&vc=1")
        check("6c half the enriched CVEs gone (records and CPEs unchanged): drop guard on candidates, 503",
              a.health()[0] == 503 and "candidates" in problems() and "no enriched" not in problems(), problems())
        moved = [dict(r) for r in accepted]
        for r in moved[:2]:
            r["configurations"] = r["vcConfigurations"]
        vc.publish(moved)
        a.rebuild("&vc=1")
        check("6c' no enriched CVEs left (format change): drop guard, 503", a.health()[0] == 503 and "candidates" in problems(), problems())
        a.rebuild("&vc=1&accept_vc_drop=1")
        check("6d ... accepted anyway: still 503, because 0 enriched CVEs is a problem in itself",
              a.health()[0] == 503 and "no enriched CVEs" in problems(), problems())
        vc.publish(accepted)                  # back to the accepted good state (2 candidates)
        a.rebuild("&vc=1&accept_vc_drop=1")
        check("6e good data again: 200", a.health()[0] == 200, problems())

        vc.dl_fail = 403                      # the presigned backup URL is refused; its error body echoes signing details
        vc.publish(accepted + [vc_record("CVE-2025-3999", ts(400), vc_cpe="cpe:2.3:a:q:q:1:*:*:*:*:*:*:*",
                                          nist_cpe="cpe:2.3:a:q:q:1:*:*:*:*:*:*:*")])
        a.rebuild("&vc=1")
        hb = json.dumps(a.health()[1])
        check("6f a failed backup download is reported without the URL's error body (no signing details)",
              "backup download failed: HTTP 403" in hb and "AWSAccessKeyId" not in hb and "StringToSign" not in hb, hb[:400])
        vc.dl_fail = None

        # fault: NIST removed the URL (404) - reported at once; DT still gets the last feeds
        sha_before = urllib.request.urlopen(f"http://127.0.0.1:{a.port}/feeds/json/cve/2.0/nvdcve-2.0-2026.meta").read()
        nist.fail = 404
        a.rebuild()
        code, h = a.health()
        sha_after = urllib.request.urlopen(f"http://127.0.0.1:{a.port}/feeds/json/cve/2.0/nvdcve-2.0-2026.meta").read()
        check("7 NIST answers 404: 503 at once, feeds unchanged", code == 503 and "404" in problems()
              and sha_before == sha_after, problems())
        # fault: NIST unreachable for a while (503) - a warning first, a problem once the data is too old
        nist.fail = 503
        a.rebuild()
        code, h = a.health()
        check("8 NIST answers 503: still 200, with a warning", code == 200 and any("503" in w for w in h["warnings"]),
              json.dumps(h)[:500])
        a.stop(); a.start(NIST_MAX_AGE_HOURS="0.0002")
        time.sleep(1.5)
        check("8 ... 503 once the last good refresh is older than NIST_MAX_AGE_HOURS",
              a.health()[0] == 503 and "last refreshed from NIST" in problems(), problems())
        nist.fail = None
        a.stop(); a.start()
        check("9 NIST back: 200", a.health()[0] == 200, problems())
        nist.fail = 403
        a.rebuild()
        check("9b NIST answers 403 (its CDN rate-limits): a warning, not a problem", a.health()[0] == 200
              and any("403" in w for w in a.health()[1]["warnings"]), json.dumps(a.health()[1])[:400])
        nist.fail = None
        nist.fail_only = {"2025": 404}         # one yearly file gone; a new CVE arrives in "modified"
        nist.put(cve("CVE-2026-5555", ts(0.5), [("cpe:2.3:a:new:thing:1:*:*:*:*:*:*:*", {})])); nist.publish()
        a.rebuild()
        ok, _ = d.sync()
        check("9c one yearly feed failing: reported (404), and \"modified\" is still refreshed",
              a.health()[0] == 503 and "feed 2025" in problems() and "CVE-2026-5555" in d.db, (problems(), ok, d.error))
        nist.fail_only = {}
        a.rebuild()
        check("9d ... back: 200", a.health()[0] == 200, problems())

        sha_before = urllib.request.urlopen(f"http://127.0.0.1:{a.port}/feeds/json/cve/2.0/nvdcve-2.0-2026.meta").read()
        # "modified" failing must not count as a fresh refresh; a failing yearly file must not stop it counting
        nist.put(cve("CVE-2026-6001", ts(0.2), [("cpe:2.3:a:x:y:1:*:*:*:*:*:*:*", {})])); nist.publish()
        time.sleep(8)
        nist.fail_paths = {"modified.json.gz": 503}
        a.stop(); a.start(NIST_MAX_AGE_HOURS="0.002")
        check("9e \"modified\" download failing: the refresh is not counted as fresh (problem once 7 s old)",
              a.health()[0] == 503 and "last refreshed from NIST" in problems(), problems())
        nist.fail_paths = {"2025.json.gz": 503}
        nist.put(cve("CVE-2025-6002", ts(0.2), [("cpe:2.3:a:x:z:1:*:*:*:*:*:*:*", {})])); nist.publish()
        time.sleep(4)
        a.stop(); a.start(NIST_MAX_AGE_HOURS="0.002", FEED_STALE_HOURS="0.001")
        code, h = a.health()
        check("9f a yearly file failing transiently: \"modified\" still counts as fresh, but that feed is reported as not checked",
              "last refreshed from NIST" not in problems() and "feed 2025 (" in problems() and "2026 (" not in problems(), problems())
        nist.fail_paths = {}
        a.stop(); a.start()
        check("9g ... NIST back: 200", a.health()[0] == 200, problems())

        sha_before = urllib.request.urlopen(f"http://127.0.0.1:{a.port}/feeds/json/cve/2.0/nvdcve-2.0-2026.meta").read()
        # fault: NIST's 2026 file comes back with 4 of 10 CVEs
        for i in range(4, 10):
            nist.cves.pop(f"CVE-2026-{1000 + i}")
        nist.publish()
        a.rebuild()
        code, h = a.health()
        sha_after = urllib.request.urlopen(f"http://127.0.0.1:{a.port}/feeds/json/cve/2.0/nvdcve-2.0-2026.meta").read()
        check("10 NIST yearly feed 60% smaller: 503, previous feed kept", code == 503 and "feed 2026" in problems()
              and sha_after.split(b"sha256:")[1] == sha_before.split(b"sha256:")[1], problems())
        a.rebuild("&accept_feed_drop=1")
        check("10 ... accepted: 200", a.health()[0] == 200, problems())

        # fault: NIST stops publishing (its newest change is three days old)
        nist.put(cve("CVE-2026-1000", ts(72), None)); nist.modified_ids = {"CVE-2026-1000"}
        for cid in list(nist.cves):
            if cid != "CVE-2026-1000":
                nist.cves[cid]["cve"]["lastModified"] = ts(80)
        nist.publish()
        a.rebuild()
        check("11 NIST quiet for 72 h: 503", a.health()[0] == 503 and "stopped publishing" in problems(), problems())
        a.stop(); a.start(NIST_QUIET_HOURS="100")

        # VulnCheck token not set
        a.stop(); a.start(VULNCHECK_TOKEN="", NIST_QUIET_HOURS="100")
        check("12 token not set: 503", a.health()[0] == 503 and "not set" in problems(), problems())
        a.stop(); a.start(VULNCHECK_TOKEN="", VULNCHECK_REQUIRED="0", NIST_QUIET_HOURS="100")
        code, h = a.health()
        check("12 ... with VULNCHECK_REQUIRED=0: 200 with a warning", code == 200 and h["warnings"], json.dumps(h)[:400])
        ok, _ = d.sync()
        check("13 DT mirror still works after all faults", ok, d.error)
        a.stop()
        cold = os.path.join(tmp, "cold"); os.makedirs(cold)
        nist.fail = 503                        # a new install whose first build cannot reach NIST
        c = Adapter(script, cold, {"NIST_FEEDS_URL": nist_url, "VULNCHECK_API_URL": vc_url, "VULNCHECK_TOKEN": GOOD})
        c.start()
        code, h = c.health()
        c.stop(); nist.fail = None
        check("14 cold cache (no feed built yet): 503, feeds missing", code == 503
              and any("not built yet" in p for p in h["problems"]), json.dumps(h)[:400])
    finally:
        a.stop()
        if os.environ.get("KEEP") != "1":
            shutil.rmtree(tmp, ignore_errors=True)
        else:
            print("kept", tmp)
    return res, notes


if __name__ == "__main__":
    res, notes = run(sys.argv[1])
    w = max(len(k) for k in res)
    for k, v in res.items():
        print(f"{k:{w}}  {'ok' if v else 'FAIL'}")
    for n in notes:
        print("  -", n[:900])
    good = all(res.values())
    print(f"RESULT: {'PASS' if good else 'FAIL'} ({sum(res.values())}/{len(res)})")
    sys.exit(0 if good else 1)
