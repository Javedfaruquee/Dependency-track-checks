#!/usr/bin/env python3
"""Scenario test for the NVD feed adapter: a fake NIST feed server, a client that follows
Dependency-Track 5.2.1's NVD mirroring rules (vuln-data-source/nvd: per-feed sha256 skip,
global watermark, per-CVE lastModified skip, newest year first, "modified" last), and the
restart and NIST-update cases where adapter version 1 lost VulnCheck CPEs.
DT 5.2.2 adds one rule (NvdVulnDataSource, MODIFIED_FEED_COVERAGE): while the watermark is less
than 6 days old it skips the yearly feeds and reads only "modified" (and keeps the watermark when
the oldest CVE in "modified" is newer than it). The 5.2.2 scenario checks that VulnCheck CPEs added
to an old CVE still reach DT (adapter 2.1 put them only into the CVE's yearly feed).

Also: a drop-guarded yearly feed that is accepted later (its rewrite must not come back below DT's
watermark), a rewrite older than a day when DT mirrors (the 8-day window), and where "modified" finds
the yearly copy (pre-2002 IDs, the feed kept in assigned.json). With --v21: the upgrade from 2.1.

usage: test_adapter.py <adapter.py> [--v1 <old adapter.py>] [--v21 <adapter 2.1>]
"""
import datetime as dt, gzip, hashlib, json, os, shutil, socket, subprocess, sys, tempfile, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

YEARS = list(range(2026, 2018, -1))


def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


def cve(cid, lm, cpes=None, pub=None):
    c = {"id": cid, "published": pub or lm, "lastModified": lm, "vulnStatus": "Analyzed",
         "descriptions": [{"lang": "en", "value": cid}]}
    if cpes:
        c["configurations"] = [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": [
            dict({"vulnerable": True, "criteria": crit, "matchCriteriaId": hashlib.md5(crit.encode()).hexdigest().upper()}, **rng)
            for crit, rng in cpes]}]}]
    return {"cve": c}


class Nist:
    """Fake https://nvd.nist.gov/feeds: yearly + modified feeds built from a dict of CVEs."""
    def __init__(self, root):
        self.root = root; os.makedirs(root, exist_ok=True); self.cves = {}; self.modified_ids = set(); self.slow = 0

    def put(self, item, modified=True):
        self.cves[item["cve"]["id"]] = item
        if modified: self.modified_ids.add(item["cve"]["id"])

    def publish(self):
        feeds = {str(y): [] for y in YEARS}; feeds["modified"] = []
        for cid, it in self.cves.items():
            y = cid.split("-")[1]
            if y in feeds: feeds[y].append(it)
            if cid in self.modified_ids: feeds["modified"].append(it)
        for name, items in feeds.items():
            body = json.dumps({"resultsPerPage": len(items), "startIndex": 0, "totalResults": len(items), "format": "NVD_CVE",
                               "version": "2.0", "timestamp": "2026-11-26T00:00:00.000", "vulnerabilities": items}).encode()
            with gzip.open(os.path.join(self.root, f"nvdcve-2.0-{name}.json.gz"), "wb") as f: f.write(body)
            lm = max((i["cve"]["lastModified"] for i in items), default="2026-01-01T00:00:00.000")
            meta = f"lastModifiedDate:{lm}-00:00\r\nsize:{len(body)}\r\nsha256:{hashlib.sha256(body).hexdigest().upper()}\r\n"
            open(os.path.join(self.root, f"nvdcve-2.0-{name}.meta"), "w", newline="").write(meta)

    def serve(self):
        root = self.root; nist = self
        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def do_GET(self):
                if nist.slow and self.path.endswith("modified.json.gz"): time.sleep(nist.slow)
                p = os.path.join(root, os.path.basename(self.path))
                if not os.path.exists(p): self.send_response(404); self.end_headers(); return
                b = open(p, "rb").read(); self.send_response(200); self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        port = free_port(); srv = ThreadingHTTPServer(("127.0.0.1", port), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return f"http://127.0.0.1:{port}"


class DT:
    """Dependency-Track 5.2.1 NVD mirroring rules (see NvdVulnDataSource / WatermarkManager); v522: 5.2.2's."""
    def __init__(self, url, v522=False):
        self.url = url; self.W = None; self.dig = {}; self.db = {}; self.ingested = 0; self.error = None
        self.v522 = v522; self.skipped_years = False; self.kept_watermark = False

    @staticmethod
    def inst(s):
        t = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)

    def sync(self):
        pending, consumed, ok, n = None, [], True, 0
        # 5.2.2: skipYearFeeds is decided once, from the watermark, when the mirror run starts
        skip_years = self.v522 and self.W is not None and self.W > dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=6)
        self.skipped_years, oldest_mod = skip_years, None
        for name in [str(y) for y in YEARS] + ["modified"]:
            if skip_years and name != "modified":
                continue
            try:
                meta = urllib.request.urlopen(f"{self.url}/json/cve/2.0/nvdcve-2.0-{name}.meta", timeout=30).read().decode()
            except Exception as e:
                self.error = f"{name}: {e}"; ok = False; break
            m = dict(l.split(":", 1) for l in meta.splitlines() if ":" in l)
            sha, mlm = m.get("sha256"), self.inst(m["lastModifiedDate"].strip())
            if sha and sha == self.dig.get(name): continue
            if self.W is not None and not self.W < mlm: continue
            data = json.loads(gzip.decompress(urllib.request.urlopen(f"{self.url}/json/cve/2.0/nvdcve-2.0-{name}.json.gz", timeout=60).read()))
            for it in data["vulnerabilities"]:
                lm = self.inst(it["cve"]["lastModified"])
                if name == "modified" and (oldest_mod is None or lm < oldest_mod): oldest_mod = lm
                if self.W is not None and not self.W < lm: continue
                self.db[it["cve"]["id"]] = it["cve"]; n += 1
                if pending is None or lm > pending: pending = lm
            consumed.append((name, sha))
        for name, sha in consumed: self.dig[name] = sha
        # 5.2.2 hasModifiedFeedCoverageGap: years skipped, but "modified" does not reach back to the watermark
        self.kept_watermark = bool(skip_years and oldest_mod is not None and oldest_mod > self.W)
        if ok and pending and not self.kept_watermark and (self.W is None or pending > self.W): self.W = pending
        self.ingested += n
        return ok, n

    def matches(self, vendor, product, version):
        def v(x): return tuple(int(p) if p.isdigit() else p for p in x.replace("-", ".").split("."))
        out = set()
        for cid, c in self.db.items():
            for cfg in c.get("configurations") or []:
                for nd in cfg.get("nodes") or []:
                    for m in nd.get("cpeMatch") or []:
                        p = m["criteria"].split(":")
                        if (p[3], p[4]) != (vendor, product): continue
                        if p[5] not in ("*", "-") and p[5] != version: continue
                        if m.get("versionEndExcluding") and not v(version) < v(m["versionEndExcluding"]): continue
                        if m.get("versionEndIncluding") and not v(version) <= v(m["versionEndIncluding"]): continue
                        out.add(cid)
        return out


class Adapter:
    def __init__(self, script, cache, nist_url, aliases=None, port=None):
        self.script, self.cache, self.nist_url, self.aliases = script, cache, nist_url, aliases; self.p = None
        self.port = port

    def start(self, wait=True):
        self.port = getattr(self, "port", None) or free_port()  # same port across restarts, like the container
        env = dict(os.environ, NIST_FEEDS_URL=self.nist_url, CACHE_DIR=self.cache, PORT=str(self.port),
                   VULNCHECK_TOKEN="test-token", FIRST_YEAR="2019", FEED_MAX_AGE_MIN="600")
        env["CPE_ALIASES_FILE"] = self.aliases or os.path.join(self.cache, "no-aliases.json")
        self.log = open(os.path.join(self.cache, f"adapter-{self.port}.log"), "w")
        self.p = subprocess.Popen([sys.executable, "-I", self.script], env=env, stdout=self.log, stderr=subprocess.STDOUT)
        self.url = f"http://127.0.0.1:{self.port}/feeds"
        for _ in range(200):
            try: urllib.request.urlopen(f"http://127.0.0.1:{self.port}/healthz", timeout=2); break
            except Exception: time.sleep(0.1)
        if wait: self.wait_ready()
        return self

    def stats(self): return json.loads(urllib.request.urlopen(f"http://127.0.0.1:{self.port}/stats", timeout=10).read())

    def wait_ready(self):
        for _ in range(300):
            s = self.stats()
            if s.get("phase") in ("ready", "error") and s.get("modified_feed", {}).get("built_at"): return s
            time.sleep(0.1)
        raise RuntimeError("adapter not ready: " + json.dumps(self.stats())[:500])

    def rebuild(self): return json.loads(urllib.request.urlopen(f"http://127.0.0.1:{self.port}/rebuild?wait=1", timeout=120).read())

    def stop(self):
        if self.p: self.p.terminate(); self.p.wait(10); self.log.close()


def seed_vulncheck(cache, candidates):
    os.makedirs(os.path.join(cache, "vc"), exist_ok=True)
    with gzip.open(os.path.join(cache, "vc", "candidates.jsonl.gz"), "wt") as f:
        for c in candidates: f.write(json.dumps({"cve": c}) + "\n")
    json.dump({"status": "loaded", "records": len(candidates), "candidates": len(candidates)}, open(os.path.join(cache, "vc", "stats.json"), "w"))


def scenario(script, label, use_aliases):
    tmp = tempfile.mkdtemp(prefix=f"nvdpp-{label}-")
    nist = Nist(os.path.join(tmp, "nist")); cache = os.path.join(tmp, "cache"); os.makedirs(cache)
    # NIST data: cJSON under two vendor names, a CVE NIST left without CPEs, a normal CVE
    nist.put(cve("CVE-2019-11834", "2019-05-09T10:00:00.000", [("cpe:2.3:a:davegamble:cjson:*:*:*:*:*:*:*:*", {"versionEndExcluding": "1.7.11"})]), modified=False)
    nist.put(cve("CVE-2023-53154", "2025-06-01T10:00:00.000", [("cpe:2.3:a:cjson_project:cjson:*:*:*:*:*:*:*:*", {"versionEndExcluding": "1.7.18"})]), modified=False)
    nist.put(cve("CVE-2026-1000", "2026-11-20T10:00:00.000"))  # no CPEs at NIST
    nist.put(cve("CVE-2026-2000", "2026-11-21T10:00:00.000", [("cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*", {})]))
    nist.publish(); nist_url = nist.serve()
    vc = cve("CVE-2026-1000", "2026-11-20T10:00:00.000", [("cpe:2.3:a:zlib:zlib:*:*:*:*:*:*:*:*", {"versionEndIncluding": "1.2.11"})])["cve"]
    seed_vulncheck(cache, [vc])
    al = None
    if use_aliases:
        al = os.path.join(tmp, "cpe-aliases.json")
        json.dump({"aliases": [{"same": ["cjson_project:cjson", "davegamble:cjson"]}]}, open(al, "w"))
    res = {}
    a = Adapter(script, cache, nist_url, al).start(); d = DT(a.url)
    ok, n = d.sync()
    res["1 first mirror: CVEs ingested"] = n
    res["1 zlib 1.2.11 matches CVE-2026-1000 (VulnCheck CPE)"] = "CVE-2026-1000" in d.matches("zlib", "zlib", "1.2.11")
    res["1 cjson_project:cjson 1.7.10 matches (expect 2 with aliases)"] = sorted(d.matches("cjson_project", "cjson", "1.7.10"))
    ok, n = d.sync(); res["2 second mirror, nothing changed: CVEs ingested"] = n
    # NIST updates the enriched CVE (still no CPEs): yearly AND modified feeds change.
    # The adapter has not rebuilt yet: the window right after a restart, or between its hourly rebuilds.
    nist.put(cve("CVE-2026-1000", "2026-11-26T09:00:00.000", pub="2026-11-20T10:00:00.000")); nist.publish()
    nist.slow = 20
    a.stop(); a.start(wait=False)
    time.sleep(1)
    ok, n = d.sync()
    nist.slow = 0
    res["3 NIST changed the CVE, adapter restarting: mirror ok"] = ok if ok else f"no ({d.error[:40]})"
    res["3 ... zlib still matches CVE-2026-1000"] = "CVE-2026-1000" in d.matches("zlib", "zlib", "1.2.11")
    a.wait_ready()
    ok, n = d.sync()
    res["4 after the adapter rebuilt: zlib matches CVE-2026-1000"] = "CVE-2026-1000" in d.matches("zlib", "zlib", "1.2.11")
    res["4 ... CVEs ingested"] = n
    a.stop(); a.start()
    ok, n = d.sync(); res["5 restart again, nothing changed: CVEs ingested"] = n
    res["5 ... zlib still matches CVE-2026-1000"] = "CVE-2026-1000" in d.matches("zlib", "zlib", "1.2.11")
    a.stop()
    shutil.rmtree(tmp, ignore_errors=True)
    return res


def scenario_522(script, label):
    """DT 5.2.2 reads only "modified" while its watermark is under 6 days old: VulnCheck CPEs for an old CVE
    (one that is in no recent NIST change) must still reach it."""
    tmp = tempfile.mkdtemp(prefix=f"nvdpp522-{label}-")
    nist = Nist(os.path.join(tmp, "nist")); cache = os.path.join(tmp, "cache"); os.makedirs(cache)
    now = dt.datetime.now(dt.timezone.utc)
    ago = lambda d: (now - dt.timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%S.000")
    nist.put(cve("CVE-2021-3000", "2023-03-01T10:00:00.000"), modified=False)   # old, NIST left it without CPEs
    nist.put(cve("CVE-2026-2100", ago(7), [("cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*", {})]))   # the oldest recent change
    nist.put(cve("CVE-2026-2200", ago(1), [("cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*", {})]))
    nist.publish(); nist_url = nist.serve()
    seed_vulncheck(cache, [])   # no VulnCheck data yet
    res = {}
    a = Adapter(script, cache, nist_url).start(); d = DT(a.url, v522=True)
    ok, n = d.sync()
    res["6 DT 5.2.2, first mirror (no watermark): reads every feed"] = ok and not d.skipped_years and {"CVE-2021-3000", "CVE-2026-2100", "CVE-2026-2200"} <= set(d.db)
    # VulnCheck now has CPEs for the old CVE; the adapter rebuilds (its hourly refresh)
    seed_vulncheck(cache, [cve("CVE-2021-3000", "2023-03-01T10:00:00.000", [("cpe:2.3:a:zlib:zlib:*:*:*:*:*:*:*:*", {"versionEndIncluding": "1.2.11"})])["cve"]])
    a.rebuild()
    res["7 the adapter copied 1 rewritten old CVE into modified (/stats)"] = (a.stats().get("feeds", {}).get("modified") or {}).get("recent_rewrites") == 1
    ok, n = d.sync()
    res["7 next mirror skips the yearly feeds (watermark under 6 days)"] = ok and d.skipped_years
    res["7 ... zlib 1.2.11 matches CVE-2021-3000 (VulnCheck CPE for an old CVE)"] = "CVE-2021-3000" in d.matches("zlib", "zlib", "1.2.11")
    res["7 ... watermark committed (no coverage gap)"] = not d.kept_watermark
    a.stop(); a.start()
    ok, n = d.sync()
    res["8 restart, nothing changed: CVEs ingested"] = n
    res["8 ... zlib still matches CVE-2021-3000"] = "CVE-2021-3000" in d.matches("zlib", "zlib", "1.2.11")
    a.stop()
    shutil.rmtree(tmp, ignore_errors=True)
    return res


ZLIB = [("cpe:2.3:a:zlib:zlib:*:*:*:*:*:*:*:*", {"versionEndIncluding": "1.2.11"})]


def ago_ts(d):
    return (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%S.000")


def post_rebuild(a, q):
    req = urllib.request.Request(f"http://127.0.0.1:{a.port}/rebuild?{q}&wait=1", data=b"", method="POST", headers={"X-NVDPP-Rebuild": "1"})
    urllib.request.urlopen(req, timeout=120).read()


def scenario_guard(script, v522):
    """A NIST yearly file shrinks (drop guard) in the pass that enriches one of its CVEs; DT mirrors other changes;
    then the drop is accepted. The rewrite was issued but never served: it must get a fresh value above DT's watermark."""
    tmp = tempfile.mkdtemp(prefix="nvdpp-guard-")
    nist = Nist(os.path.join(tmp, "nist")); cache = os.path.join(tmp, "cache"); os.makedirs(cache)
    for i in range(100):
        nist.put(cve(f"CVE-2021-{i:04d}", "2022-01-01T00:00:00.000", [("cpe:2.3:a:x:y%d:1:*:*:*:*:*:*:*" % i, {})]), modified=False)
    nist.put(cve("CVE-2021-3000", "2023-03-01T10:00:00.000"), modified=False)
    nist.put(cve("CVE-2026-2100", ago_ts(7), [("cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*", {})]))
    nist.put(cve("CVE-2026-2200", ago_ts(3), [("cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*", {})]))
    nist.publish(); url = nist.serve(); seed_vulncheck(cache, [])
    a = Adapter(script, cache, url).start(); d = DT(a.url, v522=v522); d.sync()
    for i in range(50):
        del nist.cves[f"CVE-2021-{i:04d}"]
    nist.publish()
    seed_vulncheck(cache, [cve("CVE-2021-3000", "2023-03-01T10:00:00.000", ZLIB)["cve"]])
    a.rebuild()                                   # 2021 held back by the drop guard
    nist.put(cve("CVE-2026-2300", ago_ts(1), [("cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*", {})])); nist.publish()
    a.rebuild(); d.sync()                         # DT's watermark moves on
    post_rebuild(a, "accept_feed_drop=1")
    d.sync()
    got = "CVE-2021-3000" in d.matches("zlib", "zlib", "1.2.11")
    a.stop(); shutil.rmtree(tmp, ignore_errors=True)
    return got


def scenario_window(script):
    """An old CVE is rewritten; NIST publishes on 3 more days and the adapter rebuilds each time; then DT 5.2.2 mirrors."""
    tmp = tempfile.mkdtemp(prefix="nvdpp-window-")
    nist = Nist(os.path.join(tmp, "nist")); cache = os.path.join(tmp, "cache"); os.makedirs(cache)
    nist.put(cve("CVE-2021-3000", "2023-03-01T10:00:00.000"), modified=False)
    nist.put(cve("CVE-2026-2100", ago_ts(7.5), [("cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*", {})]))
    nist.put(cve("CVE-2026-2200", ago_ts(5), [("cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*", {})]))
    nist.publish(); url = nist.serve(); seed_vulncheck(cache, [])
    a = Adapter(script, cache, url).start(); d = DT(a.url, v522=True); d.sync()
    seed_vulncheck(cache, [cve("CVE-2021-3000", "2023-03-01T10:00:00.000", ZLIB)["cve"]]); a.rebuild()
    for k, day in enumerate((4, 3, 2)):
        nist.put(cve(f"CVE-2026-23{k}0", ago_ts(day), [("cpe:2.3:a:openssl:openssl:3.0.%d:*:*:*:*:*:*:*" % (k + 2), {})])); nist.publish(); a.rebuild()
    d.sync()
    got = d.skipped_years and "CVE-2021-3000" in d.matches("zlib", "zlib", "1.2.11")
    a.stop(); shutil.rmtree(tmp, ignore_errors=True)
    return got


def scenario_outside_window(script):
    """A rewrite made when NIST's newest change was 20 days old; NIST then publishes today. The old rewrite is
    outside the window: "modified" does not carry it (DT already read it from its yearly feed, and copying every
    rewrite forever would make "modified" as big as all of them)."""
    tmp = tempfile.mkdtemp(prefix="nvdpp-outside-")
    nist = Nist(os.path.join(tmp, "nist")); cache = os.path.join(tmp, "cache"); os.makedirs(cache)
    nist.put(cve("CVE-2021-3000", "2023-03-01T10:00:00.000"), modified=False)
    nist.put(cve("CVE-2026-2100", ago_ts(20), [("cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*", {})]))
    nist.publish(); url = nist.serve()
    seed_vulncheck(cache, [cve("CVE-2021-3000", "2023-03-01T10:00:00.000", ZLIB)["cve"]])
    a = Adapter(script, cache, url).start(); d = DT(a.url); d.sync()
    first = (a.stats().get("feeds", {}).get("modified") or {}).get("recent_rewrites")
    nist.put(cve("CVE-2026-2200", ago_ts(0.1), [("cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*", {})])); nist.publish(); a.rebuild()
    later = (a.stats().get("feeds", {}).get("modified") or {}).get("recent_rewrites")
    got = d.matches("zlib", "zlib", "1.2.11") == {"CVE-2021-3000"} and first == 1 and later == 0
    a.stop(); shutil.rmtree(tmp, ignore_errors=True)
    return got if got else f"no (copied {first}, then {later})"


def scenario_late_nist(script):
    """NIST publishes its feed files after the fact: a change made 12 hours ago can appear only now. A rewrite
    in between must not lift DT's watermark above NIST's newest change, or DT skips that late change."""
    tmp = tempfile.mkdtemp(prefix="nvdpp-late-")
    nist = Nist(os.path.join(tmp, "nist")); cache = os.path.join(tmp, "cache"); os.makedirs(cache)
    nist.put(cve("CVE-2021-3001", "2023-03-01T10:00:00.000"), modified=False)
    nist.put(cve("CVE-2026-2100", ago_ts(1), [("cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*", {})]))
    nist.publish(); url = nist.serve(); seed_vulncheck(cache, [])
    a = Adapter(script, cache, url).start(); d = DT(a.url); d.sync()
    seed_vulncheck(cache, [cve("CVE-2021-3001", "2023-03-01T10:00:00.000", ZLIB)["cve"]]); a.rebuild(); d.sync()
    nist.put(cve("CVE-2026-2400", ago_ts(0.5), [("cpe:2.3:a:openssl:openssl:3.0.2:*:*:*:*:*:*:*", {})])); nist.publish()
    a.rebuild(); d.sync()
    got = "CVE-2026-2400" in d.db and "CVE-2021-3001" in d.matches("zlib", "zlib", "1.2.11")
    a.stop(); shutil.rmtree(tmp, ignore_errors=True)
    return got if got else f"no (watermark {d.W})"


def unit_copy_lookup(script):
    """iter_from_yearly: a pre-2002 ID is in the 2002 feed; a CVE whose feed assigned.json names is found there."""
    import importlib.util
    tmp = tempfile.mkdtemp(prefix="nvdpp-unit-")
    old = os.environ.get("CACHE_DIR"); os.environ["CACHE_DIR"] = tmp
    try:
        spec = importlib.util.spec_from_file_location("adapter_unit", script); ad = importlib.util.module_from_spec(spec); spec.loader.exec_module(ad)
    finally:
        if old is None: os.environ.pop("CACHE_DIR", None)
        else: os.environ["CACHE_DIR"] = old
    os.makedirs(ad.FEEDS_DIR, exist_ok=True)
    for y, ids in (("2002", ["CVE-1999-0001", "CVE-2002-0002"]), ("2019", ["CVE-2020-0009"]), ("2020", [])):
        with gzip.open(os.path.join(ad.FEEDS_DIR, f"{y}.json.gz"), "wt") as f:
            f.write(json.dumps({"format": "NVD_CVE", "vulnerabilities": [{"cve": {"id": c, "lastModified": "2026-11-26T00:00:00.000"}} for c in ids]}))
    years = [str(y) for y in range(2026, 2001, -1)]
    try:
        got = {it["cve"]["id"] for it in ad.iter_from_yearly({"CVE-1999-0001", "CVE-2020-0009"}, years, {"CVE-2020-0009": "2019"})}
    except TypeError:   # an adapter without the feed_of argument
        got = {it["cve"]["id"] for it in ad.iter_from_yearly({"CVE-1999-0001", "CVE-2020-0009"}, years)}
    shutil.rmtree(tmp, ignore_errors=True)
    return got == {"CVE-1999-0001", "CVE-2020-0009"}


def scenario_upgrade(v21, v22):
    """Adapter 2.1 with DT 5.2.1, VulnCheck enriches an old CVE, then adapter 2.2 and DT 5.2.2 together:
    only "modified" is rebuilt, and DT 5.2.2 gets the CPE."""
    tmp = tempfile.mkdtemp(prefix="nvdpp-upgrade-")
    nist = Nist(os.path.join(tmp, "nist")); cache = os.path.join(tmp, "cache"); os.makedirs(cache)
    nist.put(cve("CVE-2021-3000", "2023-03-01T10:00:00.000"), modified=False)
    nist.put(cve("CVE-2026-2100", ago_ts(7), [("cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*", {})]))
    nist.put(cve("CVE-2026-2200", ago_ts(3), [("cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*", {})]))
    nist.publish(); url = nist.serve(); seed_vulncheck(cache, [])
    a = Adapter(v21, cache, url).start(); d = DT(a.url); d.sync()
    seed_vulncheck(cache, [cve("CVE-2021-3000", "2023-03-01T10:00:00.000", ZLIB)["cve"]]); a.rebuild()
    nist.put(cve("CVE-2026-2300", ago_ts(2), [("cpe:2.3:a:openssl:openssl:3.0.1:*:*:*:*:*:*:*", {})])); nist.publish(); a.rebuild()
    s1 = json.load(open(os.path.join(cache, "feeds", "state.json")))
    a.stop(); a = Adapter(v22, cache, url, port=a.port).start()
    s2 = json.load(open(os.path.join(cache, "feeds", "state.json")))
    rebuilt = sorted(n for n in s2 if s1.get(n, {}).get("built_at") != s2[n].get("built_at"))
    d.v522 = True; d.sync()
    got = rebuilt == ["modified"] and d.skipped_years and "CVE-2021-3000" in d.matches("zlib", "zlib", "1.2.11")
    a.stop(); shutil.rmtree(tmp, ignore_errors=True)
    return got if got else f"no (rebuilt {rebuilt})"


if __name__ == "__main__":
    v2 = sys.argv[1]
    runs = [("v2", v2, True)]
    if "--v1" in sys.argv: runs.insert(0, ("v1", sys.argv[sys.argv.index("--v1") + 1], False))
    allres = {}
    for label, script, al in runs:
        allres[label] = scenario(script, label, al)
        allres[label].update(scenario_522(script, label))
        allres[label]["9 drop guard accepted later (DT 5.2.1): zlib matches CVE-2021-3000"] = scenario_guard(script, False)
        allres[label]["9 ... the same with DT 5.2.2"] = scenario_guard(script, True)
        allres[label]["10 rewrite 3 days before DT 5.2.2 mirrors: zlib matches CVE-2021-3000"] = scenario_window(script)
        allres[label]["11 copy lookup: CVE-1999 in the 2002 feed, feed from assigned.json"] = unit_copy_lookup(script)
        allres[label]["13 a rewrite older than the window is no longer copied"] = scenario_outside_window(script)
        allres[label]["14 a NIST change published late still reaches DT after a rewrite"] = scenario_late_nist(script)
        if "--v21" in sys.argv and label == "v2":
            allres[label]["12 upgrade 2.1 -> 2.2 with DT 5.2.2: only modified rebuilt, CPE arrives"] = scenario_upgrade(sys.argv[sys.argv.index("--v21") + 1], script)
    keys = list(next(iter(allres.values())).keys())
    w = max(len(k) for k in keys)
    print(f"{'check':{w}}  " + "  ".join(f"{l:>28}" for l in allres))
    for k in keys:
        print(f"{k:{w}}  " + "  ".join(f"{str(allres[l].get(k)):>28}" for l in allres))
    r = allres["v2"]
    good = (r["1 zlib 1.2.11 matches CVE-2026-1000 (VulnCheck CPE)"] and len(r["1 cjson_project:cjson 1.7.10 matches (expect 2 with aliases)"]) == 2
            and r["2 second mirror, nothing changed: CVEs ingested"] == 0 and r["3 ... zlib still matches CVE-2026-1000"]
            and r["4 after the adapter rebuilt: zlib matches CVE-2026-1000"] and r["5 restart again, nothing changed: CVEs ingested"] == 0
            and r["5 ... zlib still matches CVE-2026-1000"]
            and r["6 DT 5.2.2, first mirror (no watermark): reads every feed"] and r["7 the adapter copied 1 rewritten old CVE into modified (/stats)"] and r["7 next mirror skips the yearly feeds (watermark under 6 days)"]
            and r["7 ... zlib 1.2.11 matches CVE-2021-3000 (VulnCheck CPE for an old CVE)"] and r["7 ... watermark committed (no coverage gap)"]
            and r["8 restart, nothing changed: CVEs ingested"] == 0 and r["8 ... zlib still matches CVE-2021-3000"]
            and r["9 drop guard accepted later (DT 5.2.1): zlib matches CVE-2021-3000"] is True and r["9 ... the same with DT 5.2.2"] is True
            and r["10 rewrite 3 days before DT 5.2.2 mirrors: zlib matches CVE-2021-3000"] is True
            and r["11 copy lookup: CVE-1999 in the 2002 feed, feed from assigned.json"] is True
            and r["13 a rewrite older than the window is no longer copied"] is True
            and r["14 a NIST change published late still reaches DT after a rewrite"] is True
            and r.get("12 upgrade 2.1 -> 2.2 with DT 5.2.2: only modified rebuilt, CPE arrives", True) is True)
    print("v2 RESULT:", "PASS" if good else "FAIL")
    sys.exit(0 if good else 1)
