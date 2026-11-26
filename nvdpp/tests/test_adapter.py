#!/usr/bin/env python3
"""Scenario test for the NVD feed adapter: a fake NIST feed server, a client that follows
Dependency-Track 5.2.1's NVD mirroring rules (vuln-data-source/nvd: per-feed sha256 skip,
global watermark, per-CVE lastModified skip, newest year first, "modified" last), and the
restart and NIST-update cases where adapter version 1 lost VulnCheck CPEs.

usage: test_adapter.py <adapter.py> [--v1 <old adapter.py>]
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
    """Dependency-Track 5.2.1 NVD mirroring rules (see NvdVulnDataSource / WatermarkManager)."""
    def __init__(self, url): self.url = url; self.W = None; self.dig = {}; self.db = {}; self.ingested = 0; self.error = None

    @staticmethod
    def inst(s):
        t = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)

    def sync(self):
        pending, consumed, ok, n = None, [], True, 0
        for name in [str(y) for y in YEARS] + ["modified"]:
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
                if self.W is not None and not self.W < lm: continue
                self.db[it["cve"]["id"]] = it["cve"]; n += 1
                if pending is None or lm > pending: pending = lm
            consumed.append((name, sha))
        for name, sha in consumed: self.dig[name] = sha
        if ok and pending and (self.W is None or pending > self.W): self.W = pending
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


if __name__ == "__main__":
    v2 = sys.argv[1]
    runs = [("v2", v2, True)]
    if "--v1" in sys.argv: runs.insert(0, ("v1", sys.argv[sys.argv.index("--v1") + 1], False))
    allres = {}
    for label, script, al in runs:
        allres[label] = scenario(script, label, al)
    keys = list(next(iter(allres.values())).keys())
    w = max(len(k) for k in keys)
    print(f"{'check':{w}}  " + "  ".join(f"{l:>28}" for l in allres))
    for k in keys:
        print(f"{k:{w}}  " + "  ".join(f"{str(allres[l].get(k)):>28}" for l in allres))
    r = allres["v2"]
    good = (r["1 zlib 1.2.11 matches CVE-2026-1000 (VulnCheck CPE)"] and len(r["1 cjson_project:cjson 1.7.10 matches (expect 2 with aliases)"]) == 2
            and r["2 second mirror, nothing changed: CVEs ingested"] == 0 and r["3 ... zlib still matches CVE-2026-1000"]
            and r["4 after the adapter rebuilt: zlib matches CVE-2026-1000"] and r["5 restart again, nothing changed: CVEs ingested"] == 0
            and r["5 ... zlib still matches CVE-2026-1000"])
    print("v2 RESULT:", "PASS" if good else "FAIL")
    sys.exit(0 if good else 1)
