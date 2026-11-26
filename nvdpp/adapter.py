"""
NVD feed adapter for Dependency-Track v5, version 2 (no cron, no CI).

DT's NVD data source downloads NVD JSON 2.0 feed files from a configurable URL
(<cveFeedsUrl>/json/cve/2.0/nvdcve-2.0-<year|modified>.meta / .json.gz).
Point that URL at this adapter (http://nvdpp:8080/feeds). It serves EVERY feed file
(all yearly feeds and "modified") rebuilt from NIST's, with two changes:

  * CVEs that NIST left without CPE configurations but VulnCheck NVD++ (community index
    nist-nvd2) has "vcConfigurations" for get those configurations (attribution below);
  * CPE vendor aliases from cpe-aliases.json are applied: when NVD files one product under
    several vendor names (cjson_project:cjson and davegamble:cjson), each match is copied
    to the other names, so a component with either CPE matches.

How DT reads the feeds (vuln-data-source/nvd in DT 5.2.1): one global watermark (the newest
lastModified it ingested) and one sha256 per feed file. DT skips a feed file whose sha256 is
unchanged or whose .meta lastModifiedDate is not after the watermark, and skips every CVE
whose lastModified is not after the watermark. Feeds are read newest year first, "modified" last.

Version 1 changed only the modified feed and passed the yearly feeds through from NIST. When
NIST touched an enriched CVE, its yearly feed (NIST's record, no CPEs) overwrote DT's copy, and
after a restart the old modified feed was skipped (same sha256), so the CPEs were lost. The
delivery bookkeeping also lived in memory, so a restart re-bumped all 56,106 enriched CVEs.

Version 2 therefore:
  * puts the same rewritten record into every feed that carries the CVE (yearly and modified);
  * gives each rewritten CVE a stable lastModified, stored in /cache/assigned.json: it changes
    only when NIST changes the CVE or the rewrite result changes (new VulnCheck data, new alias),
    so DT ingests each change exactly once, across restarts;
  * new values are just above NIST's newest change (and above any value handed out before), so
    DT's watermark never runs ahead of NIST;
  * serves the last good build after a restart and rebuilds in the background; only a cold cache
    answers 503 (DT then retries on its next run).
If VulnCheck is unavailable, the last candidates are kept; without any, only aliases apply.

Attribution: CPE data in enriched records comes from VulnCheck NVD++
(https://vulncheck.com/nvd2); VulnCheck community terms require attribution.
"""
import datetime as dt
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import sys
import threading
import time
import traceback
import uuid
import urllib.error
import urllib.request
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:  # optional; only used for very large single JSON files
    import ijson
except ImportError:
    ijson = None

TOKEN = os.environ.get("VULNCHECK_TOKEN", "").strip()
NIST_BASE = os.environ.get("NIST_FEEDS_URL", "https://nvd.nist.gov/feeds").rstrip("/")
VC_API = os.environ.get("VULNCHECK_API_URL", "https://api.vulncheck.com").rstrip("/")
VC_INDEX = os.environ.get("VULNCHECK_INDEX", "nist-nvd2")
CACHE = os.environ.get("CACHE_DIR", "/cache")
PORT = int(os.environ.get("PORT", "8080"))
FEED_MAX_AGE_MIN = int(os.environ.get("FEED_MAX_AGE_MIN", "60"))
VC_MAX_AGE_HOURS = int(os.environ.get("VC_MAX_AGE_HOURS", "24"))
GAP_SINCE = os.environ.get("GAP_SINCE", "2026-04-15")

FEED_RE = re.compile(r"^/feeds/json/cve/2\.0/nvdcve-2\.0-(modified|\d{4})\.(meta|json\.gz)$")
CPP_PRODUCTS = {
    "openssl", "zlib", "libpng", "curl", "libcurl", "sqlite", "libxml2", "libexpat", "expat", "cjson",
    "fmt", "boost", "protobuf", "libjpeg-turbo", "freetype", "glibc", "busybox", "libtiff", "ffmpeg",
    "gnutls", "mbed_tls", "wolfssl", "libssh", "libssh2", "nghttp2", "c-ares", "pcre2", "libarchive",
    "xz", "zstandard", "lz4", "harfbuzz", "libwebp", "openjpeg", "mosquitto", "zephyr", "lwip",
    "libuv", "libevent", "libyaml", "jsoncpp", "rapidjson", "nlohmann_json", "spdlog", "poco",
    "qt", "opencv", "grpc", "abseil", "libsodium", "libgcrypt", "libtasn1", "gstreamer", "dbus",
}

CPP_VENDOR_PRODUCTS = {
    ("openssl", "openssl"), ("zlib", "zlib"), ("libpng", "libpng"), ("haxx", "curl"), ("haxx", "libcurl"),
    ("sqlite", "sqlite"), ("xmlsoft", "libxml2"), ("libxml2_project", "libxml2"), ("libexpat_project", "libexpat"),
    ("cjson_project", "cjson"), ("davegamble", "cjson"), ("fmt", "fmt"), ("boost", "boost"), ("google", "protobuf"),
    ("libjpeg-turbo", "libjpeg-turbo"), ("freetype", "freetype"), ("gnu", "glibc"), ("busybox", "busybox"),
    ("libtiff", "libtiff"), ("ffmpeg", "ffmpeg"), ("gnu", "gnutls"), ("arm", "mbed_tls"), ("wolfssl", "wolfssl"),
    ("libssh", "libssh"), ("libssh2", "libssh2"), ("nghttp2", "nghttp2"), ("c-ares", "c-ares"),
    ("c-ares_project", "c-ares"), ("pcre", "pcre2"), ("libarchive", "libarchive"), ("tukaani", "xz"),
    ("facebook", "zstandard"), ("lz4_project", "lz4"), ("harfbuzz_project", "harfbuzz"), ("webmproject", "libwebp"),
    ("uclouvain", "openjpeg"), ("eclipse", "mosquitto"), ("zephyrproject", "zephyr"), ("lwip_project", "lwip"),
    ("libuv", "libuv"), ("libevent_project", "libevent"), ("pyyaml", "libyaml"), ("jsoncpp_project", "jsoncpp"),
    ("tencent", "rapidjson"), ("nlohmann", "json"), ("gabime", "spdlog"), ("pocoproject", "poco"), ("qt", "qt"),
    ("opencv", "opencv"), ("grpc", "grpc"), ("abseil", "abseil"), ("libsodium_project", "libsodium"),
    ("gnupg", "libgcrypt"), ("gnu", "libtasn1"), ("gstreamer_project", "gstreamer"), ("freedesktop", "dbus"),
    ("linux", "linux_kernel"), ("gnu", "binutils"), ("llvm", "llvm"), ("imagemagick", "imagemagick"),
    ("libraw", "libraw"), ("openldap", "openldap"), ("mit", "kerberos_5"), ("libgit2_project", "libgit2"),
    ("mozilla", "nss"), ("gnome", "libxslt"), ("xmlsoft", "libxslt"), ("libsdl", "sdl"), ("assimp", "assimp"),
}

os.makedirs(os.path.join(CACHE, "feeds"), exist_ok=True)
os.makedirs(os.path.join(CACHE, "vc"), exist_ok=True)
CAND_FILE = os.path.join(CACHE, "vc", "candidates.jsonl.gz")
VC_STATS_FILE = os.path.join(CACHE, "vc", "stats.json")
BUMPS_FILE = os.path.join(CACHE, "delivered.json")   # CVEs DT has received, with the lastModified it got
PENDING_FILE = os.path.join(CACHE, "pending.json")   # version 1 only; no longer used
ASSIGNED_FILE = os.path.join(CACHE, "assigned.json")  # CVE -> lastModified served, NIST lastModified, content signature
ISSUED_FILE = os.path.join(CACHE, "issued.json")      # newest lastModified handed out so far
FEEDS_DIR = os.path.join(CACHE, "feeds")
FEED_STATE_FILE = os.path.join(FEEDS_DIR, "state.json")
VP_FILE = os.path.join(FEEDS_DIR, "vendor-products.json")
CAND_FOUND_FILE = os.path.join(FEEDS_DIR, "candidates-in-yearly.json")
ALIASES_FILE = os.environ.get("CPE_ALIASES_FILE",
                              os.path.join(os.path.dirname(os.path.abspath(__file__)), "cpe-aliases.json"))
FIRST_YEAR = int(os.environ.get("FIRST_YEAR", "2002"))

state_lock = threading.Lock()
build_lock = threading.Lock()
state = {
    "phase": "starting",
    "vulncheck": {"status": "not loaded", "error": None},
    "modified_feed": {"built_at": None, "error": None},
    "feeds": {},
    "aliases": {},
    "progress": {},
}


def log(msg):
    print(f"{dt.datetime.now(dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')} {msg}", flush=True)


def set_state(**kw):
    with state_lock:
        state.update(kw)


def parse_ts(s):
    """NVD timestamps: '2026-11-11T14:15:16.123' (UTC, naive) or ISO with offset."""
    if not s:
        return None
    t = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return t.astimezone(dt.timezone.utc)


def fmt_ts(t):
    t = t.astimezone(dt.timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}"


def http_get(url, headers=None, timeout=120):
    req = urllib.request.Request(url, headers=headers or {})
    return urllib.request.urlopen(req, timeout=timeout)


def has_cpe_config(configs):
    if not configs:
        return False
    for c in configs:
        for n in (c or {}).get("nodes") or []:
            if n.get("cpeMatch"):
                return True
    return False


# ---------------------------------------------------------------- VulnCheck
def detect_prefix(open_member):
    """Find where the records are inside one JSON file of the backup."""
    with open_member() as f:
        for prefix, event, value in ijson.parse(f):
            if prefix == "" and event == "start_array":
                return "item"
            if prefix == "" and event == "map_key" and value in ("id", "cve"):
                return ""  # the file is a single record
            if event == "start_array" and prefix and "." not in prefix:
                return prefix + ".item"
    return None


def records_in(doc):
    """Return the list of records in one parsed JSON document of the backup."""
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict):
        if "id" in doc or "cve" in doc:
            return [doc]
        for key in ("data", "vulnerabilities", "results", "items"):
            if isinstance(doc.get(key), list):
                return doc[key]
        for v in doc.values():
            if isinstance(v, list):
                return v
    return []


def iter_records(zip_path):
    with zipfile.ZipFile(zip_path) as z:
        members = [m for m in z.infolist() if not m.is_dir() and re.search(r"\.json(\.gz)?$", m.filename)]
        log(f"backup contains {len(members)} JSON file(s)")
        for i, m in enumerate(members):
            def opener(m=m):
                raw = z.open(m)
                return gzip.GzipFile(fileobj=raw) if m.filename.endswith(".gz") else raw
            if m.file_size > (768 << 20) and ijson is not None:
                prefix = detect_prefix(opener)  # stream very large files
                if prefix is not None:
                    with opener() as f:
                        for rec in ijson.items(f, prefix, use_float=True):
                            yield rec
            else:
                with opener() as f:
                    recs = records_in(json.load(f))  # stdlib json (C-accelerated) is fast
                if i < 2:
                    log(f"  {m.filename}: {len(recs)} records")
                for rec in recs:
                    yield rec
            with state_lock:
                state["progress"]["files_parsed"] = i + 1
                state["progress"]["files_total"] = len(members)


def load_vulncheck(force=False):
    """Download and digest the VulnCheck backup into candidates.jsonl.gz."""
    if not TOKEN:
        set_state(vulncheck={"status": "disabled", "error": "VULNCHECK_TOKEN not set"})
        return
    fresh = os.path.exists(CAND_FILE) and (time.time() - os.path.getmtime(CAND_FILE)) < VC_MAX_AGE_HOURS * 3600
    if fresh and not force:
        with open(VC_STATS_FILE) as f:
            set_state(vulncheck=json.load(f))
        log("VulnCheck candidates are fresh; reusing cache")
        return
    set_state(phase="downloading VulnCheck backup")
    try:
        with http_get(f"{VC_API}/v3/backup/{VC_INDEX}",
                      {"Accept": "application/json", "Authorization": f"Bearer {TOKEN}"}, 60) as r:
            meta = json.load(r)
        entry = (meta.get("data") or [None])[0]
        if not entry or not entry.get("url"):
            raise RuntimeError(f"no backup URL in response: {json.dumps(meta)[:300]}")
        zpath = os.path.join(CACHE, "vc", "backup.zip")
        reuse = False
        if os.path.exists(zpath) and entry.get("sha256"):
            hh = hashlib.sha256()
            with open(zpath, "rb") as zf:
                for chunk in iter(lambda: zf.read(1 << 20), b""):
                    hh.update(chunk)
            reuse = hh.hexdigest() == entry["sha256"].lower()
        h = hashlib.sha256()
        done = 0
        if reuse:
            log(f"reusing downloaded {entry.get('filename')} (sha256 matches)")
        else:
            log(f"downloading {entry.get('filename')} (added {entry.get('date_added')})")
        with (open(os.devnull, "rb") if reuse else http_get(entry["url"], timeout=600)) as r, \
                open(os.devnull if reuse else zpath, "wb") as out:
            while True:
                b = r.read(1 << 20)
                if not b:
                    break
                out.write(b)
                h.update(b)
                done += len(b)
                with state_lock:
                    state["progress"]["downloaded_mb"] = round(done / 1048576, 1)
        if not reuse and entry.get("sha256") and entry["sha256"].lower() != h.hexdigest():
            raise RuntimeError("backup sha256 mismatch")
        set_state(phase="parsing VulnCheck backup")
        stats = {"status": "loaded", "error": None, "backup": entry.get("filename"),
                 "backup_date": entry.get("date_added"), "loaded_at": fmt_ts(dt.datetime.now(dt.timezone.utc)),
                 "records": 0, "rejected": 0, "nist_has_cpes": 0, "vc_has_cpes": 0, "candidates": 0,
                 "candidates_published_since_gap": 0, "gap_since": GAP_SINCE,
                 "nist_no_cpes_published_since_gap": 0, "candidates_by_year": {}, "cpp_examples": []}
        gap = parse_ts(GAP_SINCE + "T00:00:00")
        tmp = CAND_FILE + ".tmp"
        seen_example_products = set()
        with gzip.open(tmp, "wt", encoding="utf-8") as out:
            for rec in iter_records(zpath):
                cve = rec.get("cve") if isinstance(rec.get("cve"), dict) else rec
                cid = cve.get("id")
                if not cid or not str(cid).startswith("CVE-"):
                    continue
                stats["records"] += 1
                if stats["records"] % 20000 == 0:
                    with state_lock:
                        state["progress"]["records_parsed"] = stats["records"]
                if (cve.get("vulnStatus") or "").lower() == "rejected":
                    stats["rejected"] += 1
                    continue
                vc = rec.get("vcConfigurations") or cve.get("vcConfigurations")
                vc_cpes = rec.get("vcVulnerableCPEs") or cve.get("vcVulnerableCPEs") or []
                nist_ok = has_cpe_config(cve.get("configurations"))
                pub = parse_ts(cve.get("published"))
                if nist_ok:
                    stats["nist_has_cpes"] += 1
                elif pub and pub >= gap:
                    stats["nist_no_cpes_published_since_gap"] += 1
                if not has_cpe_config(vc):
                    continue
                stats["vc_has_cpes"] += 1
                if nist_ok:
                    continue
                # Candidate: NIST has no CPEs, VulnCheck has.
                out_cve = {k: v for k, v in cve.items() if not k.startswith("vc")}
                out_cve["configurations"] = vc
                out.write(json.dumps({"cve": out_cve}, separators=(",", ":")) + "\n")
                stats["candidates"] += 1
                y = (cve.get("published") or "????")[:4]
                stats["candidates_by_year"][y] = stats["candidates_by_year"].get(y, 0) + 1
                if pub and pub >= gap:
                    stats["candidates_published_since_gap"] += 1
                    # C/C++ examples with an exact vulnerable version, for the gap test SBOM
                    if len(stats["cpp_examples"]) < 12:
                        for cpe in vc_cpes:
                            p = cpe.split(":")
                            if len(p) > 5 and p[2] == "a" and p[4] in CPP_PRODUCTS and p[5] not in ("*", "-", "") \
                                    and p[4] not in seen_example_products:
                                stats["cpp_examples"].append({"cve": cid, "cpe": cpe, "vendor": p[3],
                                                              "product": p[4], "version": p[5]})
                                seen_example_products.add(p[4])
                                break
        os.replace(tmp, CAND_FILE)
        os.remove(zpath)  # keep only the digest, to save disk space
        with open(VC_STATS_FILE, "w") as f:
            json.dump(stats, f, indent=1)
        set_state(vulncheck=stats)
        log(f"VulnCheck: {stats['records']} records, {stats['candidates']} candidates "
            f"({stats['candidates_published_since_gap']} published since {GAP_SINCE})")
    except Exception as e:  # keep serving NIST data
        err = f"{type(e).__name__}: {e}"
        if isinstance(e, urllib.error.HTTPError):
            try:
                err += " | " + e.read().decode("utf-8", "replace")[:300]
            except Exception:
                pass
        log("VulnCheck load failed: " + err)
        prev = {}
        if os.path.exists(VC_STATS_FILE):
            with open(VC_STATS_FILE) as f:
                prev = json.load(f)
        prev.update({"status": "failed" if not prev.get("records") else "stale", "error": err})
        set_state(vulncheck=prev)


def iter_candidates():
    if not os.path.exists(CAND_FILE):
        return
    with gzip.open(CAND_FILE, "rt", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)



# ---------------------------------------------------------------- helpers
def read_json(path, default):
    if os.path.exists(path):
        try:
            with open(path) as f:
                return json.load(f)
        except ValueError:
            log(f"ignoring unreadable {path}")
    return default


def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f)
    os.replace(tmp, path)


def file_version(path):
    if not os.path.exists(path):
        return "none"
    st = os.stat(path)
    return f"{int(st.st_mtime)}-{st.st_size}"


def iter_feed_items(path):
    """Stream the items of the "vulnerabilities" array of an NVD JSON 2.0 feed (.json.gz)."""
    dec = json.JSONDecoder()
    with gzip.open(path, "rt", encoding="utf-8") as f:
        buf, pos = "", 0
        while True:
            chunk = f.read(1 << 20)
            buf += chunk
            i = buf.find('"vulnerabilities"')
            j = buf.find("[", i) if i >= 0 else -1
            if j >= 0:
                pos = j + 1
                break
            if not chunk:
                return
        while True:
            while True:
                while pos < len(buf) and buf[pos] in " \r\n\t,":
                    pos += 1
                if pos < len(buf):
                    break
                chunk = f.read(1 << 20)
                if not chunk:
                    return
                buf, pos = buf[pos:] + chunk, 0
            if buf[pos] == "]":
                return
            try:
                obj, end = dec.raw_decode(buf, pos)
            except json.JSONDecodeError:
                chunk = f.read(1 << 20)
                if not chunk:
                    raise
                buf, pos = buf[pos:] + chunk, 0
                continue
            yield obj
            pos = end
            if pos > (8 << 20):
                buf, pos = buf[pos:], 0


# ---------------------------------------------------------------- CPE vendor aliases
def load_aliases():
    """cpe-aliases.json: {"aliases": [{"same": ["cjson_project:cjson", "davegamble:cjson"], "note": "..."}]}"""
    groups = []
    doc = read_json(ALIASES_FILE, {})
    for g in doc.get("aliases", []):
        pairs = []
        for x in g.get("same", []):
            v, _, p = str(x).strip().lower().partition(":")
            if v and p:
                pairs.append((v, p))
        if len(set(pairs)) >= 2:
            groups.append(sorted(set(pairs)))
    amap = {}
    for pairs in groups:
        for pr in pairs:
            amap.setdefault(pr, set()).update(q for q in pairs if q != pr)
    version = hashlib.sha256(json.dumps(sorted(groups)).encode()).hexdigest()[:12] if groups else "none"
    return {k: sorted(v) for k, v in amap.items()}, version, len(groups)


def apply_aliases(cve, amap):
    """Copy every CPE match on an aliased vendor:product to the other names. Returns copies added."""
    added = 0
    for c in cve.get("configurations") or []:
        for n in (c or {}).get("nodes") or []:
            ms = n.get("cpeMatch") or []
            def key(m, crit=None):
                return (crit or m.get("criteria"), m.get("versionStartIncluding"), m.get("versionStartExcluding"),
                        m.get("versionEndIncluding"), m.get("versionEndExcluding"), m.get("vulnerable"))
            have = {key(m) for m in ms}
            extra = []
            for m in ms:
                p = (m.get("criteria") or "").split(":")
                if len(p) < 13:
                    continue
                for v, pr in amap.get((p[3].lower(), p[4].lower()), []):
                    q = list(p); q[3], q[4] = v, pr
                    crit = ":".join(q)
                    k = key(m, crit)
                    if k in have:
                        continue
                    nm = dict(m)
                    nm["criteria"] = crit
                    if m.get("matchCriteriaId"):
                        nm["matchCriteriaId"] = str(uuid.uuid5(uuid.NAMESPACE_URL, m["matchCriteriaId"] + "|" + crit)).upper()
                    extra.append(nm)
                    have.add(k)
            if extra:
                n["cpeMatch"] = ms + extra
                added += len(extra)
    return added


# ---------------------------------------------------------------- stable lastModified values
class Assigner:
    """Hands out stable lastModified values for rewritten CVEs (persisted in /cache)."""

    def __init__(self, base):
        self.base = base  # NIST's newest change (lastModifiedDate of its modified feed)
        self.rec = read_json(ASSIGNED_FILE, {})
        self.legacy = read_json(BUMPS_FILE, {}) if not self.rec else {}  # migrate from version 1 once
        # every value DT may have ingested from us (incl. version 1 bumps) is a floor for new ones,
        # because DT's watermark can be that high
        seen = [read_json(ISSUED_FILE, {}).get("last")] + [r.get("lm") for r in self.rec.values()] \
            + list(read_json(BUMPS_FILE, {}).values())
        seen = [parse_ts(x) for x in seen if x]
        self.last = max(seen) if seen else None
        self.new = self.kept = self.migrated = 0

    def lm(self, cve, nist_lm, aliased):
        cid = cve["id"]
        sig = hashlib.sha1(json.dumps(cve.get("configurations"), sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        r = self.rec.get(cid)
        if r and r.get("src") == nist_lm and r.get("sig") == sig:
            self.kept += 1
            return r["lm"]
        old = self.legacy.get(cid)
        if r is None and old and not aliased and parse_ts(old) > (parse_ts(nist_lm) or parse_ts(old)):
            self.rec[cid] = {"lm": old, "src": nist_lm, "sig": sig}  # DT already has this record from version 1
            self.migrated += 1
            return old
        t = self.base + dt.timedelta(milliseconds=1)
        if self.last and t <= self.last:
            t = self.last + dt.timedelta(milliseconds=1)
        src = parse_ts(nist_lm)
        if src and t <= src:
            t = src + dt.timedelta(milliseconds=1)
        self.last = t
        v = fmt_ts(t)
        self.rec[cid] = {"lm": v, "src": nist_lm, "sig": sig}
        self.new += 1
        return v

    def save(self):
        write_json(ASSIGNED_FILE, self.rec)
        if self.last:
            write_json(ISSUED_FILE, {"last": fmt_ts(self.last)})


# ---------------------------------------------------------------- feed builds
def nist_meta(name):
    with http_get(f"{NIST_BASE}/json/cve/2.0/nvdcve-2.0-{name}.meta", timeout=60) as r:
        text = r.read().decode()
    out = {}
    for line in text.splitlines():
        k, _, v = line.partition(":")
        out[k.strip()] = v.strip()
    return out


def write_feed(name, items, transform):
    """Write FEEDS_DIR/<name>.json.gz + .meta from an item iterator; returns counts."""
    out_tmp = os.path.join(FEEDS_DIR, f"{name}.json.gz.tmp")
    sha = hashlib.sha256()
    size = count = 0
    max_lm = None
    stats = {"enriched": 0, "aliased_cves": 0, "alias_matches_added": 0}
    with gzip.open(out_tmp, "wb") as gz:
        def put(b):
            nonlocal size
            gz.write(b); sha.update(b); size += len(b)
        put(('{"resultsPerPage":0,"startIndex":0,"format":"NVD_CVE","version":"2.0",'
             f'"timestamp":"{fmt_ts(dt.datetime.now(dt.timezone.utc))}","vulnerabilities":[').encode())
        for item in items:
            transform(item, stats)
            t = parse_ts(item["cve"].get("lastModified"))
            if t and (max_lm is None or t > max_lm):
                max_lm = t
            put((("," if count else "") + json.dumps(item, separators=(",", ":"))).encode("utf-8"))
            count += 1
        put(f'],"totalResults":{count}}}'.encode())
    gz_size = os.path.getsize(out_tmp)
    max_lm = max_lm or dt.datetime.now(dt.timezone.utc)
    # milliseconds matter: DT compares this instant with its watermark (Instant.parse keeps them)
    meta = (f"lastModifiedDate:{fmt_ts(max_lm)}Z\r\n"
            f"size:{size}\r\nzipSize:{gz_size}\r\ngzSize:{gz_size}\r\nsha256:{sha.hexdigest().upper()}\r\n")
    os.replace(out_tmp, os.path.join(FEEDS_DIR, f"{name}.json.gz"))
    with open(os.path.join(FEEDS_DIR, f"{name}.meta.tmp"), "w", newline="") as f:
        f.write(meta)
    os.replace(os.path.join(FEEDS_DIR, f"{name}.meta.tmp"), os.path.join(FEEDS_DIR, f"{name}.meta"))
    stats.update(cves=count, meta_last_modified=fmt_ts(max_lm), sha256=sha.hexdigest()[:16])
    return stats


def make_transform(cand_cfg, amap, assigner, seen, vp):
    def transform(item, stats):
        cve = item["cve"]
        cid = cve.get("id")
        seen.add(cid)
        nist_lm = cve.get("lastModified")
        enriched = False
        if cid in cand_cfg and not has_cpe_config(cve.get("configurations")):
            cve["configurations"] = json.loads(json.dumps(cand_cfg[cid]))
            enriched = True
        added = apply_aliases(cve, amap) if amap else 0
        for c in cve.get("configurations") or []:  # vendor names per product, for /aliases/suggest
            for n in (c or {}).get("nodes") or []:
                for m in n.get("cpeMatch") or []:
                    p = (m.get("criteria") or "").split(":")
                    if len(p) > 5 and p[4] in CPP_PRODUCTS:
                        vp.setdefault(p[4], set()).add(p[3])
        if enriched or added:
            cve["lastModified"] = assigner.lm(cve, nist_lm, bool(added))
            stats["enriched"] += enriched
            stats["aliased_cves"] += bool(added)
            stats["alias_matches_added"] += added
    return transform


def build_all(force=False):
    """Rebuild every feed whose NIST input, VulnCheck candidates or alias file changed."""
    t0 = time.time()
    set_state(phase="building feeds")
    amap, aver, ngroups = load_aliases()
    cver = file_version(CAND_FILE)
    cand_cfg = {}
    for item in iter_candidates():
        cand_cfg[item["cve"]["id"]] = item["cve"]["configurations"]
    mod_meta = nist_meta("modified")
    base = parse_ts(mod_meta.get("lastModifiedDate")) or dt.datetime.now(dt.timezone.utc)
    assigner = Assigner(base)
    fstate = read_json(FEED_STATE_FILE, {})
    vp = {k: set(v) for k, v in read_json(VP_FILE, {}).items()}
    cand_found = set(read_json(CAND_FOUND_FILE, []))
    set_state(aliases={"file": ALIASES_FILE, "groups": ngroups, "version": aver})
    years = [str(y) for y in range(dt.datetime.now(dt.timezone.utc).year, FIRST_YEAR - 1, -1)]
    for name in years + ["modified"]:
        meta = mod_meta if name == "modified" else nist_meta(name)
        key = f"{meta.get('sha256')}|{cver}|{aver}"
        have = os.path.exists(os.path.join(FEEDS_DIR, f"{name}.meta"))
        if not force and have and fstate.get(name, {}).get("key") == key:
            continue
        set_state(phase=f"building feed {name}")
        raw = os.path.join(FEEDS_DIR, f"nist-{name}.json.gz")
        with http_get(f"{NIST_BASE}/json/cve/2.0/nvdcve-2.0-{name}.json.gz", timeout=900) as r, open(raw, "wb") as out:
            shutil.copyfileobj(r, out, 1 << 20)
        seen = set()
        transform = make_transform(cand_cfg, amap, assigner, seen, vp)
        if name == "modified":
            # candidates that are in no NIST feed yet (VulnCheck ahead of NIST): deliver them here
            def items():
                yield from iter_feed_items(raw)
                for it in iter_candidates():
                    cid = it["cve"]["id"]
                    if cid not in seen and cid not in cand_found:
                        yield {"cve": it["cve"]}
            st = write_feed(name, items(), transform)
        else:
            st = write_feed(name, iter_feed_items(raw), transform)
            cand_found |= {c for c in seen if c in cand_cfg}
        os.remove(raw)
        st.update(key=key, built_at=fmt_ts(dt.datetime.now(dt.timezone.utc)), nist_sha256=(meta.get("sha256") or "")[:16])
        fstate[name] = st
        write_json(FEED_STATE_FILE, fstate)
        assigner.save()
        with state_lock:
            state["feeds"][name] = st
        log(f"feed {name} built: {st}")
    write_json(VP_FILE, {k: sorted(v) for k, v in vp.items()})
    write_json(CAND_FOUND_FILE, sorted(cand_found))
    assigner.save()
    info = {"built_at": fmt_ts(dt.datetime.now(dt.timezone.utc)), "error": None, "seconds": round(time.time() - t0, 1),
            "candidates": len(cand_cfg), "assigned_total": len(assigner.rec), "assigned_new": assigner.new,
            "assigned_kept": assigner.kept, "migrated_from_v1": assigner.migrated,
            "last_issued": fmt_ts(assigner.last) if assigner.last else None, "nist_base": fmt_ts(base)}
    set_state(modified_feed=info, phase="ready")
    log(f"build done: {info}")


def rebuild(force_vc=False, force=False):
    if not build_lock.acquire(blocking=False):
        return False
    try:
        load_vulncheck(force=force_vc)
        build_all(force=force)
    except Exception as e:
        log("build failed: " + traceback.format_exc())
        with state_lock:
            state["modified_feed"]["error"] = f"{type(e).__name__}: {e}"
            state["phase"] = "ready" if os.path.exists(os.path.join(FEEDS_DIR, "modified.meta")) else "error"
    finally:
        build_lock.release()
    return True


def maybe_rebuild_async():
    p = os.path.join(FEEDS_DIR, "modified.meta")
    if os.path.exists(p) and (time.time() - os.path.getmtime(p)) < FEED_MAX_AGE_MIN * 60:
        return
    threading.Thread(target=rebuild, daemon=True).start()


def refresher():
    """Keep the feeds close to NIST's while the adapter runs (no external scheduler needed)."""
    while True:
        time.sleep(FEED_MAX_AGE_MIN * 60)
        rebuild()


def cpp_examples(limit=15):
    """C/C++ components with an exact vulnerable version, from CVEs only VulnCheck has CPEs for."""
    gap = parse_ts(GAP_SINCE + "T00:00:00")
    best = {}
    for item in iter_candidates():
        cve = item["cve"]
        pub = parse_ts(cve.get("published"))
        if not pub or pub < gap:
            continue
        for c in cve.get("configurations") or []:
            for n in c.get("nodes") or []:
                for m in n.get("cpeMatch") or []:
                    if not m.get("vulnerable"):
                        continue
                    p = (m.get("criteria") or "").split(":")
                    if len(p) < 13 or p[2] != "a" or (p[3], p[4]) not in CPP_VENDOR_PRODUCTS:
                        continue
                    ver = p[5]
                    if ver in ("*", "-", ""):
                        ver = m.get("versionEndIncluding") or (m.get("versionStartIncluding") if m.get("versionEndExcluding") else None)
                    if not ver:
                        continue
                    p[5] = ver
                    key = (p[3], p[4])
                    if key not in best or pub > best[key]["_pub"]:
                        best[key] = {"cve": cve["id"], "cpe": ":".join(p), "vendor": p[3], "product": p[4],
                                     "version": ver, "published": cve.get("published"), "_pub": pub}
    out = sorted(best.values(), key=lambda x: x["_pub"], reverse=True)[:limit]
    for x in out:
        x.pop("_pub", None)
    return out


# ---------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        log("http " + (fmt % args))

    def send_bytes(self, code, body, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, path, ctype):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(os.path.getsize(path)))
        self.end_headers()
        with open(path, "rb") as f:
            shutil.copyfileobj(f, self.wfile, 1 << 20)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/healthz":
            return self.send_bytes(200, b"ok", "text/plain")
        if path == "/stats":
            with state_lock:
                body = json.dumps(state, indent=1, default=str).encode()
            return self.send_bytes(200, body, "application/json")
        if path == "/rebuild":
            t = threading.Thread(target=rebuild, kwargs={"force_vc": "vc=1" in self.path, "force": "all=1" in self.path},
                                 daemon=True)
            t.start()
            if "wait=1" in self.path:
                t.join()
                while build_lock.locked():  # another build was already running
                    time.sleep(2)
                with state_lock:
                    body = json.dumps(state["modified_feed"], default=str).encode()
                return self.send_bytes(200, body, "application/json")
            return self.send_bytes(202, b"rebuild started", "text/plain")
        if path == "/aliases":
            amap, aver, n = load_aliases()
            return self.send_bytes(200, json.dumps({"file": ALIASES_FILE, "version": aver, "groups": n,
                                                     "map": {f"{k[0]}:{k[1]}": [f"{v}:{p}" for v, p in vs]
                                                             for k, vs in amap.items()}}, indent=1).encode(),
                                   "application/json")
        if path == "/aliases/suggest":
            vp = read_json(VP_FILE, {})
            amap, _, _ = load_aliases()
            sug = {p: vs for p, vs in sorted(vp.items()) if len(vs) > 1
                   and not all((v, p) in amap for v in vs)}
            return self.send_bytes(200, json.dumps({"note": "C/C++ products that NVD files under more than one vendor "
                                                            "and that cpe-aliases.json does not cover yet. Check each "
                                                            "before adding it: some are different products.",
                                                    "products": sug}, indent=1).encode(), "application/json")
        if path == "/examples":
            return self.send_bytes(200, json.dumps(cpp_examples()).encode(), "application/json")
        if path == "/candidate-ids":
            ids = [i["cve"]["id"] for i in iter_candidates()]
            return self.send_bytes(200, json.dumps(ids).encode(), "application/json")
        m = FEED_RE.match(path)
        if not m:
            return self.send_bytes(404, b"not found", "text/plain")
        name, kind = m.groups()
        ctype = "text/plain" if kind == "meta" else "application/gzip"
        p = os.path.join(FEEDS_DIR, f"{name}.meta" if kind == "meta" else f"{name}.json.gz")
        if not os.path.exists(p):
            # cold cache: never hand DT an unenriched NIST file; DT retries on its next run
            maybe_rebuild_async()
            return self.send_bytes(503, f"feed {name} is being built".encode(), "text/plain")
        if kind == "meta" and name == "modified":
            maybe_rebuild_async()  # DT's own mirror run triggers refreshes; serve the last build now
        return self.send_file(p, ctype)


def main():
    log(f"NVD feed adapter v2 starting; VulnCheck token set: {bool(TOKEN)}; index {VC_INDEX}; aliases {ALIASES_FILE}")
    with state_lock:
        state["feeds"] = read_json(FEED_STATE_FILE, {})
    threading.Thread(target=rebuild, daemon=True).start()
    threading.Thread(target=refresher, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    sys.exit(main())
