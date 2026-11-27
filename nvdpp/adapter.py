"""
NVD feed adapter for Dependency-Track v5, version 2.2 (no cron, no CI).

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
DT 5.2.2 adds one rule: while its watermark is less than 6 days old it skips the yearly feeds and
reads only "modified" (NVD's modified feed covers the last 8 days).

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

Version 2.1 makes stale data visible (it used to answer /healthz "ok" whatever happened):
  * GET /health answers 200 when the data is fresh and 503 with the reasons when it is not:
    feeds missing, the last good NIST refresh older than NIST_MAX_AGE_HOURS, NIST itself publishing no
    change for NIST_QUIET_HOURS, VulnCheck data older than VC_STALE_HOURS or never loaded, the token unset
    (VULNCHECK_REQUIRED=1) or rejected. A rejected token, a removed URL (HTTP 4xx) or a drop-guard stop is
    reported at once (from NIST, 403 counts as rate limiting and is transient); network errors and 5xx
    answers only once the data is older than the limit. The state is kept in /cache/health.json, so a
    restart does not hide a failure.
  * Every refresh (hourly, and at start) checks the VulnCheck token with the small metadata call, without
    downloading the backup again while it is fresh. A revoked or mistyped token shows within the hour.
  * Drop guards: a new VulnCheck backup with more than VC_DROP_PCT % fewer records or CVEs with CPEs, or more
    than VC_CANDIDATE_DROP_PCT % fewer enriched CVEs, or a NIST yearly feed with more than FEED_DROP_PCT %
    fewer CVEs, is not used; the previous data stays and /health reports it. After checking, accept it with
    POST /rebuild?vc=1&accept_vc_drop=1 or POST /rebuild?accept_feed_drop=1 (the downloaded backup is kept
    for this, so it is not downloaded again).
  * One build worker runs every rebuild; requests made while a build runs are queued for the next one and
    never dropped. GET /rebuild only queues a plain refresh; vc=1, all=1 and the accept flags need POST with
    the header X-NVDPP-Rebuild: 1, which a web page cannot send to localhost without permission.
  * A failing feed no longer stops the others: each feed is built on its own and "modified" is always tried.
  * GET /candidates/sample lists enriched CVEs the adapter first served before a given time (wall clock,
    kept in assigned.json), so a health check can confirm that Dependency-Track has their CPEs.
/healthz stays a plain liveness answer ("ok" while the process runs).

Version 2.2 is for DT 5.2.2, which reads only the modified feed on its daily mirrors (see above). A CVE
that VulnCheck enriches, or whose aliases change, gets a new lastModified, but if NIST did not change it
recently it is in no NIST modified feed, so version 2.1 put it only into its yearly feed, which DT 5.2.2
no longer reads: the new CPEs never reached DT. Version 2.2 also copies every rewritten CVE whose
lastModified is less than MODIFIED_EXTRA_DAYS (8) days older than NIST's newest change into the modified
feed, taken from our own yearly feed (the same record, nothing downloaded). DT 5.2.1 reads both copies
of such a CVE, as it already did for CVEs that are in NIST's yearly and modified feeds.

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
import urllib.parse
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
VERSION = "2.2"
NIST_MAX_AGE_HOURS = float(os.environ.get("NIST_MAX_AGE_HOURS", "6"))   # last good refresh from NIST
NIST_QUIET_HOURS = float(os.environ.get("NIST_QUIET_HOURS", "48"))      # NIST's newest change
VC_STALE_HOURS = float(os.environ.get("VC_STALE_HOURS", "48"))          # VulnCheck data (refreshed every VC_MAX_AGE_HOURS)
VULNCHECK_REQUIRED = os.environ.get("VULNCHECK_REQUIRED", "1").strip().lower() not in ("0", "false", "no", "")
VC_DROP_PCT = float(os.environ.get("VC_DROP_PCT", "1"))
VC_CANDIDATE_DROP_PCT = float(os.environ.get("VC_CANDIDATE_DROP_PCT", "10"))  # NIST enriches some every day
FEED_DROP_PCT = float(os.environ.get("FEED_DROP_PCT", "1"))
FEED_STALE_HOURS = float(os.environ.get("FEED_STALE_HOURS", "72"))   # a feed not checked against NIST for this long
# rewritten CVEs this much older than NIST's newest change still go into "modified" (DT 5.2.2 reads only that
# feed while its watermark is under 6 days old; NVD's modified feed covers 8)
MODIFIED_EXTRA_DAYS = float(os.environ.get("MODIFIED_EXTRA_DAYS", "8"))
REBUILD_HOSTS = {h.strip().lower() for h in os.environ.get("REBUILD_HOSTS", "localhost,127.0.0.1,::1,nvdpp").split(",") if h.strip()}

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
HEALTH_FILE = os.path.join(CACHE, "health.json")   # last attempts, successes and errors (survives restarts)

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


# ---------------------------------------------------------------- health bookkeeping
class DropGuard(RuntimeError):
    """A new input is much smaller than the previous one; it is not used until someone accepts it."""


health = {}  # persisted in HEALTH_FILE: build_*, nist_newest, vc_* (see health_report)


def now_utc():
    return dt.datetime.now(dt.timezone.utc)


def note_health(**kw):
    with state_lock:
        health.update(kw)
        write_json(HEALTH_FILE, health)


def err_text(e):
    err = f"{type(e).__name__}: {e}"
    if isinstance(e, urllib.error.HTTPError):
        try:
            err += " | " + e.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
    return err


def is_permanent(e, source="vulncheck"):
    """Failures that do not fix themselves: a rejected token, a removed URL, a drop-guard stop.
    NIST's CDN answers 403 when it rate-limits, so 403 from NIST counts as transient."""
    if isinstance(e, DropGuard):
        return True
    if isinstance(e, FeedErrors):
        return any(is_permanent(x, "nist") for _, x in e.errors)
    return (isinstance(e, urllib.error.HTTPError) and 400 <= e.code < 500 and e.code not in (408, 429)
            and not (source == "nist" and e.code == 403))


class FeedErrors(RuntimeError):
    """Some feeds could not be built; the others were. modified_ok: the modified feed is current."""
    def __init__(self, errors, modified_ok):
        self.errors, self.modified_ok = errors, modified_ok
        super().__init__("; ".join(f"feed {n}: {err_text(x)}" for n, x in errors))


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


def vc_backup_entry():
    """The small metadata call: newest backup of the index (also proves that the token is accepted)."""
    with http_get(f"{VC_API}/v3/backup/{VC_INDEX}",
                  {"Accept": "application/json", "Authorization": f"Bearer {TOKEN}"}, 60) as r:
        meta = json.load(r)
    entry = (meta.get("data") or [None])[0]
    if not entry or not entry.get("url"):
        raise RuntimeError(f"no backup URL in response: {json.dumps(meta)[:300]}")
    return entry


def vc_failed(e):
    err = err_text(e)
    log("VulnCheck load failed: " + err)
    prev = read_json(VC_STATS_FILE, {})
    prev.update({"status": "failed" if not prev.get("records") else "stale", "error": err})
    set_state(vulncheck=prev)
    note_health(vc_attempt_at=fmt_ts(now_utc()), vc_error=err, vc_error_permanent=is_permanent(e),
                vc_error_drop=isinstance(e, DropGuard))


def load_vulncheck(force=False, accept_drop=False):
    """Download and digest the VulnCheck backup into candidates.jsonl.gz.
    accept_drop: use a backup the drop guard stopped (POST /rebuild?vc=1&accept_vc_drop=1)."""
    if not TOKEN:
        set_state(vulncheck=dict(read_json(VC_STATS_FILE, {}), status="disabled", error="VULNCHECK_TOKEN not set"))
        return
    fresh = os.path.exists(CAND_FILE) and (time.time() - os.path.getmtime(CAND_FILE)) < VC_MAX_AGE_HOURS * 3600
    if fresh and not force:
        stats = read_json(VC_STATS_FILE, {})
        # the cached data is fresh, so nothing is downloaded, but the token is checked on every refresh
        # with the small metadata call: a revoked or mistyped token must not stay green for a day
        try:
            vc_backup_entry()
        except Exception as e:
            vc_failed(e)
            return
        if health.get("vc_error_drop"):
            stats.update({"status": "stale", "error": health["vc_error"]})   # needs a full load or an accept
        else:
            if health.get("vc_error"):
                log("VulnCheck accepts the token again; the cached candidates are fresh")
            note_health(vc_attempt_at=fmt_ts(now_utc()), vc_ok_at=fmt_ts(now_utc()), vc_error=None,
                        vc_error_permanent=False, vc_error_drop=False)
        set_state(vulncheck=stats)
        log("VulnCheck token accepted; candidates are fresh, reusing cache")
        return
    set_state(phase="downloading VulnCheck backup")
    try:
        entry = vc_backup_entry()
        zpath = os.path.join(CACHE, "vc", "backup.zip")
        reuse = False
        if os.path.exists(zpath) and entry.get("sha256"):
            kept = read_json(zpath + ".sha256.json", {})   # stored at download time (the zip can exceed 1 GB)
            if kept.get("size") == os.path.getsize(zpath) and kept.get("sha256"):
                reuse = kept["sha256"] == entry["sha256"].lower()
            else:
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
        if reuse:
            src = open(os.devnull, "rb")
        else:
            try:
                src = http_get(entry["url"], timeout=600)
            except urllib.error.HTTPError as e:   # the body of a presigned-URL error can echo signing details
                raise RuntimeError(f"backup download failed: HTTP {e.code} {e.reason}") from None
        with src as r, open(os.devnull if reuse else zpath, "wb") as out:
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
        if not reuse:
            write_json(zpath + ".sha256.json", {"sha256": h.hexdigest(), "size": os.path.getsize(zpath)})
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
        prev = read_json(VC_STATS_FILE, {})
        if not accept_drop:
            # a truncated or broken backup must not replace good data (it would remove CPEs from Dependency-Track)
            for k, pct in (("records", VC_DROP_PCT), ("vc_has_cpes", VC_DROP_PCT), ("candidates", VC_CANDIDATE_DROP_PCT)):
                if prev.get(k) and stats[k] < prev[k] * (1 - pct / 100):
                    os.remove(tmp)
                    raise DropGuard(f"the new VulnCheck backup has {stats[k]} {k}, the previous one {prev[k]} "
                                    f"(more than {pct:g}% fewer); keeping the previous data. Check the backup, "
                                    "then accept it with POST /rebuild?vc=1&accept_vc_drop=1")
        os.replace(tmp, CAND_FILE)
        os.remove(zpath)  # keep only the digest, to save disk space (kept above when the drop guard stops)
        if os.path.exists(zpath + ".sha256.json"):
            os.remove(zpath + ".sha256.json")
        with open(VC_STATS_FILE, "w") as f:
            json.dump(stats, f, indent=1)
        set_state(vulncheck=stats)
        note_health(vc_attempt_at=fmt_ts(now_utc()), vc_ok_at=fmt_ts(now_utc()), vc_error=None,
                    vc_error_permanent=False, vc_error_drop=False)
        log(f"VulnCheck: {stats['records']} records, {stats['candidates']} candidates "
            f"({stats['candidates_published_since_gap']} published since {GAP_SINCE})")
    except Exception as e:  # keep serving the previous data
        vc_failed(e)


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

    def __init__(self, base, served_max=None):
        self.base = base  # NIST's newest change (lastModifiedDate of its modified feed)
        self.rec = read_json(ASSIGNED_FILE, {})
        self.legacy = read_json(BUMPS_FILE, {}) if not self.rec else {}  # migrate from version 1 once
        # every value DT may have ingested from us (incl. version 1 bumps), and the newest lastModified in any
        # feed we served (NIST's own values too, in case NIST's .meta lags its file), is a floor for new ones,
        # because DT's watermark can be that high
        seen = [read_json(ISSUED_FILE, {}).get("last"), served_max] + [r.get("lm") for r in self.rec.values()] \
            + list(read_json(BUMPS_FILE, {}).values())
        seen = [x if isinstance(x, dt.datetime) else parse_ts(x) for x in seen if x]
        self.last = max(seen) if seen else None
        self.new = self.kept = self.migrated = 0

    def lm(self, cve, nist_lm, aliased, feed=None):
        """feed: the yearly feed the record is in (kept so "modified" can copy it from there)."""
        cid = cve["id"]
        sig = hashlib.sha1(json.dumps(cve.get("configurations"), sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        r = self.rec.get(cid)
        # a value issued but never served (its feed was then not written: drop guard, error) is not reused:
        # DT's watermark may have passed it meanwhile. Records from version 2.0 have no "at" and keep theirs.
        if r and r.get("src") == nist_lm and r.get("sig") == sig and not ("at" in r and r["at"] is None):
            self.kept += 1
            if feed and r.get("feed") != feed:
                r["feed"] = feed
            return r["lm"]
        old = self.legacy.get(cid)
        if r is None and old and not aliased and parse_ts(old) > (parse_ts(nist_lm) or parse_ts(old)):
            self.rec[cid] = {"lm": old, "src": nist_lm, "sig": sig, "at": old}  # DT already has it from version 1
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
        self.rec[cid] = {"lm": v, "src": nist_lm, "sig": sig, "at": None}   # at: set when a feed with it is published
        if feed:
            self.rec[cid]["feed"] = feed
        self.new += 1
        return v

    def served(self, published):
        """Stamp the wall-clock time a value was first published. published: {CVE: lastModified it went out with}
        from a feed that was written. A CVE that went out with another lastModified (e.g. as a VulnCheck record
        in "modified" while its yearly feed was held back) does not count: its issued value was not served."""
        now = fmt_ts(now_utc())
        for cid, lm in published.items():
            r = self.rec.get(cid)
            if r is not None and r.get("at", now) is None and r.get("lm") == lm:
                r["at"] = now

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


def write_feed(name, items, transform, prev_count=None):
    """Write FEEDS_DIR/<name>.json.gz + .meta from an item iterator; returns counts.
    With prev_count, a result with more than FEED_DROP_PCT % fewer CVEs is not used (DropGuard)."""
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
    if prev_count and count < prev_count * (1 - FEED_DROP_PCT / 100):
        os.remove(out_tmp)
        raise DropGuard(f"NIST's file gives {count} CVEs, the previous build had {prev_count} "
                        f"(more than {FEED_DROP_PCT:g}% fewer); keeping the previous feed. Check NIST's file, "
                        "then accept it with POST /rebuild?accept_feed_drop=1")
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


def recent_rewrites(assigner, cutoff):
    """{CVE: lastModified} of the rewritten CVEs whose assigned lastModified is at or after cutoff."""
    out = {}
    for cid, r in assigner.rec.items():
        t = parse_ts(r.get("lm"))
        if t and t >= cutoff:
            out[cid] = r["lm"]
    return out


def iter_from_yearly(want, years, feed_of=None):
    """The records of the CVEs in want, as our own yearly feeds (FEEDS_DIR/<year>.json.gz) carry them.
    feed_of: {CVE: yearly feed it was rewritten in} (assigned.json). Without it, the feed of the ID's year
    (NVD files CVEs by ID year; IDs older than the first feed are in that feed)."""
    feed_of = feed_of or {}
    by_year = {}
    for cid in want:
        y = feed_of.get(cid)
        if y not in years:
            parts = cid.split("-")
            y = parts[1] if len(parts) > 2 and parts[1].isdigit() else None
            if y and int(y) < int(years[-1]):
                y = years[-1]
        if y in years:
            by_year.setdefault(y, set()).add(cid)
    for y in years:
        ids = by_year.get(y)
        path = os.path.join(FEEDS_DIR, f"{y}.json.gz")
        if not ids or not os.path.exists(path):
            continue
        for it in iter_feed_items(path):
            if (it.get("cve") or {}).get("id") in ids:
                yield it


def make_transform(cand_cfg, amap, assigner, seen, vp, feed=None):
    """seen: {CVE: lastModified it is written with}, filled as the feed is written. feed: the yearly feed's
    name (None for "modified")."""
    def transform(item, stats):
        cve = item["cve"]
        cid = cve.get("id")
        seen[cid] = cve.get("lastModified")
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
            cve["lastModified"] = seen[cid] = assigner.lm(cve, nist_lm, bool(added), feed)
            stats["enriched"] += enriched
            stats["aliased_cves"] += bool(added)
            stats["alias_matches_added"] += added
    return transform


def build_all(force=False, accept_drop=False):
    """Rebuild every feed whose NIST input, VulnCheck candidates or alias file changed.
    accept_drop: use NIST yearly files the drop guard stopped. Failing feeds keep their last build and are
    raised together at the end (FeedErrors), after every other feed was tried."""
    t0 = time.time()
    set_state(phase="building feeds")
    amap, aver, ngroups = load_aliases()
    cver = file_version(CAND_FILE)
    cand_cfg = {}
    for item in iter_candidates():
        cand_cfg[item["cve"]["id"]] = item["cve"]["configurations"]
    mod_meta = nist_meta("modified")
    nist_newest = parse_ts(mod_meta.get("lastModifiedDate"))
    if nist_newest:
        note_health(nist_newest=fmt_ts(nist_newest))
    base = nist_newest or dt.datetime.now(dt.timezone.utc)
    fstate = read_json(FEED_STATE_FILE, {})
    # (an empty feed's .meta carries its build time, not a served lastModified: left out)
    served = [parse_ts(v.get("meta_last_modified")) for v in fstate.values()
              if isinstance(v, dict) and v.get("cves") and v.get("meta_last_modified")]
    assigner = Assigner(base, max([t for t in served if t], default=None))
    vp = {k: set(v) for k, v in read_json(VP_FILE, {}).items()}
    cand_found = set(read_json(CAND_FOUND_FILE, []))
    set_state(aliases={"file": ALIASES_FILE, "groups": ngroups, "version": aver})
    years = [str(y) for y in range(dt.datetime.now(dt.timezone.utc).year, FIRST_YEAR - 1, -1)]
    errors, modified_ok = [], False   # one failing feed must not stop the others, least of all "modified"
    for name in years + ["modified"]:
        raw = os.path.join(FEEDS_DIR, f"nist-{name}.json.gz")
        try:
            meta = mod_meta if name == "modified" else nist_meta(name)
            key = f"{meta.get('sha256')}|{cver}|{aver}"
            if name == "modified":   # the yearly feeds are built first: their rewrites are known here
                cutoff = base - dt.timedelta(days=MODIFIED_EXTRA_DAYS)
                recent = recent_rewrites(assigner, cutoff)
                key += "|recent:" + hashlib.sha1(json.dumps(sorted(recent.items())).encode()).hexdigest()[:16]
            have = os.path.exists(os.path.join(FEEDS_DIR, f"{name}.meta"))
            if not force and have and fstate.get(name, {}).get("key") == key:
                modified_ok = modified_ok or name == "modified"
                fstate[name]["checked_at"] = fmt_ts(now_utc())   # checked against NIST: unchanged
                continue
            set_state(phase=f"building feed {name}")
            with http_get(f"{NIST_BASE}/json/cve/2.0/nvdcve-2.0-{name}.json.gz", timeout=900) as r, open(raw, "wb") as out:
                shutil.copyfileobj(r, out, 1 << 20)
            seen = {}
            transform = make_transform(cand_cfg, amap, assigner, seen, vp, None if name == "modified" else name)
            if name == "modified":
                copied = set()

                def items():
                    yield from iter_feed_items(raw)
                    # candidates that are in no NIST feed yet (VulnCheck ahead of NIST): deliver them here
                    for it in iter_candidates():
                        cid = it["cve"]["id"]
                        if cid not in seen and cid not in cand_found:
                            yield {"cve": it["cve"]}
                    # rewritten CVEs that changed recently but not at NIST: DT 5.2.2 reads only this feed while
                    # its watermark is under 6 days old, so they come here too (as our yearly feed has them)
                    want = {c for c in recent if c not in seen}
                    feed_of = {c: assigner.rec[c].get("feed") for c in want if assigner.rec.get(c, {}).get("feed")}
                    for it in iter_from_yearly(want, years, feed_of):
                        cid = it["cve"]["id"]
                        t = parse_ts(it["cve"].get("lastModified"))
                        if cid in seen or cid in copied or t is None or t < cutoff:
                            continue
                        copied.add(cid)
                        yield it

                def mod_transform(item, stats):
                    cid = item["cve"].get("id")
                    if cid in copied:   # already rewritten (and given its lastModified) for its yearly feed
                        seen[cid] = item["cve"].get("lastModified")
                        return
                    transform(item, stats)
                st = write_feed(name, items(), mod_transform)
                st["recent_rewrites"] = len(copied)
                # recently rewritten, but not copied: its yearly feed was held back (drop guard, error) or lacks
                # it, or the rewrite was undone since. Worth a look if the number stays up.
                missing = len({c for c in recent if c not in seen})
                if missing:
                    log(f"feed modified: {missing} recently rewritten CVEs not copied from their yearly feed")
                st["recent_not_copied"] = missing
                modified_ok = True
            else:
                # NIST's yearly files only grow (rejected CVEs stay in them): a much smaller one is broken
                prev = None if accept_drop else fstate.get(name, {}).get("cves")
                st = write_feed(name, iter_feed_items(raw), transform, prev_count=prev)
                cand_found |= {c for c in seen if c in cand_cfg}
        except Exception as e:
            log(f"feed {name} not built: {err_text(e)}")
            errors.append((name, e))
            if os.path.exists(raw):
                os.remove(raw)
            continue
        os.remove(raw)
        assigner.served(seen)
        st.update(key=key, built_at=fmt_ts(dt.datetime.now(dt.timezone.utc)), checked_at=fmt_ts(now_utc()),
                  nist_sha256=(meta.get("sha256") or "")[:16])
        fstate[name] = st
        write_json(FEED_STATE_FILE, fstate)
        assigner.save()
        with state_lock:
            state["feeds"][name] = st
        log(f"feed {name} built: {st}")
    write_json(FEED_STATE_FILE, fstate)
    write_json(VP_FILE, {k: sorted(v) for k, v in vp.items()})
    write_json(CAND_FOUND_FILE, sorted(cand_found))
    assigner.save()
    info = {"built_at": fmt_ts(dt.datetime.now(dt.timezone.utc)), "error": None, "seconds": round(time.time() - t0, 1),
            "candidates": len(cand_cfg), "assigned_total": len(assigner.rec), "assigned_new": assigner.new,
            "assigned_kept": assigner.kept, "migrated_from_v1": assigner.migrated,
            "last_issued": fmt_ts(assigner.last) if assigner.last else None, "nist_base": fmt_ts(base),
            "recent_rewrites": (fstate.get("modified") or {}).get("recent_rewrites")}
    set_state(modified_feed=info, phase="ready")
    log(f"build done: {info}")
    if errors:
        raise FeedErrors(errors, modified_ok)


def rebuild_once(force_vc=False, force=False, accept_vc_drop=False, accept_feed_drop=False):
    with build_lock:   # only the builder thread takes it; health_report reads it as "building"
        load_vulncheck(force=force_vc, accept_drop=accept_vc_drop)
        started = fmt_ts(now_utc())  # the feeds are as fresh as NIST was when the build started
        try:
            build_all(force=force, accept_drop=accept_feed_drop)
        except Exception as e:
            log("build failed: " + traceback.format_exc())
            with state_lock:
                state["modified_feed"]["error"] = err_text(e)
                state["phase"] = "ready" if os.path.exists(os.path.join(FEEDS_DIR, "modified.meta")) else "error"
            # when only some yearly feeds failed, "modified" (the day-to-day changes) is still current
            extra = {"build_ok_at": started} if isinstance(e, FeedErrors) and e.modified_ok else {}
            note_health(build_attempt_at=started, build_error=err_text(e),
                        build_error_permanent=is_permanent(e, "nist"), **extra)
        else:
            note_health(build_attempt_at=started, build_ok_at=started, build_error=None, build_error_permanent=False)


# One builder thread runs every rebuild. A request made while a build runs is queued for the next pass
# (flags are merged), so no request is ever dropped and a caller can wait for the pass that includes it.
build_cv = threading.Condition()
FLAGS = ("force_vc", "force", "accept_vc_drop", "accept_feed_drop")
pending = dict({"wanted": False}, **dict.fromkeys(FLAGS, False))
passes = {"started": 0, "finished": 0}


def request_rebuild(**flags):
    """Queue a rebuild. Returns the number of the pass that will include this request."""
    with build_cv:
        pending["wanted"] = True
        for k in FLAGS:
            pending[k] = pending[k] or bool(flags.get(k))
        build_cv.notify_all()
        return passes["started"] + 1


def wait_for_pass(n, timeout=None):
    with build_cv:
        return build_cv.wait_for(lambda: passes["finished"] >= n, timeout)


def builder():
    while True:
        with build_cv:
            build_cv.wait_for(lambda: pending["wanted"])
            flags = {k: pending[k] for k in FLAGS}
            pending.update(dict({"wanted": False}, **dict.fromkeys(FLAGS, False)))
            passes["started"] += 1
        try:
            rebuild_once(**flags)
        except Exception:
            log("rebuild pass failed: " + traceback.format_exc())
        finally:
            with build_cv:
                passes["finished"] += 1
                build_cv.notify_all()


def maybe_rebuild_async():
    p = os.path.join(FEEDS_DIR, "modified.meta")
    if os.path.exists(p) and (time.time() - os.path.getmtime(p)) < FEED_MAX_AGE_MIN * 60:
        return
    request_rebuild()


def refresher():
    """Keep the feeds close to NIST's while the adapter runs (no external scheduler needed)."""
    while True:
        time.sleep(FEED_MAX_AGE_MIN * 60)
        request_rebuild()


def health_report():
    """Is the data the adapter serves fresh? Returns (ok, report)."""
    now = now_utc()
    with state_lock:
        h = dict(health)
        phase = state.get("phase") or ""
        vstate = dict(state.get("vulncheck") or {})
    with build_cv:
        finished = passes["finished"]
        building = pending["wanted"] or passes["started"] > finished   # queued, or a pass is running
    problems, warnings = [], []

    def age_h(ts):
        t = parse_ts(ts) if ts else None
        return None if t is None else (now - t).total_seconds() / 3600

    def r(x):
        return None if x is None else round(x, 3)

    names = [str(y) for y in range(now.year, FIRST_YEAR - 1, -1)] + ["modified"]
    missing = [n for n in names if not os.path.exists(os.path.join(FEEDS_DIR, f"{n}.meta"))]
    if missing:
        problems.append(f"{len(missing)} of {len(names)} feed files are not built yet "
                        f"({', '.join(missing[:4])}{', ...' if len(missing) > 4 else ''}); Dependency-Track gets "
                        "503 for them and its NVD mirror fails")

    # NIST: the last refresh that worked, the last error, and whether NIST itself still publishes
    b_age = age_h(h.get("build_ok_at"))
    err = h.get("build_error")
    if b_age is None:
        if not missing:
            (warnings if building else problems).append(
                "no successful refresh from NIST is recorded yet" + (" (the first one is running)" if building else "")
                + (f"; last error: {err}" if err else ""))
    elif b_age > NIST_MAX_AGE_HOURS:
        problems.append(f"the feeds were last refreshed from NIST {b_age:.1f} h ago (limit {NIST_MAX_AGE_HOURS:g} h)"
                        + (f"; last error: {err}" if err else ""))
    elif err:
        (problems if h.get("build_error_permanent") else warnings).append(f"the last refresh from NIST failed: {err}")
    fst = read_json(FEED_STATE_FILE, {})
    old_feeds = [(n, age_h(fst[n]["checked_at"])) for n in names if (fst.get(n) or {}).get("checked_at")
                 and age_h(fst[n]["checked_at"]) > FEED_STALE_HOURS]
    if old_feeds:
        problems.append("feed " + ", ".join(f"{n} ({a:.0f} h)" for n, a in old_feeds[:4]) + f" not checked against NIST "
                        f"for more than {FEED_STALE_HOURS:g} h: its NIST download keeps failing, so VulnCheck and alias "
                        "updates to its CVEs stop")
    q_age = age_h(h.get("nist_newest"))
    if q_age is not None and q_age > NIST_QUIET_HOURS:
        problems.append(f"NIST's newest CVE change is {q_age:.0f} h old (limit {NIST_QUIET_HOURS:g} h): "
                        "NIST may have stopped publishing")

    # VulnCheck
    stats = read_json(VC_STATS_FILE, {})
    v_age = age_h(stats.get("loaded_at"))
    verr = h.get("vc_error")
    if not TOKEN:
        msg = "VULNCHECK_TOKEN is not set, so VulnCheck CPEs are not refreshed"
        if v_age is not None:
            msg += f" (the feeds still carry VulnCheck data loaded {v_age:.0f} h ago)"
        (problems if VULNCHECK_REQUIRED else warnings).append(msg)
    elif v_age is None:
        loading = phase.startswith(("downloading VulnCheck", "parsing VulnCheck"))
        problems.append("VulnCheck data has not been loaded yet" + (f": {verr}" if verr else " (loading)" if loading else ""))
    elif v_age > VC_STALE_HOURS:
        problems.append(f"VulnCheck data is {v_age:.0f} h old (limit {VC_STALE_HOURS:g} h)"
                        + (f"; last error: {verr}" if verr else ""))
    elif verr:
        (problems if h.get("vc_error_permanent") else warnings).append(
            f"the last VulnCheck refresh failed: {verr}; serving the data loaded at {stats.get('loaded_at')}")
    if TOKEN and v_age is not None and not stats.get("candidates"):
        problems.append("the VulnCheck data gives no enriched CVEs at all (0 candidates): its format may have "
                        "changed, so new CVEs without NIST CPEs get none")

    report = {
        "status": "degraded" if problems else "ok", "version": VERSION, "checked_at": fmt_ts(now),
        "problems": problems, "warnings": warnings, "phase": phase, "building": building, "build_passes": finished,
        "feeds": {"expected": len(names), "missing": missing},
        "nist": {"last_ok_at": h.get("build_ok_at"), "age_hours": r(b_age), "last_attempt_at": h.get("build_attempt_at"),
                 "last_error": err, "newest_change": h.get("nist_newest"), "newest_change_age_hours": r(q_age)},
        "vulncheck": {"required": VULNCHECK_REQUIRED, "token_set": bool(TOKEN), "status": vstate.get("status"),
                      "loaded_at": stats.get("loaded_at"), "age_hours": r(v_age), "backup_date": stats.get("backup_date"),
                      "records": stats.get("records"), "vc_has_cpes": stats.get("vc_has_cpes"),
                      "candidates": stats.get("candidates"), "last_attempt_at": h.get("vc_attempt_at"),
                      "last_error": verr},
        "limits": {"FEED_STALE_HOURS": FEED_STALE_HOURS, "NIST_MAX_AGE_HOURS": NIST_MAX_AGE_HOURS, "NIST_QUIET_HOURS": NIST_QUIET_HOURS,
                   "VC_STALE_HOURS": VC_STALE_HOURS, "VC_DROP_PCT": VC_DROP_PCT, "FEED_DROP_PCT": FEED_DROP_PCT},
    }
    return not problems, report


def candidate_sample(before=None, n=20):
    """Enriched CVEs first served before `before` (Dependency-Track should have their CPEs by now):
    the newest half and an even spread over the rest."""
    assigned = read_json(ASSIGNED_FILE, {})
    elig, total = [], 0
    for item in iter_candidates():
        total += 1
        cve = item["cve"]
        r = assigned.get(cve["id"]) or {}
        # when a published feed first carried this record; records from version 2 have no "at": use lastModified
        at = r.get("at") if "at" in r else r.get("lm")
        t = parse_ts(at) if at else None
        if t is None or (before is not None and t >= before):
            continue
        prods = sorted({":".join(m["criteria"].split(":")[3:5]) for c in cve.get("configurations") or []
                        for nd in (c or {}).get("nodes") or [] for m in nd.get("cpeMatch") or [] if m.get("criteria")})
        elig.append((t, cve["id"], prods[:5]))
    elig.sort(reverse=True)
    n = max(0, n)
    pick, rest = elig[: n // 2], elig[n // 2:]
    k = min(n - len(pick), len(rest))
    if k > 0:
        step = len(rest) / k
        pick += [rest[int(i * step)] for i in range(k)]
    return {"candidates": total, "eligible": len(elig), "served_before": fmt_ts(before) if before else None,
            "sample": [{"id": c, "served_at": fmt_ts(t), "cpe_products": p} for t, c, p in pick]}


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

    def rebuild(self, q, post):
        return handle_rebuild(self, q, post)

    def do_POST(self):
        path = self.path.split("?")[0]
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        if path != "/rebuild":
            return self.send_bytes(404, b"not found", "text/plain")
        return self.rebuild(urllib.parse.parse_qs(self.path.partition("?")[2]), post=True)

    def do_GET(self):
        path = self.path.split("?")[0]
        q = urllib.parse.parse_qs(self.path.partition("?")[2])
        if path == "/healthz":  # liveness only
            return self.send_bytes(200, b"ok", "text/plain")
        if path == "/health":   # is the data fresh? 200 or 503 with the reasons
            ok, rep = health_report()
            return self.send_bytes(200 if ok else 503, json.dumps(rep, indent=1).encode(), "application/json")
        if path == "/candidates/sample":
            before = None
            raw = (q.get("served_before") or [""])[0]
            try:
                n = int((q.get("n") or ["20"])[0])
                if raw:
                    before = (dt.datetime.fromtimestamp(int(raw) / 1000, dt.timezone.utc) if raw.isdigit()
                              else parse_ts(raw))
            except ValueError:
                return self.send_bytes(400, b"served_before: epoch milliseconds or ISO time; n: a number", "text/plain")
            return self.send_bytes(200, json.dumps(candidate_sample(before, min(n, 200))).encode(), "application/json")
        if path == "/stats":
            with state_lock:
                body = json.dumps(state, indent=1, default=str).encode()
            return self.send_bytes(200, body, "application/json")
        if path == "/rebuild":
            return self.rebuild(q, post=False)
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


def handle_rebuild(handler, q, post):
    flag = lambda k: (q.get(k) or ["0"])[0] == "1"
    flags = {"force_vc": flag("vc"), "force": flag("all"), "accept_vc_drop": flag("accept_vc_drop"),
             "accept_feed_drop": flag("accept_feed_drop")}
    host = (handler.headers.get("Host") or "").strip().lower()
    host = host[1:host.index("]")] if host.startswith("[") and "]" in host else host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    if post and host not in REBUILD_HOSTS:   # a DNS-rebinding page is same-origin, but its Host is its own name
        return handler.send_bytes(403, f"Host {host!r} is not allowed (REBUILD_HOSTS)".encode(), "text/plain")
    if any(flags.values()) and not (post and handler.headers.get("X-NVDPP-Rebuild") == "1"):
        # forcing a download or accepting guarded data must not be possible from a web page (CSRF)
        return handler.send_bytes(405, b"vc=1, all=1, accept_vc_drop=1 and accept_feed_drop=1 need POST with the "
                                       b"header X-NVDPP-Rebuild: 1", "text/plain")
    ticket = request_rebuild(**flags)
    if flag("wait"):
        wait_for_pass(ticket)
        with state_lock:
            body = json.dumps(dict(state["modified_feed"], build_pass=ticket), default=str).encode()
        return handler.send_bytes(200, body, "application/json")
    return handler.send_bytes(202, f"rebuild queued as pass {ticket}".encode(), "text/plain")


def main():
    log(f"NVD feed adapter v{VERSION} starting; VulnCheck token set: {bool(TOKEN)}; index {VC_INDEX}; "
        f"aliases {ALIASES_FILE}")
    with state_lock:
        state["feeds"] = read_json(FEED_STATE_FILE, {})
        health.update(read_json(HEALTH_FILE, {}))
    request_rebuild()   # the startup refresh (serves the last build meanwhile)
    threading.Thread(target=builder, daemon=True).start()
    threading.Thread(target=refresher, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    sys.exit(main())
