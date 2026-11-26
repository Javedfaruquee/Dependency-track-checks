"""
NVD feed adapter for Dependency-Track v5 (no cron, no CI).

DT's NVD data source downloads NVD JSON 2.0 feed files from a configurable URL
(<cveFeedsUrl>/json/cve/2.0/nvdcve-2.0-<year|modified>.meta / .json.gz).
Point that URL at this adapter (http://nvdpp:8080/feeds) and it:

  * passes the yearly feeds through from NIST unchanged;
  * rebuilds the "modified" feed: NIST's modified feed, plus every CVE that NIST
    left without CPE configurations but for which VulnCheck NVD++ (community
    index nist-nvd2) has "vcConfigurations". Those are copied into the standard
    "configurations" field that DT reads. Each such CVE gets a stable bumped
    lastModified (once), so DT ingests it once and then skips it.

While running, the adapter rebuilds the modified feed every FEED_MAX_AGE_MIN minutes
(and when DT asks for an older build), so it stays close to NIST. No external
scheduler is needed. VulnCheck data is refreshed when older than VC_MAX_AGE_HOURS.
Enriched CVEs DT has not fetched yet get a fresh lastModified on every build; once
DT has downloaded a build, its CVEs keep their value, so DT ingests each one once.
If VulnCheck is unavailable, the modified feed is NIST's, unchanged.

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
PENDING_FILE = os.path.join(CACHE, "pending.json")   # CVEs in the current build that DT has not fetched yet

state_lock = threading.Lock()
build_lock = threading.Lock()
state = {
    "phase": "starting",
    "vulncheck": {"status": "not loaded", "error": None},
    "modified_feed": {"built_at": None, "error": None},
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


# ---------------------------------------------------------------- feeds
def read_json(path, default):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return default


def write_json(path, obj):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f)
    os.replace(tmp, path)


def mark_delivered(build_id):
    """DT downloaded the whole modified feed of this build: its pending CVEs are now delivered."""
    with build_lock:
        pending = read_json(PENDING_FILE, {})
        if pending.get("build_id") != build_id or not pending.get("ids"):
            return
        delivered = read_json(BUMPS_FILE, {})
        for cid in pending["ids"]:
            delivered[cid] = pending["bump"]
        write_json(BUMPS_FILE, delivered)
        n = len(pending["ids"])
        pending["ids"] = []
        write_json(PENDING_FILE, pending)
        log(f"DT fetched build {build_id}: {n} VulnCheck-enriched CVEs marked as delivered")


def build_modified():
    """NIST modified feed + VulnCheck-enriched CVEs -> /cache/feeds/modified.*"""
    t0 = time.time()
    set_state(phase="building modified feed")
    with http_get(f"{NIST_BASE}/json/cve/2.0/nvdcve-2.0-modified.meta", timeout=60) as r:
        nist_meta = r.read().decode()
    nist_meta_lm = None
    for line in nist_meta.splitlines():
        if line.startswith("lastModifiedDate:"):
            nist_meta_lm = parse_ts(line.split(":", 1)[1].strip())
    raw_path = os.path.join(CACHE, "feeds", "nist-modified.json.gz")
    with http_get(f"{NIST_BASE}/json/cve/2.0/nvdcve-2.0-modified.json.gz", timeout=600) as r, open(raw_path, "wb") as out:
        shutil.copyfileobj(r, out)

    # candidates: id -> configurations (only CVEs where NIST has none)
    cand_cfg = {}
    for item in iter_candidates():
        cand_cfg[item["cve"]["id"]] = item["cve"]["configurations"]

    with gzip.open(raw_path, "rb") as f:
        nist_items = json.load(f).get("vulnerabilities") or []
    nist_max = max((parse_ts(i["cve"]["lastModified"]) for i in nist_items), default=dt.datetime.now(dt.timezone.utc))

    # CVEs DT already received keep the lastModified they were given; all others get a fresh one,
    # just above the newest NIST change in this build, so DT's watermark lets them through.
    delivered = read_json(BUMPS_FILE, {})
    for cid in [c for c in delivered if c not in cand_cfg]:
        del delivered[cid]  # NIST added CPEs itself; its own record takes over
    new_bump = fmt_ts(nist_max + dt.timedelta(seconds=1))
    bumps = {cid: delivered.get(cid, new_bump) for cid in cand_cfg}
    pending_ids = [cid for cid in cand_cfg if cid not in delivered]
    build_id = f"{time.time_ns()}"

    out_tmp = os.path.join(CACHE, "feeds", "modified.json.gz.tmp")
    sha = hashlib.sha256()
    size = 0
    count = enriched_in_feed = appended = 0
    max_out = nist_meta_lm or nist_max
    in_feed = set()

    def emit(gz, s, first):
        nonlocal size
        b = (("" if first else ",") + s).encode("utf-8")
        gz.write(b)
        sha.update(b)
        size += len(b)

    def with_bump(cve):
        nonlocal max_out
        cid = cve["id"]
        if cid in bumps:
            orig = parse_ts(cve.get("lastModified"))
            b = parse_ts(bumps[cid])
            if orig is None or b > orig:
                cve["lastModified"] = bumps[cid]
                orig = b
            if orig > max_out:
                max_out = orig
        return cve

    with gzip.open(out_tmp, "wb") as gz:
        head = ('{"resultsPerPage":0,"startIndex":0,"format":"NVD_CVE","version":"2.0",'
                f'"timestamp":"{fmt_ts(dt.datetime.now(dt.timezone.utc))}","vulnerabilities":[')
        hb = head.encode()
        gz.write(hb); sha.update(hb); size += len(hb)
        first = True
        for item in nist_items:
            cve = item["cve"]
            cid = cve["id"]
            in_feed.add(cid)
            if not has_cpe_config(cve.get("configurations")) and cid in cand_cfg:
                cve["configurations"] = cand_cfg[cid]
                with_bump(cve)
                enriched_in_feed += 1
            emit(gz, json.dumps(item, separators=(",", ":")), first)
            first = False
            count += 1
        for item in iter_candidates():
            cid = item["cve"]["id"]
            if cid in in_feed:
                continue
            with_bump(item["cve"])
            emit(gz, json.dumps(item, separators=(",", ":")), first)
            first = False
            count += 1
            appended += 1
        tail = f'],"totalResults":{count}}}'.encode()
        gz.write(tail); sha.update(tail); size += len(tail)
    gz_size = os.path.getsize(out_tmp)
    meta = (f"lastModifiedDate:{max_out.strftime('%Y-%m-%dT%H:%M:%SZ')}\r\n"
            f"size:{size}\r\nzipSize:{gz_size}\r\ngzSize:{gz_size}\r\nsha256:{sha.hexdigest().upper()}\r\n")
    os.replace(out_tmp, os.path.join(CACHE, "feeds", "modified.json.gz"))
    with open(os.path.join(CACHE, "feeds", "modified.meta"), "w", newline="") as f:
        f.write(meta)
    write_json(BUMPS_FILE, delivered)
    write_json(PENDING_FILE, {"build_id": build_id, "bump": new_bump, "ids": pending_ids})
    info = {"built_at": fmt_ts(dt.datetime.now(dt.timezone.utc)), "build_id": build_id, "error": None,
            "pending_for_dt": len(pending_ids), "already_delivered": len(cand_cfg) - len(pending_ids),
            "pending_last_modified": new_bump, "nist_cves": len(nist_items),
            "enriched_in_nist_feed": enriched_in_feed, "appended_from_vulncheck": appended, "total_cves": count,
            "nist_feed_max_last_modified": fmt_ts(nist_max), "meta_last_modified": max_out.isoformat(),
            "seconds": round(time.time() - t0, 1)}
    set_state(modified_feed=info, phase="ready")
    log(f"modified feed built: {info}")


def rebuild(force_vc=False):
    if not build_lock.acquire(blocking=False):
        return False
    try:
        load_vulncheck(force=force_vc)
        build_modified()
    except Exception as e:
        log("build failed: " + traceback.format_exc())
        with state_lock:
            state["modified_feed"]["error"] = f"{type(e).__name__}: {e}"
            state["phase"] = "ready" if os.path.exists(os.path.join(CACHE, "feeds", "modified.meta")) else "error"
    finally:
        build_lock.release()
    return True


def maybe_rebuild_async():
    p = os.path.join(CACHE, "feeds", "modified.meta")
    if os.path.exists(p) and (time.time() - os.path.getmtime(p)) < FEED_MAX_AGE_MIN * 60:
        return
    threading.Thread(target=rebuild, daemon=True).start()


def refresher():
    """Keep the modified feed close to NIST's while the adapter runs (no external scheduler needed)."""
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

    def proxy(self, url, ctype):
        try:
            with http_get(url, timeout=600) as r:
                length = r.headers.get("Content-Length")
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                if length:
                    self.send_header("Content-Length", length)
                else:
                    self.send_header("Connection", "close")
                self.end_headers()
                shutil.copyfileobj(r, self.wfile, 1 << 20)
        except urllib.error.HTTPError as e:
            self.send_bytes(e.code, f"upstream {e.code}".encode(), "text/plain")

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/healthz":
            return self.send_bytes(200, b"ok", "text/plain")
        if path == "/stats":
            with state_lock:
                body = json.dumps(state, indent=1, default=str).encode()
            return self.send_bytes(200, body, "application/json")
        if path == "/rebuild":
            t = threading.Thread(target=rebuild, kwargs={"force_vc": "vc=1" in self.path}, daemon=True)
            t.start()
            if "wait=1" in self.path:
                t.join()
                while build_lock.locked():  # another build was already running
                    time.sleep(2)
                with state_lock:
                    body = json.dumps(state["modified_feed"], default=str).encode()
                return self.send_bytes(200, body, "application/json")
            return self.send_bytes(202, b"rebuild started", "text/plain")
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
        if name != "modified":
            return self.proxy(f"{NIST_BASE}/json/cve/2.0/nvdcve-2.0-{name}.{kind}", ctype)
        meta_path = os.path.join(CACHE, "feeds", "modified.meta")
        if not os.path.exists(meta_path):
            # first build still running: let DT retry later rather than ingest a half state
            maybe_rebuild_async()
            return self.send_bytes(503, b"modified feed is being built", "text/plain")
        if kind == "meta":
            maybe_rebuild_async()  # DT's own mirror run triggers refreshes; serve the last build now
            return self.send_file(meta_path, ctype)
        with state_lock:
            build_id = state["modified_feed"].get("build_id")
        self.send_file(os.path.join(CACHE, "feeds", "modified.json.gz"), ctype)
        if build_id:
            mark_delivered(build_id)


def main():
    log(f"NVD feed adapter starting; VulnCheck token set: {bool(TOKEN)}; index {VC_INDEX}")
    threading.Thread(target=rebuild, daemon=True).start()
    threading.Thread(target=refresher, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    sys.exit(main())
