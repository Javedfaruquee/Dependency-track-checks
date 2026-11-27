#!/usr/bin/env python3
"""dt-health-check.py 1.0 - is Dependency-Track's vulnerability data still current, and does it reach the findings?

Why: in Dependency-Track 5.2 (5.2.1 and 5.2.2) vulnerability data stops without anyone noticing.
  - A data source mirror that fails or stops running leaves the last data in place; nothing alerts.
  - The NVD feed adapter keeps serving its last build when NIST or VulnCheck fail, and DT's NVD mirror
    still reports COMPLETED.
  - An analyzer that fails keeps the findings it reported before (ReconcileVulnAnalysisResultsActivity
    keeps attributions of failed analyzers), so its findings look current but are not. A disabled
    analyzer loses its findings.
  - OSS Index results are cached for 24 h, so a revoked token shows up a day late.

What it checks:
  1. Every enabled vulnerability and KEV data source: the latest mirror run must be COMPLETED within
     max_age_hours (FAILED, missing, or stuck RUNNING is a problem). Sources and analyzers listed in
     require_enabled must be enabled. The NVD source must read nvd_feeds_url when that is set.
  2. With --test-extensions: DT's own live test (POST .../test) for every enabled testable extension,
     for example the OSS Index token and the NVD feed URL. Needs SYSTEM_CONFIGURATION_UPDATE.
  3. The NVD feed adapter: GET /health (fresh NIST and VulnCheck data, no drop-guard stop).
  4. VulnCheck CPEs in DT: a sample of CVEs the adapter enriched before DT's last NVD mirror run must
     have CPE data in DT (GET /api/v1/vulnerability/source/NVD/vuln/{id}).
  5. A canary project (health/dt-health-canary.cdx.json): uploaded, analysed, and every expectation
     checked, for example "the internal analyzer reports CVE-2022-37434 on zlib 1.2.11 by CPE".
     DT shows one analyzer per finding (the first attribution), so each analyzer gets a component that
     only it reports. With rotate (default) the components are re-created on every run (their group
     alternates), so findings of a failed analyzer cannot linger.
  6. Analysis latency: how long DT took to analyse the canary. Longer than canary.max_analysis_minutes is
     its own problem (DT's analysis is behind, so every finding is older than it looks), not an analyzer
     failure; longer than canary.warn_analysis_minutes is a warning.
  7. DT's own alerts: an enabled SYSTEM notification rule must cover each group in
     require_notification_groups (default DATASOURCE_MIRRORING: DT reports failed mirrors itself). An
     enabled rule that sends ANALYZER notifications straight to chat or e-mail is a warning: DT sends one
     per project, and DT re-analyses projects around the clock, so an analyzer outage floods the channel.
  8. Portfolio re-analysis: DT re-analyses every project once its analysis is 24 h old (portfolio-analysis
     runs every minute). The projects with the oldest BOM import, plus random pages, must have been analysed
     within portfolio_analysis.max_age_hours (36; raise it with dt.task.portfolio-analysis.max-analysis-age-ms);
     otherwise new CVEs stop reaching existing products while everything else stays green. 6 calls for any
     portfolio size.
  9. Trivy's vulnerability DB age (GET <trivy>/version), when DT's Trivy analyzer is enabled.
 10. With --state (keep it between runs): a mirror run that stays PENDING or RUNNING longer than
     max_age_hours is a problem, and counts that drop by more than trend.max_drop_pct are warnings.

Scale: the number of API calls does not depend on the portfolio (sources, analyzers, the sample and the
canary only); the report gives it (apiCallsExcludingPolls). Waiting for the canary adds event-token polls,
which grow with DT's backlog but are bounded (at most 6 + wait/30; tokenPolls). One run gives one result,
however many projects there are. Run one scheduler only: overlapping runs replace each other's canary.

Exit codes: 0 healthy (warnings are listed), 1 problems found, 2 could not check (DT unreachable, usage).

usage: dt-health-check.py --url https://dt.example.com [--config health/dt-health.json] [--report out.json]
                          [--state state.json] [--adapter-url URL] [--test-extensions] [--no-canary]
                          [--max-age-hours H] [--wait 900] [--allow-http]
Auth: DT_API_KEY (X-Api-Key) or DT_BEARER. The key needs VIEW_PORTFOLIO, VIEW_VULNERABILITY,
SYSTEM_CONFIGURATION_READ (also for the notification rules), BOM_UPLOAD and PROJECT_CREATION_UPLOAD (canary); --test-extensions also
SYSTEM_CONFIGURATION_UPDATE. No key is sent to the adapter. http:// to DT only for localhost unless
--allow-http. Only the Python standard library is used.
"""
import argparse, base64, calendar, copy, json, math, os, random, sys, time, urllib.error, urllib.parse, urllib.request, uuid

VERSION = "1.0"
POINTS = {"vuln-data-source": "vuln-data-sources", "kev-data-source": "kev-data-sources"}  # mirror-run API


class DtError(Exception):
    pass


class AnalysisTimeout(DtError):
    """The canary's analysis did not finish in time: DT's analysis is behind."""


class AuthError(Exception):
    """HTTP 401: the key is not accepted. Not a DtError, so no check swallows it: the run stops with exit 2."""


def q(s):
    return urllib.parse.quote(str(s), safe="")


def hours_since(ms, now):
    return None if not ms else (now - ms / 1000) / 3600


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: urllib would resend X-Api-Key / Authorization to wherever they point."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


class Http:
    def __init__(self, url, headers=None, timeout=60, allow_http=False, check_scheme=True):
        self.url = url.rstrip("/")
        u = urllib.parse.urlparse(self.url)
        host = u.hostname or ""
        local = host in ("localhost", "127.0.0.1", "::1")
        if check_scheme and u.scheme != "https" and not (u.scheme == "http" and (local or allow_http)):
            raise DtError(f"refusing {u.scheme}:// for {host}: use https, or --allow-http")
        self.h = dict(headers or {}, Accept="application/json")
        self.timeout = timeout
        self.calls = 0
        self.polls = 0   # event-token polls: they grow with DT's backlog, so they are counted apart
        self.last_headers = {}

    def call(self, method, path, body=None, ok=(), retries=3, auth401=True):
        """Returns (status, json). Statuses in `ok` are returned instead of raised.
        auth401=False: a 401 is a DtError (DT answers 401 for some missing permissions), not AuthError."""
        data = None
        headers = dict(self.h)
        if body is not None or method in ("POST", "PUT"):
            data = json.dumps(body if body is not None else {}).encode()
            headers["Content-Type"] = "application/json"   # DT's @Consumes(JSON) answers 415 without it
        for attempt in range(retries + 1):
            self.calls += 1
            req = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
            try:
                with OPENER.open(req, timeout=self.timeout) as r:
                    self.last_headers = r.headers   # HTTPMessage: .get() ignores case (Envoy sends lower case)
                    raw = r.read()
                    try:
                        return r.status, (json.loads(raw) if raw else None)
                    except ValueError:
                        return r.status, raw.decode("utf-8", "replace")
            except urllib.error.HTTPError as e:
                raw = e.read()
                if e.code in ok:
                    try:
                        return e.code, json.loads(raw) if raw else None
                    except ValueError:
                        return e.code, raw.decode("utf-8", "replace")
                if e.code == 401 and auth401:
                    raise AuthError(f"{method} {path.split('?')[0]}: HTTP 401: the API key (DT_API_KEY or DT_BEARER) is not accepted")
                if e.code in (429, 502, 503, 504) and attempt < retries:
                    time.sleep(2 ** attempt); continue
                hint = " (the API key lacks a permission; see the usage text)" if e.code in (401, 403) else ""
                if 300 <= e.code < 400:
                    hint = f" (a redirect to {e.headers.get('Location')}: not followed, use the final URL)"
                raise DtError(f"{method} {path.split('?')[0]}: HTTP {e.code}{hint} {raw[:300]!r}")
            except (urllib.error.URLError, OSError) as e:
                if attempt < retries:
                    time.sleep(2 ** attempt); continue
                raise DtError(f"{method} {self.url}{path.split('?')[0]}: {getattr(e, 'reason', e)}")


class Dt(Http):
    def get(self, path, ok404=False):
        st, body = self.call("GET", path, ok=(404,) if ok404 else ())
        return None if st == 404 else body

    def paged(self, path, key, size=100):
        """v1 lists honour pageSize only together with pageNumber. Dedupe by key."""
        out, seen, sep = [], set(), "&" if "?" in path else "?"
        for page in range(1, 10000):
            items = self.get(f"{path}{sep}pageSize={size}&pageNumber={page}") or []
            new = 0
            for x in items:
                k = key(x)
                if k not in seen:
                    seen.add(k); out.append(x); new += 1
            if len(items) < size or new == 0:
                break
        return out

    def items_v2(self, path):
        out, token = [], None
        for _ in range(100):
            body = self.get(path + (f"?page_token={q(token)}" if token else "")) or {}
            out += body.get("items") or []
            token = body.get("next_page_token")
            if not token:
                break
        return out

    def wait_token(self, token, max_sec):
        """Polls every 2 s at first, then every 30 s after the first minute: at most 6 + max_sec/30 polls."""
        t0 = time.time()
        deadline, delay = t0 + max_sec, 2
        while True:
            self.polls += 1
            r = self.get(f"/api/v1/event/token/{q(token)}") or {}
            if not r.get("processing"):
                if r.get("status") == "FAILED":
                    raise DtError(f"DT reports the canary's processing as FAILED (token {token}): usually every "
                                  "analyzer failed (DT then keeps all old findings everywhere)")
                return r.get("status")
            if time.time() > deadline:
                raise AnalysisTimeout(f"the canary analysis is still running after {max_sec / 60:g} min (token {token})")
            time.sleep(min(delay, max(0.5, deadline - time.time())))
            delay = 30 if time.time() - t0 > 60 else min(delay * 1.5, 15)


class Report:
    def __init__(self):
        self.checks, self.metrics = [], {}

    def add(self, area, name, status, detail, **extra):
        self.checks.append(dict({"area": area, "name": name, "status": status, "detail": detail}, **extra))

    def count(self, status):
        return sum(1 for c in self.checks if c["status"] == status)


def judge_run(run, max_age, now, seen=None):
    """Latest mirror run -> (status, detail). seen: {"sig", "first_seen"} from --state for a run that is not
    finished, so a run stuck in PENDING (no started_at) is a problem once it has been seen for max_age."""
    if run is None:
        return "problem", "no mirror run recorded (never run, or no longer retained)"
    st = run.get("status")
    started, done = run.get("started_at"), run.get("completed_at")
    if st == "FAILED":
        age = hours_since(done or started, now)
        when = f" {age:.1f} h ago" if age is not None else ""
        return "problem", f"the last mirror run FAILED{when}: {run.get('failure_reason') or 'no reason given'}"
    if st == "COMPLETED":
        age = hours_since(done, now)
        if age is None:
            return "problem", "the last mirror run has no completion time"
        if age > max_age:
            return "problem", f"the last mirror run completed {age:.1f} h ago (limit {max_age:g} h)"
        return "ok", f"mirror run completed {age:.1f} h ago"
    age = hours_since(started, now)
    seen_age = hours_since(seen["first_seen"] * 1000, now) if seen else None
    stuck = max(a for a in (age, seen_age, -1) if a is not None)
    if stuck > max_age:
        return "problem", (f"a mirror run has been {st} for {stuck:.1f} h (limit {max_age:g} h): DT starts no new run "
                           "while it is there, so this source is frozen")
    return "warning", (f"a mirror run is {st}" + (f" since {age:.1f} h" if age is not None else "")
                       + (f", seen like this for {seen_age:.1f} h" if seen_age else "")
                       + "; the result of the run before it is not visible"
                       + ("" if seen is not None else " (keep --state between runs to catch a stuck run)"))


def check_sources(dt, cfg, rep, args, now, state):
    """Extensions, enabled flags, mirror runs. Returns ({key: enabled}, {key: config}, {key: run})."""
    enabled, configs, runs, testable = {}, {}, {}, {}
    for ep in ("vuln-data-source", "kev-data-source", "vuln-analyzer"):
        try:
            exts = dt.items_v2(f"/api/v2/extension-points/{ep}/extensions")
        except DtError as e:
            rep.add("config", ep, "problem", f"could not list the extensions: {e}")
            continue
        for x in exts:
            key = f"{ep}/{x['name']}"
            testable[key] = bool(x.get("testable"))
            c = {}
            if x.get("configurable", True):
                try:
                    c = (dt.get(f"/api/v2/extension-points/{ep}/extensions/{q(x['name'])}/config", ok404=True)
                         or {}).get("config") or {}
                except DtError as e:
                    rep.add("config", key, "problem", f"could not read the configuration: {e}")
                    continue
            configs[key] = c
            enabled[key] = bool(c.get("enabled", not x.get("configurable", True)))
    req = cfg.get("require_enabled", [])
    for key in req:
        if key not in enabled:
            rep.add("config", key, "problem", "required, but Dependency-Track has no such extension")
        elif not enabled[key]:
            rep.add("config", key, "problem", "required, but disabled: its data or findings are not updated"
                    + (" (DT deletes a disabled analyzer's findings at the next analysis)" if "analyzer" in key else ""))
    if req and all(enabled.get(k) for k in req):
        rep.add("config", "require_enabled", "ok", f"all {len(req)} required sources and analyzers are enabled")
    want = (cfg.get("nvd_feeds_url") or "").rstrip("/")
    if want and enabled.get("vuln-data-source/nvd"):
        have = str(configs["vuln-data-source/nvd"].get("cveFeedsUrl") or "").rstrip("/")
        if have != want:
            rep.add("config", "vuln-data-source/nvd", "problem",
                    f"cveFeedsUrl is {have or 'not set'}, expected {want}: the adapter's VulnCheck CPEs and aliases do not reach DT")
        else:
            rep.add("config", "vuln-data-source/nvd", "ok", f"cveFeedsUrl is {want}")
    per = {k: v for k, v in (cfg.get("sources") or {}).items() if not k.startswith("_")}
    if state is not None:   # a source disabled since must not look stuck when it comes back
        nt = state.setdefault("nonterminal", {})
        for k in [k for k in nt if not enabled.get(k)]:
            nt.pop(k)
    for key, on in sorted(enabled.items()):
        ep, name = key.split("/", 1)
        if ep not in POINTS:
            continue
        if not on:
            continue
        max_age = args.max_age_hours if args.max_age_hours is not None else \
            float((per.get(key) or {}).get("max_age_hours", cfg.get("max_age_hours", 30)))
        try:
            run = dt.get(f"/api/v2/{POINTS[ep]}/{q(name)}/mirror-runs/latest", ok404=True)
        except DtError as e:
            rep.add("mirror", key, "problem", f"could not read the latest mirror run: {e}")
            continue
        runs[key] = run
        nt = state.setdefault("nonterminal", {}) if state is not None else None
        seen = None
        if run and run.get("status") not in ("COMPLETED", "FAILED") and nt is not None:
            sig = f"{run.get('status')}|{run.get('started_at')}"
            if (nt.get(key) or {}).get("sig") != sig:
                nt[key] = {"sig": sig, "first_seen": now}
            seen = nt[key]
        elif nt is not None:
            nt.pop(key, None)
        st, detail = judge_run(run, max_age, now, seen)
        rep.add("mirror", key, st, detail, run=run)
    return enabled, configs, runs, testable


def check_extension_tests(dt, enabled, configs, testable, rep):
    for key in sorted(k for k, on in enabled.items() if on and testable.get(k)):
        ep, name = key.split("/", 1)
        try:
            st, body = dt.call("POST", f"/api/v2/extension-points/{ep}/extensions/{q(name)}/test",
                               {"config": configs.get(key) or {}}, ok=(400, 403))
        except DtError as e:
            rep.add("test", key, "problem", f"the test call failed: {e}")
            continue
        if st == 403:
            rep.add("test", key, "problem", "the key lacks SYSTEM_CONFIGURATION_UPDATE, which --test-extensions needs")
            continue
        if st == 400:
            rep.add("test", key, "problem", f"DT refused the test (for example an unresolvable secret): {str(body)[:300]}")
            continue
        checks = (body or {}).get("checks") or []
        failed = [c for c in checks if c.get("status") == "FAILED"]
        summary = ", ".join(f"{c.get('name')} {c.get('status')}" for c in checks) or "no checks"
        if failed:
            rep.add("test", key, "problem", "; ".join(f"{c.get('name')} FAILED: {c.get('message') or ''}".strip()
                                                     for c in failed), checks=checks)
        elif not checks or all(c.get("status") == "SKIPPED" for c in checks):
            rep.add("test", key, "warning", f"DT ran no check ({summary})", checks=checks)
        else:
            rep.add("test", key, "ok", summary, checks=checks)


CHAT_OR_MAIL = {"slack", "msteams", "mattermost", "webex", "email", "jira"}


def check_notification_rules(dt, cfg, rep):
    """DT's own alerts: failed mirrors reach someone; per-project ANALYZER alerts don't flood a channel."""
    need = cfg.get("require_notification_groups", ["DATASOURCE_MIRRORING"])
    try:
        rules = dt.paged("/api/v1/notification/rule", key=lambda r: r.get("uuid"))
    except DtError as e:
        rep.add("alerts", "rules", "problem", f"could not read DT's notification rules: {e}")
        return
    live = [r for r in rules if r.get("enabled") and r.get("scope") == "SYSTEM"]
    for g in need:
        hits = [r for r in live if g in (r.get("notifyOn") or [])
                and (r.get("notificationLevel") or r.get("level")) in ("INFORMATIONAL", "WARNING", "ERROR")]
        if hits and any(not r.get("filterExpression") for r in hits):
            rep.add("alerts", g, "ok", "DT alerts on it itself: " + ", ".join(r.get("name", "?") for r in hits[:3]))
        elif hits:
            rep.add("alerts", g, "warning", f"the rules for {g} all have a filter expression; check that it lets failures "
                                            "through: " + ", ".join(r.get("name", "?") for r in hits[:3]))
        else:
            rep.add("alerts", g, "problem", f"no enabled SYSTEM notification rule covers {g}, so DT does not report "
                                            "it itself between health check runs")
    for r in live:
        pub = r.get("publisher") or {}
        kind = str(pub.get("extensionName") or pub.get("name") or "").lower()
        if "ANALYZER" in (r.get("notifyOn") or []) and any(k in kind for k in CHAT_OR_MAIL):
            rep.add("alerts", f"rule {r.get('name')}", "warning",
                    f"sends ANALYZER notifications to {pub.get('name') or kind}: DT sends one per project, so an "
                    "analyzer outage floods it (DT re-analyses projects around the clock). Send ANALYZER to a receiver that groups "
                    "alerts, and rely on this check's canary")


def adapter_url(args, cfg, configs):
    if args.adapter_url:
        return args.adapter_url.rstrip("/")
    a = cfg.get("adapter") or {}
    if a.get("url"):
        return a["url"].rstrip("/")
    feeds = str((configs.get("vuln-data-source/nvd") or {}).get("cveFeedsUrl") or "").rstrip("/")
    host = urllib.parse.urlparse(feeds).hostname or ""
    if feeds and host != "nvd.nist.gov" and feeds.endswith("/feeds"):
        return feeds[: -len("/feeds")]
    return None


def check_adapter(dt, url, cfg, runs, rep, now):
    """Adapter /health, then the VulnCheck sample in DT. Returns the adapter's health report or None."""
    try:
        ad = Http(url, timeout=30, check_scheme=False)   # nothing secret is sent to the adapter
        st, h = ad.call("GET", "/health", ok=(503,), retries=1)
    except DtError as e:
        rep.add("adapter", "health", "problem", f"the NVD feed adapter does not answer: {e}")
        return None
    if not isinstance(h, dict):
        rep.add("adapter", "health", "problem", f"{url}/health gave no health report (adapter older than 2.1?): {str(h)[:200]}")
        return None
    for p in h.get("problems") or []:
        rep.add("adapter", "health", "problem", p)
    for w in h.get("warnings") or []:
        rep.add("adapter", "health", "warning", w)
    if st != 200 and not h.get("problems"):
        rep.add("adapter", "health", "problem", f"{url}/health answered HTTP {st} without reasons: {str(h)[:200]}")
    if st == 200 and not h.get("problems"):
        v = h.get("vulncheck") or {}
        rep.add("adapter", "health", "ok", f"fresh (NIST refreshed {(h.get('nist') or {}).get('age_hours')} h ago, "
                                           f"VulnCheck data {v.get('age_hours')} h old, {v.get('candidates')} enriched CVEs)")
    for k in ("records", "vc_has_cpes", "candidates"):
        if (h.get("vulncheck") or {}).get(k) is not None:
            rep.metrics[f"adapter/vulncheck_{k}"] = h["vulncheck"][k]

    # VulnCheck CPEs in DT: only CVEs the adapter served well before DT's last NVD mirror run started
    s = cfg.get("vulncheck_sample") or {}
    run = runs.get("vuln-data-source/nvd")
    if not run or run.get("status") != "COMPLETED" or not run.get("started_at"):
        rep.add("vulncheck", "in-dt", "warning", "skipped: no completed NVD mirror run to compare with")
        return h
    before = int(run["started_at"] - float(s.get("settle_hours", 6)) * 3600 * 1000)
    try:
        _, smp = ad.call("GET", f"/candidates/sample?served_before={before}&n={int(s.get('n', 20))}", retries=1)
    except DtError as e:
        rep.add("vulncheck", "in-dt", "problem", f"could not get a sample from the adapter: {e}")
        return h
    sample = (smp or {}).get("sample") or []
    if not sample:
        rep.add("vulncheck", "in-dt", "warning", f"nothing to check: the adapter first served no enriched CVE before "
                                                 f"{time.strftime('%Y-%m-%d %H:%M', time.gmtime(before / 1000))} UTC")
        return h
    missing = []
    for c in sample:
        try:
            v = dt.get(f"/api/v1/vulnerability/source/NVD/vuln/{q(c['id'])}", ok404=True)
        except DtError as e:
            rep.add("vulncheck", "in-dt", "problem", f"could not read {c['id']} from DT: {e}")
            return h
        cpes = [a for a in ((v or {}).get("affectedComponents") or []) if a.get("identityType") == "CPE"]
        if not cpes:
            missing.append(c["id"] + (" (not in DT)" if v is None else " (no CPE in DT)"))
    ratio = 1 - len(missing) / len(sample)
    need = float(s.get("min_ratio", 0.9))
    detail = f"{len(sample) - len(missing)} of {len(sample)} sampled CVEs enriched by the adapter have CPEs in DT"
    if missing:
        detail += ": missing " + ", ".join(missing[:8]) + (" ..." if len(missing) > 8 else "")
    rep.add("vulncheck", "in-dt", "ok" if ratio >= need else "problem", detail + ("" if ratio >= need else
            f" (need {need:.0%}): DT's NVD mirror does not take the adapter's records"), sample=[c["id"] for c in sample])
    return h


def identity(c):
    return ((c.get("purl") or "").split("?")[0].split("#")[0].lower(), (c.get("cpe") or "").lower(),
            (c.get("name") or "").lower(), (c.get("version") or "").lower())


def check_canary(dt, cfg, cfg_dir, enabled, rep, args):
    can = cfg.get("canary") or {}
    name, version = can.get("project", "dt-health-canary"), str(can.get("version", "1"))
    path = can.get("sbom", "dt-health-canary.cdx.json")
    path = path if os.path.isabs(path) else os.path.join(cfg_dir, path)
    bom = json.load(open(path, encoding="utf-8"))
    comps = {c["bom-ref"]: c for c in bom.get("components", [])}
    prefix = can.get("group_prefix", "dt-health-canary")
    group = prefix
    proj = dt.get(f"/api/v1/project/lookup?name={q(name)}&version={q(version)}", ok404=True)
    if can.get("rotate", True):
        current = set()
        if proj:
            current = {c.get("group") for c in dt.paged(f"/api/v1/component/project/{q(proj['uuid'])}?sortName=name&sortOrder=asc",
                                                         key=lambda c: c["uuid"])}
        group = f"{prefix}-b" if f"{prefix}-a" in current else f"{prefix}-a"
    up = copy.deepcopy(bom)
    for c in up.get("components", []):
        c["group"] = group
    up["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"
    up.setdefault("metadata", {})["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    body = {"projectName": name, "projectVersion": version, "autoCreate": True,
            "bom": base64.b64encode(json.dumps(up).encode()).decode()}
    if can.get("tag"):
        body["projectTags"] = [{"name": can["tag"]}]
    t0 = time.time()
    _, res = dt.call("PUT", "/api/v1/bom", body, auth401=False)   # 401 here: no PROJECT_CREATION_UPLOAD
    token = (res or {}).get("token")
    if not token:
        raise DtError(f"the canary upload returned no token: {res}")
    limit = args.wait if args.wait is not None else float(can.get("max_analysis_minutes", 30)) * 60
    warn = float(can.get("warn_analysis_minutes", 10)) * 60
    behind = (f": DT's vulnerability analysis is behind, so new SBOMs get findings late and every finding is "
              f"older than it looks (limit {limit / 60:g} min)")
    try:
        dt.wait_token(token, limit)
    except AnalysisTimeout as e:
        rep.add("canary", "analysis-latency", "problem", f"{e}{behind}")
        rep.metrics["canary/analysis_seconds"] = round(time.time() - t0)
        return {"group": group, "analysis": "timeout", "seconds": round(time.time() - t0, 1)}
    took = time.time() - t0
    rep.metrics["canary/analysis_seconds"] = round(took)
    if took > limit:
        rep.add("canary", "analysis-latency", "problem", f"DT took {took / 60:.1f} min to analyse the canary{behind}")
    else:
        rep.add("canary", "analysis-latency", "warning" if took > warn else "ok",
                f"DT analysed the canary in {took / 60:.1f} min" + (f" (more than {warn / 60:g} min: DT's analysis "
                                                                     "is slowing down)" if took > warn else ""))
    puuid = (res or {}).get("projectUuid") or (dt.get(f"/api/v1/project/lookup?name={q(name)}&version={q(version)}") or {})["uuid"]
    dcomps = dt.paged(f"/api/v1/component/project/{q(puuid)}?sortName=name&sortOrder=asc", key=lambda c: c["uuid"])
    if dcomps and not any(d.get("group") == group for d in dcomps):
        rep.add("canary", "concurrent", "warning", "another dt-health-check run replaced the canary while this one waited "
                                                   "(run one scheduler only); the canary was not judged in this run")
        return {"project": puuid, "group": group, "analysis": "replaced"}
    ref_of = {}
    for ref, c in comps.items():
        want = identity(c)
        hits = [d for d in dcomps if d.get("group") == group and identity(d) == want]
        if len(hits) == 1:
            ref_of[hits[0]["uuid"]] = ref
        else:
            rep.add("canary", ref, "problem", f"the canary component {c.get('name')} {c.get('version')} is "
                                              f"{'missing' if not hits else 'there more than once'} in DT after the upload")
    findings = dt.paged(f"/api/v1/finding/project/{q(puuid)}?suppressed=true",
                        key=lambda f: (f["component"]["uuid"], f["vulnerability"]["uuid"]))
    by_ref = {}
    for f in findings:
        ref = ref_of.get(f["component"]["uuid"])
        if ref:
            by_ref.setdefault(ref, []).append({"vulnId": f["vulnerability"].get("vulnId"),
                                               "source": f["vulnerability"].get("source"),
                                               "analyzer": (f.get("attribution") or {}).get("analyzerIdentity")})
    for e in can.get("expect", []):
        eid = e["id"]
        off = [c for c in e.get("when", []) if not enabled.get(c)]
        anyc = e.get("when_any") or []
        if off or (anyc and not any(enabled.get(c) for c in anyc)):
            rep.add("canary", eid, "skipped", "not checked: " + (", ".join(off) if off else " / ".join(anyc)) + " disabled")
            continue
        fs = by_ref.get(e["ref"], [])
        sel = [f for f in fs if (not e.get("analyzer") or f["analyzer"] == e["analyzer"])
               and (not e.get("sources") or f["source"] in e["sources"])
               and (not e.get("vuln") or f["vulnId"] == e["vuln"])]
        need = int(e.get("min", 1))
        what = (e.get("vuln") or f"{need}+ finding(s)") + (f" from {'/'.join(e['sources'])}" if e.get("sources") else "") \
            + f" by {e.get('analyzer') or 'any analyzer'} on {comps[e['ref']].get('name')} {comps[e['ref']].get('version')}" \
            + f" ({e['ref']})"
        rep.metrics[f"canary/{eid}"] = len(sel)
        if len(sel) >= need:
            rep.add("canary", eid, "ok", f"{what}: {len(sel)} found", means=e.get("means"))
        else:
            seen = ", ".join(f"{f['vulnId']} [{f['analyzer']}]" for f in fs[:8]) or "no findings at all"
            rep.add("canary", eid, "problem", f"missing {what}; the component has: {seen}"
                    + (f" (checks that {e['means']})" if e.get("means") else ""), means=e.get("means"))
    return {"project": puuid, "group": group, "findings": len(findings), "seconds": round(time.time() - t0, 1)}


def check_portfolio_analysis(dt, cfg, rep, now, canary_name):
    """DT re-analyses each project once its analysis is older than 24 h (portfolio-analysis task, every minute,
    50 in flight). If that stops, new CVEs never reach existing products. A sample keeps the cost constant:
    the page of projects with the oldest BOM import (their findings stay current only through re-analysis),
    plus up to 5 random pages. GET /api/v1/project (the concise list has no lastVulnerabilityAnalysis)."""
    pc = cfg.get("portfolio_analysis") or {}
    if pc.get("enabled", True) is False:
        return
    max_h, ratio = float(pc.get("max_age_hours", 36)), float(pc.get("max_stale_ratio", 0.1))
    size, extra = 20, max(0, math.ceil(int(pc.get("sample", 100)) / 20))
    base = f"/api/v1/project?excludeInactive=true&pageSize={size}"
    try:
        rows = dt.get(f"{base}&pageNumber=1&sortName=lastBomImport&sortOrder=asc") or []
        total = int(dt.last_headers.get("X-Total-Count") or len(rows))
        pages = max(1, math.ceil(total / size))
        for pg in sorted(random.SystemRandom().sample(range(1, pages + 1), min(extra, pages))):
            rows += dt.get(f"{base}&pageNumber={pg}&sortName=name&sortOrder=asc") or []
    except DtError as e:
        rep.add("portfolio", "re-analysis", "problem", f"could not sample the projects: {e}")
        return
    seen, considered, stale = set(), 0, []
    for p in rows:
        if p.get("uuid") in seen:
            continue
        seen.add(p.get("uuid"))
        if p.get("name") == canary_name or p.get("collectionLogic") not in (None, "NONE"):
            continue
        if (p.get("metrics") or {}).get("components") == 0 or not p.get("lastBomImport"):
            continue
        if hours_since(p["lastBomImport"], now) < 1:
            continue   # just uploaded: its first analysis may still run
        considered += 1
        age = hours_since(p.get("lastVulnerabilityAnalysis"), now)
        if age is None or age > max_h:
            stale.append((age if age is not None else float("inf"), f"{p.get('name')} {p.get('version') or ''}".strip()))
    rep.metrics["portfolio/sampled"] = considered
    if not considered:
        rep.add("portfolio", "re-analysis", "ok", f"no analysed projects in the sample ({total} active projects)")
        return
    stale.sort(reverse=True)
    names = ", ".join(f"{n} ({'never' if a == float('inf') else f'{a:.0f} h'})" for a, n in stale[:5])
    detail = (f"{len(stale)} of {considered} sampled projects (of {total} active) were last analysed more than "
              f"{max_h:g} h ago" + (f": {names}" if stale else ""))
    if len(stale) / considered > ratio:
        rep.add("portfolio", "re-analysis", "problem", detail + ": DT's daily re-analysis is behind or stopped, so "
                                                              "new CVEs do not reach existing products")
    else:
        rep.add("portfolio", "re-analysis", "ok", detail)


def check_trivy_db(cfg, configs, enabled, rep, now):
    """Trivy keeps scanning with an old DB when it cannot update it; DT's analyzer then 'succeeds'."""
    tc = cfg.get("trivy") or {}
    if not enabled.get("vuln-analyzer/trivy") or tc.get("enabled", True) is False:
        return
    url = (tc.get("url") or str((configs.get("vuln-analyzer/trivy") or {}).get("apiUrl") or "")).rstrip("/")
    if not url:
        return
    try:
        st, v = Http(url, timeout=20, check_scheme=False).call("GET", "/version", ok=(401, 403, 404, 405), retries=1)
    except DtError as e:
        rep.add("trivy", "db", "warning", f"could not read the Trivy DB age from {url}/version: {e}")
        return
    db = (v or {}).get("VulnerabilityDB") if isinstance(v, dict) else None
    if st != 200 or not db:
        rep.add("trivy", "db", "warning", f"{url}/version gave no DB metadata (HTTP {st}); Trivy's DB age is not checked")
        return
    updated = str(db.get("UpdatedAt") or "")
    try:
        t = calendar.timegm(time.strptime(updated[:19], "%Y-%m-%dT%H:%M:%S"))   # Trivy gives UTC
    except ValueError:
        rep.add("trivy", "db", "warning", f"Trivy DB UpdatedAt {updated!r} not understood")
        return
    age = (now - t) / 3600
    max_h = float(tc.get("db_max_age_hours", 48))
    rep.metrics["trivy/db_age_hours"] = round(age, 1)
    rep.add("trivy", "db", "problem" if age > max_h else "ok",
            f"Trivy's vulnerability DB was built {age:.0f} h ago" + (f" (limit {max_h:g} h): the Trivy server cannot "
                                                                    "update it, and Trivy findings are going stale" if age > max_h else ""))


def trend(rep, state, cfg):
    t = cfg.get("trend") or {}
    pct, min_drop = float(t.get("max_drop_pct", 20)), float(t.get("min_drop", 2))
    prev = state.get("metrics") or {}
    for k, v in sorted(rep.metrics.items()):
        p = prev.get(k)
        if k.endswith(("_seconds", "_hours", "/sampled")):
            continue   # timings and sample sizes are not counts of data
        if isinstance(p, (int, float)) and p > 0 and v < p and (p - v) >= min_drop and (p - v) / p * 100 > pct:
            rep.add("trend", k, "warning", f"dropped from {p} to {v} since the last run (more than {pct:g}%)")
    state["metrics"] = dict(rep.metrics)


def load_state(path, rep):
    if not path or not os.path.exists(path):
        return {}
    try:
        return json.load(open(path, encoding="utf-8"))
    except ValueError:
        rep.add("trend", "state", "warning", f"{path} is unreadable; starting afresh")
        return {}


def save_state(path, state):
    if not path:
        return
    state["at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=1)
    os.replace(tmp, path)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--config", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "health", "dt-health.json"))
    ap.add_argument("--report")
    ap.add_argument("--state", help="JSON file kept between runs: stuck mirror runs and trend warnings")
    ap.add_argument("--adapter-url", help="NVD feed adapter base URL (default: from the NVD source's cveFeedsUrl)")
    ap.add_argument("--test-extensions", action="store_true", help="run DT's live extension tests (needs SYSTEM_CONFIGURATION_UPDATE)")
    ap.add_argument("--no-canary", action="store_true")
    ap.add_argument("--max-age-hours", type=float, help="override max_age_hours for every source")
    ap.add_argument("--wait", type=int, help="seconds to wait for the canary analysis (default canary.max_analysis_minutes)")
    ap.add_argument("--allow-http", action="store_true")
    a = ap.parse_args(argv)
    key, bearer = os.environ.get("DT_API_KEY"), os.environ.get("DT_BEARER")
    rep = Report()
    out = {"tool": "dt-health-check.py", "version": VERSION, "url": a.url,
           "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    try:
        cfg = json.load(open(a.config, encoding="utf-8"))
        if not (key or bearer):
            raise DtError("set DT_API_KEY or DT_BEARER")
        dt = Dt(a.url, {"X-Api-Key": key} if key else {"Authorization": f"Bearer {bearer}"}, allow_http=a.allow_http)
        ver = dt.get("/api/version") or {}
        out["dtVersion"] = ver.get("version")
        now = time.time()
        state = load_state(a.state, rep) if a.state else None
        enabled, configs, runs, testable = check_sources(dt, cfg, rep, a, now, state)
        out["enabled"] = {k: v for k, v in sorted(enabled.items())}
        check_notification_rules(dt, cfg, rep)
        if a.test_extensions:
            check_extension_tests(dt, enabled, configs, testable, rep)
        url = adapter_url(a, cfg, configs)
        if url:
            out["adapter"] = url
            out["adapterHealth"] = check_adapter(dt, url, cfg, runs, rep, now)
        elif (cfg.get("adapter") or {}).get("required"):
            rep.add("adapter", "health", "problem", "no NVD feed adapter: the NVD source reads NIST directly, so "
                                                    "VulnCheck CPEs and vendor aliases are not applied")
        check_trivy_db(cfg, configs, enabled, rep, now)
        check_portfolio_analysis(dt, cfg, rep, now, (cfg.get("canary") or {}).get("project", "dt-health-canary"))
        if not a.no_canary:
            try:
                out["canary"] = check_canary(dt, cfg, os.path.dirname(os.path.abspath(a.config)), enabled, rep, a)
            except DtError as e:
                rep.add("canary", "upload", "problem", f"the canary could not be checked: {e}")
        if state is not None:
            trend(rep, state, cfg)
            save_state(a.state, state)
    except (DtError, AuthError, OSError, ValueError) as e:
        print(f"dt-health-check: cannot check: {e}", file=sys.stderr)
        out.update(result="ERROR", error=str(e), checks=rep.checks)
        if a.report:
            json.dump(out, open(a.report, "w", encoding="utf-8"), indent=1)
        return 2
    problems, warnings = rep.count("problem"), rep.count("warning")
    out.update(result="FAIL" if problems else "PASS", problems=problems, warnings=warnings,
               checks=rep.checks, metrics=rep.metrics, apiCalls=dt.calls, tokenPolls=dt.polls,
               apiCallsExcludingPolls=dt.calls - dt.polls, seconds=round(time.time() - now, 1))
    print(f"dt-health-check {VERSION}: {a.url} (Dependency-Track {out.get('dtVersion')})")
    for c in rep.checks:
        print(f"  {c['status'].upper():8} {c['area']:9} {c['name']:32} {c['detail']}")
    print(f"RESULT: {out['result']} ({problems} problems, {warnings} warnings; {dt.calls - dt.polls} DT API calls "
          f"and {dt.polls} token polls, {out['seconds']:g} s)" + (f" -> {a.report}" if a.report else ""))
    if a.report:
        with open(a.report, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=1)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
