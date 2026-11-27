#!/usr/bin/env python3
"""A small stand-in for the Dependency-Track 5.2.1 REST API, for testing ci/dt-vex-upload.py without a server.

It copies the 5.2.1 behaviour that matters for VEX (read from the source, tag 5.2.1; 5.2.2 changes none of it):
  - BOM upload returns a token. The import runs first, then the vulnerability analysis, which DT labels with
    the same token (ImportBomActivity), so GET /api/v1/event/token/{token} stays "processing" until the
    analysis has finished.
  - VEX import (CycloneDXVexImporter): skipped completely when the project has no findings yet; a statement
    is skipped when the vulnerability is unknown; components are matched by purl, purl coordinates, CPE, or
    group+name+version; the analysis is stored even when the component has no finding for it (makeAnalysis).
  - v1 lists honour pageSize only together with pageNumber, and otherwise return the first 100 items.
For gap 2 (ci/dt-health-check.py) it also copies:
  - extensions (GET /api/v2/extension-points/{ep}/extensions, .../{name}/config, POST .../test) and the
    latest mirror run per data source (GET /api/v2/{vuln|kev}-data-sources/{name}/mirror-runs/latest);
  - analyzers and ReconcileVulnAnalysisResultsActivity: each enabled analyzer reports its findings; an
    attribution is deleted when its analyzer did not report it and did not fail, so a disabled analyzer
    loses its findings and a failed one keeps them; if every analyzer failed nothing is reconciled.
    The findings list shows the first attribution (FindingDao: ORDER BY id LIMIT 1); new attributions
    of one run are created in analyzer-name order;
  - a component's identity on re-upload includes group and CPE (ComponentIdentity), so a new group gives
    new components without findings;
  - optional permissions per API key (State.perms): 403 when the key lacks every permission a route
    accepts (any-of, as @PermissionRequired).
Time is simulated: events become due after the configured delays and are applied on the next request.
"""
import base64, email.parser, email.policy, json, random, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse, unquote

API_KEY, BEARER = "test-key", "test-bearer"


def purl_coords(p):
    return p.split("#", 1)[0].split("?", 1)[0] if p else None


class State:
    def __init__(self, import_delay=1.0, analysis_delay=2.0, vex_delay=0.5):
        self.lock = threading.RLock()
        self.d_import, self.d_analysis, self.d_vex = import_delay, analysis_delay, vex_delay
        self.projects = {}          # uuid -> {name, version, components{uuid: comp}, findings set, analyses {}}
        self.vulns = {}             # (source, id) -> {uuid, vulnId, source}
        self.rules = []             # (vuln key, name, version)
        self.runs = {}              # token -> list of runs {start, end}
        self.events = []            # (due, fn)
        self.vex_uploads = 0
        self.last_vex = None
        self.drop_vuln_ids = set()  # simulate a DT bug: never apply these vulnerability ids
        self.log = []
        self.next_id = 0            # DT's internal component id (tie-breaker when sortName is given)
        self.rules2 = []            # (vuln key, analyzer, field "cpe"|"purl", value) - gap 2
        self.extensions = {}        # ep -> {name: {"configurable", "testable", "config", "test"}}
        self.mirror_runs = {}       # (ep, name) -> run dict or None
        self.failing = set()        # analyzers whose analysis fails
        self.perms = None           # None: every permission; else a set (the key's permissions)
        self.analyses_run = 0
        self.lower_headers = False    # send header names in lower case, as Envoy/Istio do
        self.secrets = None           # None: every secret reference resolves; else the set of secret names
        self.notification_rules = []  # v1 rule JSON (name, enabled, scope, notificationLevel, notifyOn, publisher)

    def add_vuln(self, vid, source="NVD", affects=(), aliases=(), cpes=()):
        v = {"uuid": str(uuid.uuid4()), "vulnId": vid, "source": source, "aliases": [dict(a) for a in aliases]}
        if cpes:
            v["affectedComponents"] = [{"identityType": "CPE", "identity": c} for c in cpes]
        self.vulns[(source, vid)] = v
        for name, version in affects:
            self.rules.append(((source, vid), name, version))
        return v

    def add_rule(self, vid, source, analyzer, cpe=None, purl=None):
        """`analyzer` reports vulnerability (source, vid) on components with this CPE or purl."""
        if (source, vid) not in self.vulns:
            self.add_vuln(vid, source)
        self.rules2.append(((source, vid), analyzer, "cpe" if cpe else "purl", (cpe or purl).lower()))

    def add_extension(self, ep, name, enabled=True, testable=False, config=None, test=None):
        self.extensions.setdefault(ep, {})[name] = {
            "configurable": True, "testable": testable, "config": dict(config or {}, enabled=enabled),
            "test": test or [{"name": "connection", "status": "PASSED"}]}

    def enabled_analyzers(self):
        ex = self.extensions.get("vuln-analyzer")
        if not ex:
            return {"internal"}
        return {n for n, e in ex.items() if e["config"].get("enabled")}

    def tick(self):
        with self.lock:
            now = time.time()
            due = sorted([e for e in self.events if e[0] <= now], key=lambda e: e[0])
            self.events = [e for e in self.events if e[0] > now]
            for _, fn in due:
                fn()

    def token_status(self, token):
        runs = self.runs.get(token)
        if not runs:
            return {"processing": False}
        now = time.time()
        started = [r for r in runs if r["created"] <= now] or runs[:1]
        run = max(started, key=lambda r: r["created"])     # latest root run with the label, as DT does
        done = now >= run["end"]
        return {"processing": not done, "status": ("FAILED" if run.get("failed") else "COMPLETED") if done else "RUNNING"}

    def project(self, name=None, version=None, uuid_=None, create=False):
        if uuid_:
            return self.projects.get(uuid_)
        for p in self.projects.values():
            if p["name"] == name and p["version"] == version:
                return p
        if create:
            p = {"uuid": str(uuid.uuid4()), "name": name, "version": version, "components": {},
                 "findings": set(), "analyses": {}, "lastBomImport": None, "lastVulnerabilityAnalysis": None}
            self.projects[p["uuid"]] = p
            return p
        return None

    def upload_bom(self, p, bom):
        token, t0 = str(uuid.uuid4()), time.time()
        imp_end = t0 + self.d_import
        self.runs[token] = [{"created": t0, "end": imp_end},
                            {"created": t0 + self.d_import * 0.9, "end": imp_end + self.d_analysis}]

        def do_import():
            # like DT: a re-upload keeps components with the same identity (and their findings and analyses)
            old = {(c["group"], c["name"], c["version"], c["purl"], c["cpe"]): u for u, c in p["components"].items()}
            new = {}
            def walk(cs):
                for c in cs or []:
                    fields = {k: c.get(k) for k in ("group", "name", "version", "purl", "cpe")}
                    key = (fields["group"], fields["name"], fields["version"], fields["purl"], fields["cpe"])
                    cu = old.get(key)
                    if cu:
                        new[cu] = p["components"][cu]
                    else:
                        cu = str(uuid.uuid4()); self.next_id += 1
                        new[cu] = {"uuid": cu, "_id": self.next_id, **fields}
                    walk(c.get("components"))
            walk(bom.get("components"))
            p["components"] = new
            p["findings"] = {f for f in p["findings"] if f[0] in new}
            p["attrib"] = {f: a for f, a in p.get("attrib", {}).items() if f[0] in new}
            p["analyses"] = {k: v for k, v in p["analyses"].items() if k[0] in new}
            p["lastBomImport"] = int(time.time() * 1000)
            self.log.append("bom imported")

        def do_analysis():
            self.analyses_run += 1
            reported = {}
            for c in p["components"].values():
                for key, name, version in self.rules:
                    if c["name"] == name and c["version"] == version:
                        reported.setdefault("internal", set()).add((c["uuid"], self.vulns[key]["uuid"]))
                for key, analyzer, field, value in self.rules2:
                    have = (c.get(field) or "").lower()
                    if field == "purl":
                        have = purl_coords(have) or ""
                    if have and have == value:
                        reported.setdefault(analyzer, set()).add((c["uuid"], self.vulns[key]["uuid"]))
            en = self.enabled_analyzers()
            failed = en & self.failing
            if en and failed == en:
                # VulnAnalysisWorkflow: "All analyzers failed" is terminal, so the token ends FAILED
                self.runs[token][-1]["failed"] = True
                self.log.append("no successful analyzers; skipping reconciliation"); return
            att = p.setdefault("attrib", {})
            for a in sorted(en - failed):
                for fk in sorted(reported.get(a, ())):
                    lst = att.setdefault(fk, [])
                    if a not in lst:
                        lst.append(a)
            for fk, lst in list(att.items()):
                lst[:] = [a for a in lst if a in failed or (a in en and fk in reported.get(a, ()))]
                if not lst:
                    del att[fk]
            p["findings"] = set(att)
            p["lastVulnerabilityAnalysis"] = int(time.time() * 1000)
            self.log.append(f"analysis done: {len(p['findings'])} findings")
        self.events += [(imp_end, do_import), (imp_end + self.d_analysis, do_analysis)]
        return token

    def upload_vex(self, p, vex):
        self.vex_uploads += 1
        self.last_vex = vex
        token, t0 = str(uuid.uuid4()), time.time()
        self.runs[token] = [{"created": t0, "end": t0 + self.d_vex}]

        def do_vex():
            if not p["findings"]:
                self.log.append("VEX skipped: project has no findings"); return
            refs = {c.get("bom-ref"): c for c in vex.get("components", [])}
            meta_ref = ((vex.get("metadata") or {}).get("component") or {}).get("bom-ref")
            for v in vex.get("vulnerabilities", []):
                if v["id"] in self.drop_vuln_ids:
                    continue
                src = (v.get("source") or {}).get("name")
                dv = self.vulns.get((src, v["id"])) if src else None
                if dv is None:
                    cands = [x for (s, i), x in self.vulns.items() if i == v["id"]]
                    dv = cands[0] if len(cands) == 1 else None
                if dv is None:
                    self.log.append(f"VEX {v['id']} skipped: unknown vulnerability"); continue
                an_in = v.get("analysis") or {}
                st = {"not_affected": "NOT_AFFECTED", "resolved": "RESOLVED", "exploitable": "EXPLOITABLE",
                      "in_triage": "IN_TRIAGE", "false_positive": "FALSE_POSITIVE"}.get(an_in.get("state"), "NOT_SET")
                for a in v.get("affects", []):
                    ref = a.get("ref")
                    scoped = ref is not None and (ref == meta_ref or str(ref).startswith("urn:cdx:"))
                    spec = refs.get(ref)
                    if not spec and not scoped:
                        continue
                    for c in p["components"].values():
                        # project-scoped refs: every component with this finding (getAllVulnerableComponents)
                        if (scoped and (c["uuid"], dv["uuid"]) in p["findings"]) or (not scoped and match(spec, c)):
                            # AnalysisQueryManager.makeAnalysis: only fields the VEX gives are changed
                            cur = p["analyses"].setdefault((c["uuid"], dv["uuid"]), {
                                "analysisState": "NOT_SET", "analysisJustification": "NOT_SET",
                                "analysisResponse": "NOT_SET", "analysisDetails": None, "isSuppressed": False})
                            cur["analysisState"] = st
                            cur["isSuppressed"] = st in ("NOT_AFFECTED", "RESOLVED", "FALSE_POSITIVE")
                            if an_in.get("justification"):
                                cur["analysisJustification"] = an_in["justification"].upper()
                            if an_in.get("response"):
                                cur["analysisResponse"] = an_in["response"][-1].upper()
                            if an_in.get("detail") is not None:
                                cur["analysisDetails"] = an_in["detail"]
            self.log.append("VEX applied")
        self.events.append((t0 + self.d_vex, do_vex))
        return token


def match(spec, c):
    if spec.get("purl") and (c.get("purl") == spec["purl"] or purl_coords(c.get("purl")) == purl_coords(spec["purl"])):
        return True
    if spec.get("cpe") and c.get("cpe") == spec["cpe"]:
        return True
    return (c.get("group") or None) == (spec.get("group") or None) and c.get("name") == spec.get("name") \
        and c.get("version") == spec.get("version")


def make_handler(state):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def send(self, code, body=None, headers=None):
            raw = b"" if body is None else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            for k, v in (headers or {}).items():
                self.send_header(k.lower() if state.lower_headers else k, str(v))
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def key_perms(self):
            """Permissions of the calling key (None: all). A subclass can map keys to teams."""
            return state.perms

        def authed(self):
            return self.headers.get("X-Api-Key") == API_KEY or self.headers.get("Authorization") == f"Bearer {BEARER}"

        def body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(n) if n else b""

        def page(self, items, q):
            if "pageNumber" in q and "pageSize" in q:
                s, n = int(q["pageSize"][0]), int(q["pageNumber"][0])
                part = items[(n - 1) * s: n * s]
            else:
                part = items[:100]
            return part, {"X-Total-Count": len(items)}

        def route(self, method):
            state.tick()
            u = urlparse(self.path)
            q = parse_qs(u.query)
            parts = [unquote(x) for x in u.path.strip("/").split("/")]
            if u.path == "/mock/state":
                with state.lock:
                    return self.send(200, {"vexUploads": state.vex_uploads, "log": state.log,
                                           "analyses": sum(len(p["analyses"]) for p in state.projects.values())})
            if u.path == "/api/version":
                return self.send(200, {"version": "5.2.1", "application": "Dependency-Track (mock)"})
            if not self.authed():
                return self.send(401, {"error": "unauthorized"})

            def lacks(*perms):   # @PermissionRequired: any of these
                have = self.key_perms()
                return have is not None and not (set(perms) & have)
            if method in ("POST", "PUT") and "json" not in (self.headers.get("Content-Type") or "") \
                    and u.path != "/api/v1/bom":
                return self.send(415, {"error": "Content-Type must be application/json"})
            with state.lock:
                if parts[:3] == ["api", "v2", "extension-points"] and len(parts) >= 5:
                    ep = parts[3]
                    exts = state.extensions.get(ep)
                    if exts is None:
                        return self.send(404, {"error": f"no extension point {ep}"})
                    if method == "GET" and len(parts) == 5:
                        if lacks("SYSTEM_CONFIGURATION", "SYSTEM_CONFIGURATION_READ"):
                            return self.send(403)
                        items = [{"name": n, "display_name": n, "configurable": e["configurable"], "testable": e["testable"]}
                                 for n, e in sorted(exts.items())]
                        return self.send(200, {"items": items, "total": {"count": len(items), "type": "EXACT"}})
                    e = exts.get(parts[5]) if len(parts) >= 7 else None
                    if e is None:
                        return self.send(404)
                    if method == "GET" and parts[6] == "config":
                        if lacks("SYSTEM_CONFIGURATION", "SYSTEM_CONFIGURATION_READ"):
                            return self.send(403)
                        return self.send(200, {"config": dict(e["config"])})
                    if method == "POST" and parts[6] == "test":
                        if lacks("SYSTEM_CONFIGURATION", "SYSTEM_CONFIGURATION_UPDATE"):
                            return self.send(403)
                        if not e["testable"]:
                            return self.send(400, {"detail": "The extension does not support testing"})
                        b = json.loads(self.body() or b"{}")
                        if state.secrets is not None and any(k.lower().endswith("token") and v not in state.secrets
                                                             for k, v in (b.get("config") or {}).items()):
                            return self.send(400, {"detail": "unresolvable secret reference"})   # validateConfigAndResolveSecrets
                        if b.get("config") != e["config"]:
                            return self.send(400, {"detail": "config differs from the stored one (mock)"})
                        if not e["config"].get("enabled"):
                            return self.send(200, {"checks": [dict(c, status="SKIPPED") for c in e["test"]]})
                        return self.send(200, {"checks": e["test"]})
                    return self.send(404)
                if method == "GET" and parts[:2] == ["api", "v2"] and len(parts) == 6 and parts[4:] == ["mirror-runs", "latest"] \
                        and parts[2] in ("vuln-data-sources", "kev-data-sources"):
                    if lacks("SYSTEM_CONFIGURATION", "SYSTEM_CONFIGURATION_READ"):
                        return self.send(403)
                    run = state.mirror_runs.get(({"vuln-data-sources": "vuln-data-source",
                                                  "kev-data-sources": "kev-data-source"}[parts[2]], parts[3]))
                    return self.send(200, run) if run else self.send(404)
                if method == "GET" and u.path in ("/api/v1/project/concise", "/api/v1/project"):
                    if lacks("VIEW_PORTFOLIO"):
                        return self.send(403)
                    full = u.path == "/api/v1/project"
                    ps = [p for p in state.projects.values()
                          if not (full and q.get("excludeInactive", ["false"])[0] == "true" and p.get("active") is False)]
                    if q.get("sortName", [None])[0] == "lastBomImport":
                        ps.sort(key=lambda p: p.get("lastBomImport") or 0, reverse=q.get("sortOrder", ["asc"])[0] == "desc")
                    elif q.get("sortName", [None])[0] == "name":
                        ps.sort(key=lambda p: p["name"], reverse=q.get("sortOrder", ["asc"])[0] == "desc")
                    items = []
                    for p in ps:
                        # ConciseProject (5.2.1) has no lastVulnerabilityAnalysis; ListProjectsResponseItem has it
                        it = {"uuid": p["uuid"], "name": p["name"], "version": p["version"], "active": p.get("active", True),
                              "collectionLogic": p.get("collectionLogic"), "lastBomImport": p.get("lastBomImport"),
                              "metrics": {"components": len(p["components"])}}
                        if full:
                            it["lastVulnerabilityAnalysis"] = p.get("lastVulnerabilityAnalysis")
                        items.append({k: v for k, v in it.items() if v is not None})   # @JsonInclude(NON_NULL)
                    part, h = self.page(items, q)
                    return self.send(200, part, h)
                if method == "GET" and u.path == "/api/v1/notification/rule":
                    if lacks("SYSTEM_CONFIGURATION", "SYSTEM_CONFIGURATION_READ"):
                        return self.send(403)
                    part, h = self.page(list(state.notification_rules), q)
                    return self.send(200, part, h)
                if method in ("PUT", "POST") and u.path == "/api/v1/bom" and lacks("BOM_UPLOAD"):
                    return self.send(403)
                if method == "PUT" and u.path == "/api/v1/vex" and lacks("VULNERABILITY_ANALYSIS", "VULNERABILITY_ANALYSIS_UPDATE"):
                    return self.send(403)
                if method == "GET" and (parts[:3] == ["api", "v1", "finding"] or u.path == "/api/v1/analysis") \
                        and lacks("VIEW_VULNERABILITY"):
                    return self.send(403)
                if method == "GET" and (parts[:3] in (["api", "v1", "component"], ["api", "v1", "vulnerability"])
                                        or u.path == "/api/v1/project/lookup") and lacks("VIEW_PORTFOLIO"):
                    return self.send(403)
                if method in ("PUT", "POST") and u.path == "/api/v1/bom":
                    raw = self.body()
                    if method == "PUT":
                        b = json.loads(raw)
                        fields = {k: b.get(k) for k in ("projectName", "projectVersion")}
                        bom = json.loads(base64.b64decode(b["bom"]))
                    else:
                        msg = email.parser.BytesParser(policy=email.policy.default).parsebytes(
                            b"Content-Type: " + self.headers["Content-Type"].encode() + b"\r\n\r\n" + raw)
                        fields, bom = {}, None
                        for part in msg.iter_parts():
                            name = part.get_param("name", header="content-disposition")
                            data = part.get_payload(decode=True)
                            if name == "bom":
                                bom = json.loads(data)
                            else:
                                fields[name] = data.decode()
                    if not state.project(fields["projectName"], fields["projectVersion"]) and \
                            lacks("PROJECT_CREATION_UPLOAD", "PORTFOLIO_MANAGEMENT", "PORTFOLIO_MANAGEMENT_CREATE"):
                        return self.send(403)
                    p = state.project(fields["projectName"], fields["projectVersion"], create=True)
                    if method == "PUT" and b.get("projectTags"):
                        p.setdefault("tags", set()).update(t["name"] for t in b["projectTags"])
                    return self.send(200, {"token": state.upload_bom(p, bom), "projectUuid": p["uuid"]})
                if method == "PUT" and u.path == "/api/v1/vex":
                    b = json.loads(self.body())
                    p = state.project(uuid_=b.get("project")) or state.project(b.get("projectName"), b.get("projectVersion"))
                    if not p:
                        return self.send(404, {"error": "project not found"})
                    return self.send(200, {"token": state.upload_vex(p, json.loads(base64.b64decode(b["vex"])))})
                if method == "GET" and parts[:4] == ["api", "v1", "event", "token"]:
                    return self.send(200, state.token_status(parts[4]))
                if method == "GET" and u.path == "/api/v1/project/lookup":
                    p = state.project(q.get("name", [None])[0], q.get("version", [None])[0])
                    return self.send(200, {"uuid": p["uuid"], "name": p["name"], "version": p["version"]}) if p else self.send(404)
                if method == "GET" and parts[:4] == ["api", "v1", "finding", "project"]:
                    p = state.project(uuid_=parts[4])
                    vul = {v["uuid"]: v for v in state.vulns.values()}
                    items = []
                    for cu, vu in sorted(p["findings"]):
                        an = p["analyses"].get((cu, vu), {})
                        if an.get("isSuppressed") and q.get("suppressed", ["false"])[0] != "true":
                            continue
                        att = p.get("attrib", {}).get((cu, vu)) or ["internal"]
                        items.append({"component": {k: v for k, v in p["components"][cu].items() if k != "_id"},
                                      "vulnerability": {k: v for k, v in vul[vu].items() if k != "affectedComponents"},
                                      "analysis": {"state": an.get("analysisState"), "isSuppressed": an.get("isSuppressed", False)},
                                      "attribution": {"analyzerIdentity": att[0]}})
                    part, h = self.page(items, q)
                    return self.send(200, part, h)
                if method == "GET" and parts[:4] == ["api", "v1", "component", "project"]:
                    p = state.project(uuid_=parts[4])
                    cs = list(p["components"].values())
                    if q.get("sortName", [None])[0] == "name":
                        # ORDER BY "name" ASC|DESC, "id"
                        cs.sort(key=lambda c: c["_id"])
                        cs.sort(key=lambda c: c["name"] or "", reverse=q.get("sortOrder", ["asc"])[0] == "desc")
                    else:
                        # ORDER BY "name", "version" DESC with no tie-breaker: equal rows come back in any order
                        random.shuffle(cs)
                        cs.sort(key=lambda c: c["version"] or "", reverse=True)
                        cs.sort(key=lambda c: c["name"] or "")
                    part, h = self.page([{k: v for k, v in c.items() if k != "_id"} for c in cs], q)
                    return self.send(200, part, h)
                if method == "GET" and parts[:4] == ["api", "v1", "vulnerability", "source"] and len(parts) == 7:
                    v = state.vulns.get((parts[4], parts[6]))
                    return self.send(200, v) if v else self.send(404)
                if method == "GET" and u.path == "/api/v1/analysis":
                    p = state.project(uuid_=q["project"][0])
                    an = p["analyses"].get((q["component"][0], q["vulnerability"][0]))
                    return self.send(200, an) if an else self.send(404)
            return self.send(404, {"error": f"no route {method} {u.path}"})

        def do_GET(self):
            self.route("GET")

        def do_PUT(self):
            self.route("PUT")

        def do_POST(self):
            self.route("POST")
    return H


def serve(state, port=0):
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"
