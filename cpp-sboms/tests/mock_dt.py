#!/usr/bin/env python3
"""A small stand-in for the Dependency-Track 5.2.1 REST API, for testing ci/dt-vex-upload.py without a server.

It copies the 5.2.1 behaviour that matters for VEX (read from the source, tag 5.2.1):
  - BOM upload returns a token. The import runs first, then the vulnerability analysis, which DT labels with
    the same token (ImportBomActivity), so GET /api/v1/event/token/{token} stays "processing" until the
    analysis has finished.
  - VEX import (CycloneDXVexImporter): skipped completely when the project has no findings yet; a statement
    is skipped when the vulnerability is unknown; components are matched by purl, purl coordinates, CPE, or
    group+name+version; the analysis is stored even when the component has no finding for it (makeAnalysis).
  - v1 lists honour pageSize only together with pageNumber, and otherwise return the first 100 items.
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

    def add_vuln(self, vid, source="NVD", affects=(), aliases=()):
        v = {"uuid": str(uuid.uuid4()), "vulnId": vid, "source": source, "aliases": [dict(a) for a in aliases]}
        self.vulns[(source, vid)] = v
        for name, version in affects:
            self.rules.append(((source, vid), name, version))
        return v

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
        return {"processing": not done, "status": "COMPLETED" if done else "RUNNING"}

    def project(self, name=None, version=None, uuid_=None, create=False):
        if uuid_:
            return self.projects.get(uuid_)
        for p in self.projects.values():
            if p["name"] == name and p["version"] == version:
                return p
        if create:
            p = {"uuid": str(uuid.uuid4()), "name": name, "version": version, "components": {},
                 "findings": set(), "analyses": {}}
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
            old = {(c["group"], c["name"], c["version"], c["purl"]): u for u, c in p["components"].items()}
            new = {}
            def walk(cs):
                for c in cs or []:
                    fields = {k: c.get(k) for k in ("group", "name", "version", "purl", "cpe")}
                    key = (fields["group"], fields["name"], fields["version"], fields["purl"])
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
            p["analyses"] = {k: v for k, v in p["analyses"].items() if k[0] in new}
            self.log.append("bom imported")

        def do_analysis():
            for c in p["components"].values():
                for key, name, version in self.rules:
                    if c["name"] == name and c["version"] == version:
                        p["findings"].add((c["uuid"], self.vulns[key]["uuid"]))
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
                self.send_header(k, str(v))
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

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
            if not self.authed():
                return self.send(401, {"error": "unauthorized"})
            with state.lock:
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
                    p = state.project(fields["projectName"], fields["projectVersion"], create=True)
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
                        items.append({"component": {k: v for k, v in p["components"][cu].items() if k != "_id"},
                                      "vulnerability": dict(vul[vu]),
                                      "analysis": {"state": an.get("analysisState"), "isSuppressed": an.get("isSuppressed", False)}})
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
