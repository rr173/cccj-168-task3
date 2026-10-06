"""HTTP API（零依赖，标准库 http.server）。

写操作在服务级锁内串行，投票的乐观并发（expected_version）仍由领域层校验，
因此并发请求得到的是确定性的 409，而不是写入竞争。
"""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .crypto import canonical_json, hmac_hex
from .errors import DomainError
from .services import Services
from .store import connect

WEB_DIR = os.path.join(os.path.dirname(__file__), "web")

MIME = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
        ".css": "text/css; charset=utf-8", ".json": "application/json; charset=utf-8"}


def build_server(db_path: str, host: str = "127.0.0.1", port: int = 8080):
    conn = connect(db_path)
    svc = Services(conn)
    svc.bootstrap()
    write_lock = threading.RLock()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # 安静日志
            pass

        def _send(self, obj, status: int = 200):
            body = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_download(self, obj, filename: str):
            body = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition",
                             f'attachment; filename="{filename}"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _auditor(self, data: dict | None = None):
            """稽核员身份：优先请求头，其次请求体字段（演示便利）。"""
            aid = self.headers.get("X-Auditor-Id")
            tok = self.headers.get("X-Auditor-Token")
            if not aid and data:
                aid, tok = data.get("auditor_id"), data.get("auditor_token")
            return aid, tok

        def _file(self, path: str):
            full = os.path.normpath(os.path.join(WEB_DIR, path.lstrip("/")))
            if not full.startswith(WEB_DIR) or not os.path.isfile(full):
                self._send({"error": "not_found", "message": "静态资源不存在"}, 404)
                return
            ext = os.path.splitext(full)[1]
            with open(full, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", MIME.get(ext, "application/octet-stream"))
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path
            try:
                if path == "/api/state":
                    self._send(svc.get_state())
                elif path == "/api/drafts":
                    self._send({"drafts": svc.list_vote_drafts()})
                elif path == "/api/archives":
                    aid, tok = self._auditor()
                    svc._require_auditor(aid, tok)
                    q = parse_qs(parsed.query)
                    self._send({"archives": svc.list_archives(
                        decision_id=(q.get("decision_id") or [None])[0],
                        cohort_id=(q.get("cohort_id") or [None])[0])})
                elif path.startswith("/api/archives/"):
                    aid, tok = self._auditor()
                    svc._require_auditor(aid, tok)
                    parts = path.split("/")
                    if len(parts) == 5 and parts[4] == "download":
                        bundle = svc.get_archive_bundle(aid, tok, parts[3])
                        self._send_download(bundle, f"archive-{parts[3]}.json")
                    else:
                        self._send(svc.get_archive(parts[3]))
                elif path.startswith("/api/cohorts/"):
                    parts = path.split("/")
                    if len(parts) == 5 and parts[4] == "drafts":
                        self._send({"drafts": svc.list_vote_drafts(parts[3])})
                    else:
                        self._send(svc.get_cohort(parts[3]))
                elif path.startswith("/api/snapshots/"):
                    self._send(svc.get_snapshot(path.split("/")[3]))
                elif path.startswith("/api/decisions/"):
                    parts = path.split("/")
                    did = parts[3]
                    if len(parts) == 5 and parts[4] == "verify":
                        self._send(svc.verify_proof(did))
                    else:
                        self._send(svc.get_decision(did))
                elif path == "/api/journal":
                    self._send({"events": svc.list_journal()})
                elif path in ("/", "/index.html"):
                    self._file("index.html")
                elif path.startswith("/"):
                    self._file(path)
                else:
                    self._send({"error": "not_found"}, 404)
            except DomainError as e:
                self._send({"error": e.code, "message": e.message}, e.status)
            except Exception as e:  # noqa: BLE001
                self._send({"error": "internal", "message": str(e)}, 500)

        def do_POST(self):
            path = self.path.split("?")[0]
            actor = self.headers.get("X-Actor", "operator")
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length) if length else b"{}"
                data = json.loads(body or b"{}")
            except Exception:  # noqa: BLE001
                self._send({"error": "bad_json", "message": "请求体不是合法 JSON"}, 400)
                return
            try:
                with write_lock:
                    self._route_post(path, actor, data)
            except DomainError as e:
                self._send({"error": e.code, "message": e.message}, e.status)
            except Exception as e:  # noqa: BLE001
                self._send({"error": "internal", "message": str(e)}, 500)

        def _route_post(self, path: str, actor: str, d: dict):
            s = svc
            if path == "/api/trials":
                self._send(s.create_trial(actor, d["title"]), 201)
            elif path == "/api/cohorts":
                self._send(s.create_cohort(
                    actor, d["trial_id"], int(d["level"]), float(d["dose"]),
                    d["dose_unit"], int(d["planned_n"]), int(d["window_days"]),
                    d.get("parent_cohort_id"), d.get("parent_decision_id"),
                    d.get("rationale", "")), 201)
            elif path.endswith("/enroll"):
                self._send(s.enroll_subject(actor, d["cohort_id"]), 201)
            elif path.endswith("/freeze"):
                self._send(s.freeze_cohort(actor, d["cohort_id"]))
            elif path.endswith("/holds"):
                self._send(s.emergency_hold(
                    actor, d.get("scope", "cohort"), d["reason"],
                    d.get("trial_id"), d.get("cohort_id")), 201)
            elif path.startswith("/api/holds/") and path.endswith("/release"):
                self._send(s.release_hold(actor, path.split("/")[3], d["reason"]))
            elif path.endswith("/administrations"):
                self._send(s.record_administration(
                    actor, d["cohort_id"], d["subject_id"],
                    d.get("dose"), d.get("dose_unit"), d.get("given_at")), 201)
            elif path.endswith("/aes"):
                self._send(s.report_ae(
                    actor, d["cohort_id"], d["subject_id"], d["term"],
                    d["severity"], d["onset_at"]), 201)
            elif path.startswith("/api/aes/") and path.endswith("/adjudicate"):
                self._send(s.adjudicate_ae(
                    actor, path.split("/")[3], bool(d["evaluable"]),
                    bool(d["counts_as_dlt"]), d.get("note", "")))
            elif path.endswith("/pending"):
                self._send(s.add_pending(
                    actor, d["cohort_id"], d["kind"], d["note"],
                    d.get("subject_id")), 201)
            elif path.startswith("/api/pending/") and path.endswith("/resolve"):
                self._send(s.resolve_pending(
                    actor, path.split("/")[3], d["resolution"],
                    bool(d.get("imputed", False))))
            elif path.startswith("/api/subjects/") and path.endswith("/replace"):
                self._send(s.replace_subject(
                    actor, d["cohort_id"], path.split("/")[3], d["reason"]), 201)
            elif path == "/api/rules":
                self._send(s.publish_ruleset(actor, d["spec"], d.get("note", "")), 201)
            elif path.endswith("/snapshots"):
                self._send(s.create_snapshot(actor, d["cohort_id"]), 201)
            elif path.startswith("/api/snapshots/") and path.endswith("/votes"):
                self._send(s.cast_vote(
                    actor, path.split("/")[3], d["member_id"], d["action"],
                    d["signature"], int(d["expected_version"])), 201)
            elif path == "/api/archives":
                # 发起归档（幂等）：相同决定+相同策略的并发/重复请求只生成一份
                aid, tok = self._auditor(d)
                view = s.request_archive(
                    aid, tok, d["decision_id"], d.get("policy", "full"),
                    d.get("cover_through_seq"))
                if view["status"] in ("queued", "generating"):
                    view = s.drive_archive(view["archive_id"])
                self._send(view, 200 if view.get("replayed") else 201)
            elif path == "/api/archives/verify":
                # 独立验真下载的归档包
                aid, tok = self._auditor(d)
                self._send(s.verify_archive_bundle(aid, tok, d.get("bundle")))
            elif path == "/api/drafts":
                # 断网草稿一次性提交（幂等）：过期返回 409 + 冲突原因与草稿记录
                view = s.submit_vote_draft(
                    actor, d["draft_id"], d["snapshot_id"], d["member_id"],
                    d["action"], d["content_hash"], d["signature"],
                    int(d.get("expected_version", 0)))
                if view["status"] == "expired":
                    c = view["conflict"] or {"code": "draft_expired",
                                             "message": "草稿已过期"}
                    self._send({"error": c["code"], "message": c["message"],
                                "draft": view,
                                "replayed": bool(view.get("replayed"))}, 409)
                else:
                    self._send({"draft": view,
                                "replayed": bool(view.get("replayed"))},
                               200 if view.get("replayed") else 201)
            elif path.startswith("/api/snapshots/") and path.endswith("/decisions"):
                self._send(s.issue_decision(actor, path.split("/")[3]), 201)
            elif path.startswith("/api/decisions/") and path.endswith("/verify"):
                # GET：校验库内证明；POST：可传入篡改后的证明做检测演练
                parts = path.split("/")
                self._send(svc.verify_proof(parts[3], d.get("proof")))
            elif path == "/api/clock":
                self._send(s.advance_clock(d["now"]))
            elif path == "/api/sign":
                # 仅演示便利端点：用委员 HMAC 密钥对投票载荷本地签名
                member = conn.execute(
                    "SELECT hmac_key FROM committee_members WHERE member_id=?",
                    (d["member_id"],)).fetchone()
                if member is None:
                    self._send({"error": "not_found", "message": "委员不存在"}, 404)
                    return
                message = canonical_json({
                    "snapshot_id": d["snapshot_id"],
                    "content_hash": d["content_hash"],
                    "action": d["action"],
                    "member_id": d["member_id"],
                })
                self._send({"signature": hmac_hex(member["hmac_key"], message)})
            elif path == "/api/demo/seed":
                from .demo import seed_demo
                self._send(seed_demo(s), 201)
            else:
                self._send({"error": "not_found", "message": f"未知端点 {path}"}, 404)

    return ThreadingHTTPServer((host, port), Handler), svc


def main():
    import argparse

    ap = argparse.ArgumentParser(description="剂量递增安全决策平台")
    ap.add_argument("--db", default=os.path.join(os.path.dirname(__file__), "..", "data", "platform.db"))
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    httpd, _ = build_server(args.db, args.host, args.port)
    print(f"平台已启动: http://{args.host}:{args.port}  (db={args.db})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    main()
