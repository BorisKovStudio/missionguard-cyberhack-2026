"""Numeric-loopback dashboard with one fixed, human-confirmed synthetic demo."""

import argparse
import json
import secrets
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
ASSETS = {"/": ("index.html", "text/html; charset=utf-8"),
          "/index.html": ("index.html", "text/html; charset=utf-8"),
          "/styles.css": ("styles.css", "text/css; charset=utf-8"),
          "/app.mjs": ("app.mjs", "text/javascript; charset=utf-8"),
          "/model.mjs": ("model.mjs", "text/javascript; charset=utf-8"),
          "/run.mjs": ("run.mjs", "text/javascript; charset=utf-8"),
          "/receipt.synthetic.json": ("receipt.synthetic.json", "application/json; charset=utf-8")}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
       "img-src 'self'; base-uri 'none'; form-action 'none'; object-src 'none'; frame-ancestors 'none'")
POLICY = "synthetic-read-v1"


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def _local(self):
        return (self.client_address[0] == "127.0.0.1"
                and self.headers.get_all("Host", []) == [f"127.0.0.1:{self.server.server_port}"]
                and sum(len(k) + len(v) for k, v in self.headers.items()) <= 8192)

    def _origin(self):
        return (self._local()
                and self.headers.get_all("Origin", []) == [f"http://127.0.0.1:{self.server.server_port}"]
                and self.headers.get_all("Sec-Fetch-Site", []) == ["same-origin"])

    def _reply(self, status, raw, content_type="application/json; charset=utf-8", head=False):
        if not isinstance(raw, bytes):
            raw = json.dumps(raw, separators=(",", ":")).encode()
        if len(raw) > 131072:
            status, raw = 503, b'{"error":"response_too_large"}'
        self.send_response(status)
        for key, value in {"Content-Type": content_type, "Content-Length": str(len(raw)),
                           "Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff",
                           "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
                           "Connection": "close"}.items():
            self.send_header(key, value)
        self.end_headers()
        self.close_connection = True
        if not head:
            self.wfile.write(raw)

    def _serve(self, head=False):
        if not self._local():
            return self._reply(403, {"error": "local_origin_required"}, head=head)
        if self.path == "/api/demo-session" and not head:
            if self.headers.get("Sec-Fetch-Site") != "same-origin":
                return self._reply(403, {"error": "same_origin_required"})
            with self.server.guard:
                if self.server.claimed:
                    return self._reply(409, {"error": "run_already_claimed"})
                # One process permits one run; a lost response cannot create a new run.
                if self.server.nonce is None:
                    self.server.nonce = secrets.token_urlsafe(32)
                    self.server.nonce_deadline = time.monotonic() + 1800
                return self._reply(200, {"policy": POLICY, "csrf_nonce": self.server.nonce})
        if self.path == "/api/demo-result" and not head:
            if self.headers.get("Sec-Fetch-Site") != "same-origin":
                return self._reply(403, {"error": "same_origin_required"})
            with self.server.guard:
                result = self.server.result
            return self._reply(200 if result else 404, result or {"error": "no_run"})
        if self.path == "/api/manual-guild-result" and not head:
            if self.headers.get_all("Sec-Fetch-Site", []) != ["same-origin"]:
                return self._reply(403, {"error": "same_origin_required"})
            try:
                from dashboard.manual_receipts import read_manual_guild_result
                result = read_manual_guild_result()
            except ValueError:
                return self._reply(503, {"error": "manual_receipt_unavailable"})
            return self._reply(200, result)
        asset = ASSETS.get(self.path)
        if not asset:
            return self._reply(404, {"error": "not_found"}, head=head)
        try:
            raw = (ROOT / asset[0]).read_bytes()
            if len(raw) > 131072:
                raise OSError()
        except OSError:
            return self._reply(503, {"error": "asset_unavailable"}, head=head)
        self._reply(200, raw, asset[1], head=head)

    def do_GET(self):
        self._serve()

    def do_HEAD(self):
        self._serve(head=True)

    def do_POST(self):
        if self.path != "/api/demo-run":
            return self._reply(404, {"error": "not_found"})
        if (not self._origin() or self.headers.get_all("Content-Type", []) != ["application/json"]
                or any(self.headers.get_all(x) for x in ("Transfer-Encoding", "Expect", "Authorization"))
                or len(self.headers.get_all("Content-Length", [])) != 1):
            return self._reply(403, {"error": "request_rejected"})
        length = self.headers.get("Content-Length", "")
        if not length.isascii() or not length.isdecimal() or not 1 <= int(length) <= 128:
            return self._reply(413, {"error": "body_bound"})
        try:
            # A fixed byte string rejects extra fields, duplicate keys and arbitrary policy.
            body = self.rfile.read(int(length))
            if body != b'{"confirm_policy":"synthetic-read-v1"}':
                return self._reply(400, {"error": "policy_confirmation_required"})
        except OSError:
            return self._reply(408, {"error": "request_timeout"})
        with self.server.guard:
            nonce = self.headers.get_all("X-Demo-CSRF", [])
            if (self.server.claimed or self.server.nonce is None or len(nonce) != 1
                    or time.monotonic() > self.server.nonce_deadline
                    or not secrets.compare_digest(nonce[0], self.server.nonce)):
                return self._reply(409, {"error": "run_unavailable_or_claimed"})
            self.server.claimed = True
            self.server.nonce = None
            run_id, started = str(uuid.uuid4()), int(time.time())
            self.server.result = {"run_id": run_id, "state": "pending", "started_at": started}
        try:
            from missionguard.http_demo import run_http_demo
            result = run_http_demo()
            if result["mode"] != "synthetic_lab" or result["hosted"] is not False:
                raise ValueError()
            envelope = {"schema_version": "dashboard-run-1", "run_id": run_id,
                        "started_at": started, "completed_at": int(time.time()),
                        "execution_source": "local_core_http", "caller": "deterministic_local",
                        "agent_runtime": "unavailable", "dataset": "synthetic",
                        "receipt": result["receipt"],
                        "evidence": {key: result[key] for key in ("allowed_status", "replayed",
                            "replay_new_dispatches", "denial_reason", "denied_new_dispatches")}}
            raw = json.dumps(envelope, separators=(",", ":")).encode()
            if len(raw) > 131072:
                raise ValueError()
            with self.server.guard:
                self.server.result = envelope
        except Exception:
            # The claim is retained. No exception details, auto-retry or zero-effects claim.
            with self.server.guard:
                self.server.result = {"run_id": run_id, "state": "unknown", "started_at": started}
            self._reply(503, {"error": "run_unknown", "run_id": run_id})
        else:
            # Response loss never deletes a completed receipt or reopens the claim.
            self._reply(200, raw)

    def log_message(self, format, *args):
        pass


class LocalServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def process_request(self, request, client_address):
        if not self.handlers.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.handlers.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.handlers.release()


def create_server(port=8765):
    server = LocalServer(("127.0.0.1", port), Handler)
    server.handlers = threading.BoundedSemaphore(8)
    server.guard = threading.Lock()
    server.nonce = None
    server.nonce_deadline = 0
    server.claimed = False
    server.result = None
    return server


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    server = create_server(parser.parse_args().port)
    print(f"MissionGuard local synthetic Run: http://127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
