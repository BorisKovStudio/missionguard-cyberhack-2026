"""Constrained loopback HTTP/1.1 transport; never a public production server."""

import argparse
from contextlib import contextmanager
import json
import re
import socket
import socketserver
import threading
import time

from .http_runtime import (MAX_RESPONSE_BYTES, Runtime, TokenRegistry, TransportError,
                           initialize_state, load_auth)
from .policy import PolicyError, strict_loads

ROUTES = frozenset({"/v1/approve", "/v1/execute", "/v1/revoke", "/v1/receipt"})
MAX_BODY, MAX_HEADERS, MAX_LINE, MAX_HEADER_COUNT = 65536, 8192, 2048, 32
HEADER_NAMES = frozenset({"host", "authorization", "content-type", "content-length",
                          "accept", "connection", "user-agent", "accept-encoding"})


class RateLimits:
    """Fixed global bucket and pre-registered digest buckets, never attacker keyed."""
    def __init__(self, keys, *, global_limit=120, token_limit=30, clock=time.monotonic):
        self.clock, self.global_limit, self.token_limit = clock, global_limit, token_limit
        self.lock = threading.Lock()
        self.buckets = {key: (0, 0) for key in ("global", *keys)}

    def admit(self, key):
        with self.lock:
            window = int(self.clock() // 60)
            prior, count = self.buckets[key]
            count = count if prior == window else 0
            limit = self.global_limit if key == "global" else self.token_limit
            if count >= limit:
                return False
            self.buckets[key] = (window, count + 1)
            return True


def _remaining(sock, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError()
    sock.settimeout(remaining)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.deadline = time.monotonic() + self.server.request_timeout
        try:
            route, headers, body_prefix = self.read_headers()
            key, grant = self.server.runtime.registry.authenticate(headers.get("authorization"))
            if not self.server.limits.admit(key):
                raise TransportError(429, "rate_limited")
            length = int(headers["content-length"])
            body = bytearray(body_prefix[:length])
            while len(body) < length:
                _remaining(self.request, self.deadline)
                piece = self.request.recv(min(4096, length - len(body)))
                if not piece:
                    raise TransportError(400, "invalid_request")
                body.extend(piece)
            try:
                payload = strict_loads(body.decode("utf-8"))
            except (UnicodeError, PolicyError):
                raise TransportError(400, "invalid_request") from None
            result = self.server.runtime.handle(route, payload, grant, deadline=self.deadline)
            self.respond(200, result)
        except TransportError as error:
            self.safe_error(error.status, error.code)
        except (TimeoutError, socket.timeout):
            self.safe_error(408, "request_timeout")
        except (OSError, ConnectionError):
            pass  # A lost response is ambiguous; never redispatch or log secrets.
        except Exception:
            self.safe_error(500, "internal_error")

    def read_headers(self):
        buffer = bytearray()
        while True:
            end = buffer.find(b"\r\n\r\n")
            if end >= 0:
                if end + 4 > MAX_HEADERS:
                    raise TransportError(431, "headers_too_large")
                break
            if len(buffer) >= MAX_HEADERS:
                raise TransportError(431, "headers_too_large")
            _remaining(self.request, self.deadline)
            piece = self.request.recv(min(4096, MAX_HEADERS - len(buffer)))
            if not piece:
                raise TransportError(400, "invalid_request")
            buffer.extend(piece)
            first_end = buffer.find(b"\r\n")
            if (first_end == -1 and len(buffer) > MAX_LINE) or first_end > MAX_LINE:
                raise TransportError(400, "invalid_request")
        lines = bytes(buffer[:end]).split(b"\r\n")
        if len(lines) - 1 > MAX_HEADER_COUNT:
            raise TransportError(431, "headers_too_large")
        if len(lines[0]) > MAX_LINE or any(c < 32 or c > 126 for c in lines[0]):
            raise TransportError(400, "invalid_request")
        words = lines[0].decode("ascii").split(" ")
        if len(words) != 3 or words[2] != "HTTP/1.1":
            raise TransportError(400, "invalid_request")
        if words[0] != "POST":
            raise TransportError(405, "method_not_allowed")
        route = words[1]
        if route not in ROUTES:
            raise TransportError(404, "not_found")
        headers = {}
        for line in lines[1:]:
            if b":" not in line or any(c < 32 or c > 126 for c in line):
                raise TransportError(400, "invalid_request")
            name, value = line.split(b":", 1)
            if not re.fullmatch(rb"[A-Za-z][A-Za-z0-9-]*", name):
                raise TransportError(400, "invalid_request")
            name = name.decode("ascii").lower()
            if name not in HEADER_NAMES or name in headers:
                raise TransportError(400, "invalid_request")
            headers[name] = value.strip(b" ").decode("ascii")
        expected_host = "127.0.0.1:" + str(self.server.server_address[1])
        if headers.get("host") != expected_host:
            raise TransportError(400, "invalid_request")
        if headers.get("content-type") != "application/json":
            raise TransportError(415, "unsupported_media_type")
        length = headers.get("content-length", "")
        if not re.fullmatch(r"[0-9]{1,6}", length):
            raise TransportError(400, "invalid_request")
        if int(length) > MAX_BODY:
            raise TransportError(413, "payload_too_large")
        if headers.get("connection", "close").lower() != "close" or headers.get("accept", "application/json") != "application/json":
            raise TransportError(400, "invalid_request")
        return route, headers, bytes(buffer[end + 4:])

    def respond(self, status, value):
        body = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_RESPONSE_BYTES:
            raise TransportError(503, "response_too_large")
        header = (f"HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\n"
                  f"Content-Length: {len(body)}\r\nConnection: close\r\nCache-Control: no-store\r\n"
                  "X-Content-Type-Options: nosniff\r\n\r\n").encode("ascii")
        _remaining(self.request, self.deadline)
        self.request.sendall(header + body)

    def safe_error(self, status, code):
        try:
            self.respond(status, {"schema_version": "1.0", "error": code})
        except (OSError, TimeoutError):
            pass


class LocalServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = False
    block_on_close = True
    allow_reuse_address = False
    request_queue_size = 8

    def __init__(self, runtime, *, port=8765, request_timeout=5.0, global_limit=120, token_limit=30):
        if type(runtime) is not Runtime or type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("invalid_server_configuration")
        if type(request_timeout) not in (int, float) or not 0 < request_timeout <= 5:
            raise ValueError("invalid_server_configuration")
        if any(type(n) is not int or not 1 <= n <= cap for n, cap in ((global_limit, 120), (token_limit, 30))):
            raise ValueError("invalid_server_configuration")
        self.runtime, self.request_timeout = runtime, request_timeout
        self.limits = RateLimits(runtime.registry.grants, global_limit=global_limit, token_limit=token_limit)
        self.slots = threading.BoundedSemaphore(8)
        super().__init__(("127.0.0.1", port), Handler)

    def process_request(self, request, client_address):
        if not self.limits.admit("global"):
            self.shutdown_request(request)
            return
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        pass  # socketserver's default traceback may reveal request-related data.


@contextmanager
def running_server(runtime, *, port=0, **options):
    """Test-only lifecycle helper. Caller owns runtime.close()."""
    server = LocalServer(runtime, port=port, **options)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=6)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Local synthetic executor only; no TLS/public hosting")
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("init")
    initialize.add_argument("--state-dir", required=True)
    serve = commands.add_parser("serve")
    serve.add_argument("--state-dir", required=True)
    serve.add_argument("--ledger-id", required=True)
    serve.add_argument("--auth-file", required=True)
    serve.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    runtime = None
    try:
        if args.command == "init":
            print(json.dumps({"schema_version": "1.0", "ledger_id": initialize_state(args.state_dir)}))
            return 0
        registry = TokenRegistry(load_auth(args.auth_file))
        runtime = Runtime(args.state_dir, args.ledger_id, registry)
        with LocalServer(runtime, port=args.port) as server:
            # No token/config/body/address values are logged.
            print(json.dumps({"mode": "synthetic_lab", "transport": "loopback_http", "ready": True}))
            server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        return 0
    except Exception:
        print(json.dumps({"ready": False, "error": "local_startup_failed"}))
        return 2
    finally:
        if runtime is not None:
            runtime.close()


if __name__ == "__main__":
    raise SystemExit(main())
