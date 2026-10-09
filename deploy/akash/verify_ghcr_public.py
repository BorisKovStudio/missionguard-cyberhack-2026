"""Explicit, anonymous, fixed-GHCR manifest verification; no image pull or retry.

Default help performs no I/O. A pass proves public manifest access and its fixed
config descriptor, not fresh layer downloads, execution or provider readiness.
"""

import argparse
import hashlib
import ipaddress
import json
import queue
import re
import socket
import ssl
import threading
import time
from urllib.parse import urlencode


HOST = "ghcr.io"
REPOSITORY = "boriskovstudio/missionguard-synthetic"
TAG = "amd64-3145ab783cd2b8c1e3eb"
MANIFEST_ID = "sha256:1674e71e40e95eca66b800ee0619f8b2a0bcabbdaf0fd827cb5c04db68cbd0ab"
CONFIG_ID = "sha256:2ab2dfd7fa39e7b33ea1e91f8697a4db4993efd8fdba38b05e009c848c02afb4"
CONFIG_BYTES = 7741
CA_FILE = "/etc/ssl/cert.pem"
SCOPE = "repository:" + REPOSITORY + ":pull"
TAG_PATH = "/v2/" + REPOSITORY + "/manifests/" + TAG
TOKEN_PATH = "/token?" + urlencode({"service": HOST, "scope": SCOPE})
DIGEST_PREFIX = "/v2/" + REPOSITORY + "/manifests/"
TOTAL_SECONDS = 60
MAX_HEADERS = 16384
MAX_HEADER_COUNT = 64
MAX_MANIFEST = 1048576
MAX_TOKEN = 65536
MAX_CHUNKS = 4096
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
BEARER = re.compile(r"[A-Za-z0-9._~+/-]{1,8192}={0,2}\Z")
FIELD = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
MANIFEST_TYPES = {
    "application/vnd.oci.image.manifest.v1+json": "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json": "application/vnd.docker.container.image.v1+json",
}
LAYER_TYPES = frozenset((
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar+zstd",
    "application/vnd.docker.image.rootfs.diff.tar",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
))
ACCEPT = ", ".join(MANIFEST_TYPES)


class Stop(Exception):
    """No remote, token or exception text is attached to a stop."""


def require(value):
    if not value:
        raise Stop()


class Deadline:
    def __init__(self):
        self.until = time.monotonic() + TOTAL_SECONDS

    def remaining(self):
        value = self.until - time.monotonic()
        require(value > 0)
        return value


def strict_json(raw, limit):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value)
            value[key] = item
        return value

    def reject(value):
        raise Stop()

    require(type(raw) is bytes and len(raw) <= limit)
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                       parse_float=reject, parse_constant=reject)
    require(type(value) is dict)
    return value


def tls_context():
    # Explicit construction/CA path avoid ambient SSL_CERT_* and SSLKEYLOGFILE.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.keylog_filename = None
    context.options |= ssl.OP_NO_COMPRESSION
    context.load_verify_locations(cafile=CA_FILE)
    context.set_alpn_protocols(["http/1.1"])
    return context


def resolve(deadline):
    results = queue.Queue(maxsize=1)
    timeout = min(5, deadline.remaining())

    def work():
        try:
            results.put(socket.getaddrinfo(HOST, 443, type=socket.SOCK_STREAM))
        except Exception:
            results.put(None)

    # A stalled system resolver cannot keep the process alive or send a token.
    threading.Thread(target=work, daemon=True).start()
    rows = results.get(timeout=min(timeout, deadline.remaining()))
    require(type(rows) is list and rows)
    family, kind, protocol, _, address = rows[0]
    require(family in (socket.AF_INET, socket.AF_INET6) and kind == socket.SOCK_STREAM)
    require(address[1] == 443 and ipaddress.ip_address(address[0]).is_global)
    return family, kind, protocol, address


class Reader:
    def __init__(self, connection, deadline):
        self.connection = connection
        self.deadline = deadline
        self.buffer = bytearray()

    def receive(self):
        self.connection.settimeout(self.deadline.remaining())
        part = self.connection.recv(4096)
        require(part)
        self.buffer.extend(part)

    def line(self, limit):
        require(limit >= 2)
        while True:
            end = self.buffer.find(b"\n")
            if end >= 0:
                require(end > 0 and self.buffer[end - 1] == 13 and end + 1 <= limit)
                value = bytes(self.buffer[:end - 1])
                del self.buffer[:end + 1]
                require(b"\r" not in value)
                return value
            require(len(self.buffer) < limit)
            self.receive()

    def exact(self, count):
        while len(self.buffer) < count:
            self.receive()
        value = bytes(self.buffer[:count])
        del self.buffer[:count]
        return value


def read_response(connection, deadline, limit):
    """Bound headers before parsing and require complete explicit HTTP framing."""
    reader = Reader(connection, deadline)
    status = reader.line(2048)
    require(re.fullmatch(rb"HTTP/1\.1 ([1-5][0-9]{2}) [\x20-\x7e]{0,120}", status) is not None)
    code = int(status.split(b" ", 2)[1])
    require(code >= 200)  # Interim responses do not create another parsing loop.
    headers, used = {}, len(status) + 2
    while True:
        line = reader.line(MAX_HEADERS - used)
        used += len(line) + 2
        if not line:
            break
        require(len(headers) < MAX_HEADER_COUNT and b":" in line)
        key, value = line.split(b":", 1)
        require(FIELD.fullmatch(key) is not None)
        require(all(32 <= item <= 126 for item in value))
        key = key.decode("ascii").lower()
        require(key not in headers)
        headers[key] = value.decode("ascii").strip(" ")
    require(headers.get("content-encoding") in (None, "identity"))
    length = headers.get("content-length")
    transfer = headers.get("transfer-encoding")
    require((length is None) != (transfer is None))
    if length is not None:
        require(re.fullmatch(r"[0-9]{1,9}", length) is not None and int(length) <= limit)
        body = reader.exact(int(length))
    else:
        require(transfer.lower() == "chunked")
        body = bytearray()
        for _ in range(MAX_CHUNKS):
            size = reader.line(64)
            require(re.fullmatch(rb"[0-9A-Fa-f]{1,8}", size) is not None)
            count = int(size, 16)
            if count == 0:
                require(reader.line(2) == b"")  # No trailers or extension fields.
                break
            require(len(body) + count <= limit)
            body.extend(reader.exact(count))
            require(reader.exact(2) == b"\r\n")
        else:
            raise Stop()
        body = bytes(body)
    require(not reader.buffer)
    deadline.remaining()
    return code, headers, body


def get(path, token, deadline, limit):
    require(path == TAG_PATH or path == TOKEN_PATH
            or path.startswith(DIGEST_PREFIX) and DIGEST.fullmatch(path[len(DIGEST_PREFIX):]) is not None)
    require(limit == (MAX_TOKEN if path == TOKEN_PATH else MAX_MANIFEST))
    require(token is None or type(token) is str and BEARER.fullmatch(token) is not None)
    require(path != TOKEN_PATH or token is None)
    family, kind, protocol, address = resolve(deadline)
    plain = socket.socket(family, kind, protocol)
    secure = None
    try:
        plain.settimeout(min(10, deadline.remaining()))
        plain.connect(address)
        plain.settimeout(min(10, deadline.remaining()))
        secure = tls_context().wrap_socket(plain, server_hostname=HOST)
        require(secure.selected_alpn_protocol() in (None, "http/1.1"))
        lines = ["GET " + path + " HTTP/1.1", "Host: " + HOST,
                 "Accept: " + ("application/json" if path == TOKEN_PATH else ACCEPT),
                 "Accept-Encoding: identity", "Connection: close",
                 "User-Agent: MissionGuard-PublicManifest/1.0"]
        if token is not None:
            lines.append("Authorization: Bearer " + token)
        secure.settimeout(deadline.remaining())
        secure.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
        return read_response(secure, deadline, limit)
    finally:
        if secure is not None:
            secure.close()
        plain.close()


def challenge(headers):
    value = headers.get("www-authenticate")
    require(type(value) is str and len(value) <= 2048)
    require(value.startswith("Bearer "))
    fields = {}
    for item in value[7:].split(","):
        match = re.fullmatch(r'\s*([a-z]+)="([^"\\\x00-\x1f\x7f]*)"\s*', item)
        require(match is not None and match[1] not in fields)
        fields[match[1]] = match[2]
    require(fields == {"realm": "https://ghcr.io/token", "service": HOST, "scope": SCOPE})


def anonymous_token(headers, raw):
    require(headers.get("content-type", "").split(";", 1)[0].strip().lower() == "application/json")
    value = strict_json(raw, MAX_TOKEN)
    require(set(value) <= {"token", "access_token", "expires_in", "issued_at"})
    token = value.get("token", value.get("access_token"))
    require(type(token) is str and BEARER.fullmatch(token) is not None)
    if "token" in value and "access_token" in value:
        require(value["token"] == value["access_token"])
    if "expires_in" in value:
        require(type(value["expires_in"]) is int and 0 < value["expires_in"] <= 86400)
    if "issued_at" in value:
        require(type(value["issued_at"]) is str and len(value["issued_at"]) <= 80)
    return token


def annotations(value):
    require(type(value) is dict and len(value) <= 32)
    require(all(type(key) is str and 0 < len(key) <= 128
                and type(item) is str and len(item) <= 1024 for key, item in value.items()))
    for key, item in value.items():
        (key + item).encode("utf-8")


def descriptor(value, types, max_size):
    require(type(value) is dict and {"mediaType", "digest", "size"} <= set(value)
            and set(value) <= {"mediaType", "digest", "size", "annotations"})
    require(type(value["mediaType"]) is str and value["mediaType"] in types)
    require(type(value["digest"]) is str and DIGEST.fullmatch(value["digest"]) is not None)
    require(type(value["size"]) is int and 0 < value["size"] <= max_size)
    if "annotations" in value:
        annotations(value["annotations"])


def manifest(headers, raw, digest):
    require(headers.get("docker-content-digest") == digest)
    require("sha256:" + hashlib.sha256(raw).hexdigest() == digest)
    media = headers.get("content-type", "").split(";", 1)[0].strip().lower()
    require(media in MANIFEST_TYPES)
    value = strict_json(raw, MAX_MANIFEST)
    require({"schemaVersion", "mediaType", "config", "layers"} <= set(value)
            and set(value) <= {"schemaVersion", "mediaType", "config", "layers", "annotations"})
    require(type(value["schemaVersion"]) is int and value["schemaVersion"] == 2)
    require(value["mediaType"] == media)
    descriptor(value["config"], {MANIFEST_TYPES[media]}, 65536)
    require(value["config"]["digest"] == CONFIG_ID)
    require(value["config"]["size"] == CONFIG_BYTES)
    layers = value["layers"]
    require(type(layers) is list and 1 <= len(layers) <= 64)
    for layer in layers:
        descriptor(layer, LAYER_TYPES, 134217728)
    require(sum(layer["size"] for layer in layers) <= 268435456)
    if "annotations" in value:
        annotations(value["annotations"])


def verify(digest):
    require(type(digest) is str and digest == MANIFEST_ID)
    deadline = Deadline()
    token = None
    code, headers, raw = get(TAG_PATH, None, deadline, MAX_MANIFEST)
    if code == 401:
        challenge(headers)
        code, headers, raw = get(TOKEN_PATH, None, deadline, MAX_TOKEN)
        require(code == 200)
        token = anonymous_token(headers, raw)
        code, headers, raw = get(TAG_PATH, token, deadline, MAX_MANIFEST)
    require(code == 200)
    manifest(headers, raw, digest)
    code, headers, raw = get(DIGEST_PREFIX + digest, token, deadline, MAX_MANIFEST)
    require(code == 200)
    manifest(headers, raw, digest)
    deadline.remaining()
    return {"schema_version": "1.0", "status": "pass", "digest": digest}


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise Stop()


def main(argv=None):
    parser = Parser(prog="verify_ghcr_public", allow_abbrev=False,
                    description="Anonymous exact GHCR manifest check; no image pull or execution")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--digest")
    try:
        args = parser.parse_args(argv)
        if not args.verify and args.digest is None:
            parser.print_help()
            return 0
        require(args.verify and args.digest is not None)
        result = verify(args.digest)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except Exception:
        print('{"digest":null,"schema_version":"1.0","status":"unknown_stop"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
