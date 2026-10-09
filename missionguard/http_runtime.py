"""Trusted local synthetic runtime. Optional fixed public fixture adapter, no external credentials."""

from contextlib import closing
from dataclasses import dataclass
import fcntl
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat
import threading
import time
from types import MappingProxyType
import uuid

from .adapters import SyntheticAdapter
from .akash_dataset import AkashDatasetAdapter
from .engine import Engine, Principal
from .policy import AUDIENCE, PolicyError, identifier, strict_loads

MAX_STATE_BYTES = 32 * 1024 * 1024
MAX_MISSIONS, MAX_EXECUTIONS, MAX_AUDIT = 16, 400, 2000
MAX_RESPONSE_BYTES = 131072
TOKEN = re.compile(r"[A-Za-z0-9_-]{43,128}\Z")


class TransportError(Exception):
    def __init__(self, status, code):
        super().__init__(code)
        self.status, self.code = status, code


@dataclass(frozen=True)
class Grant:
    principal: Principal
    mission_ids: frozenset
    expires_at: int


class TokenRegistry:
    """Immutable digest mapping, supplied by the trusted local operator, not HTTP."""

    def __init__(self, config, *, clock=time.time):
        if type(config) is not dict or set(config) != {"schema_version", "tokens"} or config["schema_version"] != "1.0":
            raise ValueError("invalid_auth_config")
        records = config["tokens"]
        if type(records) is not list or not 1 <= len(records) <= 32:
            raise ValueError("invalid_auth_config")
        grants = {}
        try:
            for row in records:
                if type(row) is not dict or set(row) != {"token_hash", "actor_id", "org_id", "role", "audience", "mission_ids", "expires_at"}:
                    raise ValueError()
                key = row["token_hash"]
                if type(key) is not str or not re.fullmatch(r"[0-9a-f]{64}", key) or key in grants:
                    raise ValueError()
                identifier(row["actor_id"]); identifier(row["org_id"])
                if row["role"] not in ("human", "agent") or row["audience"] != AUDIENCE:
                    raise ValueError()
                ids = row["mission_ids"]
                if type(ids) is not list or not 1 <= len(ids) <= 100 or len(set(ids)) != len(ids):
                    raise ValueError()
                for item in ids:
                    identifier(item)
                expiry = row["expires_at"]
                if type(expiry) is not int or not 0 < expiry - int(clock()) <= 3600:
                    raise ValueError()
                grants[key] = Grant(Principal(row["actor_id"], row["org_id"], row["role"], row["audience"]),
                                    frozenset(ids), expiry)
        except (PolicyError, TypeError, KeyError, ValueError):
            raise ValueError("invalid_auth_config") from None
        self.grants = MappingProxyType(grants)
        self.clock = clock

    def authenticate(self, header):
        if type(header) is not str or not header.startswith("Bearer ") or not TOKEN.fullmatch(header[7:]):
            raise TransportError(401, "unauthorized")
        key = hashlib.sha256(header[7:].encode("ascii")).hexdigest()
        grant = self.grants.get(key)
        self.revalidate(grant)
        return key, grant

    def revalidate(self, grant):
        """Check the original trusted grant again at the admission boundary."""
        if not any(value is grant for value in self.grants.values()) or int(self.clock()) >= grant.expires_at:
            raise TransportError(401, "unauthorized")


def private_path(path, *, directory=False):
    path = Path(path)
    info = path.lstat()
    valid_kind = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not valid_kind or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600):
        raise ValueError("private_owned_path_required")
    return path


def load_auth(path):
    path = private_path(path)
    with path.open("rb") as source:
        raw = source.read(65537)
    return strict_loads(raw.decode("utf-8"))


class StateLease:
    def __init__(self, directory):
        self.directory = private_path(directory, directory=True).resolve()
        self.path = self.directory / "ledger.sqlite"
        self.fd = os.open(self.directory / "executor.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if os.fstat(self.fd).st_uid != os.getuid() or stat.S_IMODE(os.fstat(self.fd).st_mode) != 0o600:
                raise ValueError("private_lock_required")
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(self.fd)
            raise ValueError("state_already_in_use_or_invalid") from None

    def close(self):
        if self.fd is not None:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self.fd = None


def initialize_state(directory):
    """Explicit empty-ledger initialization, never called automatically by serve."""
    directory = Path(directory)
    if not directory.exists():
        directory.mkdir(mode=0o700)
    lease = StateLease(directory)
    try:
        if lease.path.exists() or lease.path.is_symlink():
            raise ValueError("state_already_exists")
        engine = Engine(lease.path, SyntheticAdapter(), store_timeout=0.2)
        ledger_id = str(uuid.uuid4())
        with closing(engine._connect()) as connection:
            connection.execute("CREATE TABLE http_metadata (ledger_id TEXT PRIMARY KEY)")
            connection.execute("INSERT INTO http_metadata VALUES (?)", (ledger_id,))
        return ledger_id
    finally:
        lease.close()


class Runtime:
    def __init__(self, directory, expected_id, registry, *, clock=time.time, adapter=None):
        if type(registry) is not TokenRegistry or type(expected_id) is not str or str(uuid.UUID(expected_id)) != expected_id:
            raise ValueError("invalid_runtime_configuration")
        if adapter is not None and type(adapter) not in (SyntheticAdapter, AkashDatasetAdapter):
            raise ValueError("synthetic_adapter_required")
        self.lease = StateLease(directory)
        self.path = self.lease.path
        self.registry, self.expected_id = registry, expected_id
        self.lock = threading.RLock()
        self.failed = False
        try:
            private_path(self.path)
            info = self.path.stat()
            self.identity = (info.st_dev, info.st_ino)
            self._check_store()
            self.engine = Engine(self.path, adapter or SyntheticAdapter(), clock=clock, store_timeout=0.2, require_existing=True)
        except BaseException:
            self.lease.close()
            raise

    def _check_store(self):
        try:
            if self.failed:
                raise ValueError()
            private_path(self.path)
            info = self.path.stat()
            if (info.st_dev, info.st_ino) != self.identity:
                raise ValueError()
            size = 0
            for suffix in ("", "-wal", "-shm"):
                path = Path(str(self.path) + suffix)
                if path.exists():
                    if path.is_symlink():
                        raise ValueError()
                    size += path.stat().st_size
            if size > MAX_STATE_BYTES:
                raise TransportError(503, "capacity_exceeded")
            with closing(sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=0.2)) as connection:
                markers = connection.execute("SELECT ledger_id FROM http_metadata LIMIT 2").fetchall()
                if markers != [(self.expected_id,)]:
                    raise ValueError()
                counts = [connection.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
                          for table in ("missions", "executions", "outbox")]
            if counts[0] > MAX_MISSIONS or counts[1] >= MAX_EXECUTIONS or counts[2] >= MAX_AUDIT - 1:
                raise TransportError(503, "capacity_exceeded")
            return counts
        except TransportError:
            raise
        except (OSError, ValueError, sqlite3.Error):
            self.failed = True
            raise TransportError(503, "store_unavailable") from None

    def handle(self, route, payload, grant, *, deadline=None):
        if route not in {"/v1/approve", "/v1/execute", "/v1/revoke", "/v1/receipt"}:
            raise TransportError(404, "not_found")
        role = "agent" if route == "/v1/execute" else "human"
        if grant.principal.role != role:
            raise TransportError(403, "forbidden")
        try:
            mission_id = payload["mission_id"]
            identifier(mission_id)
        except (PolicyError, TypeError, KeyError):
            raise TransportError(400, "invalid_request") from None
        if mission_id not in grant.mission_ids:
            raise TransportError(403, "forbidden")
        remaining = 5.0 if deadline is None else deadline - time.monotonic()
        if remaining <= 0 or not self.lock.acquire(timeout=remaining):
            raise TransportError(408, "request_timeout")
        try:
            if deadline is not None and time.monotonic() >= deadline:
                raise TransportError(408, "request_timeout")
            self.registry.revalidate(grant)
            counts = self._check_store()
            if deadline is not None and time.monotonic() >= deadline:
                raise TransportError(408, "request_timeout")
            self.registry.revalidate(grant)
            try:
                if route == "/v1/execute":
                    return self.engine.execute(payload, grant.principal)
                if route == "/v1/approve":
                    if counts[0] >= MAX_MISSIONS:
                        raise TransportError(503, "capacity_exceeded")
                    return self.engine.approve(payload, grant.principal)
                if type(payload) is not dict or set(payload) != {"schema_version", "mission_id"} or payload["schema_version"] != "1.0":
                    raise TransportError(400, "invalid_request")
                if route == "/v1/revoke":
                    self.engine.revoke(mission_id, grant.principal)
                    return {"schema_version": "1.0", "mission_id": mission_id, "revoked": True}
                return self.engine.receipt(mission_id, grant.principal)
            except PolicyError as error:
                raise TransportError(403 if error.reason in ("identity_mismatch", "expired", "adapter_unavailable") else 400,
                                     "forbidden" if error.reason in ("identity_mismatch", "expired", "adapter_unavailable") else "invalid_request") from None
            except sqlite3.IntegrityError:
                raise TransportError(409, "approval_conflict") from None
            except sqlite3.Error:
                raise TransportError(503, "store_unavailable") from None
        finally:
            self.lock.release()

    def close(self):
        self.lease.close()
