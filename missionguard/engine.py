"""Durable single-host admission ledger. No network or model authorization."""

from dataclasses import dataclass
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import time
import uuid

from .akash_dataset import AkashDatasetAdapter

from .policy import (AUDIENCE, FIELDS, MAX_BYTES, PolicyError, authorize_arguments,
                     canonical, digest, identifier, require, validate_contract,
                     validate_projection, validate_request)


@dataclass(frozen=True)
class Principal:
    """Trusted server-side context, not an agent-supplied request object."""

    actor_id: str
    org_id: str
    role: str
    audience: str = AUDIENCE


class Engine:
    def __init__(self, db_path, adapter, *, clock=time.time, store_timeout=2.0, require_existing=False):
        self.path = Path(db_path)
        if str(db_path) == ":memory:" or self.path.is_symlink():
            raise ValueError("A trusted persistent database path is required")
        self.require_existing = require_existing
        if require_existing:
            if not self.path.is_file():
                raise ValueError("Existing persistent ledger required")
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
            except FileExistsError:
                pass
        os.chmod(self.path, 0o600)
        self.adapter = adapter
        self.clock = clock
        self.store_timeout = store_timeout
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS missions (
                    mission_id TEXT PRIMARY KEY, contract_json TEXT NOT NULL,
                    contract_hash TEXT NOT NULL, alias TEXT NOT NULL UNIQUE,
                    calls_used INTEGER NOT NULL DEFAULT 0 CHECK(calls_used >= 0),
                    rows_reserved INTEGER NOT NULL DEFAULT 0 CHECK(rows_reserved >= 0),
                    revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
                );
                CREATE TABLE IF NOT EXISTS executions (
                    execution_id TEXT PRIMARY KEY, mission_id TEXT NOT NULL,
                    idem_key TEXT NOT NULL, request_hash TEXT NOT NULL,
                    operation TEXT NOT NULL, status TEXT NOT NULL,
                    reason TEXT NOT NULL, result_json TEXT, created_at INTEGER NOT NULL,
                    UNIQUE(mission_id, idem_key),
                    FOREIGN KEY(mission_id) REFERENCES missions(mission_id)
                );
                CREATE TABLE IF NOT EXISTS outbox (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_json TEXT NOT NULL
                );
            """)

    def _connect(self):
        target = self.path.resolve().as_uri() + "?mode=rw" if self.require_existing else self.path
        connection = sqlite3.connect(target, timeout=self.store_timeout, isolation_level=None,
                                     uri=self.require_existing)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def _now(self):
        return int(self.clock())

    @staticmethod
    def _binding(contract, principal, *, human=False):
        require(type(principal) is Principal, "identity_mismatch")
        require(principal.role in (("human",) if human else ("human", "agent")), "identity_mismatch")
        require(principal.actor_id == contract["actor_id"] and principal.org_id == contract["org_id"]
                and principal.audience == contract["audience"], "identity_mismatch")

    def _adapter_binding(self, contract):
        require(contract["environment"] == "synthetic_lab"
                and self.adapter.environment == contract["environment"]
                and self.adapter.connection_ref == contract["connection_ref"]
                and self.adapter.bounded is True, "adapter_unavailable")

    @staticmethod
    def _budget(mission):
        if mission is None:
            return None
        contract = json.loads(mission["contract_json"])
        return {"calls_used": mission["calls_used"], "calls_limit": contract["budget"]["max_calls"],
                "rows_reserved": mission["rows_reserved"], "rows_limit": contract["budget"]["max_rows"]}

    @staticmethod
    def _decision(status, reason, *, mission=None, execution=None, result=None, replayed=False):
        mode = json.loads(mission["contract_json"])["environment"] if mission is not None else "synthetic_lab"
        return {"schema_version": "1.0", "status": status, "reason": reason,
                "execution_id": execution, "mode": mode, "budget": Engine._budget(mission),
                "result": result, "replayed": replayed}

    def _audit(self, connection, mission, event_type, operation, reason, latency=0):
        event = {"schema_version": "1.0", "event_id": str(uuid.uuid4()),
                 "mission_alias": mission["alias"] if mission is not None else "unbound",
                 "mode": json.loads(mission["contract_json"])["environment"] if mission is not None else "synthetic_lab",
                 "event_type": event_type, "operation": operation if operation in FIELDS else "unknown",
                 "reason": reason, "timestamp": self._now(),
                 "calls_used": mission["calls_used"] if mission is not None else 0,
                 "rows_reserved": mission["rows_reserved"] if mission is not None else 0,
                 "latency_ms": max(0, int(latency))}
        connection.execute("INSERT INTO outbox(event_json) VALUES (?)", (canonical(event),))

    def approve(self, contract, principal):
        validate_contract(contract)
        contract = json.loads(canonical(contract))
        self._binding(contract, principal, human=True)
        require(0 < contract["expires_at"] - self._now() <= 3600, "expired")
        self._adapter_binding(contract)
        contract_hash = digest(contract, "contract")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("INSERT INTO missions(mission_id,contract_json,contract_hash,alias) VALUES (?,?,?,?)",
                               (contract["mission_id"], canonical(contract), contract_hash, "m_" + uuid.uuid4().hex))
            connection.execute("COMMIT")
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()
        return {"mission_id": contract["mission_id"], "contract_hash": contract_hash, "schema_version": "1.0"}

    def _deny_without_mission(self, reason):
        try:
            with closing(self._connect()) as connection:
                self._audit(connection, None, "denied", "unknown", reason)
        except sqlite3.Error:
            return self._decision("denied", "store_unavailable")
        return self._decision("denied", reason)

    def execute(self, request, principal):
        try:
            validate_request(request)
            request = json.loads(canonical(request))
        except (PolicyError, TypeError, KeyError, RecursionError) as error:
            return self._deny_without_mission(error.reason if isinstance(error, PolicyError) else "invalid_request")
        connection = None
        mission = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            mission = connection.execute("SELECT * FROM missions WHERE mission_id=?", (request["mission_id"],)).fetchone()
            require(mission is not None, "identity_mismatch")
            contract = json.loads(mission["contract_json"])
            self._binding(contract, principal)
            require(request["contract_hash"] == mission["contract_hash"], "hash_mismatch")
            self._adapter_binding(contract)
            previous = connection.execute("SELECT * FROM executions WHERE mission_id=? AND idem_key=?",
                                          (request["mission_id"], request["idempotency_key"])).fetchone()
            request_hash = digest(request, "request")
            if previous is not None:
                require(previous["request_hash"] == request_hash, "idempotency_conflict")
                self._audit(connection, mission, "replayed", request["operation"], previous["reason"])
                connection.execute("COMMIT")
                return self._decision(previous["status"], previous["reason"], mission=mission,
                                      execution=previous["execution_id"],
                                      result=json.loads(previous["result_json"]) if previous["result_json"] else None,
                                      replayed=True)
            require(not mission["revoked"], "revoked")
            require(self._now() < contract["expires_at"], "expired")
            authorize_arguments(contract, request)
            rows = request["arguments"]["limit"]
            require(mission["calls_used"] + 1 <= contract["budget"]["max_calls"]
                    and mission["rows_reserved"] + rows <= contract["budget"]["max_rows"], "budget_exhausted")
            execution_id = str(uuid.uuid4())
            connection.execute("UPDATE missions SET calls_used=calls_used+1, rows_reserved=rows_reserved+? WHERE mission_id=?",
                               (rows, request["mission_id"]))
            connection.execute("INSERT INTO executions VALUES (?,?,?,?,?,?,?,?,?)",
                               (execution_id, request["mission_id"], request["idempotency_key"], request_hash,
                                request["operation"], "pending", "pending", None, self._now()))
            mission = connection.execute("SELECT * FROM missions WHERE mission_id=?", (request["mission_id"],)).fetchone()
            self._audit(connection, mission, "admitted", request["operation"], "pending")
            connection.execute("COMMIT")
        except PolicyError as error:
            try:
                if connection is None:
                    return self._decision("denied", "store_unavailable")
                # Never expose a mission's existence, budget or alias to a mismatched identity.
                visible = None if error.reason == "identity_mismatch" else mission
                self._audit(connection, visible, "denied", request["operation"], error.reason)
                connection.execute("COMMIT")
                return self._decision("denied", error.reason, mission=visible)
            except sqlite3.Error:
                return self._decision("denied", "store_unavailable")
        except sqlite3.Error:
            # Commit may have succeeded, but dispatch has not happened in this process.
            return self._decision("denied", "store_unavailable")
        finally:
            if connection is not None:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                connection.close()

        started = time.monotonic()
        try:
            rows = self.adapter.invoke(request["operation"], request["arguments"],
                                       max_rows=request["arguments"]["limit"], max_bytes=MAX_BYTES)
            rows = validate_projection(request["operation"], request["arguments"], rows)
            result = {"rows": rows, "fetched_at": self._now(), "source": ("akash_public_synthetic_http" if type(self.adapter) is AkashDatasetAdapter else "synthetic_fixture")}
            canonical(result)
            status, reason = "allowed", "ok"
        except Exception:
            result, status, reason = None, "unknown", "upstream_unknown"
        connection = None
        try:
            connection = self._connect()
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("UPDATE executions SET status=?, reason=?, result_json=? WHERE execution_id=?",
                               (status, reason, canonical(result) if result is not None else None, execution_id))
            mission = connection.execute("SELECT * FROM missions WHERE mission_id=?", (request["mission_id"],)).fetchone()
            self._audit(connection, mission, "completed" if status == "allowed" else "unknown",
                        request["operation"], reason, (time.monotonic() - started) * 1000)
            connection.execute("COMMIT")
        except sqlite3.Error:
            result, status, reason = None, "unknown", "store_unavailable"
        finally:
            if connection is not None:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                connection.close()
        return self._decision(status, reason, mission=mission, execution=execution_id, result=result)

    def revoke(self, mission_id, principal):
        identifier(mission_id)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                mission = connection.execute("SELECT * FROM missions WHERE mission_id=?", (mission_id,)).fetchone()
                require(mission is not None, "identity_mismatch")
                self._binding(json.loads(mission["contract_json"]), principal, human=True)
                if not mission["revoked"]:
                    connection.execute("UPDATE missions SET revoked=1 WHERE mission_id=?", (mission_id,))
                    self._audit(connection, mission, "revoked", "unknown", "revoked")
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def receipt(self, mission_id, principal):
        identifier(mission_id)
        with closing(self._connect()) as connection:
            connection.execute("BEGIN")
            try:
                mission = connection.execute("SELECT * FROM missions WHERE mission_id=?", (mission_id,)).fetchone()
                require(mission is not None, "identity_mismatch")
                contract = json.loads(mission["contract_json"])
                self._binding(contract, principal)
                executions = connection.execute("SELECT * FROM executions WHERE mission_id=? ORDER BY created_at, execution_id",
                                                (mission_id,)).fetchall()
                events = [json.loads(row[0]) for row in connection.execute("SELECT event_json FROM outbox ORDER BY sequence")]
                result = {"schema_version": "1.0", "mode": contract["environment"], "mission": contract,
                          "contract_hash": mission["contract_hash"], "budget": self._budget(mission),
                          "revoked": bool(mission["revoked"]),
                          "executions": [{"execution_id": row["execution_id"], "operation": row["operation"],
                                          "status": row["status"], "reason": row["reason"], "replayed": False,
                                          "result": json.loads(row["result_json"]) if row["result_json"] else None,
                                          "created_at": row["created_at"]} for row in executions],
                          "audit_events": [event for event in events if event["mission_alias"] == mission["alias"]],
                          "limitations": ["Synthetic fixture, not live EventMatch evidence.",
                                          "Live contract/auth/identity/bounds have not been verified.",
                                          "Sponsor runtimes, open-web and Akash eligibility are unverified.",
                                          "CLI Principal is trusted local test context, not production authentication.",
                                          "Revoke stops new admissions, not previously admitted in-flight work."]}
                connection.execute("COMMIT")
                return result
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def audit_events(self):
        """Local trusted outbox API; never expose globally through unauthenticated HTTP."""
        with closing(self._connect()) as connection:
            return [json.loads(row[0]) for row in connection.execute("SELECT event_json FROM outbox ORDER BY sequence")]
