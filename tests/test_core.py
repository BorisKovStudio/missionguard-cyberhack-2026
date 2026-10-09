"""Core acceptance controls. All identities/data/adapters are synthetic."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from copy import deepcopy
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from missionguard.adapters import EventMatchAdapter, SyntheticAdapter
from missionguard.demo import FIXTURE_CLOCK, fixture_contract, run_demo, tool_request
from missionguard.engine import Engine, Principal
from missionguard.policy import PolicyError, canonical, digest, strict_loads


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "ledger.sqlite"
        self.now = FIXTURE_CLOCK
        self.adapter = SyntheticAdapter()
        self.engine = Engine(self.path, self.adapter, clock=lambda: self.now, store_timeout=0.01)
        self.human = Principal("demo-human", "demo-org", "human")
        self.agent = Principal("demo-human", "demo-org", "agent")
        self.contract = fixture_contract()
        self.approved = self.engine.approve(self.contract, self.human)

    def test_allowed_projected_read_and_idempotency(self):
        request = tool_request(self.approved)
        result = self.engine.execute(request, self.agent)
        self.assertEqual("allowed", result["status"])
        self.assertEqual(3, result["budget"]["rows_reserved"])
        self.assertEqual(1, self.adapter.dispatch_count)
        self.assertEqual(set(request["arguments"]["fields"]), set(result["result"]["rows"][0]))
        again = self.engine.execute(request, self.agent)
        self.assertTrue(again["replayed"])
        self.assertEqual(result["execution_id"], again["execution_id"])
        self.assertEqual(1, self.adapter.dispatch_count)

    def test_idempotency_conflict(self):
        request = tool_request(self.approved)
        self.engine.execute(request, self.agent)
        request["arguments"]["limit"] = 2
        self.assertEqual("idempotency_conflict", self.engine.execute(request, self.agent)["reason"])
        self.assertEqual(1, self.adapter.dispatch_count)

    def test_scope_and_unknown_fields_deny_before_adapter(self):
        for mutation, reason in [
            (lambda r: r.update(url="https://example.invalid"), "invalid_request"),
            (lambda r: r.update(operation="events.delete"), "operation_denied"),
            (lambda r: r["arguments"].update(event_ids=["foreign-event"]), "resource_denied"),
            (lambda r: r["arguments"].update(fields=["private_notes"]), "field_denied"),
            (lambda r: r["arguments"].update(limit=4), "limit_denied"),
            (lambda r: r["arguments"].update(limit=True), "invalid_request"),
            (lambda r: r.update(contract_hash="0" * 64), "hash_mismatch"),
        ]:
            with self.subTest(reason=reason):
                request = tool_request(self.approved)
                mutation(request)
                self.assertEqual(reason, self.engine.execute(request, self.agent)["reason"])
        self.assertEqual(0, self.adapter.dispatch_count)

    def test_identity_does_not_leak_budget(self):
        for principal in (Principal("other", "demo-org", "agent"), Principal("demo-human", "other", "agent"),
                          Principal("demo-human", "demo-org", "agent", audience="wrong"),
                          {"actor_id": "demo-human", "org_id": "demo-org", "role": "agent"}):
            decision = self.engine.execute(tool_request(self.approved), principal)
            self.assertEqual("identity_mismatch", decision["reason"])
            self.assertIsNone(decision["budget"])
        self.assertEqual(0, self.adapter.dispatch_count)

    def test_absent_and_foreign_missions_are_indistinguishable(self):
        principal = Principal("other", "demo-org", "agent")
        existing = self.engine.execute(tool_request(self.approved), principal)
        request = tool_request(self.approved)
        request["mission_id"] = "absent"
        absent = self.engine.execute(request, principal)
        self.assertEqual(existing, absent)
        for mission_id in ("absent", self.contract["mission_id"]):
            with self.assertRaises(PolicyError) as error:
                self.engine.receipt(mission_id, principal)
            self.assertEqual("identity_mismatch", error.exception.reason)

    def test_ttl_and_revoke(self):
        self.now = self.contract["expires_at"]
        self.assertEqual("expired", self.engine.execute(tool_request(self.approved), self.agent)["reason"])
        self.now = FIXTURE_CLOCK
        self.engine.revoke(self.contract["mission_id"], self.human)
        self.assertEqual("revoked", self.engine.execute(tool_request(self.approved), self.agent)["reason"])
        self.assertEqual(0, self.adapter.dispatch_count)

    def test_agent_cannot_approve_or_revoke_or_reset_mission(self):
        with self.assertRaises(PolicyError):
            self.engine.approve(self.contract, self.agent)
        with self.assertRaises(PolicyError):
            self.engine.revoke(self.contract["mission_id"], self.agent)
        with self.assertRaises(sqlite3.IntegrityError):
            self.engine.approve(self.contract, self.human)

    def test_last_budget_unit_across_independent_engines(self):
        contract = deepcopy(self.contract)
        contract["mission_id"] = "race"
        contract["budget"] = {"max_calls": 1, "max_rows": 1}
        approved = self.engine.approve(contract, self.human)
        second = Engine(self.path, self.adapter, clock=lambda: self.now)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(engine.execute,
                       tool_request(approved, operation="events.get", key="race-" + str(index),
                                    ids=["evt-ai"], fields=["event_id"], limit=1), self.agent)
                       for index, engine in enumerate((self.engine, second))]
            outcomes = [future.result() for future in futures]
        self.assertEqual(["allowed", "denied"], sorted(d["status"] for d in outcomes))
        self.assertEqual(1, self.adapter.dispatch_count)
        self.assertEqual("budget_exhausted", next(d for d in outcomes if d["status"] == "denied")["reason"])

    def test_small_result_does_not_refund_rows(self):
        request = tool_request(self.approved, ids=["evt-ai"], limit=3)
        outcome = self.engine.execute(request, self.agent)
        self.assertEqual(1, len(outcome["result"]["rows"]))
        self.assertEqual(3, outcome["budget"]["rows_reserved"])

    def test_timeout_does_not_retry_or_refund(self):
        def timeout(*args, **kwargs):
            self.adapter.dispatch_count += 1
            raise TimeoutError()
        self.adapter.invoke = timeout
        request = tool_request(self.approved)
        first = self.engine.execute(request, self.agent)
        second = self.engine.execute(request, self.agent)
        self.assertEqual("unknown", first["status"])
        self.assertTrue(second["replayed"])
        self.assertEqual(1, second["budget"]["calls_used"])
        self.assertEqual(3, second["budget"]["rows_reserved"])
        self.assertEqual(1, self.adapter.dispatch_count)

    def test_pending_after_crash_is_not_dispatched_again(self):
        def crash(*args, **kwargs):
            raise KeyboardInterrupt()
        self.adapter.invoke = crash
        request = tool_request(self.approved)
        with self.assertRaises(KeyboardInterrupt):
            self.engine.execute(request, self.agent)
        recovered = Engine(self.path, SyntheticAdapter(), clock=lambda: self.now)
        decision = recovered.execute(request, self.agent)
        self.assertEqual("pending", decision["status"])
        self.assertTrue(decision["replayed"])
        self.assertEqual(0, recovered.adapter.dispatch_count)

    def test_completed_budget_and_idempotency_survive_new_process(self):
        contract = deepcopy(self.contract)
        contract["mission_id"] = "restart-one"
        contract["budget"] = {"max_calls": 1, "max_rows": 1}
        approved = self.engine.approve(contract, self.human)
        request = tool_request(approved, ids=["evt-ai"], fields=["event_id"], limit=1)
        first = self.engine.execute(request, self.agent)
        self.assertEqual("allowed", first["status"])
        # Reopen the same committed ledger in a fresh interpreter, not a container.
        program = """
import json, sys
from missionguard.engine import Engine, Principal
from missionguard.adapters import SyntheticAdapter
payload = json.loads(sys.stdin.read())
adapter = SyntheticAdapter()
engine = Engine(payload['path'], adapter, clock=lambda: payload['now'])
agent = Principal('demo-human', 'demo-org', 'agent')
request = payload['request']
prior = engine.execute(request, agent)
request['idempotency_key'] = 'fresh-after-restart'
fresh = engine.execute(request, agent)
print(json.dumps({'prior': prior, 'fresh': fresh, 'dispatches': adapter.dispatch_count}))
"""
        result = subprocess.run([sys.executable, "-B", "-c", program],
                                input=json.dumps({"path": str(self.path), "now": self.now, "request": request}),
                                capture_output=True, text=True, timeout=10, check=True,
                                cwd=Path(__file__).resolve().parents[1])
        evidence = json.loads(result.stdout)
        self.assertEqual("allowed", evidence["prior"]["status"])
        self.assertTrue(evidence["prior"]["replayed"])
        self.assertEqual(first["execution_id"], evidence["prior"]["execution_id"])
        self.assertEqual("budget_exhausted", evidence["fresh"]["reason"])
        self.assertEqual(1, evidence["fresh"]["budget"]["calls_used"])
        self.assertEqual(1, evidence["fresh"]["budget"]["rows_reserved"])
        self.assertEqual(0, evidence["dispatches"])

    def test_unknown_reservation_survives_ledger_reopen(self):
        contract = deepcopy(self.contract)
        contract["mission_id"] = "restart-unknown"
        contract["budget"] = {"max_calls": 1, "max_rows": 1}
        approved = self.engine.approve(contract, self.human)
        request = tool_request(approved, ids=["evt-ai"], fields=["event_id"], limit=1)
        self.adapter.invoke = lambda *args, **kwargs: (_ for _ in ()).throw(TimeoutError())
        self.assertEqual("unknown", self.engine.execute(request, self.agent)["status"])
        recovered = Engine(self.path, SyntheticAdapter(), clock=lambda: self.now)
        prior = recovered.execute(request, self.agent)
        self.assertEqual("unknown", prior["status"])
        self.assertTrue(prior["replayed"])
        request["idempotency_key"] = "fresh-after-unknown"
        self.assertEqual("budget_exhausted", recovered.execute(request, self.agent)["reason"])
        self.assertEqual(0, recovered.adapter.dispatch_count)

    def test_revoke_expiry_and_approval_uniqueness_survive_ledger_reopen(self):
        self.engine.revoke(self.contract["mission_id"], self.human)
        recovered = Engine(self.path, SyntheticAdapter(), clock=lambda: self.now)
        self.assertEqual("revoked", recovered.execute(tool_request(self.approved), self.agent)["reason"])
        with self.assertRaises(sqlite3.IntegrityError):
            recovered.approve(self.contract, self.human)
        contract = deepcopy(self.contract)
        contract["mission_id"] = "restart-expired"
        approved = recovered.approve(contract, self.human)
        self.now = contract["expires_at"]
        expired = Engine(self.path, SyntheticAdapter(), clock=lambda: self.now)
        self.assertEqual("expired", expired.execute(tool_request(approved), self.agent)["reason"])
        self.assertEqual(0, recovered.adapter.dispatch_count)
        self.assertEqual(0, expired.adapter.dispatch_count)

    def test_store_locked_is_fail_closed(self):
        connection = sqlite3.connect(self.path, isolation_level=None)
        try:
            connection.execute("BEGIN IMMEDIATE")
            result = self.engine.execute(tool_request(self.approved), self.agent)
            self.assertEqual("store_unavailable", result["reason"])
            self.assertEqual(0, self.adapter.dispatch_count)
        finally:
            connection.execute("ROLLBACK")
            connection.close()

    def test_audit_failure_rolls_back_admission(self):
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("DROP TABLE outbox")
        decision = self.engine.execute(tool_request(self.approved), self.agent)
        self.assertEqual("store_unavailable", decision["reason"])
        self.assertEqual(0, self.adapter.dispatch_count)
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual((0, 0), connection.execute("SELECT calls_used,rows_reserved FROM missions").fetchone())
            self.assertEqual(0, connection.execute("SELECT COUNT(*) FROM executions").fetchone()[0])

    def test_strict_json_and_restricted_canonical_format(self):
        for raw in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', '{"x":1.5}',
                    '{"x":9007199254740992}', '{"x":"\\ud800"}', '[]' * 40000,
                    '{"x":' + '9' * 5000 + '}'):
            with self.subTest(raw=raw[:40]), self.assertRaises(PolicyError):
                strict_loads(raw)
        self.assertEqual('{"a":1,"z":"é"}', canonical({"z": "é", "a": 1}))
        self.assertEqual(digest({"a": 1}, "contract"), digest({"a": 1}, "contract"))
        self.assertNotEqual(digest({"a": 1}, "contract"), digest({"a": 1}, "request"))

    def test_real_adapter_is_disabled(self):
        live = Engine(Path(self.temp.name) / "live.sqlite", EventMatchAdapter(), clock=lambda: self.now)
        contract = deepcopy(self.contract)
        contract["environment"] = "eventmatch_live"
        contract["connection_ref"] = "eventmatch-unverified"
        with self.assertRaises(PolicyError) as error:
            live.approve(contract, self.human)
        self.assertEqual("adapter_unavailable", error.exception.reason)

    def test_response_schema_blocks_nested_payloads_and_wrong_resources(self):
        contract = deepcopy(self.contract)
        contract["mission_id"] = "output-schema"
        contract["budget"] = {"max_calls": 10, "max_rows": 10}
        approved = self.engine.approve(contract, self.human)
        for index, row in enumerate([
            {"event_id": "evt-ai", "title": {"private_notes": "not-approved"}},
            {"event_id": "foreign-event", "title": "Unapproved source"},
            {"title": "Missing internal resource ID"},
            {"event_id": "evt-ai", "title": "x" * 301},
        ]):
            self.adapter.invoke = lambda *args, row=row, **kwargs: [row]
            result = self.engine.execute(tool_request(approved, key="bad-response-" + str(index),
                                                     fields=["title"], limit=1), self.agent)
            self.assertEqual("unknown", result["status"])
            self.assertIsNone(result["result"])

    def test_internal_event_id_is_not_leaked_when_not_requested(self):
        result = self.engine.execute(tool_request(self.approved, fields=["title"], limit=1), self.agent)
        self.assertEqual("allowed", result["status"])
        self.assertEqual({"title"}, set(result["result"]["rows"][0]))

    def test_receipt_and_telemetry_are_separate(self):
        self.engine.execute(tool_request(self.approved), self.agent)
        receipt = self.engine.receipt(self.contract["mission_id"], self.human)
        self.assertEqual("synthetic_lab", receipt["mode"])
        self.assertEqual(1, len(receipt["executions"]))
        encoded = json.dumps(self.engine.audit_events())
        for forbidden in ("demo-human", "demo-org", "evt-ai", "example.invalid", self.contract["purpose"]):
            self.assertNotIn(forbidden, encoded)
        with self.assertRaises(PolicyError):
            self.engine.receipt(self.contract["mission_id"], Principal("other", "demo-org", "human"))

    def test_demo_proves_synthetic_race(self):
        evidence = run_demo()
        self.assertEqual(["allowed", "denied"], evidence["race_statuses"])
        self.assertEqual(1, evidence["race_adapter_dispatches"])
        self.assertEqual(0, evidence["denied_adapter_dispatches"])


if __name__ == "__main__":
    unittest.main()
