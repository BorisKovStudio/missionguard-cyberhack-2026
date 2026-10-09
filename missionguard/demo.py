"""Reproducible local synthetic checkpoint. No network, secret or real account."""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from pathlib import Path
from tempfile import TemporaryDirectory

from .adapters import SyntheticAdapter
from .engine import Engine, Principal

FIXTURE_CLOCK = 1791568800


def fixture_contract():
    return json.loads((Path(__file__).resolve().parent.parent / "fixtures" / "mission.json").read_text())


def tool_request(approved, *, operation="events.list", key="read-1", ids=None, fields=None, limit=3):
    return {"schema_version": "1.0", "mission_id": approved["mission_id"],
            "contract_hash": approved["contract_hash"], "idempotency_key": key,
            "operation": operation,
            "arguments": {"event_ids": ids or ["evt-ai", "evt-security", "evt-design"],
                          "fields": fields or ["event_id", "title", "source_url"], "limit": limit}}


def run_demo():
    human = Principal("demo-human", "demo-org", "human")
    agent = Principal("demo-human", "demo-org", "agent")
    with TemporaryDirectory(prefix="missionguard-synthetic-") as directory:
        adapter = SyntheticAdapter()
        engine = Engine(Path(directory) / "ledger.sqlite", adapter, clock=lambda: FIXTURE_CLOCK)
        approved = engine.approve(fixture_contract(), human)
        allowed = engine.execute(tool_request(approved), agent)
        replay = engine.execute(tool_request(approved), agent)
        before = adapter.dispatch_count
        denied = engine.execute(tool_request(approved, key="forbidden-resource", ids=["other-account-event"]), agent)
        denied_dispatches = adapter.dispatch_count - before
        engine.execute(tool_request(approved, key="analysis-1", operation="analyses.get",
                                    ids=["evt-ai"], fields=["event_id", "summary", "topics"], limit=1), agent)
        race_contract = deepcopy(fixture_contract())
        race_contract["mission_id"] = "demo-last-unit"
        race_contract["budget"] = {"max_calls": 1, "max_rows": 1}
        race = engine.approve(race_contract, human)
        before = adapter.dispatch_count
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(engine.execute,
                       tool_request(race, key="race-" + str(index), operation="events.get",
                                    ids=["evt-ai"], fields=["event_id", "title"], limit=1), agent)
                       for index in range(2)]
            decisions = [future.result() for future in futures]
        receipt = engine.receipt(approved["mission_id"], human)
        evidence = {"mode": "synthetic_lab", "fixture_clock": FIXTURE_CLOCK,
                    "allowed_status": allowed["status"], "replay_no_dispatch": replay["replayed"],
                    "resource_denial": denied["reason"], "denied_adapter_dispatches": denied_dispatches,
                    "race_statuses": sorted(d["status"] for d in decisions),
                    "race_adapter_dispatches": adapter.dispatch_count - before,
                    "receipt": receipt}
        return evidence


if __name__ == "__main__":
    print(json.dumps(run_demo(), ensure_ascii=False, indent=2))
