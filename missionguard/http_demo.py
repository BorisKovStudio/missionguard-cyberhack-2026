"""Self-cleaning loopback demo. Conditional public fixture reads carry no credentials."""

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import http.client
import json
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory
import time

from .demo import fixture_contract, tool_request
from .akash_dataset import AkashDatasetAdapter
from .http_runtime import Runtime, TokenRegistry, initialize_state
from .http_server import running_server
from .policy import AUDIENCE


@dataclass(frozen=True, repr=False)
class LocalFixture:
    port: int
    human_token: str
    agent_token: str
    contract: dict
    runtime: Runtime


@contextmanager
def local_fixture(*, clock=time.time, adapter=None, **server_options):
    """Host-only synthetic test credentials, NOT agent-facing tool arguments."""
    now = int(clock())
    contract = fixture_contract()
    contract["expires_at"] = now + 1800
    if adapter is not None: contract["connection_ref"] = adapter.connection_ref
    human, agent = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    records = [{"token_hash": hashlib.sha256(token.encode("ascii")).hexdigest(),
                "actor_id": "demo-human", "org_id": "demo-org", "role": role,
                "audience": AUDIENCE, "mission_ids": [contract["mission_id"]], "expires_at": now + 1800}
               for token, role in ((human, "human"), (agent, "agent"))]
    registry = TokenRegistry({"schema_version": "1.0", "tokens": records}, clock=clock)
    with TemporaryDirectory(prefix="missionguard-http-") as directory:
        state = Path(directory) / "state"
        ledger_id = initialize_state(state)
        runtime = Runtime(state, ledger_id, registry, clock=clock, adapter=adapter)
        try:
            with running_server(runtime, **server_options) as server:
                yield LocalFixture(server.server_address[1], human, agent, contract, runtime)
        finally:
            runtime.close()


def post(fixture, path, payload, *, human=False):
    """Bounded local demo helper, no retries/redirects/proxy/environment routing."""
    if path not in {"/v1/approve", "/v1/execute", "/v1/revoke", "/v1/receipt"}:
        raise ValueError("invalid_demo_route")
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    token = fixture.human_token if human else fixture.agent_token
    connection = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=5)
    try:
        connection.request("POST", path, body=body, headers={"Authorization": "Bearer " + token,
                           "Content-Type": "application/json", "Connection": "close", "Accept": "application/json"})
        response = connection.getresponse()
        raw = response.read(131073)
        if len(raw) > 131072:
            raise ValueError("demo_response_too_large")
        return response.status, json.loads(raw)
    finally:
        connection.close()


def run_http_demo(*, adapter=None):
    with local_fixture(adapter=adapter) as fixture:
        status, approved = post(fixture, "/v1/approve", fixture.contract, human=True)
        if status != 200:
            raise ValueError("demo_approval_failed")
        request = tool_request(approved)
        _, allowed = post(fixture, "/v1/execute", request)
        before = fixture.runtime.engine.adapter.dispatch_count
        _, replay = post(fixture, "/v1/execute", request)
        replay_dispatches = fixture.runtime.engine.adapter.dispatch_count - before
        request["idempotency_key"] = "http-deny"
        request["arguments"]["event_ids"] = ["foreign-fictional-event"]
        before = fixture.runtime.engine.adapter.dispatch_count
        _, denied = post(fixture, "/v1/execute", request)
        denied_dispatches = fixture.runtime.engine.adapter.dispatch_count - before
        _, receipt = post(fixture, "/v1/receipt", {"schema_version": "1.0", "mission_id": approved["mission_id"]}, human=True)
        return {"mode": "synthetic_lab", "transport": "loopback_http", "allowed_status": allowed["status"],
                "replayed": replay["replayed"], "replay_new_dispatches": replay_dispatches,
                "denial_reason": denied["reason"], "denied_new_dispatches": denied_dispatches,
                "receipt": receipt, "hosted": False, "https": False,
                **({"data_host": "akash_public_synthetic", "dataset_upstream_dispatches": fixture.runtime.engine.adapter.dispatch_count} if type(adapter) is AkashDatasetAdapter else {})}


if __name__ == "__main__":
    print(json.dumps(run_http_demo(), ensure_ascii=False, indent=2))
