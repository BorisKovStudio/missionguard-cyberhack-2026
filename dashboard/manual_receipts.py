"""Explicit server-only read seam for a past manual Guild result, not Run."""

from datetime import datetime
from decimal import Decimal, InvalidOperation
import hashlib
import json
from pathlib import Path
import re
import uuid

RECEIPT_FILE = Path(__file__).resolve().parents[1] / "integrations/guild/manual-guild-result.json"
RECEIPT_SHA256 = "ba3beed38f77244364097cc4009442061e2d009180bda25e700734be36c4f4b2"


def project_guild_manual(value):
    """Keep manual provenance separate; never forward raw session metadata."""
    try:
        if (value["schema_version"] != "1.0" or value["dataset"] != "synthetic"
                or value["agent_runtime"] != "guild_hosted_coded"
                or value["tool_runtime"] != "local_core_http"
                or value["trigger"] != "manual_guild_test_ui"
                or value["fresh_per_click"] is not False
                or type(value["application_llm_calls"]) is not int
                or value["application_llm_calls"] != 1):
            raise ValueError()
        run_id = str(uuid.UUID(value["run_id"]))
        if run_id != value["run_id"]:
            raise ValueError()
        times = {}
        for key in ("source_timestamp", "core_observed_at", "retrieved_at"):
            stamp = value[key]
            if type(stamp) is not str or len(stamp) > 48:
                raise ValueError()
            parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                raise ValueError()
            times[key] = stamp
        output = value["output"]
        if type(output) is not str or not 1 <= len(output.encode("utf-8")) <= 8192:
            raise ValueError()
        if value["requested_model"] != "gpt-4o-2024-08-06":
            raise ValueError()
        usage = {key: value["usage"][key] for key in ("input_tokens", "output_tokens", "total_tokens")}
        if (any(type(n) is not int or not 0 <= n <= 128000 for n in usage.values())
                or usage["input_tokens"] + usage["output_tokens"] != usage["total_tokens"]):
            raise ValueError()
        cost = value["cost"]
        estimate = cost["estimated_usd"]
        if (type(estimate) is not str or len(estimate) > 24
                or not Decimal(estimate).is_finite() or Decimal(estimate) < 0
                or cost["billed_usd"] is not None
                or cost["basis"] != "published_model_list_price_not_verified_invoice"):
            raise ValueError()
        return {"schema_version": "dashboard-manual-guild-1", "run_id": run_id,
                "dataset": "synthetic", "execution_source": "manual_guild_test_ui",
                "agent_runtime": "guild_hosted_coded", "tool_runtime": "local_core_http",
                "fresh_per_click": False, "model": value["requested_model"], **times,
                "usage": usage, "estimated_usd": estimate, "billed_usd": None,
                "cost_basis": "list_price_estimate_not_invoice",
                "platform_internal_retries": "unverified_accepted_risk",
                "output_kind": "untrusted_model_text_identifiers_redacted",
                "output": re.sub(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b",
                                 "[evidence identifier withheld]", output)}
    except (KeyError, TypeError, ValueError, InvalidOperation, UnicodeError):
        raise ValueError("manual_guild_receipt_invalid") from None


def read_manual_guild_result():
    """Read only the hash-bound, already captured owner receipt; zero network.

    Not installed on the current server and never invoked on import, Run, page
    load or a timer. No Keychain, provider helper, execution or retry is called.
    This is past manual evidence, never fresh execution or a different Core Run.
    """
    try:
        if RECEIPT_FILE.is_symlink():
            raise ValueError()
        with RECEIPT_FILE.open("rb") as source:
            raw = source.read(131073)
        if len(raw) > 131072 or hashlib.sha256(raw).hexdigest() != RECEIPT_SHA256:
            raise ValueError()
        return project_guild_manual(json.loads(raw))
    except (OSError, ValueError, UnicodeError):
        raise ValueError("manual_guild_receipt_unavailable") from None
