"""Closed-schema validation and versioned, restricted canonical JSON."""

import hashlib
import json
import re
from datetime import datetime
from urllib.parse import urlsplit

VERSION = "1.0"
AUDIENCE = "missionguard-executor-v1"
MAX_BYTES = 65536
FIELDS = {
    "events.list": {"event_id", "title", "starts_at", "source_url", "updated_at"},
    "events.get": {"event_id", "title", "starts_at", "source_url", "updated_at"},
    "analyses.get": {"event_id", "summary", "topics", "source_url", "updated_at"},
}
REASONS = {
    "ok", "invalid_request", "mission_not_found", "identity_mismatch", "hash_mismatch",
    "expired", "revoked", "operation_denied", "resource_denied", "field_denied",
    "limit_denied", "budget_exhausted", "idempotency_conflict", "adapter_unavailable",
    "store_unavailable", "upstream_unknown", "pending",
}


class PolicyError(ValueError):
    """A safe, enumerated reason; never include attacker-controlled text."""

    def __init__(self, reason="invalid_request"):
        self.reason = reason
        super().__init__(reason)


def require(condition, reason="invalid_request"):
    if not condition:
        raise PolicyError(reason)


def closed(value, keys):
    require(type(value) is dict and set(value) == set(keys))


def identifier(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", value) is not None)


def integer(value, low, high):
    require(type(value) is int and low <= value <= high)


def unique_strings(value, maximum=100):
    require(type(value) is list and 1 <= len(value) <= maximum)
    for item in value:
        identifier(item)
    require(len(set(value)) == len(value))


def _reject_number(_):
    raise PolicyError()


def _bounded_int(raw):
    require(len(raw.lstrip("-")) <= 16)
    value = int(raw)
    integer(value, -(2**53 - 1), 2**53 - 1)
    return value


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def _check_canonical(value, depth=0):
    require(depth <= 32)
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        integer(value, -(2**53 - 1), 2**53 - 1)
    elif type(value) is str:
        try:
            value.encode("utf-8", "strict")
        except UnicodeError:
            raise PolicyError() from None
    elif type(value) is list:
        for item in value:
            _check_canonical(item, depth + 1)
    elif type(value) is dict:
        for key, item in value.items():
            require(type(key) is str and key.isascii())
            _check_canonical(item, depth + 1)
    else:
        raise PolicyError()


def canonical(value):
    """mg-canonical-v1; deliberately not a general RFC8785 implementation."""
    _check_canonical(value)
    result = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    require(len(result.encode("utf-8")) <= MAX_BYTES)
    return result


def digest(value, domain):
    return hashlib.sha256(("missionguard:" + domain + ":mg-canonical-v1\n" + canonical(value)).encode("utf-8")).hexdigest()


def strict_loads(raw):
    try:
        require(type(raw) in (str, bytes))
        if type(raw) is bytes:
            require(len(raw) <= MAX_BYTES)
            raw = raw.decode("utf-8", "strict")
        require(len(raw.encode("utf-8", "strict")) <= MAX_BYTES)
        value = json.loads(raw, object_pairs_hook=_unique_object, parse_int=_bounded_int,
                           parse_float=_reject_number, parse_constant=_reject_number)
        _check_canonical(value)
        return value
    except (UnicodeError, RecursionError, json.JSONDecodeError):
        raise PolicyError() from None


def validate_contract(value):
    closed(value, {"schema_version", "mission_id", "purpose", "actor_id", "org_id", "audience",
                   "environment", "connection_ref", "registry_version", "expires_at", "budget", "grants"})
    require(value["schema_version"] == VERSION and value["registry_version"] == VERSION)
    require(value["audience"] == AUDIENCE)
    require(value["environment"] in ("synthetic_lab", "eventmatch_live"))
    for key in ("mission_id", "actor_id", "org_id", "connection_ref"):
        identifier(value[key])
    require(type(value["purpose"]) is str and 1 <= len(value["purpose"]) <= 1000)
    integer(value["expires_at"], 1, 2**53 - 1)
    closed(value["budget"], {"max_calls", "max_rows"})
    integer(value["budget"]["max_calls"], 1, 100)
    integer(value["budget"]["max_rows"], 1, 1000)
    require(type(value["grants"]) is list and 1 <= len(value["grants"]) <= len(FIELDS))
    seen = set()
    for grant in value["grants"]:
        closed(grant, {"operation", "resource_ids", "fields", "max_rows_per_call"})
        operation = grant["operation"]
        require(type(operation) is str and operation in FIELDS and operation not in seen)
        seen.add(operation)
        unique_strings(grant["resource_ids"])
        unique_strings(grant["fields"], 10)
        require(set(grant["fields"]) <= FIELDS[operation])
        integer(grant["max_rows_per_call"], 1, 100)
        if operation != "events.list":
            require(grant["max_rows_per_call"] == 1)
    canonical(value)


def validate_request(value):
    closed(value, {"schema_version", "mission_id", "contract_hash", "idempotency_key", "operation", "arguments"})
    require(value["schema_version"] == VERSION)
    for key in ("mission_id", "idempotency_key"):
        identifier(value[key])
    require(type(value["contract_hash"]) is str and re.fullmatch("[a-f0-9]{64}", value["contract_hash"]) is not None)
    require(type(value["operation"]) is str)
    require(value["operation"] in FIELDS, "operation_denied")
    closed(value["arguments"], {"event_ids", "fields", "limit"})
    args = value["arguments"]
    unique_strings(args["event_ids"])
    unique_strings(args["fields"], 10)
    integer(args["limit"], 1, 100)
    if value["operation"] != "events.list":
        require(len(args["event_ids"]) == 1 and args["limit"] == 1, "limit_denied")
    canonical(value)


def authorize_arguments(contract, request):
    grant = next((g for g in contract["grants"] if g["operation"] == request["operation"]), None)
    require(grant is not None, "operation_denied")
    args = request["arguments"]
    require(set(args["event_ids"]) <= set(grant["resource_ids"]), "resource_denied")
    require(set(args["fields"]) <= set(grant["fields"]), "field_denied")
    require(args["limit"] <= grant["max_rows_per_call"], "limit_denied")


def validate_projection(operation, arguments, rows):
    """Validate provider output BEFORE dropping the internal resource identifier."""
    require(type(rows) is list and len(rows) <= arguments["limit"])
    projected = []
    seen = set()
    for row in rows:
        require(type(row) is dict and set(row) <= set(arguments["fields"]) | {"event_id"})
        require("event_id" in row)
        identifier(row["event_id"])
        require(row["event_id"] in arguments["event_ids"] and row["event_id"] not in seen)
        seen.add(row["event_id"])
        for field, value in row.items():
            require(field in FIELDS[operation])
            if field == "event_id":
                continue
            if field in ("title", "summary"):
                maximum = 300 if field == "title" else 4000
                require(type(value) is str and 1 <= len(value) <= maximum)
            elif field == "topics":
                require(type(value) is list and len(value) <= 20)
                require(all(type(topic) is str and 1 <= len(topic) <= 120 for topic in value))
            elif field == "updated_at":
                integer(value, 0, 2**53 - 1)
            elif field == "starts_at":
                if value is not None:
                    require(type(value) is str and len(value) <= 40)
                    try:
                        require(datetime.fromisoformat(value).tzinfo is not None)
                    except ValueError:
                        raise PolicyError() from None
            elif field == "source_url":
                if value is not None:
                    require(type(value) is str and len(value) <= 2048 and not any(ord(c) <= 32 for c in value))
                    try:
                        url = urlsplit(value)
                        require(url.scheme in ("https", "http") and bool(url.hostname)
                                and url.username is None and url.password is None)
                    except ValueError:
                        raise PolicyError() from None
        projected.append({field: row[field] for field in arguments["fields"] if field in row})
    canonical(projected)
    return projected
