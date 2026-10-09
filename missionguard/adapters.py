"""Trusted adapters. The synthetic implementation has no network capability."""

import json
from pathlib import Path
import threading


class SyntheticAdapter:
    environment = "synthetic_lab"
    connection_ref = "synthetic-fixed"
    bounded = True

    def __init__(self):
        fixtures = Path(__file__).resolve().parent.parent / "fixtures"
        self.events = json.loads((fixtures / "events.json").read_text())
        self.analyses = json.loads((fixtures / "analyses.json").read_text())
        self.dispatch_count = 0
        self._lock = threading.Lock()

    def invoke(self, operation, arguments, *, max_rows, max_bytes):
        with self._lock:
            self.dispatch_count += 1
        source = self.analyses if operation == "analyses.get" else self.events
        selected = []
        for row in source:
            if row["event_id"] not in arguments["event_ids"]:
                continue
            selected.append({key: row[key] for key in set(arguments["fields"]) | {"event_id"} if key in row})
            if len(selected) == max_rows:
                break
        if len(json.dumps(selected).encode("utf-8")) > max_bytes:
            raise ValueError("bounded synthetic response exceeded")
        return selected


class EventMatchAdapter:
    """Fail-closed placeholder, NOT an implemented or verified live integration."""

    environment = "eventmatch_live"
    connection_ref = "eventmatch-unverified"
    bounded = False

    def invoke(self, operation, arguments, *, max_rows, max_bytes):
        raise RuntimeError("Live EventMatch contract/auth/identity/bounds have not been verified")
