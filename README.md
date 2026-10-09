# MissionGuard — Task-Aware Security for AI Agents

MissionGuard checks whether a tool call belongs to the user's approved mission,
not merely whether a broad API token permits it. A deterministic enforcement
engine applies a structured policy before dispatch; the language model cannot
grant itself more authority.

## Hackathon demonstration

The hosted demo uses fictional event records only — **not live EventMatch data**.
The actual recorded path is browser → hosted Core HTTP → an Akash Network public
synthetic API. An allowed read returned three fictional rows. Identical-key
replay and an out-of-scope request each caused zero additional upstream
adapter dispatches. The single-host SQLite ledger durably reserves budgets
before dispatch; unknown outcomes retain reservations and are not replayed.

The public demo is deliberately one-shot. A consumed claim is retained across
restart. Read the recorded result; do not reset the state to repeat a mission.
The checkbox is fictional-demo consent, not production human authentication.

## Sponsor roles and honest boundaries

- Akash Network: actual public synthetic API workload; no private credentials,
  EventMatch data, or MissionGuard ledger are placed on the provider.
- Guild.ai / OpenAI: separately recorded real manual private-draft model run,
  678 tokens. It is not a fresh model invocation by the dashboard Run button.
- ClickHouse: separately verified three-row INSERT/SELECT cloud probe, not
  continuous ingestion or the authorization engine. Original guard diagnosis
  remains unresolved; the proof is not correlated with this public mission.
- Semgrep: historical offline scoped scan, not Guardian, a cloud scan, or a
  blanket clean-security certification. The new controller was not covered.
- Live EventMatch: disabled and not verified in this submission.

## Local synthetic reproduction

Python 3.13 standard library; no install, external credentials, or cloud calls
are needed for the default demos. Run from this checkout:

```sh
python3 -B -m missionguard.demo
python3 -B -m missionguard.http_demo
```

Both demos create isolated temporary fictional state and clean it up. They do
not resume or reset the hosted ledger. `dashboard/serve.py` is the local-only
preview/controller, not a production deployment recipe.

`deploy/public_demo.py` is the fixed public-host entry behind the owner's HTTPS
reverse proxy. Its `init` command is explicit and only for a genuinely new,
owner-approved mission state; `serve` never initializes or refunds state.
The Akash endpoint host is fixed in source and its port is trusted operator
startup configuration, not agent/browser input. Public provider HTTP is
unauthenticated and fictional; a canonical fixture digest checks integrity,
not TLS identity. Never use this transport for confidential data.

## Security model

Policies bind resources, output fields, expiry, identity mapping and cumulative
call/row reservations. Decisions and idempotency are persisted before dispatch.
Backend authorization is independent and still required. The demo is a
single-host prototype, not distributed fencing, a complete prompt-injection
classifier, production identity, or protection against an agent possessing a
separate bypass credential.

This repository is an explicit minimal submission-source snapshot. Private
operator journals, credentials, persistent runtime state, unrelated projects
and EventMatch source/configuration are intentionally excluded.

## Review links and acceptance tests

Working project: https://missionguard.boriskov.com/

EventMatch integration uses fictional synthetic data only; no live EventMatch API or real-user data. Backend authorization remains independent.

Run the offline Core acceptance suite:

```sh
python3 -B -m unittest discover -s tests -v
```
