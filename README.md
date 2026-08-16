# Corporate Asset Scanner

Single-tenant, on-prem scanner for corporate networks: discovers, fingerprints, reconciles and
correlates assets (servers, IoT, IP cameras, VoIP, UPS), prioritises vulnerabilities by
real-world exploitability, and produces AI-assisted insight on top of deterministic facts.

The value is not in scanning — that is commoditised. It is in entity resolution, the
unmanaged-device (shadow-IT) diff, confidence-based noise reduction, and grounded AI insight.

**Start here:** [`AGENTS.md`](AGENTS.md) — the operating rules. Read it before writing code.

## Where things are

| Path | What it holds |
|---|---|
| [`docs/architecture/ports.md`](docs/architecture/ports.md) | The six port contracts, the error hierarchy, the `Secret` primitive |
| [`docs/data/asset-dossier-contract.md`](docs/data/asset-dossier-contract.md) | The redacted, typed object the LLM reasons over |
| [`docs/data/data-model.md`](docs/data/data-model.md) | The schema of record; applied by `0001_expand` |
| [`docs/adr/`](docs/adr/) | One ADR per material decision |
| `domain/` | The deterministic core: models, ports, errors. **stdlib + pydantic only** |
| `adapters/postgres/` | `ScopeAuthority`, `ObservationSink`, `AssetRepository` over Postgres — the only place psycopg lives |
| `adapters/collector/` | Passive discovery (ARP / DHCP / mDNS). Read-only and store-free by construction |
| `engine/` | Orchestration; the scope gate runs before anything is recorded |
| `config/` | Startup configuration — validated once, fail-fast |
| `migrations/` | Alembic revisions — hand-written raw SQL, no ORM ([how](migrations/README.md)) |
| `tests/` | Unit tests, the mechanically enforced `domain/` boundary, and `integration/` against a real Postgres |

## Architectural rule that shapes the layout

`domain/` may not import infrastructure — no DB driver, cloud SDK, queue, or LLM client
(AGENTS.md §2.1). Dependencies point inward: `adapters/` and `engine/` know the domain, never
the reverse. This is enforced by `tests/test_domain_boundary.py`, which parses every module
under `domain/` and rejects any import outside stdlib, `pydantic`, and `domain` itself. If a
domain module seems to need an infrastructure package, the abstraction is in the wrong layer —
move it, do not widen the allowlist.

## Getting started

Requires [uv](https://docs.astral.sh/uv/) and Docker.

```bash
cp .env.example .env        # then edit: nothing has a fallback in code
uv sync                     # create .venv, install pinned deps
docker compose up -d        # Postgres + MinIO + LocalStack

set -a; . ./.env; set +a    # alembic reads the DSN through config.load_config()
uv run alembic upgrade head # apply the store schema
```

Every port is published on `127.0.0.1` only. Postgres defaults to host port **5433** (5432 is
commonly taken by another local stack); change `POSTGRES_PORT` and `SCANNER_DATABASE_URL`
together if you want otherwise. LocalStack is pinned to the last license-free community
release — the 2026.x images refuse to start without an auth token.

Checks:

```bash
uv run ruff check .              # lint
uv run ruff format --check .
uv run mypy                      # strict; paths come from pyproject.toml
uv run pytest                    # everything
uv run pytest -m "not integration"  # unit only — no database needed
```

The integration tests run against the **real** compose Postgres: append-only triggers, the
SP-GiST containment index, and the partial unique index on strong anchors do not exist outside
it, so a mock or SQLite would prove nothing (ADR-0002). They provision their own
`<db>_test` database, apply the schema by running the actual migration, and roll back after
each test. With Docker stopped they skip with a message telling you what to start; set
`SCANNER_REQUIRE_INTEGRATION=1` to make that a failure instead (what CI should do).

Configuration is validated at startup by `config.load_config()`, which raises `ConfigError`
listing **every** missing variable. There are no silent defaults for credentials or endpoints;
the two optional variables (`SCANNER_REGION`, `SCANNER_LOG_LEVEL`) have documented, harmless
defaults. Secret-bearing values are wrapped in `domain.secret.Secret`, which redacts in `repr`
and `str` — `.reveal()` is the only path to the raw value, and greps as the list of places a
secret is actually used.

## Status

**M0 complete (P1–P4).** A capture goes end to end: parsers turn an ARP table, DHCP leases, or
mDNS output into provenance-complete observations; the engine calls `require_authorized` on
every target *before* anything is recorded; the sink writes them idempotently into the
append-only spine; entity resolution collapses them into assets by stable anchors.

What the system guarantees, each proven by tests against a real Postgres:

- **Scope is a gate, not a filter.** Deny-by-default — no authorization, a revoked one, an
  expired one, or another tenant's one all deny. Every decision lands in `audit_log` before it
  is returned, and an out-of-scope target leaves no observation and no asset.
- **Evidence is immutable.** `observation`, `audit_log` and `asset_merge_event` refuse `UPDATE`
  and `DELETE` at the database. Re-ingesting a capture in the same run adds nothing; a later run
  is new evidence about the same assets.
- **Identity is deterministic.** A hard match comes only from `serial`, `cert_fingerprint` or
  `mac`. Hostnames and IPs are attached but never identify — they rotate. A strong anchor never
  changes owner: a conflict raises rather than silently re-pointing evidence.
- **Merges are reversible.** The event and the status change commit together, a reversal is a
  new event rather than an edit, and an LLM-proposed merge without a rationale is rejected by
  both the adapter and a `CHECK` constraint. Nothing produces `llm_proposed` yet — the guard is
  in place before the generator that will need it.
- **The collector is read-only by construction.** It imports no socket, no subprocess, and no
  database driver, so extracting it behind an mTLS boundary later is a transport change
  (`tests/test_adapter_boundaries.py` fails if that decays).

Next: M1 — active scanning under the gentle-profile rules (AGENTS.md §2.7) and credentialed
collection, which is what supplies the serials and package-manager versions this design is
waiting for. Deferred by design: RLS, live packet capture, and the `vulnerability_match` /
`triage_snapshot` / `insight` tables (M2/M3).
