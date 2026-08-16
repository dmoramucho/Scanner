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
| `adapters/` | The only layer that touches infrastructure (Postgres, vault, RAG, LLM) |
| `engine/` | Orchestration; enforces scope before a packet is emitted |
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

**P2 — store and database-enforced invariants.** The M0 schema is applied by migration
`0001_expand` (raw SQL, no ORM), and its guarantees are proven against a real Postgres:
`observation` / `audit_log` / `asset_merge_event` refuse `UPDATE` and `DELETE`, strong anchors
are unique per tenant while IPs are free to repeat, `cidr >>= $target` answers the engine's
scope pre-flight, and an LLM-proposed merge without a rationale is rejected.

`adapters/` and `engine/` are still empty. Next: P3 (`ScopeAuthority` adapter + engine
pre-flight), P4 (ingestion into `observation`), then entity resolution — see
`docs/architecture/ports.md` §10. Deferred by design: RLS, and the `software_component` /
`vulnerability_match` / `triage_snapshot` / `insight` tables (M2/M3).
