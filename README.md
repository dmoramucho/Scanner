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
| [`docs/runbooks/`](docs/runbooks/) | Operator procedures — including the real-device scan validation |
| `domain/` | The deterministic core: models, ports, errors. **stdlib + pydantic only** |
| `adapters/postgres/` | `ScopeAuthority`, `ObservationSink`, `AssetRepository` over Postgres — the only place psycopg lives |
| `adapters/collector/` | Passive discovery (ARP / DHCP / mDNS). Read-only and store-free by construction |
| `adapters/scanner/` | Active scanning: the nmap orchestrator. The only place that knows what a scanner flag is |
| `adapters/inspector/` | Credentialed reads over SSH — read-only, allow-listed commands, credential-safe |
| `adapters/probe/` | The circuit breaker's health check: one TCP connect, no data, no root |
| `engine/` | Orchestration; the scope gate runs before anything is recorded, and the scan-safety policy lives here |
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

**M0 and M1 complete (P1–P8).** A capture goes end to end: parsers turn an ARP
table, DHCP leases, or mDNS output into provenance-complete observations; the engine calls
`require_authorized` on every target *before* anything is recorded; the sink writes them
idempotently into the append-only spine; entity resolution collapses them into assets by stable
anchors. Three kinds of discovery now feed one reconciled inventory: passive (ARP/DHCP/mDNS), active
(nmap under a gentle, breaker-protected profile), and credentialed (read-only SSH). All three
pass the same scope gate, write through the same append-only spine, and resolve through the same
entity resolution — so a camera seen three ways is one asset with three kinds of provenance.

What the system guarantees, each proven by tests:

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
  both the adapter and a `CHECK` constraint.
- **Fragile devices get the gentle profile.** The `GENTLE` scan profile means no `-A`, no
  `--version-all`, `--version-intensity 0`, SYN not connect, a `-T2` ceiling, a scan delay,
  capped rate and parallelism, and a curated IoT port set rather than all 65535 — asserted flag
  by flag, so loosening it fails the build (AGENTS.md §2.7). A device that nothing positively
  identifies as robust is treated as fragile, the same fail-safe direction as deny-by-default.
- **A device that stops answering stops being scanned.** Health checks bracket every scan; a
  device that was up before and silent after trips the circuit breaker, which backs off, records
  the trip as an observation rather than a counter, and moves on. One casualty never aborts the
  run — three in a row does (ADR-0004). The check itself is the lightest touch in the system: a
  single TCP connect to a port discovery already found open, no data sent, no root, and it raises
  rather than assuming health when it has no port to check (ADR-0007).
- **Nothing goes near a shell.** The nmap invocation is an argument list, and the target is
  validated as a real IP address before any command exists. nmap's XML is parsed as untrusted
  input, with external entities and entity expansion refused (ADR-0003).
- **A failure is never an empty success.** A missing binary, non-zero exit, timeout, or
  unparseable output raises a specific domain error; "host is down" is a distinct, explicit
  result.
- **Ground truth outranks inference.** A credentialed read projects `version_source=
  'package_manager'` components over the banner-inferred ones for that asset; the superseded rows
  are retired, never deleted, so what we believed on an earlier date is still answerable
  (ADR-0006).
- **Credentials reach the wire and nothing else.** The SSH inspector resolves its credential
  through `SecretsPort`, holds a redacting `Secret`, and calls `reveal()` on exactly one line —
  a test greps the package and fails if it appears anywhere else. No log record, exception,
  traceback, or observation payload carries it, on success or on any failure path.
- **An inspector cannot write to a device.** Five constant commands, allow-listed by verb *and*
  arguments (`dpkg -l` is permitted, `dpkg --install` is not), with a canary test that fails if
  the list grows at all. Unknown SSH host keys are rejected; ambient keys and agents are
  disabled, so only the vault's credential can ever authenticate.
- **Adapters stay in their lane.** The collector imports no socket, subprocess, or database
  driver; the scanner imports no database driver and never `shell=True`; the inspector touches
  no store (`tests/test_adapter_boundaries.py`).

**One thing fixtures cannot prove, and it is owed:**
[`docs/runbooks/validate-gentle-scan.md`](docs/runbooks/validate-gentle-scan.md) is the procedure
for pointing a `GENTLE` scan at one real device, under real authorisation, and confirming it
survives. Until someone runs it, "we do not break embedded devices" is a well-tested design
intention rather than an observed fact. The runbook also names the gaps it runs into — chiefly that there is
still no CLI, so the procedure runs from a short script.

Next (M2/M3): CPE→CVE correlation with NVD/KEV/EPSS, the triage dossier, and the grounded insight
generator. Deferred by design: vendor inspectors (VAPIX, ISAPI, BusyBox), RLS, live packet
capture, default-credential probing, and any form of exploitation (never).
