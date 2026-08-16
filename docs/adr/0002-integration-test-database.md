# ADR-0002 — How the integration tests get a database

- **Status:** accepted
- **Date:** 2026-08-15
- **Stage:** P2 (store & database-enforced invariants).
- **Context refs:** AGENTS.md §3 (the database protects integrity), §4.3 (no fake
  implementations), §5 (tests where they earn their keep now), §6 (local-first stack);
  [ADR-0001](0001-persistence-and-migrations.md); `docs/data/data-model.md` §1, §7.

## Context

Migration `0001_expand` moves several product rules out of application code and into the
database: append-only triggers on `observation` / `audit_log` / `asset_merge_event`, a partial
unique index that makes strong anchors unique per tenant while letting IPs repeat, an SP-GiST
containment index answering `cidr >>= $target`, and CHECK constraints such as
`merge_llm_has_rationale`.

None of those exist outside PostgreSQL. A test double or SQLite would assert that our *test
harness* behaves — the guarantee under test would be absent (AGENTS.md §4.3). So these tests
need a real Postgres, which raises the question this ADR answers: which one, provisioned how,
and isolated how.

## Decision

**One dedicated database on the compose Postgres, created per session, schema applied by the
real migration, per-test isolation by transaction rollback.**

1. **Which database.** `SCANNER_TEST_DATABASE_URL` if set; otherwise the dev DSN
   (`SCANNER_DATABASE_URL`) with `_test` appended to the database name. The test suite
   therefore contains **no credentials and no fallback URL** — if neither variable is present
   there is nothing to connect to, and the tests say so.
2. **How it is provisioned.** Dropped and recreated once per session (`drop database … with
   (force)`), then `alembic upgrade head` is run against it **as a subprocess**. The migration
   under test is the only thing that ever creates the schema, so schema drift between "what the
   tests assume" and "what a deploy applies" cannot happen. The subprocess also exercises
   `alembic.ini` and `migrations/env.py`, which an in-process `command.upgrade()` would bypass.
3. **How tests are isolated.** Each test gets a connection whose transaction is rolled back at
   teardown; cases that expect an error use a nested `conn.transaction()` savepoint so the
   connection stays usable afterwards.
4. **Destructive fixtures never touch the dev database.** They only ever operate on the derived
   `_test` (and `_test_cycle`) names.
5. **Unreachable Postgres is a skip, not a failure** — with an escape hatch:
   `SCANNER_REQUIRE_INTEGRATION=1` turns it into a failure.

## Alternatives considered

| Option | Why not |
|---|---|
| **testcontainers-python** | Genuinely good isolation, but adds a dependency (plus Docker-API surface) to do what `docker compose up -d` already does. §6 makes compose the local-first stack; spinning a *second*, different Postgres in tests means the tests no longer run against the thing we ship. Revisit if CI ever lacks a compose stack. |
| **SQLite / an in-memory database** | Has no `cidr` type, no SP-GiST, no partial indexes over an `IN` predicate, no plpgsql triggers. It would silently not test any of the four invariants this migration exists for. |
| **Mocks / a fake repository** | Tests the mock. The whole point of P2 is that the *database* refuses, even to `psql` (AGENTS.md §3). |
| **Reuse the dev database, roll back** | One `drop database` typo away from destroying local development data, and a failed test that leaves an open transaction blocks the developer's own session. |
| **Truncate between tests instead of rollback** | Slower, and it has to enumerate tables — a list that silently rots the moment a migration adds one. Rollback needs no maintenance. |
| **Schema-per-test instead of database-per-session** | Cheaper in theory, but `create extension` and the `forbid_mutation()` function are database-scoped; splitting them across schemas complicates the migration for a test-only benefit. |
| **Apply the DDL directly in a fixture** | Fast, and exactly the trap: the tests would pass against DDL that the migration never applies. |

## Trade-off accepted

Running the suite now requires the compose stack. That is a real cost — `uv run pytest` on a
laptop with Docker stopped skips 27 tests — and a skipped invariant test reads like a passing
one. Three mitigations: the skip message says exactly what to start, `-m "not integration"`
makes the split explicit and intentional, and `SCANNER_REQUIRE_INTEGRATION=1` exists for
whoever wires up CI.

**When CI arrives (LATER, AGENTS.md §5), it must set `SCANNER_REQUIRE_INTEGRATION=1`.** In CI a
silent skip is an untested invariant, which is worse than a red build.

A second, smaller cost: `tests/conftest.py` loads `.env` into the environment so the suite works
right after `cp .env.example .env`. It is a ~15-line parser that never overrides an
already-set variable and is not used by the application, which reads real environment variables
only.

## Consequences

- `pytest` gains a session-scoped `migrated_database` fixture and a function-scoped `conn`.
- Test databases are dropped at session end; a crashed run leaves `<db>_test` behind, which the
  next run drops and recreates anyway.
- When RLS moves to NOW, the cross-tenant negative tests slot into this same harness — they
  need `SET app.tenant_id`, which is another thing only a real Postgres can do.
