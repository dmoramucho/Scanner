# Migrations

Alembic, used purely as a versioned migration runner. Every revision is **hand-written raw
SQL** inside `op.execute("""…""")`, mirroring `docs/data/data-model.md` — the schema of record.

## Why there is no `--autogenerate`

There are no SQLAlchemy models in this project (ADR-0001), so `target_metadata` is `None`.
Autogenerate would diff the live database against an empty metadata set and emit `DROP`
statements for the entire schema. It is not a supported workflow here; write the SQL.

## Layout

| File | What it is |
|---|---|
| `../alembic.ini` | Config. Deliberately has **no** `sqlalchemy.url` |
| `env.py` | Reads the DSN from `config.load_config()` — the same validated, fail-fast path the app uses. Nothing credential-shaped is ever committed |
| `versions/0001_expand.py` | The M0 store schema (expand phase) |
| `script.py.mako` | Template for new revisions |

## Running

`env.py` reads `SCANNER_DATABASE_URL` through the `config` module, so the environment has to be
loaded first:

```bash
set -a; . ./.env; set +a
uv run alembic upgrade head      # apply
uv run alembic downgrade -1      # roll back one revision
uv run alembic current           # what is applied
uv run alembic upgrade head --sql  # emit SQL for a DBA to apply by hand
```

An on-prem deploy installs the migration path separately from the application runtime —
`uv sync --no-default-groups --group migrations` — so SQLAlchemy never enters the app process.

## Rules

- `expand → migrate → validate → contract`. `0001` is expand: it only adds.
- Every revision has a real `downgrade()`, in reverse dependency order. **The database is never
  reset to fix a migration** (AGENTS.md §5).
- Postgres has transactional DDL: a revision that fails part-way leaves nothing half-applied.
- The guarantees a revision claims (triggers, partial indexes, constraints) are proven by the
  integration tests in `tests/integration/`, not by inspection. See ADR-0002.
- `tenant_id` goes on every tenant-scoped table from the first migration. RLS is LATER
  (AGENTS.md §5) — `tests/integration/test_schema_invariants.py` asserts it is *not* enabled, so
  turning it on is a deliberate migration with cross-tenant tests, never an accident.
