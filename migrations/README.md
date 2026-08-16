# Migrations

Empty at P1 by design — no tables exist yet. The schema of record is `docs/data/data-model.md`
and it is built in **P2**, as versioned migrations following `expand → migrate → validate →
contract` (AGENTS.md §5). The database is never reset to fix a migration.

The tooling choice (psycopg 3 for access, Alembic for versioning, raw SQL in revisions) is
recorded in [ADR-0001](../docs/adr/0001-persistence-and-migrations.md). The dependencies land
with the first migration, not before.
