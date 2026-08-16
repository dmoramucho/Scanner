"""Alembic environment.

Two properties matter here, both from ADR-0001:

1. **The URL is never hardcoded.** It comes from `config.load_config()`, the same
   validated, fail-fast path the application uses, so a migration cannot be run against a
   database the app could not itself reach. Nothing credential-shaped lives in
   `alembic.ini`, and the DSN is unwrapped from its `Secret` exactly once, here.
2. **`target_metadata` is None.** There are no SQLAlchemy models in this project;
   revisions are hand-written raw SQL. `--autogenerate` would compare the live database
   against an empty metadata set and cheerfully emit DROP statements for the entire schema.
"""

from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

from config import load_config

alembic_config = context.config

if alembic_config.config_file_name is not None:
    fileConfig(alembic_config.config_file_name)

#: No ORM metadata by design (ADR-0001) — autogenerate is not a supported workflow here.
target_metadata = None


def _database_url() -> str:
    """The store URL, in the form SQLAlchemy needs to reach it through psycopg 3.

    `SCANNER_DATABASE_URL` is a plain libpq DSN (`postgresql://...`) because that is what
    psycopg and every ops tool expect. SQLAlchemy reads a bare `postgresql://` scheme as
    "use psycopg2", which is not installed — so the driver is named explicitly here rather
    than leaking a SQLAlchemy-shaped URL into the application's configuration.
    """
    url = load_config().database_url.reveal()
    for prefix in ("postgresql+psycopg://", "postgresql+psycopg2://"):
        if url.startswith(prefix):
            return url
    for prefix in ("postgresql://", "postgres://"):
        if url.startswith(prefix):
            return "postgresql+psycopg://" + url[len(prefix) :]
    raise ValueError(f"SCANNER_DATABASE_URL is not a PostgreSQL DSN: {url.split('://')[0]}://…")


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of executing it (`alembic upgrade head --sql`).

    Useful when a DBA applies the change by hand on an on-prem box.
    """
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Apply migrations against a live connection, in a transaction.

    Postgres has transactional DDL: a revision that fails part-way leaves no half-applied
    schema behind (AGENTS.md §5 — never reset the database to fix a migration).
    """
    engine = create_engine(_database_url(), poolclass=NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
