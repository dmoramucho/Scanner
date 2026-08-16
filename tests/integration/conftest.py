"""Integration-test fixtures: a real Postgres, the real migration, real SQL.

These tests exist to prove what the *database* guarantees — append-only triggers, partial
unique indexes, SP-GiST containment, CHECK constraints. A mock or SQLite would prove
nothing about any of them, because none of those constructs exist outside Postgres.

Provisioning, per ADR-0002:
  * A dedicated database (`<dev-db>_test`, or `SCANNER_TEST_DATABASE_URL` if set) on the
    compose server, dropped and recreated once per session so every run starts empty.
  * Schema applied by running `alembic upgrade head` against it — the migration under test
    is the only thing that ever creates the schema, so drift between the two is impossible.
  * Per-test isolation by transaction rollback: fast, and no test can leak rows into
    another.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from typing import Any, NoReturn

import psycopg
import pytest
from psycopg import sql

from tests.integration.helpers import alembic, dbname_of, maintenance_dsn, with_dbname

#: Set to "1" to turn "the database is unreachable" from a skip into a failure. Intended
#: for CI (LATER, AGENTS.md §5): there, a silently skipped integration test is an untested
#: invariant, which is worse than a red build.
REQUIRE_INTEGRATION = os.environ.get("SCANNER_REQUIRE_INTEGRATION") == "1"


def _skip_or_fail(reason: str) -> NoReturn:
    message = (
        f"{reason} Start the local stack with `docker compose up -d` and set "
        "SCANNER_DATABASE_URL (or SCANNER_TEST_DATABASE_URL); see .env.example."
    )
    if REQUIRE_INTEGRATION:
        pytest.fail(message)
    pytest.skip(message, allow_module_level=True)


def _test_database_url() -> str:
    """Explicit `SCANNER_TEST_DATABASE_URL`, else the dev DSN with `_test` appended.

    Deriving from the dev DSN keeps credentials out of the test suite entirely: there is
    no fallback URL with a password baked into the source, and no way to accidentally run
    the destructive fixtures against the dev database.
    """
    explicit = os.environ.get("SCANNER_TEST_DATABASE_URL", "").strip()
    if explicit:
        return explicit

    dev_dsn = os.environ.get("SCANNER_DATABASE_URL", "").strip()
    if not dev_dsn:
        _skip_or_fail("Neither SCANNER_TEST_DATABASE_URL nor SCANNER_DATABASE_URL is set.")

    dbname = dbname_of(dev_dsn) or "scanner"
    if dbname.endswith("_test"):
        return dev_dsn
    return with_dbname(dev_dsn, f"{dbname}_test")


def _drop_database(url: str) -> None:
    identifier = sql.Identifier(dbname_of(url))
    with psycopg.connect(maintenance_dsn(url), autocommit=True) as admin:
        admin.execute(sql.SQL("drop database if exists {} with (force)").format(identifier))


def _recreate_database(url: str) -> None:
    """Drop and create the test database. Identifiers go through `psycopg.sql`, never
    string interpolation — even here, where the name comes from our own configuration."""
    _drop_database(url)
    with psycopg.connect(maintenance_dsn(url), autocommit=True) as admin:
        admin.execute(sql.SQL("create database {}").format(sql.Identifier(dbname_of(url))))


@pytest.fixture(scope="session")
def migrated_database() -> Iterator[str]:
    """A freshly created database with `0001_expand` applied.

    Session-scoped: the schema is fixed for the run; only the data inside it changes.
    """
    url = _test_database_url()
    try:
        _recreate_database(url)
    except psycopg.OperationalError as exc:
        _skip_or_fail(f"Cannot reach Postgres: {exc}.")

    result = alembic("upgrade", "head", url=url)
    if result.returncode != 0:
        pytest.fail(f"alembic upgrade head failed:\n{result.stdout}\n{result.stderr}")

    yield url

    _drop_database(url)


@pytest.fixture
def conn(migrated_database: str) -> Iterator[psycopg.Connection[tuple[Any, ...]]]:
    """A connection whose work is always rolled back, so no test can see another's rows."""
    with psycopg.connect(migrated_database) as connection:
        try:
            yield connection
        finally:
            connection.rollback()
