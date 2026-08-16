"""The migration is only trustworthy if it goes both ways.

`downgrade` is not decoration: when a release goes wrong on an on-prem box at 03:00, the
rollback path is the alternative to restoring from backup. The database is never reset to
repair a migration (AGENTS.md §5), so this is exercised on every run — against its own
scratch database, so a mid-test schema teardown cannot disturb the other tests.
"""

from __future__ import annotations

from collections.abc import Iterator

import psycopg
import pytest
from psycopg import sql

from tests.integration.helpers import alembic, dbname_of, maintenance_dsn, with_dbname

pytestmark = pytest.mark.integration

#: What `0001_expand` creates.
EXPAND_TABLES = {
    "asset",
    "asset_identifier",
    "asset_merge_event",
    "audit_log",
    "managed_record",
    "observation",
    "scope_authorization",
}

#: What `0002_software_component` adds — the current-state projection ER writes into.
SOFTWARE_TABLES = {"software_component"}

#: What `0003_cve_cache` adds — the local cache of an external vulnerability feed. Neither
#: table is tenant-scoped: a CVE is a fact about software in the world (m3-design §2).
CVE_CACHE_TABLES = {"cve_cache", "cve_query_cache"}

#: What `0004_kev_epss_cache` adds — the two prioritisation signals, and the load marker that
#: makes "this CVE is not in KEV" distinguishable from "the catalog was never loaded".
SIGNAL_CACHE_TABLES = {"kev_cache", "epss_cache", "feed_snapshot"}

EXPECTED_TABLES = EXPAND_TABLES | SOFTWARE_TABLES | CVE_CACHE_TABLES | SIGNAL_CACHE_TABLES

#: Still not created by anything — they arrive with the features that need them
#: (AGENTS.md §5). `vulnerability_match` is P14's; `triage_snapshot` and `insight` are
#: Half B's.
DEFERRED_TABLES = {"vulnerability_match", "triage_snapshot", "insight"}

HEAD_REVISION = "0004_kev_epss_cache"


def _table_names(url: str) -> set[str]:
    with psycopg.connect(url) as conn:
        rows = conn.execute(
            "select tablename from pg_tables where schemaname = 'public'"
        ).fetchall()
    return {str(row[0]) for row in rows}


def _function_exists(url: str, name: str) -> bool:
    with psycopg.connect(url) as conn:
        row = conn.execute("select count(*) from pg_proc where proname = %s", (name,)).fetchone()
    assert row is not None
    return bool(row[0])


@pytest.fixture
def scratch_database(migrated_database: str) -> Iterator[str]:
    """An empty database of its own, so upgrade/downgrade can run without collateral."""
    scratch_url = with_dbname(migrated_database, f"{dbname_of(migrated_database)}_cycle")
    identifier = sql.Identifier(dbname_of(scratch_url))
    admin_dsn = maintenance_dsn(migrated_database)

    with psycopg.connect(admin_dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("drop database if exists {} with (force)").format(identifier))
        admin.execute(sql.SQL("create database {}").format(identifier))
    try:
        yield scratch_url
    finally:
        with psycopg.connect(admin_dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("drop database if exists {} with (force)").format(identifier))


def _current_revision(url: str) -> str:
    with psycopg.connect(url) as conn:
        row = conn.execute("select version_num from alembic_version").fetchone()
    assert row is not None
    return str(row[0])


def test_upgrade_then_downgrade_is_a_round_trip(scratch_database: str) -> None:
    """Every revision, forward and back. The rollback path is the alternative to restoring
    from backup at 03:00, so it is exercised on every run."""
    upgrade = alembic("upgrade", "head", url=scratch_database)
    assert upgrade.returncode == 0, f"{upgrade.stdout}\n{upgrade.stderr}"

    after_upgrade = _table_names(scratch_database)
    assert after_upgrade >= EXPECTED_TABLES
    assert _function_exists(scratch_database, "forbid_mutation")

    downgrade = alembic("downgrade", "base", url=scratch_database)
    assert downgrade.returncode == 0, f"{downgrade.stdout}\n{downgrade.stderr}"

    after_downgrade = _table_names(scratch_database)
    assert after_downgrade & EXPECTED_TABLES == set(), "downgrade left tables behind"
    assert not _function_exists(scratch_database, "forbid_mutation")
    # Alembic's own bookkeeping table survives a downgrade by design — the schema is at
    # base, not absent.
    assert after_downgrade == {"alembic_version"}


def test_downgrading_one_step_removes_only_the_latest_revision(scratch_database: str) -> None:
    """`downgrade -1` is the rollback an operator reaches for after a bad release: it must
    undo the last revision and leave everything earlier untouched."""
    assert alembic("upgrade", "head", url=scratch_database).returncode == 0

    assert alembic("downgrade", "-1", url=scratch_database).returncode == 0

    remaining = _table_names(scratch_database)
    assert remaining & SIGNAL_CACHE_TABLES == set()
    # earlier revisions untouched
    assert remaining >= EXPAND_TABLES | SOFTWARE_TABLES | CVE_CACHE_TABLES
    assert _current_revision(scratch_database) == "0003_cve_cache"


def test_upgrade_is_recorded_at_the_expected_revision(scratch_database: str) -> None:
    assert alembic("upgrade", "head", url=scratch_database).returncode == 0

    assert _current_revision(scratch_database) == HEAD_REVISION


def test_the_deferred_m2_m3_tables_are_still_not_created(scratch_database: str) -> None:
    """Scope discipline, asserted: `insight` and friends arrive with the features that
    need them, not early (AGENTS.md §5)."""
    assert alembic("upgrade", "head", url=scratch_database).returncode == 0

    assert _table_names(scratch_database) & DEFERRED_TABLES == set()
