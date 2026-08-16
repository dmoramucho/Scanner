"""What migration 0001_expand makes the *database* guarantee.

Every assertion here is about a construct the application cannot bypass: a trigger, a
partial unique index, an SP-GiST containment index, a CHECK constraint. Application-level
equivalents would be conventions; these are guarantees (data-model.md §1).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg import errors, sql

pytestmark = pytest.mark.integration

Connection = psycopg.Connection[tuple[Any, ...]]

NOW = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)
TENANT = UUID("11111111-1111-1111-1111-111111111111")
OTHER_TENANT = UUID("22222222-2222-2222-2222-222222222222")

APPEND_ONLY_TABLES = ["observation", "audit_log", "asset_merge_event"]


# --------------------------------------------------------------------------- helpers


def insert_asset(conn: Connection, tenant: UUID = TENANT) -> UUID:
    row = conn.execute(
        """
        insert into asset (tenant_id, first_seen_at, last_seen_at)
        values (%s, %s, %s) returning id
        """,
        (tenant, NOW, NOW),
    ).fetchone()
    assert row is not None
    return UUID(str(row[0]))


def insert_observation(conn: Connection, *, asset_id: UUID | None = None, run_id: UUID) -> UUID:
    row = conn.execute(
        """
        insert into observation (
            tenant_id, asset_id, observation_type, payload, source, source_type,
            source_identifier, collector, collector_version, collection_method,
            confidence, content_hash, observed_at, collected_at, run_id
        ) values (
            %s, %s, 'open_ports', %s::jsonb, 'nmap', 'active_scan',
            '10.10.5.7', 'scanner-collector', '0.1.0', 'syn_scan',
            0.7, sha256(%s), %s, %s, %s
        ) returning id
        """,
        (TENANT, asset_id, '{"ports": [443]}', b'{"ports": [443]}', NOW, NOW, run_id),
    ).fetchone()
    assert row is not None
    return UUID(str(row[0]))


def insert_audit_entry(conn: Connection) -> UUID:
    row = conn.execute(
        """
        insert into audit_log (tenant_id, actor, actor_type, action, resource_type, result)
        values (%s, 'engine', 'service', 'scope.authorize', 'target', 'denied')
        returning id
        """,
        (TENANT,),
    ).fetchone()
    assert row is not None
    return UUID(str(row[0]))


def insert_merge_event(conn: Connection) -> UUID:
    survivor, merged = insert_asset(conn), insert_asset(conn)
    row = conn.execute(
        """
        insert into asset_merge_event (tenant_id, kind, survivor_id, merged_id, derivation)
        values (%s, 'merge', %s, %s, 'deterministic') returning id
        """,
        (TENANT, survivor, merged),
    ).fetchone()
    assert row is not None
    return UUID(str(row[0]))


def insert_identifier(conn: Connection, kind: str, value: str, *, tenant: UUID = TENANT) -> UUID:
    asset_id = insert_asset(conn, tenant)
    row = conn.execute(
        """
        insert into asset_identifier
            (tenant_id, asset_id, kind, value, confidence, first_seen_at, last_seen_at)
        values (%s, %s, %s, %s, 1.0, %s, %s) returning id
        """,
        (tenant, asset_id, kind, value, NOW, NOW),
    ).fetchone()
    assert row is not None
    return UUID(str(row[0]))


def seed_append_only_row(conn: Connection, table: str) -> UUID:
    if table == "observation":
        return insert_observation(conn, run_id=uuid4())
    if table == "audit_log":
        return insert_audit_entry(conn)
    if table == "asset_merge_event":
        return insert_merge_event(conn)
    raise AssertionError(f"unknown append-only table: {table}")


def count_rows(conn: Connection, table: str, row_id: UUID) -> int:
    row = conn.execute(
        sql.SQL("select count(*) from {} where id = %s").format(sql.Identifier(table)), (row_id,)
    ).fetchone()
    assert row is not None
    return int(row[0])


# --------------------------------------------------------- append-only enforcement


@pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
def test_update_is_rejected_on_append_only_table(conn: Connection, table: str) -> None:
    """Evidence and audit rows are immutable — the trigger refuses, not the app."""
    row_id = seed_append_only_row(conn, table)

    with pytest.raises(errors.RaiseException) as exc_info, conn.transaction():
        conn.execute(
            sql.SQL("update {} set tenant_id = %s where id = %s").format(sql.Identifier(table)),
            (OTHER_TENANT, row_id),
        )

    assert "append-only" in str(exc_info.value)
    assert table in str(exc_info.value)
    assert count_rows(conn, table, row_id) == 1


@pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
def test_delete_is_rejected_on_append_only_table(conn: Connection, table: str) -> None:
    """A merged asset is never hard-deleted, an audit trail is never pruned in place."""
    row_id = seed_append_only_row(conn, table)

    with pytest.raises(errors.RaiseException) as exc_info, conn.transaction():
        conn.execute(
            sql.SQL("delete from {} where id = %s").format(sql.Identifier(table)), (row_id,)
        )

    assert "append-only" in str(exc_info.value)
    assert count_rows(conn, table, row_id) == 1


@pytest.mark.parametrize("table", APPEND_ONLY_TABLES)
def test_append_only_trigger_is_attached(conn: Connection, table: str) -> None:
    """Guard against a future migration recreating a table and losing its trigger."""
    row = conn.execute(
        """
        select count(*) from pg_trigger t
        join pg_class c on c.oid = t.tgrelid
        where c.relname = %s and not t.tgisinternal
        """,
        (table,),
    ).fetchone()
    assert row is not None
    assert row[0] == 1


# ------------------------------------------------------------- scope containment


def insert_authorization(conn: Connection, cidr: str, *, active: bool = True) -> UUID:
    row = conn.execute(
        """
        insert into scope_authorization (tenant_id, cidr, written_auth_ref, active, authorized_at)
        values (%s, %s::cidr, 'signed-auth-2026-001', %s, %s) returning id
        """,
        (TENANT, cidr, active, NOW),
    ).fetchone()
    assert row is not None
    return UUID(str(row[0]))


def authorizations_containing(conn: Connection, target: str) -> list[UUID]:
    """The engine's pre-flight query: `cidr >>= $target` (ports.md §3)."""
    rows = conn.execute(
        """
        select id from scope_authorization
        where tenant_id = %s and active and cidr >>= %s::inet
        """,
        (TENANT, target),
    ).fetchall()
    return [UUID(str(row[0])) for row in rows]


def test_containment_matches_an_in_range_target(conn: Connection) -> None:
    authorization_id = insert_authorization(conn, "10.10.0.0/16")
    insert_authorization(conn, "192.168.50.0/24")

    assert authorizations_containing(conn, "10.10.5.7") == [authorization_id]


def test_containment_returns_nothing_for_an_out_of_range_target(conn: Connection) -> None:
    """Deny-by-default has teeth only if the query genuinely finds nothing (AGENTS.md §2.5)."""
    insert_authorization(conn, "10.10.0.0/16")

    assert authorizations_containing(conn, "10.11.0.1") == []
    assert authorizations_containing(conn, "8.8.8.8") == []


def test_containment_ignores_an_inactive_authorization(conn: Connection) -> None:
    """A revoked authorization must stop matching the moment it is deactivated."""
    insert_authorization(conn, "10.10.0.0/16", active=False)

    assert authorizations_containing(conn, "10.10.5.7") == []


def test_containment_matches_a_single_host_authorization(conn: Connection) -> None:
    authorization_id = insert_authorization(conn, "10.20.30.40/32")

    assert authorizations_containing(conn, "10.20.30.40") == [authorization_id]
    assert authorizations_containing(conn, "10.20.30.41") == []


# --------------------------------------------------------------- identity anchors


@pytest.mark.parametrize("kind", ["serial", "cert_fingerprint", "mac"])
def test_strong_anchor_rejects_a_duplicate(conn: Connection, kind: str) -> None:
    """Strong anchors drive entity resolution: two assets cannot claim the same one."""
    insert_identifier(conn, kind, "ACCC8E1F2A3B")

    with pytest.raises(errors.UniqueViolation), conn.transaction():
        insert_identifier(conn, kind, "ACCC8E1F2A3B")


@pytest.mark.parametrize("kind", ["ip", "hostname"])
def test_weak_anchor_allows_a_duplicate(conn: Connection, kind: str) -> None:
    """IP and hostname rotate — they are locators, not identity, so duplicates are data,
    not errors (data-model.md §5)."""
    first = insert_identifier(conn, kind, "10.10.5.7")
    second = insert_identifier(conn, kind, "10.10.5.7")

    assert first != second


def test_strong_anchor_uniqueness_is_scoped_to_the_tenant(conn: Connection) -> None:
    """The `tenant_id` discipline is NOW even though RLS is LATER (AGENTS.md §5): two
    tenants may legitimately hold the same serial."""
    first = insert_identifier(conn, "serial", "SHARED-SERIAL-1", tenant=TENANT)
    second = insert_identifier(conn, "serial", "SHARED-SERIAL-1", tenant=OTHER_TENANT)

    assert first != second


# --------------------------------------------------- other database-held invariants


def test_observation_dedup_index_rejects_a_retry_within_a_run(conn: Connection) -> None:
    """Idempotent ingestion is an index, not application logic: the same content in the
    same run lands once (ports.md §5)."""
    run_id = uuid4()
    insert_observation(conn, run_id=run_id)

    with pytest.raises(errors.UniqueViolation), conn.transaction():
        insert_observation(conn, run_id=run_id)


def test_the_same_observation_in_a_later_run_is_a_new_row(conn: Connection) -> None:
    """Re-observation is additional evidence, never a discarded duplicate (AGENTS.md §3)."""
    first = insert_observation(conn, run_id=uuid4())
    second = insert_observation(conn, run_id=uuid4())

    assert first != second


def test_llm_proposed_merge_without_a_rationale_is_rejected(conn: Connection) -> None:
    """AGENTS.md §2.8 — an LLM-proposed merge must carry its reasoning."""
    survivor, merged = insert_asset(conn), insert_asset(conn)

    with pytest.raises(errors.CheckViolation), conn.transaction():
        conn.execute(
            """
            insert into asset_merge_event (tenant_id, kind, survivor_id, merged_id, derivation)
            values (%s, 'merge', %s, %s, 'llm_proposed')
            """,
            (TENANT, survivor, merged),
        )


def test_merged_asset_must_point_at_a_survivor(conn: Connection) -> None:
    """`asset_merge_consistent`: a merged asset without a survivor would be unreachable."""
    asset_id = insert_asset(conn)

    with pytest.raises(errors.CheckViolation), conn.transaction():
        conn.execute("update asset set status = 'merged' where id = %s", (asset_id,))


def test_row_level_security_is_not_enabled_yet(conn: Connection) -> None:
    """RLS is deliberately LATER (AGENTS.md §5). Asserted so that enabling it is a
    conscious migration with cross-tenant tests, never an accident."""
    rows = conn.execute(
        """
        select relname from pg_class
        where relrowsecurity and relnamespace = 'public'::regnamespace
        """
    ).fetchall()

    assert rows == []
