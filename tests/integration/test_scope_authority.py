"""The scope gate — the negative tests carry the weight here (AGENTS.md §2.5, §42, §75).

An authorization test that only checks the happy path proves nothing: the property we need
is that *absence* of evidence denies, that a revoked or expired authorization stops
working, that another tenant's authorization is not ours, and that every one of those
decisions leaves an audit trail. Each test uses its own `tenant_id`, so nothing here can
pass by accidentally inheriting another test's rows.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest

from adapters.postgres.scope_authority import SCOPE_ACTION, PostgresScopeAuthority
from domain.errors import ScopeViolation
from domain.ports import ScopeAuthority

pytestmark = pytest.mark.integration

Connection = psycopg.Connection[tuple[Any, ...]]

IN_SCOPE = ip_address("10.10.5.7")
OUT_OF_SCOPE = ip_address("192.168.99.14")


@pytest.fixture
def tenant() -> UUID:
    """A tenant of this test's own, so isolation never depends on cleanup."""
    return uuid4()


@pytest.fixture
def authority(autocommit_conn: Connection) -> PostgresScopeAuthority:
    return PostgresScopeAuthority(
        autocommit_conn, actor="engine", request_id="req-1", correlation_id="corr-1"
    )


def authorize_range(
    conn: Connection,
    tenant: UUID,
    cidr: str,
    *,
    active: bool = True,
    expires_at: datetime | None = None,
) -> UUID:
    row = conn.execute(
        """
        insert into scope_authorization
            (tenant_id, cidr, written_auth_ref, active, authorized_at, expires_at)
        values (%s, %s::cidr, 'signed-auth-2026-001', %s, %s, %s) returning id
        """,
        (tenant, cidr, active, datetime(2026, 1, 1, tzinfo=UTC), expires_at),
    ).fetchone()
    assert row is not None
    return UUID(str(row[0]))


def audit_entries(conn: Connection, tenant: UUID) -> list[tuple[Any, ...]]:
    return conn.execute(
        """
        select result, resource_id, actor, actor_type, request_id, correlation_id, metadata
        from audit_log
        where tenant_id = %s and action = %s
        order by occurred_at
        """,
        (tenant, SCOPE_ACTION),
    ).fetchall()


def observation_count(conn: Connection, tenant: UUID) -> int:
    row = conn.execute(
        "select count(*) from observation where tenant_id = %s", (tenant,)
    ).fetchone()
    assert row is not None
    return int(row[0])


# ------------------------------------------------------------------ deny-by-default


def test_denies_when_the_tenant_has_no_authorization_at_all(
    authority: PostgresScopeAuthority, autocommit_conn: Connection, tenant: UUID
) -> None:
    """Deny-by-default: nothing configured means nothing authorized. This is the state a
    fresh tenant is in, and it must not be permissive."""
    decision = authority.authorize(tenant, IN_SCOPE)

    assert decision.allowed is False
    assert decision.matched_authorization_id is None
    assert "deny-by-default" in decision.reason
    assert audit_entries(autocommit_conn, tenant)[0][0] == "denied"


def test_denies_a_target_outside_every_authorized_range(
    authority: PostgresScopeAuthority, autocommit_conn: Connection, tenant: UUID
) -> None:
    authorize_range(autocommit_conn, tenant, "10.10.0.0/16")

    decision = authority.authorize(tenant, OUT_OF_SCOPE)

    assert decision.allowed is False
    assert decision.matched_authorization_id is None


def test_out_of_scope_target_is_denied_audited_and_never_observed(
    authority: PostgresScopeAuthority, autocommit_conn: Connection, tenant: UUID
) -> None:
    """The three properties that matter together: the call fails closed, the denial is on
    the record, and nothing about the target was written to the observation spine."""
    authorize_range(autocommit_conn, tenant, "10.10.0.0/16")

    with pytest.raises(ScopeViolation) as exc_info:
        authority.require_authorized(tenant, OUT_OF_SCOPE)

    assert str(OUT_OF_SCOPE) in str(exc_info.value)

    entries = audit_entries(autocommit_conn, tenant)
    assert len(entries) == 1
    assert entries[0][0] == "denied"
    assert entries[0][1] == str(OUT_OF_SCOPE)

    assert observation_count(autocommit_conn, tenant) == 0


def test_denies_an_inactive_authorization(
    authority: PostgresScopeAuthority, autocommit_conn: Connection, tenant: UUID
) -> None:
    """Revocation has to take effect immediately — a deactivated authorization is not a
    grandfathered one."""
    authorize_range(autocommit_conn, tenant, "10.10.0.0/16", active=False)

    assert authority.authorize(tenant, IN_SCOPE).allowed is False


def test_denies_an_expired_authorization(
    authority: PostgresScopeAuthority, autocommit_conn: Connection, tenant: UUID
) -> None:
    """A time-boxed engagement stops at its end date without anyone flipping a flag."""
    authorize_range(
        autocommit_conn,
        tenant,
        "10.10.0.0/16",
        expires_at=datetime.now(UTC) - timedelta(days=1),
    )

    decision = authority.authorize(tenant, IN_SCOPE)

    assert decision.allowed is False
    assert "deny-by-default" in decision.reason


def test_another_tenants_authorization_does_not_authorize_us(
    authority: PostgresScopeAuthority, autocommit_conn: Connection, tenant: UUID
) -> None:
    """`tenant_id` scoping is the discipline that RLS will later enforce (AGENTS.md §5);
    until then this test is the enforcement."""
    other_tenant = uuid4()
    authorize_range(autocommit_conn, other_tenant, "10.10.0.0/16")

    assert authority.authorize(tenant, IN_SCOPE).allowed is False
    assert authority.authorize(other_tenant, IN_SCOPE).allowed is True


def test_require_authorized_raises_rather_than_returning_a_denial(
    authority: PostgresScopeAuthority, tenant: UUID
) -> None:
    """At the point of emission a returned value can be ignored; an exception cannot."""
    with pytest.raises(ScopeViolation):
        authority.require_authorized(tenant, IN_SCOPE)


# ------------------------------------------------------------------ the allow path


def test_allows_a_target_inside_an_active_authorization(
    authority: PostgresScopeAuthority, autocommit_conn: Connection, tenant: UUID
) -> None:
    authorization_id = authorize_range(autocommit_conn, tenant, "10.10.0.0/16")

    decision = authority.authorize(tenant, IN_SCOPE)

    assert decision.allowed is True
    assert decision.matched_authorization_id == authorization_id
    assert decision.target == str(IN_SCOPE)
    assert "10.10.0.0/16" in decision.reason


def test_require_authorized_is_silent_when_the_target_is_in_scope(
    authority: PostgresScopeAuthority, autocommit_conn: Connection, tenant: UUID
) -> None:
    authorize_range(autocommit_conn, tenant, "10.10.0.0/16")

    authority.require_authorized(tenant, IN_SCOPE)  # must not raise


def test_the_most_specific_authorization_is_the_one_recorded(
    authority: PostgresScopeAuthority, autocommit_conn: Connection, tenant: UUID
) -> None:
    """When ranges overlap, the audit trail should name the narrow carve-out an operator
    deliberately wrote, not the /8 it happens to sit inside."""
    authorize_range(autocommit_conn, tenant, "10.0.0.0/8")
    specific = authorize_range(autocommit_conn, tenant, "10.10.5.0/24")

    assert authority.authorize(tenant, IN_SCOPE).matched_authorization_id == specific


def test_a_single_host_authorization_covers_only_that_host(
    authority: PostgresScopeAuthority, autocommit_conn: Connection, tenant: UUID
) -> None:
    authorize_range(autocommit_conn, tenant, "10.10.5.7/32")

    assert authority.authorize(tenant, IN_SCOPE).allowed is True
    assert authority.authorize(tenant, ip_address("10.10.5.8")).allowed is False


# ---------------------------------------------------------------------- the audit


def test_every_decision_is_audited_exactly_once(
    authority: PostgresScopeAuthority, autocommit_conn: Connection, tenant: UUID
) -> None:
    authorize_range(autocommit_conn, tenant, "10.10.0.0/16")

    authority.authorize(tenant, IN_SCOPE)
    authority.authorize(tenant, OUT_OF_SCOPE)

    results = [entry[0] for entry in audit_entries(autocommit_conn, tenant)]
    assert results == ["success", "denied"]


def test_the_audit_entry_identifies_who_asked_and_why_it_was_decided(
    authority: PostgresScopeAuthority, autocommit_conn: Connection, tenant: UUID
) -> None:
    authorization_id = authorize_range(autocommit_conn, tenant, "10.10.0.0/16")

    authority.authorize(tenant, IN_SCOPE)

    result, resource_id, actor, actor_type, request_id, correlation_id, metadata = audit_entries(
        autocommit_conn, tenant
    )[0]
    assert (result, resource_id) == ("success", str(IN_SCOPE))
    assert (actor, actor_type) == ("engine", "service")
    assert (request_id, correlation_id) == ("req-1", "corr-1")
    assert metadata["matched_cidr"] == "10.10.0.0/16"
    assert metadata["matched_authorization_id"] == str(authorization_id)
    assert "10.10.0.0/16" in metadata["reason"]


def test_a_transactional_connection_is_refused(migrated_database: str) -> None:
    """An audit entry the caller can roll back is not an audit trail, so the adapter will
    not accept a connection that could do that."""
    with psycopg.connect(migrated_database) as transactional:
        with pytest.raises(ValueError, match="autocommit"):
            PostgresScopeAuthority(transactional)
        transactional.rollback()


def test_a_failed_audit_write_fails_closed(
    authority: PostgresScopeAuthority, autocommit_conn: Connection, tenant: UUID
) -> None:
    """If the decision cannot be recorded, the caller must not receive an authorization.
    An unauditable scan is not an authorized scan."""
    authorize_range(autocommit_conn, tenant, "10.10.0.0/16")
    autocommit_conn.execute(
        """
        create trigger audit_log_reject_insert before insert on audit_log
            for each row execute function forbid_mutation()
        """
    )
    try:
        with pytest.raises(psycopg.errors.RaiseException):
            authority.authorize(tenant, IN_SCOPE)  # would otherwise have been allowed
    finally:
        autocommit_conn.execute("drop trigger audit_log_reject_insert on audit_log")

    assert audit_entries(autocommit_conn, tenant) == []


# --------------------------------------------------------------------- conformance


def test_the_adapter_satisfies_the_port(autocommit_conn: Connection) -> None:
    """Structural conformance to `domain.ports.ScopeAuthority`, checked by mypy through
    this annotation and at runtime by the calls above."""
    gate: ScopeAuthority = PostgresScopeAuthority(autocommit_conn)

    assert callable(gate.authorize)
    assert callable(gate.require_authorized)
