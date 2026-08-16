"""End to end on fixtures: capture → parse → scope gate → observation spine.

This is where the three P3 pieces meet, and where the property that matters most is
asserted in its full form: an out-of-scope address that appears in a real capture is
denied, audited, and leaves no trace in `observation` — while the in-scope addresses in
the same capture are recorded with complete provenance.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest

from adapters.collector.passive import Capture, CollectionResult, PassiveCollector
from adapters.postgres.observation_sink import PostgresObservationSink
from adapters.postgres.scope_authority import SCOPE_ACTION, PostgresScopeAuthority
from domain.errors import ValidationError
from engine.sweep import PassiveSweep

pytestmark = pytest.mark.integration

Connection = psycopg.Connection[tuple[Any, ...]]

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "passive"

CAPTURED_AT = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)
COLLECTED_AT = datetime(2026, 8, 13, 12, 0, 5, tzinfo=UTC)

AUTHORIZED_RANGE = "10.10.0.0/16"
OUT_OF_SCOPE_TARGET = "192.168.99.14"

#: Every provenance column the contract requires on an observation (AGENTS.md §2.2).
PROVENANCE_COLUMNS = (
    "source",
    "source_type",
    "collector",
    "collector_version",
    "collection_method",
    "confidence",
    "content_hash",
    "observed_at",
    "collected_at",
    "ingested_at",
    "run_id",
)


@pytest.fixture
def tenant() -> UUID:
    return uuid4()


@pytest.fixture
def captures() -> list[Capture]:
    return [
        Capture("arp", (FIXTURES / "arp_table.txt").read_text(), CAPTURED_AT),
        Capture("dhcp", (FIXTURES / "dhcpd.leases").read_text(), CAPTURED_AT),
        Capture("mdns", (FIXTURES / "avahi_browse.txt").read_text(), CAPTURED_AT),
    ]


@pytest.fixture
def sweep(autocommit_conn: Connection) -> PassiveSweep:
    return PassiveSweep(
        PostgresScopeAuthority(autocommit_conn, actor="engine", correlation_id="sweep-1"),
        PostgresObservationSink(autocommit_conn),
    )


def authorize_range(conn: Connection, tenant: UUID, cidr: str) -> None:
    conn.execute(
        """
        insert into scope_authorization (tenant_id, cidr, written_auth_ref, authorized_at)
        values (%s, %s::cidr, 'signed-auth-2026-001', %s)
        """,
        (tenant, cidr, datetime(2026, 1, 1, tzinfo=UTC)),
    )


def collect(tenant: UUID, run_id: UUID, captures: list[Capture]) -> CollectionResult:
    return PassiveCollector().collect(
        tenant_id=tenant, run_id=run_id, captures=captures, collected_at=COLLECTED_AT
    )


def observed_ips(conn: Connection, tenant: UUID) -> set[str]:
    rows = conn.execute(
        "select payload ->> 'ip' from observation where tenant_id = %s", (tenant,)
    ).fetchall()
    return {str(row[0]) for row in rows}


def test_passive_sweep_records_in_scope_sightings_with_full_provenance(
    sweep: PassiveSweep, autocommit_conn: Connection, tenant: UUID, captures: list[Capture]
) -> None:
    authorize_range(autocommit_conn, tenant, AUTHORIZED_RANGE)

    outcome = sweep.run(tenant, collect(tenant, uuid4(), captures).candidates)

    assert outcome.recorded > 0
    rows = autocommit_conn.execute(
        f"select {', '.join(PROVENANCE_COLUMNS)} from observation where tenant_id = %s",  # noqa: S608
        (tenant,),
    ).fetchall()
    assert len(rows) == outcome.recorded
    for row in rows:
        assert all(value is not None for value in row), "a provenance column came back null"


def test_all_three_passive_sources_reach_the_store(
    sweep: PassiveSweep, autocommit_conn: Connection, tenant: UUID, captures: list[Capture]
) -> None:
    authorize_range(autocommit_conn, tenant, AUTHORIZED_RANGE)

    sweep.run(tenant, collect(tenant, uuid4(), captures).candidates)

    rows = autocommit_conn.execute(
        "select distinct source, source_type, collection_method from observation "
        "where tenant_id = %s order by source",
        (tenant,),
    ).fetchall()
    assert [tuple(row) for row in rows] == [
        ("arp", "passive", "arp_table"),
        ("dhcp", "authoritative", "dhcp_lease_file"),
        ("mdns", "passive", "mdns_browse"),
    ]


def test_an_out_of_scope_target_is_denied_audited_and_never_observed(
    sweep: PassiveSweep, autocommit_conn: Connection, tenant: UUID, captures: list[Capture]
) -> None:
    """The capture genuinely contains 192.168.99.14 (it is in the ARP, DHCP and mDNS
    fixtures), so this asserts the gate — not the fixture."""
    authorize_range(autocommit_conn, tenant, AUTHORIZED_RANGE)
    candidates = collect(tenant, uuid4(), captures).candidates
    assert OUT_OF_SCOPE_TARGET in {str(target) for target, _ in candidates}

    outcome = sweep.run(tenant, candidates)

    assert outcome.denied == 3  # once per source that saw it
    assert set(outcome.denied_targets) == {OUT_OF_SCOPE_TARGET}
    assert OUT_OF_SCOPE_TARGET not in observed_ips(autocommit_conn, tenant)

    denials = autocommit_conn.execute(
        """
        select count(*) from audit_log
        where tenant_id = %s and action = %s and result = 'denied' and resource_id = %s
        """,
        (tenant, SCOPE_ACTION, OUT_OF_SCOPE_TARGET),
    ).fetchone()
    assert denials is not None
    assert denials[0] == 3


def test_nothing_is_recorded_when_the_tenant_has_no_authorization(
    sweep: PassiveSweep, autocommit_conn: Connection, tenant: UUID, captures: list[Capture]
) -> None:
    """Deny-by-default, end to end: an unconfigured tenant sweeps to nothing, loudly on
    the audit trail rather than silently."""
    outcome = sweep.run(tenant, collect(tenant, uuid4(), captures).candidates)

    assert outcome.recorded == 0
    assert outcome.denied > 0
    assert observed_ips(autocommit_conn, tenant) == set()

    audited = autocommit_conn.execute(
        "select count(*) from audit_log where tenant_id = %s and result = 'denied'", (tenant,)
    ).fetchone()
    assert audited is not None
    assert audited[0] == outcome.denied


def test_replaying_the_same_capture_in_the_same_run_adds_nothing(
    sweep: PassiveSweep, autocommit_conn: Connection, tenant: UUID, captures: list[Capture]
) -> None:
    """A retried collector run must not inflate the evidence base."""
    authorize_range(autocommit_conn, tenant, AUTHORIZED_RANGE)
    run_id = uuid4()

    first = sweep.run(tenant, collect(tenant, run_id, captures).candidates)
    second = sweep.run(tenant, collect(tenant, run_id, captures).candidates)

    assert second.recorded == 0
    assert second.duplicates == first.recorded

    total = autocommit_conn.execute(
        "select count(*) from observation where tenant_id = %s", (tenant,)
    ).fetchone()
    assert total is not None
    assert total[0] == first.recorded


def test_a_later_run_of_the_same_capture_is_recorded_as_fresh_evidence(
    sweep: PassiveSweep, autocommit_conn: Connection, tenant: UUID, captures: list[Capture]
) -> None:
    authorize_range(autocommit_conn, tenant, AUTHORIZED_RANGE)

    first = sweep.run(tenant, collect(tenant, uuid4(), captures).candidates)
    second = sweep.run(tenant, collect(tenant, uuid4(), captures).candidates)

    assert second.recorded == first.recorded
    total = autocommit_conn.execute(
        "select count(*) from observation where tenant_id = %s", (tenant,)
    ).fetchone()
    assert total is not None
    assert total[0] == first.recorded * 2


def test_the_sweep_refuses_an_observation_belonging_to_another_tenant(
    sweep: PassiveSweep, autocommit_conn: Connection, tenant: UUID, captures: list[Capture]
) -> None:
    """A cross-tenant write is worse than a refused run (AGENTS.md §5)."""
    authorize_range(autocommit_conn, tenant, AUTHORIZED_RANGE)
    foreign = collect(uuid4(), uuid4(), captures).candidates

    with pytest.raises(ValidationError, match="does not match the sweep tenant"):
        sweep.run(tenant, foreign)
