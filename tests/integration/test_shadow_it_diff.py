"""The diff against the real store, end to end: discovery + CMDB → the four categories.

The matching rules are covered hermetically in `tests/test_reconciliation.py`. This file
proves the round trip — that assets discovered by the M0/M1 pipeline and records imported by
P10 reconcile against each other, and that what the diff concluded is written back onto
`asset.management_state` and `managed_record.asset_id` (m2-design §4).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest

from adapters.managed.cmdb_csv import ColumnMapping, CsvCmdbSource
from adapters.postgres.asset_repository import PostgresAssetRepository
from adapters.postgres.managed_record_sink import PostgresManagedRecordSink
from adapters.postgres.reconciliation_store import PostgresReconciliationStore
from domain.models import AnchorObservation, ManagementState
from engine.managed_import import ManagedImport
from engine.shadow_it import ShadowItReconciler

pytestmark = pytest.mark.integration

Connection = psycopg.Connection[tuple[Any, ...]]

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "cmdb"
NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
EXPORTED_AT = datetime(2026, 8, 14, 9, 0, tzinfo=UTC)

MAPPING = ColumnMapping(
    external_id="Asset ID",
    hostname="Device Name",
    serial="S/N",
    mac="MAC Address",
    ip="IP",
    owner="Owner",
    extras={"site": "Site"},
)


@pytest.fixture
def tenant() -> UUID:
    return uuid4()


def seed_observation(conn: Connection, tenant: UUID, source: str = "arp") -> UUID:
    row = conn.execute(
        """
        insert into observation (
            tenant_id, observation_type, payload, source, source_type, collector,
            collector_version, collection_method, confidence, content_hash,
            observed_at, collected_at, run_id
        ) values (
            %s, 'identity', '{}'::jsonb, %s, 'passive', 'passive-collector',
            '0.1.0', 'arp_table', 0.9, sha256(%s), %s, %s, %s
        ) returning id
        """,
        (tenant, source, uuid4().bytes, NOW, NOW, uuid4()),
    ).fetchone()
    assert row is not None
    return UUID(str(row[0]))


def discover(conn: Connection, tenant: UUID, anchors: list[AnchorObservation]) -> UUID:
    """An asset as the M0/M1 pipeline would have produced it."""
    return PostgresAssetRepository(conn).upsert_from_anchors(
        tenant, anchors, seed_observation(conn, tenant)
    )


def import_cmdb(conn: Connection, tenant: UUID, name: str = "clean.csv") -> None:
    ManagedImport(
        CsvCmdbSource(FIXTURES / name, MAPPING, observed_at=EXPORTED_AT),
        PostgresManagedRecordSink(conn),
    ).run(tenant)


def reconciler(conn: Connection) -> ShadowItReconciler:
    return ShadowItReconciler(PostgresReconciliationStore(conn))


def management_state(conn: Connection, asset_id: UUID) -> str:
    row = conn.execute("select management_state from asset where id = %s", (asset_id,)).fetchone()
    assert row is not None
    return str(row[0])


def linked_asset(conn: Connection, tenant: UUID, external_id: str) -> UUID | None:
    row = conn.execute(
        "select asset_id from managed_record where tenant_id = %s and external_id = %s",
        (tenant, external_id),
    ).fetchone()
    assert row is not None
    return UUID(str(row[0])) if row[0] else None


def test_a_discovered_and_registered_device_comes_out_matched_and_managed(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    """The healthy baseline, across the whole pipeline: scanning found it, the CMDB lists
    it, and the two are now the same thing."""
    import_cmdb(autocommit_conn, tenant)
    asset_id = discover(
        autocommit_conn,
        tenant,
        [AnchorObservation(kind="serial", value="SN-ABC-1234", confidence=1.0)],
    )

    diff = reconciler(autocommit_conn).run(tenant, computed_at=NOW)

    assert asset_id in {finding.asset_id for finding in diff.matched}
    assert management_state(autocommit_conn, asset_id) == ManagementState.MANAGED.value
    assert linked_asset(autocommit_conn, tenant, "CMDB-0001") == asset_id


def test_an_unregistered_device_is_shadow_it(autocommit_conn: Connection, tenant: UUID) -> None:
    """The number the product exists to show."""
    import_cmdb(autocommit_conn, tenant)
    rogue = discover(
        autocommit_conn,
        tenant,
        [AnchorObservation(kind="mac", value="de:ad:be:ef:00:01", confidence=0.9)],
    )

    diff = reconciler(autocommit_conn).run(tenant, computed_at=NOW)

    assert diff.shadow_it_count == 1
    assert diff.unmanaged[0].asset_id == rogue
    assert management_state(autocommit_conn, rogue) == ManagementState.UNMANAGED.value


def test_a_cmdb_record_with_no_device_is_stale_and_creates_nothing(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    import_cmdb(autocommit_conn, tenant)

    diff = reconciler(autocommit_conn).run(tenant, computed_at=NOW)

    assert diff.counts["stale"] == 3  # nothing was discovered at all
    assets = autocommit_conn.execute(
        "select count(*) from asset where tenant_id = %s", (tenant,)
    ).fetchone()
    assert assets is not None
    assert assets[0] == 0  # a stale record never conjures an asset
    assert linked_asset(autocommit_conn, tenant, "CMDB-0001") is None


def test_an_ambiguous_case_writes_unknown_not_unmanaged(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    """The safety-critical property, persisted: two devices answer to the name the CMDB
    gives, so neither is accused, and the field on the asset says `unknown`."""
    import_cmdb(autocommit_conn, tenant)
    twin_a = discover(
        autocommit_conn,
        tenant,
        [AnchorObservation(kind="hostname", value="printer-3f", confidence=0.6)],
    )
    twin_b = discover(
        autocommit_conn,
        tenant,
        [
            AnchorObservation(kind="hostname", value="printer-3f", confidence=0.6),
            AnchorObservation(kind="ip", value="10.10.5.99", confidence=0.9),
        ],
    )

    diff = reconciler(autocommit_conn).run(tenant, computed_at=NOW)

    assert diff.shadow_it_count == 0
    assert {twin_a, twin_b} <= diff.ambiguous_assets
    for asset_id in (twin_a, twin_b):
        assert management_state(autocommit_conn, asset_id) == ManagementState.UNKNOWN.value


def test_a_merged_asset_is_not_counted_as_shadow_it(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    """A merged asset is history pointing at its survivor, not a device. Counting it would
    double-count one machine and inflate the headline (AGENTS.md §3)."""
    from domain.models import MergeRequest

    import_cmdb(autocommit_conn, tenant)
    repository = PostgresAssetRepository(autocommit_conn)
    survivor = discover(
        autocommit_conn,
        tenant,
        [AnchorObservation(kind="serial", value="SN-ABC-1234", confidence=1.0)],
    )
    absorbed = discover(
        autocommit_conn,
        tenant,
        [AnchorObservation(kind="serial", value="SN-DUPLICATE", confidence=1.0)],
    )
    repository.record_merge(
        MergeRequest(survivor_id=survivor, merged_id=absorbed, derivation="deterministic")
    )

    diff = reconciler(autocommit_conn).run(tenant, computed_at=NOW)

    assert absorbed not in diff.assets_considered
    assert diff.shadow_it_count == 0


def test_the_diff_is_stable_across_runs(autocommit_conn: Connection, tenant: UUID) -> None:
    """Recomputing over unchanged state changes nothing — including the writes, which are
    assignments rather than accumulations."""
    import_cmdb(autocommit_conn, tenant)
    discover(
        autocommit_conn,
        tenant,
        [AnchorObservation(kind="serial", value="SN-ABC-1234", confidence=1.0)],
    )
    discover(
        autocommit_conn,
        tenant,
        [AnchorObservation(kind="mac", value="de:ad:be:ef:00:01", confidence=0.9)],
    )

    engine = reconciler(autocommit_conn)
    first = engine.run(tenant, computed_at=NOW)
    second = engine.run(tenant, computed_at=NOW)

    assert first.counts == second.counts
    assert first.model_dump() == second.model_dump()


def test_a_link_that_stops_being_right_is_cleared(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    """A record linked last month whose device has since been merged away must not keep
    pointing at it: the diff is recomputed from scratch, and so are its links."""
    import_cmdb(autocommit_conn, tenant)
    asset_id = discover(
        autocommit_conn,
        tenant,
        [AnchorObservation(kind="serial", value="SN-ABC-1234", confidence=1.0)],
    )
    reconciler(autocommit_conn).run(tenant, computed_at=NOW)
    assert linked_asset(autocommit_conn, tenant, "CMDB-0001") == asset_id

    # The asset goes away as a distinct device (merged into another).
    from domain.models import MergeRequest

    survivor = discover(
        autocommit_conn,
        tenant,
        [AnchorObservation(kind="serial", value="SN-SURVIVOR", confidence=1.0)],
    )
    PostgresAssetRepository(autocommit_conn).record_merge(
        MergeRequest(survivor_id=survivor, merged_id=asset_id, derivation="deterministic")
    )

    reconciler(autocommit_conn).run(tenant, computed_at=NOW)

    assert linked_asset(autocommit_conn, tenant, "CMDB-0001") is None


def test_the_diff_does_not_cross_tenants(autocommit_conn: Connection, tenant: UUID) -> None:
    """Another tenant's CMDB row must never mark our device managed (AGENTS.md §5)."""
    other = uuid4()
    import_cmdb(autocommit_conn, other)
    ours = discover(
        autocommit_conn,
        tenant,
        [AnchorObservation(kind="serial", value="SN-ABC-1234", confidence=1.0)],
    )

    diff = reconciler(autocommit_conn).run(tenant, computed_at=NOW)

    assert diff.shadow_it_count == 1
    assert diff.unmanaged[0].asset_id == ours
    assert management_state(autocommit_conn, ours) == ManagementState.UNMANAGED.value


def test_a_full_estate_partitions_into_the_four_categories(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    """The demo, in miniature: some devices registered, one rogue, some CMDB rows with
    nothing behind them, and one case nobody can settle."""
    import_cmdb(autocommit_conn, tenant)
    registered = discover(
        autocommit_conn,
        tenant,
        [AnchorObservation(kind="serial", value="SN-ABC-1234", confidence=1.0)],
    )
    rogue = discover(
        autocommit_conn,
        tenant,
        [AnchorObservation(kind="mac", value="de:ad:be:ef:00:01", confidence=0.9)],
    )
    # Two genuinely distinct devices that answer to the same name — each has its own MAC,
    # so entity resolution keeps them apart, and neither MAC is in the CMDB.
    twin_a = discover(
        autocommit_conn,
        tenant,
        [
            AnchorObservation(kind="mac", value="11:11:11:11:11:11", confidence=0.9),
            AnchorObservation(kind="hostname", value="printer-3f", confidence=0.6),
        ],
    )
    twin_b = discover(
        autocommit_conn,
        tenant,
        [
            AnchorObservation(kind="mac", value="22:22:22:22:22:22", confidence=0.9),
            AnchorObservation(kind="hostname", value="printer-3f", confidence=0.6),
        ],
    )

    diff = reconciler(autocommit_conn).run(tenant, computed_at=NOW)

    assert {finding.asset_id for finding in diff.matched} == {registered}
    assert {finding.asset_id for finding in diff.unmanaged} == {rogue}
    assert {twin_a, twin_b} <= diff.ambiguous_assets
    assert diff.counts["stale"] >= 1  # CMDB-0002 has no discovered device
    assert diff.assets_considered == {registered, rogue, twin_a, twin_b}
    assert 0 < diff.ambiguous_rate < 1
