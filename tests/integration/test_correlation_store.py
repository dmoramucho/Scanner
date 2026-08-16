"""Correlation against the real store: idempotency, and the constraints that outrank us.

The matching logic is covered hermetically in `tests/test_correlation.py`. This file asserts
what only the database can show — that a re-correlation refreshes rather than duplicating,
that `derivation` cannot be anything but `deterministic`, and that a match written by the
correlator satisfies every CHECK the schema has carried since M0.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest

from adapters.postgres.asset_repository import PostgresAssetRepository
from adapters.postgres.vulnerability_match_store import PostgresVulnerabilityMatchStore
from domain.models import (
    AnchorObservation,
    ConfidenceState,
    SoftwareComponent,
    VersionSource,
    VulnerabilityMatchInput,
)

pytestmark = pytest.mark.integration

Connection = psycopg.Connection[tuple[Any, ...]]

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
APACHE = "cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*"


@pytest.fixture
def tenant() -> UUID:
    return uuid4()


def seed_observation(conn: Connection, tenant: UUID) -> UUID:
    row = conn.execute(
        """
        insert into observation (
            tenant_id, observation_type, payload, source, source_type, collector,
            collector_version, collection_method, confidence, content_hash,
            observed_at, collected_at, run_id
        ) values (
            %s, 'software', '{}'::jsonb, 'ssh', 'credentialed', 'ssh-inspector',
            '0.1.0', 'ssh_read_only', 0.95, sha256(%s), %s, %s, %s
        ) returning id
        """,
        (tenant, uuid4().bytes, NOW, NOW, uuid4()),
    ).fetchone()
    assert row is not None
    return UUID(str(row[0]))


def seed_asset_with_component(
    conn: Connection, tenant: UUID, *, version_source: VersionSource, cpe: str | None = APACHE
) -> tuple[UUID, UUID]:
    repository = PostgresAssetRepository(conn)
    asset_id = repository.upsert_from_anchors(
        tenant,
        [AnchorObservation(kind="serial", value=f"SN-{uuid4().hex[:8]}", confidence=1.0)],
        seed_observation(conn, tenant),
    )
    repository.set_current_software(
        asset_id,
        [
            SoftwareComponent(
                cpe=cpe,
                name="apache2",
                version="2.4.52",
                version_source=version_source,
                confidence=0.95,
            )
        ],
    )
    row = conn.execute(
        "select id from software_component where asset_id = %s and is_current", (asset_id,)
    ).fetchone()
    assert row is not None
    return asset_id, UUID(str(row[0]))


def match(
    tenant: UUID,
    asset_id: UUID,
    component_id: UUID,
    *,
    cve_id: str = "CVE-2024-27316",
    confidence: ConfidenceState = ConfidenceState.CONFIRMED,
    kev: bool = False,
    epss: float | None = 0.5,
) -> VulnerabilityMatchInput:
    return VulnerabilityMatchInput(
        tenant_id=tenant,
        asset_id=asset_id,
        component_id=component_id,
        cve_id=cve_id,
        matched_cpe="cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
        version_source=VersionSource.PACKAGE_MANAGER,
        confidence_state=confidence,
        kev=kev,
        epss=epss,
    )


def test_only_components_with_a_cpe_are_offered_for_correlation(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    """A component with no CPE has nothing to look up, and inventing one would be guessing
    at identity (m3-design §2)."""
    seed_asset_with_component(autocommit_conn, tenant, version_source=VersionSource.PACKAGE_MANAGER)
    seed_asset_with_component(
        autocommit_conn, tenant, version_source=VersionSource.BANNER, cpe=None
    )

    components = PostgresVulnerabilityMatchStore(autocommit_conn).components_with_cpe(tenant)

    assert len(components) == 1
    assert components[0].cpe == APACHE
    assert components[0].version_source is VersionSource.PACKAGE_MANAGER


def test_a_match_round_trips_with_its_confidence_and_signals(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    asset_id, component_id = seed_asset_with_component(
        autocommit_conn, tenant, version_source=VersionSource.PACKAGE_MANAGER
    )
    store = PostgresVulnerabilityMatchStore(autocommit_conn)

    record = store.record_match(match(tenant, asset_id, component_id, kev=True, epss=0.94))

    assert record.created is True
    row = autocommit_conn.execute(
        """
        select cve_id, version_source, confidence_state, kev, epss, derivation, is_current
        from vulnerability_match where tenant_id = %s
        """,
        (tenant,),
    ).fetchone()
    assert row is not None
    assert row[0] == "CVE-2024-27316"
    assert row[1] == "package_manager"
    assert row[2] == "confirmed"
    assert row[3] is True
    assert row[4] == pytest.approx(0.94)
    assert row[5] == "deterministic"
    assert row[6] is True


def test_re_correlating_refreshes_rather_than_duplicating(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    """A re-correlation is routine — feeds change, components change — so a run must be safe
    to repeat (AGENTS.md §62)."""
    asset_id, component_id = seed_asset_with_component(
        autocommit_conn, tenant, version_source=VersionSource.PACKAGE_MANAGER
    )
    store = PostgresVulnerabilityMatchStore(autocommit_conn)

    first = store.record_match(match(tenant, asset_id, component_id, kev=False, epss=0.1))
    second = store.record_match(match(tenant, asset_id, component_id, kev=True, epss=0.94))

    assert first.created is True
    assert second.created is False
    assert first.match_id == second.match_id

    rows = autocommit_conn.execute(
        "select kev, epss from vulnerability_match where tenant_id = %s", (tenant,)
    ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] is True  # a CVE that gained a KEV listing since the last run
    assert rows[0][1] == pytest.approx(0.94)


def test_the_database_refuses_a_match_that_is_not_deterministic(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    """The belt to the type system's braces: no model decides that a vulnerability exists,
    and the CHECK says so where it cannot be argued with (AGENTS.md §2.8, §4.8)."""
    asset_id, component_id = seed_asset_with_component(
        autocommit_conn, tenant, version_source=VersionSource.PACKAGE_MANAGER
    )

    with pytest.raises(psycopg.errors.CheckViolation), autocommit_conn.transaction():
        autocommit_conn.execute(
            """
            insert into vulnerability_match (
                tenant_id, asset_id, component_id, cve_id, matched_cpe, version_source,
                confidence_state, derivation
            ) values (%s, %s, %s, 'CVE-2024-1', 'cpe:2.3:a:x:y:*:*:*:*:*:*:*:*',
                      'package_manager', 'confirmed', 'llm_generated')
            """,
            (tenant, asset_id, component_id),
        )


def test_the_database_refuses_an_unknown_confidence_state(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    asset_id, component_id = seed_asset_with_component(
        autocommit_conn, tenant, version_source=VersionSource.PACKAGE_MANAGER
    )

    with pytest.raises(psycopg.errors.CheckViolation), autocommit_conn.transaction():
        autocommit_conn.execute(
            """
            insert into vulnerability_match (
                tenant_id, asset_id, component_id, cve_id, matched_cpe, version_source,
                confidence_state
            ) values (%s, %s, %s, 'CVE-2024-1', 'cpe:2.3:a:x:y:*:*:*:*:*:*:*:*',
                      'package_manager', 'probably-fine')
            """,
            (tenant, asset_id, component_id),
        )


def test_an_epss_score_outside_zero_to_one_is_refused(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    asset_id, component_id = seed_asset_with_component(
        autocommit_conn, tenant, version_source=VersionSource.PACKAGE_MANAGER
    )

    with pytest.raises(psycopg.errors.CheckViolation), autocommit_conn.transaction():
        autocommit_conn.execute(
            """
            insert into vulnerability_match (
                tenant_id, asset_id, component_id, cve_id, matched_cpe, version_source,
                confidence_state, epss
            ) values (%s, %s, %s, 'CVE-2024-1', 'cpe:2.3:a:x:y:*:*:*:*:*:*:*:*',
                      'package_manager', 'confirmed', 1.5)
            """,
            (tenant, asset_id, component_id),
        )


def test_the_kev_view_finds_actively_exploited_findings(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    """The query the override exists to make cheap: "what on this estate is being exploited
    right now?" — and it must include the `probable` ones (dossier contract §7)."""
    asset_id, component_id = seed_asset_with_component(
        autocommit_conn, tenant, version_source=VersionSource.BANNER
    )
    store = PostgresVulnerabilityMatchStore(autocommit_conn)

    store.record_match(
        match(
            tenant,
            asset_id,
            component_id,
            cve_id="CVE-2021-44228",
            confidence=ConfidenceState.PROBABLE,
            kev=True,
        )
    )
    store.record_match(match(tenant, asset_id, component_id, cve_id="CVE-2024-0001", kev=False))

    rows = autocommit_conn.execute(
        """
        select cve_id, confidence_state from vulnerability_match
        where tenant_id = %s and is_current and kev
        """,
        (tenant,),
    ).fetchall()

    assert [(str(r[0]), str(r[1])) for r in rows] == [("CVE-2021-44228", "probable")]


def test_matches_do_not_cross_tenants(autocommit_conn: Connection, tenant: UUID) -> None:
    other = uuid4()
    asset_id, component_id = seed_asset_with_component(
        autocommit_conn, tenant, version_source=VersionSource.PACKAGE_MANAGER
    )
    store = PostgresVulnerabilityMatchStore(autocommit_conn)

    store.record_match(match(tenant, asset_id, component_id))

    theirs = autocommit_conn.execute(
        "select count(*) from vulnerability_match where tenant_id = %s", (other,)
    ).fetchone()
    assert theirs is not None
    assert theirs[0] == 0
