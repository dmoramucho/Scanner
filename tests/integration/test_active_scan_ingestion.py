"""The scan engine against the real store: same spine, same entity resolution.

The engine's logic is covered hermetically in `tests/test_active_scan_engine.py`. This file
asserts the claim m1-design §6 makes about M1 — that active scanning is a new *source* of
observations and changes nothing downstream: the existing `ObservationSink` records its
output idempotently, and the existing `AssetRepository` resolves it into the same assets
passive discovery would.

The scanner and the health probe are still fakes: CI needs no nmap and no network. The
database is real, because idempotency and entity resolution are properties of the database
(ADR-0002).
"""

from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest

from adapters.postgres.asset_repository import PostgresAssetRepository
from adapters.postgres.observation_sink import PostgresObservationSink
from adapters.postgres.scope_authority import SCOPE_ACTION, PostgresScopeAuthority
from domain.models import (
    AnchorObservation,
    IPAddress,
    ObservationInput,
    ScanProfile,
    ScanResult,
)
from engine.active_scan import ActiveScanEngine, BreakerPolicy, ScanCandidate

pytestmark = pytest.mark.integration

Connection = psycopg.Connection[tuple[Any, ...]]

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
CAMERA = ip_address("10.10.5.31")
OUTSIDE = ip_address("192.168.99.14")
CAMERA_MAC = "00:40:8c:9d:1e:2f"


class ScriptedScanner:
    """Returns a fixed, realistic scan result for any target it is given."""

    def __init__(self, tenant_id: UUID, run_id: UUID) -> None:
        self.tenant_id = tenant_id
        self.run_id = run_id
        self.calls: list[tuple[str, ScanProfile]] = []

    def scan(self, tenant_id: UUID, target: IPAddress, profile: ScanProfile) -> ScanResult:
        address = str(target)
        self.calls.append((address, profile))
        return ScanResult(
            target=address,
            profile=profile,
            host_up=True,
            observations=[
                ObservationInput(
                    tenant_id=self.tenant_id,
                    run_id=self.run_id,
                    asset_id=None,
                    observation_type="open_ports",
                    payload={"ip": address, "ports": [{"port": 554, "protocol": "tcp"}]},
                    source="nmap",
                    source_type="active_scan",
                    source_identifier=address,
                    collector="nmap-scanner",
                    collector_version="0.1.0",
                    collection_method=f"nmap_{profile.value}",
                    version_source=None,
                    confidence=0.9,
                    observed_at=NOW,
                    collected_at=NOW,
                    raw_record_ref=None,
                )
            ],
            anchors=[AnchorObservation(kind="mac", value=CAMERA_MAC, confidence=0.9)],
            started_at=NOW,
            finished_at=NOW,
        )


class AlwaysUp:
    def is_responsive(self, target: IPAddress) -> bool:
        return True


@pytest.fixture
def tenant() -> UUID:
    return uuid4()


def authorize_range(conn: Connection, tenant: UUID, cidr: str) -> None:
    conn.execute(
        """
        insert into scope_authorization (tenant_id, cidr, written_auth_ref, authorized_at)
        values (%s, %s::cidr, 'signed-auth-2026-001', %s)
        """,
        (tenant, cidr, datetime(2026, 1, 1, tzinfo=UTC)),
    )


def build_engine(conn: Connection, tenant: UUID, run_id: UUID) -> tuple[ActiveScanEngine, Any]:
    scanner = ScriptedScanner(tenant, run_id)
    engine = ActiveScanEngine(
        PostgresScopeAuthority(conn, actor="engine", correlation_id="active-scan-1"),
        scanner,
        AlwaysUp(),
        PostgresObservationSink(conn),
        PostgresAssetRepository(conn),
        run_id=run_id,
        breaker=BreakerPolicy(backoff_seconds=0.0),
        sleep=lambda _: None,
        clock=lambda: NOW,
    )
    return engine, scanner


def observation_count(conn: Connection, tenant: UUID) -> int:
    row = conn.execute(
        "select count(*) from observation where tenant_id = %s and source = 'nmap'", (tenant,)
    ).fetchone()
    assert row is not None
    return int(row[0])


def test_scan_output_lands_in_the_spine_and_resolves_to_an_asset(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    authorize_range(autocommit_conn, tenant, "10.10.0.0/16")
    engine, _ = build_engine(autocommit_conn, tenant, uuid4())

    outcome = engine.run(tenant, [ScanCandidate(CAMERA, mac_vendor="Axis Communications AB")])

    assert outcome.scanned == 1
    assert outcome.recorded == 1
    assert outcome.assets == 1
    assert observation_count(autocommit_conn, tenant) == 1

    anchors = autocommit_conn.execute(
        "select kind, value from asset_identifier where tenant_id = %s order by kind", (tenant,)
    ).fetchall()
    assert [(str(row[0]), str(row[1])) for row in anchors] == [
        ("ip", str(CAMERA)),
        ("mac", CAMERA_MAC),
    ]


def test_a_rescan_in_the_same_run_adds_nothing(autocommit_conn: Connection, tenant: UUID) -> None:
    """Idempotency is the sink's, unchanged: M1 is a new source, not a new write path."""
    authorize_range(autocommit_conn, tenant, "10.10.0.0/16")
    run_id = uuid4()
    engine, _ = build_engine(autocommit_conn, tenant, run_id)

    first = engine.run(tenant, [ScanCandidate(CAMERA)])
    second = engine.run(tenant, [ScanCandidate(CAMERA)])

    assert first.recorded == 1
    assert second.recorded == 0
    assert second.duplicates == 1
    assert second.asset_ids == first.asset_ids
    assert observation_count(autocommit_conn, tenant) == 1


def test_an_active_scan_resolves_to_the_same_asset_as_a_passive_sighting(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    """The moat, across sources: the camera passive discovery found by MAC is the camera the
    scan just measured — one asset, two kinds of evidence (AGENTS.md §3)."""
    authorize_range(autocommit_conn, tenant, "10.10.0.0/16")
    repository = PostgresAssetRepository(autocommit_conn)
    seed_observation = autocommit_conn.execute(
        """
        insert into observation (
            tenant_id, observation_type, payload, source, source_type, collector,
            collector_version, collection_method, confidence, content_hash,
            observed_at, collected_at, run_id
        ) values (
            %s, 'identity', '{}'::jsonb, 'arp', 'passive', 'passive-collector',
            '0.1.0', 'arp_table', 0.9, sha256('{}'::bytea), %s, %s, %s
        ) returning id
        """,
        (tenant, NOW, NOW, uuid4()),
    ).fetchone()
    assert seed_observation is not None
    passive_asset = repository.upsert_from_anchors(
        tenant,
        [AnchorObservation(kind="mac", value=CAMERA_MAC, confidence=0.9)],
        UUID(str(seed_observation[0])),
    )

    engine, _ = build_engine(autocommit_conn, tenant, uuid4())
    outcome = engine.run(tenant, [ScanCandidate(CAMERA, mac=CAMERA_MAC)])

    assert outcome.asset_ids == frozenset({passive_asset})


def test_an_out_of_scope_target_is_denied_audited_and_never_scanned(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    """The P3 property, holding for active scanning too — with a real audit trail."""
    authorize_range(autocommit_conn, tenant, "10.10.0.0/16")
    engine, scanner = build_engine(autocommit_conn, tenant, uuid4())

    outcome = engine.run(tenant, [ScanCandidate(OUTSIDE), ScanCandidate(CAMERA)])

    assert outcome.denied == 1
    assert [address for address, _ in scanner.calls] == [str(CAMERA)]
    assert observation_count(autocommit_conn, tenant) == 1

    denials = autocommit_conn.execute(
        """
        select count(*) from audit_log
        where tenant_id = %s and action = %s and result = 'denied' and resource_id = %s
        """,
        (tenant, SCOPE_ACTION, str(OUTSIDE)),
    ).fetchone()
    assert denials is not None
    assert denials[0] == 1


def test_a_trip_is_persisted_as_evidence(autocommit_conn: Connection, tenant: UUID) -> None:
    """A counter in a run summary disappears; a device that cannot survive a scan is
    something an operator needs to know next month, so it goes into the spine."""
    authorize_range(autocommit_conn, tenant, "10.10.0.0/16")
    run_id = uuid4()
    scanner = ScriptedScanner(tenant, run_id)

    class DiesAfterScan:
        def __init__(self) -> None:
            self.checks = 0

        def is_responsive(self, target: IPAddress) -> bool:
            self.checks += 1
            return self.checks == 1

    engine = ActiveScanEngine(
        PostgresScopeAuthority(autocommit_conn, actor="engine"),
        scanner,
        DiesAfterScan(),
        PostgresObservationSink(autocommit_conn),
        PostgresAssetRepository(autocommit_conn),
        run_id=run_id,
        breaker=BreakerPolicy(health_check_attempts=1, backoff_seconds=0.0),
        sleep=lambda _: None,
        clock=lambda: NOW,
    )

    outcome = engine.run(tenant, [ScanCandidate(CAMERA)])

    assert outcome.tripped == 1
    rows = autocommit_conn.execute(
        """
        select payload ->> 'state', source, collection_method from observation
        where tenant_id = %s and observation_type = 'device_health'
        """,
        (tenant,),
    ).fetchall()
    assert [(str(r[0]), str(r[1]), str(r[2])) for r in rows] == [
        ("unresponsive_after_scan", "health_probe", "circuit_breaker")
    ]


def test_the_engine_only_uses_ports_not_adapters() -> None:
    """The engine is wired from real adapters here, but it names none of them: `engine/`
    imports `domain.ports` and nothing from `adapters/` (AGENTS.md §2.1)."""
    source = (Path(__file__).resolve().parents[2] / "engine" / "active_scan.py").read_text(
        encoding="utf-8"
    )

    assert "adapters" not in source
    assert "psycopg" not in source
