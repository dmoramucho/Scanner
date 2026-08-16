"""M1's closing claim, against the real store.

Three sources — passive discovery, an active scan, and a credentialed read — reconcile to
*one* asset, and the credentialed read wins on version truth. That last part is the payoff
of `version_source`: a banner-inferred `Apache/2.4.52` is a candidate, a `dpkg` entry is
the device's own account of itself, and the current-state projection reflects the stronger
evidence (AGENTS.md §3, m1-design §6).

The device is a fake; the database, the sink, and the entity resolution are real, because
supersession and idempotency are properties of the store (ADR-0002).
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest

from adapters.postgres.asset_repository import PostgresAssetRepository
from adapters.postgres.observation_sink import PostgresObservationSink
from adapters.postgres.scope_authority import SCOPE_ACTION, PostgresScopeAuthority
from domain.errors import DependencyError
from domain.models import (
    AnchorObservation,
    DeviceFingerprint,
    InspectionResult,
    IPAddress,
    ObservationInput,
    SoftwareComponent,
    VersionSource,
)
from domain.ports import CredentialedInspector
from engine.credentialed_scan import CredentialedInspectionEngine

pytestmark = pytest.mark.integration

Connection = psycopg.Connection[tuple[Any, ...]]

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
SERVER = "10.10.5.7"
OUTSIDE = "192.168.99.14"
SERVER_MAC = "aa:bb:cc:dd:ee:ff"


class ScriptedInspector:
    """A device that reports two packages and its own name."""

    def __init__(self, run_id: UUID, *, failure: Exception | None = None) -> None:
        self.run_id = run_id
        self.failure = failure
        self.inspected: list[str] = []

    def inspect(self, tenant_id: UUID, target: IPAddress, credential_ref: str) -> InspectionResult:
        address = str(target)
        self.inspected.append(address)
        if self.failure is not None:
            raise self.failure

        components = [
            SoftwareComponent(
                cpe=None,
                name=name,
                version=version,
                version_source=VersionSource.PACKAGE_MANAGER,
                confidence=0.95,
            )
            for name, version in (("ubuntu", "22.04"), ("apache2", "2.4.52-1ubuntu4.9"))
        ]
        return InspectionResult(
            target=address,
            inspector="ssh-inspector",
            observations=[
                ObservationInput(
                    tenant_id=tenant_id,
                    run_id=self.run_id,
                    asset_id=None,
                    observation_type="software",
                    payload={"ip": address, "components": [c.name for c in components]},
                    source="ssh",
                    source_type="credentialed",
                    source_identifier=address,
                    collector="ssh-inspector",
                    collector_version="0.1.0",
                    collection_method="ssh_read_only",
                    version_source=VersionSource.PACKAGE_MANAGER,
                    confidence=0.95,
                    observed_at=NOW,
                    collected_at=NOW,
                    raw_record_ref=None,
                )
            ],
            components=components,
            anchors=[AnchorObservation(kind="mac", value=SERVER_MAC, confidence=0.9)],
            started_at=NOW,
            finished_at=NOW,
        )


class OneInspector:
    def __init__(self, inspector: CredentialedInspector) -> None:
        self.inspector = inspector

    def for_device(self, fingerprint: DeviceFingerprint) -> CredentialedInspector | None:
        return self.inspector if fingerprint.credential_ref else None


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


def seed_observation(conn: Connection, tenant: UUID, source: str) -> UUID:
    row = conn.execute(
        """
        insert into observation (
            tenant_id, observation_type, payload, source, source_type, collector,
            collector_version, collection_method, confidence, content_hash,
            observed_at, collected_at, run_id
        ) values (
            %s, 'identity', %s::jsonb, %s, 'passive', 'passive-collector',
            '0.1.0', 'arp_table', 0.9, sha256(%s), %s, %s, %s
        ) returning id
        """,
        (tenant, '{"ip": "10.10.5.7"}', source, source.encode(), NOW, NOW, uuid4()),
    ).fetchone()
    assert row is not None
    return UUID(str(row[0]))


def build_engine(
    conn: Connection, tenant: UUID, inspector: CredentialedInspector
) -> CredentialedInspectionEngine:
    return CredentialedInspectionEngine(
        PostgresScopeAuthority(conn, actor="engine", correlation_id="credentialed-1"),
        OneInspector(inspector),
        PostgresObservationSink(conn),
        PostgresAssetRepository(conn),
    )


def current_software(conn: Connection, asset_id: UUID) -> list[tuple[str, str, str]]:
    rows = conn.execute(
        """
        select name, version, version_source from software_component
        where asset_id = %s and is_current order by name
        """,
        (asset_id,),
    ).fetchall()
    return [(str(row[0]), str(row[1]), str(row[2])) for row in rows]


def fingerprint(
    address: str, *, credential_ref: str | None = "vault://ssh/app-01"
) -> DeviceFingerprint:
    return DeviceFingerprint(target=address, open_ports=(22,), credential_ref=credential_ref)


def test_credentialed_truth_supersedes_banner_inference(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    """The confidence-stratification payoff, end to end.

    The asset starts with a banner-inferred Apache — the best an uncredentialed scan can
    do. After the credentialed read, the current set is what `dpkg` says, marked
    `package_manager`. The banner row is retired rather than deleted, so "what did we think
    on date X?" still answers (AGENTS.md §3).
    """
    authorize_range(autocommit_conn, tenant, "10.10.0.0/16")
    repository = PostgresAssetRepository(autocommit_conn)
    asset_id = repository.upsert_from_anchors(
        tenant,
        [AnchorObservation(kind="mac", value=SERVER_MAC, confidence=0.9)],
        seed_observation(autocommit_conn, tenant, "nmap"),
    )
    repository.set_current_software(
        asset_id,
        [
            SoftwareComponent(
                cpe=None,
                name="apache2",
                version="2.4.52",
                version_source=VersionSource.BANNER,  # inferred from a header
                confidence=0.6,
            )
        ],
    )
    assert current_software(autocommit_conn, asset_id) == [("apache2", "2.4.52", "banner")]

    outcome = build_engine(autocommit_conn, tenant, ScriptedInspector(uuid4())).run(
        tenant, [fingerprint(SERVER)]
    )

    assert outcome.inspected == 1
    assert outcome.asset_ids == frozenset({asset_id})  # the same asset, not a new one
    assert current_software(autocommit_conn, asset_id) == [
        ("apache2", "2.4.52-1ubuntu4.9", "package_manager"),
        ("ubuntu", "22.04", "package_manager"),
    ]

    retired = autocommit_conn.execute(
        """
        select version, version_source from software_component
        where asset_id = %s and not is_current
        """,
        (asset_id,),
    ).fetchall()
    assert [(str(row[0]), str(row[1])) for row in retired] == [("2.4.52", "banner")]


def test_all_three_sources_reconcile_to_one_asset(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    """M1's closing claim: passive, active, and credentialed evidence about one device is
    one asset with three kinds of provenance — not three rows (AGENTS.md §3)."""
    authorize_range(autocommit_conn, tenant, "10.10.0.0/16")
    repository = PostgresAssetRepository(autocommit_conn)
    mac_anchor = [AnchorObservation(kind="mac", value=SERVER_MAC, confidence=0.9)]

    passive_asset = repository.upsert_from_anchors(
        tenant, mac_anchor, seed_observation(autocommit_conn, tenant, "arp")
    )
    active_asset = repository.upsert_from_anchors(
        tenant, mac_anchor, seed_observation(autocommit_conn, tenant, "nmap")
    )

    outcome = build_engine(autocommit_conn, tenant, ScriptedInspector(uuid4())).run(
        tenant, [fingerprint(SERVER)]
    )

    assert {passive_asset, active_asset} == {passive_asset}  # already the same asset
    assert outcome.asset_ids == frozenset({passive_asset})

    sources = autocommit_conn.execute(
        "select distinct source, source_type from observation where tenant_id = %s order by source",
        (tenant,),
    ).fetchall()
    assert [(str(row[0]), str(row[1])) for row in sources] == [
        ("arp", "passive"),
        ("nmap", "passive"),
        ("ssh", "credentialed"),
    ]


def test_an_out_of_scope_device_is_denied_audited_and_never_connected_to(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    """Authenticating to a device is emission; emission goes through the gate."""
    authorize_range(autocommit_conn, tenant, "10.10.0.0/16")
    inspector = ScriptedInspector(uuid4())

    outcome = build_engine(autocommit_conn, tenant, inspector).run(
        tenant, [fingerprint(OUTSIDE), fingerprint(SERVER)]
    )

    assert outcome.denied == 1
    assert inspector.inspected == [SERVER]

    denials = autocommit_conn.execute(
        """
        select count(*) from audit_log
        where tenant_id = %s and action = %s and result = 'denied' and resource_id = %s
        """,
        (tenant, SCOPE_ACTION, OUTSIDE),
    ).fetchone()
    assert denials is not None
    assert denials[0] == 1

    stored = autocommit_conn.execute(
        "select count(*) from observation where tenant_id = %s and source = 'ssh'", (tenant,)
    ).fetchone()
    assert stored is not None
    assert stored[0] == 1  # only the authorised device produced anything


def test_a_device_with_no_credentialed_path_keeps_its_banner_versions(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    """No credential is not an error, and it must not disturb what we already knew."""
    authorize_range(autocommit_conn, tenant, "10.10.0.0/16")
    repository = PostgresAssetRepository(autocommit_conn)
    asset_id = repository.upsert_from_anchors(
        tenant,
        [AnchorObservation(kind="mac", value=SERVER_MAC, confidence=0.9)],
        seed_observation(autocommit_conn, tenant, "nmap"),
    )
    repository.set_current_software(
        asset_id,
        [
            SoftwareComponent(
                cpe=None,
                name="apache2",
                version="2.4.52",
                version_source=VersionSource.BANNER,
                confidence=0.6,
            )
        ],
    )

    outcome = build_engine(autocommit_conn, tenant, ScriptedInspector(uuid4())).run(
        tenant, [fingerprint(SERVER, credential_ref=None)]
    )

    assert outcome.skipped_no_path == 1
    assert outcome.failed == 0
    assert current_software(autocommit_conn, asset_id) == [("apache2", "2.4.52", "banner")]


def test_a_failed_inspection_leaves_the_store_untouched(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    authorize_range(autocommit_conn, tenant, "10.10.0.0/16")
    failing = ScriptedInspector(uuid4(), failure=DependencyError("refused", retryable=True))

    outcome = build_engine(autocommit_conn, tenant, failing).run(tenant, [fingerprint(SERVER)])

    assert outcome.failed == 1
    stored = autocommit_conn.execute(
        "select count(*) from observation where tenant_id = %s", (tenant,)
    ).fetchone()
    assert stored is not None
    assert stored[0] == 0


def test_repeated_inspection_does_not_inflate_the_graph(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    authorize_range(autocommit_conn, tenant, "10.10.0.0/16")
    engine = build_engine(autocommit_conn, tenant, ScriptedInspector(uuid4()))

    first = engine.run(tenant, [fingerprint(SERVER)])
    second = engine.run(tenant, [fingerprint(SERVER)])

    assert second.recorded == 0
    assert second.duplicates == 1
    assert second.asset_ids == first.asset_ids

    assets = autocommit_conn.execute(
        "select count(*) from asset where tenant_id = %s", (tenant,)
    ).fetchone()
    assert assets is not None
    assert assets[0] == 1
    assert len(current_software(autocommit_conn, next(iter(first.asset_ids)))) == 2
