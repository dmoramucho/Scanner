"""Entity resolution: the part where the data model earns its keep.

The properties under test are the ones that make the asset graph trustworthy — a stable
anchor means one asset, a rotating locator means nothing, a merge can always be undone, and
an LLM-proposed merge cannot slip through without its reasoning.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest

from adapters.postgres.asset_repository import PostgresAssetRepository
from domain.errors import ConflictError, NotFoundError, ValidationError
from domain.models import AnchorObservation, MergeRequest, SoftwareComponent, VersionSource
from domain.ports import AssetRepository

pytestmark = pytest.mark.integration

Connection = psycopg.Connection[tuple[Any, ...]]

NOW = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)

SERIAL = AnchorObservation(kind="serial", value="ACCC8E1F2A3B", confidence=1.0)
OTHER_SERIAL = AnchorObservation(kind="serial", value="XYZ-999", confidence=1.0)
MAC = AnchorObservation(kind="mac", value="aa:bb:cc:dd:ee:ff", confidence=0.9)
OTHER_MAC = AnchorObservation(kind="mac", value="00:40:8c:9d:1e:2f", confidence=0.9)
HOSTNAME = AnchorObservation(kind="hostname", value="cam-lobby-01", confidence=0.6)
IP = AnchorObservation(kind="ip", value="10.10.5.31", confidence=0.9)


@pytest.fixture
def tenant() -> UUID:
    return uuid4()


@pytest.fixture
def repo(autocommit_conn: Connection) -> PostgresAssetRepository:
    return PostgresAssetRepository(autocommit_conn)


@pytest.fixture
def observation_id(autocommit_conn: Connection, tenant: UUID) -> UUID:
    """A real observation row — identifiers reference it, so it has to exist."""
    row = autocommit_conn.execute(
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
    assert row is not None
    return UUID(str(row[0]))


def identifiers_of(conn: Connection, asset_id: UUID) -> list[tuple[str, str]]:
    rows = conn.execute(
        "select kind, value from asset_identifier where asset_id = %s order by kind, value",
        (asset_id,),
    ).fetchall()
    return [(str(row[0]), str(row[1])) for row in rows]


def merge_events(conn: Connection, tenant: UUID) -> list[tuple[Any, ...]]:
    return conn.execute(
        """
        select kind, survivor_id, merged_id, reverses_id, derivation, rationale
        from asset_merge_event where tenant_id = %s order by created_at, kind
        """,
        (tenant,),
    ).fetchall()


# --------------------------------------------------------------------- resolution


def test_two_observations_sharing_a_serial_resolve_to_one_asset(
    repo: PostgresAssetRepository, tenant: UUID, observation_id: UUID
) -> None:
    """The headline case: one device, seen twice, is one asset."""
    first = repo.upsert_from_anchors(tenant, [SERIAL, IP], observation_id)
    second = repo.upsert_from_anchors(tenant, [SERIAL, HOSTNAME], observation_id)

    assert first == second
    assert repo.resolve(tenant, [SERIAL]).asset_id == first


def test_differing_serials_resolve_to_two_assets(
    repo: PostgresAssetRepository, tenant: UUID, observation_id: UUID
) -> None:
    """A differing serial beats every softer signal — even a shared hostname and IP
    (AGENTS.md §2.8: deterministic anchors win)."""
    first = repo.upsert_from_anchors(tenant, [SERIAL, HOSTNAME, IP], observation_id)
    second = repo.upsert_from_anchors(tenant, [OTHER_SERIAL, HOSTNAME, IP], observation_id)

    assert first != second


def test_resolve_returns_nothing_for_an_unknown_anchor(
    repo: PostgresAssetRepository, tenant: UUID
) -> None:
    resolution = repo.resolve(tenant, [SERIAL])

    assert resolution.asset_id is None
    assert resolution.confidence == 0.0
    assert resolution.matched_on == []


def test_a_rotating_locator_never_identifies_an_asset(
    repo: PostgresAssetRepository, autocommit_conn: Connection, tenant: UUID, observation_id: UUID
) -> None:
    """An IP and a hostname are attached to an asset but never resolve one: they rotate,
    and identifying from them is how two devices silently become one (AGENTS.md §3)."""
    asset_id = repo.upsert_from_anchors(tenant, [SERIAL, HOSTNAME, IP], observation_id)
    assert (HOSTNAME.kind, HOSTNAME.value) in identifiers_of(autocommit_conn, asset_id)

    resolution = repo.resolve(tenant, [HOSTNAME, IP])

    assert resolution.asset_id is None  # a new-asset candidate, not a match
    assert resolution.matched_on == []


def test_anchor_priority_puts_the_strongest_evidence_first(
    repo: PostgresAssetRepository, tenant: UUID, observation_id: UUID
) -> None:
    repo.upsert_from_anchors(tenant, [SERIAL, MAC], observation_id)

    resolution = repo.resolve(tenant, [SERIAL, MAC])

    assert resolution.matched_on == ["serial", "mac"]
    assert resolution.confidence == pytest.approx(0.99)  # the serial's weight, not the MAC's


def test_resolution_confidence_reflects_how_well_the_anchor_was_read(
    repo: PostgresAssetRepository, tenant: UUID, observation_id: UUID
) -> None:
    """A MAC we are only half sure we read must not produce a fully confident identity."""
    repo.upsert_from_anchors(tenant, [MAC], observation_id)

    resolution = repo.resolve(
        tenant, [AnchorObservation(kind="mac", value=MAC.value, confidence=0.5)]
    )

    assert resolution.asset_id is not None
    assert resolution.confidence == pytest.approx(0.45)  # 0.90 weight × 0.5 reading


def test_disagreeing_strong_anchors_let_the_stronger_one_win(
    repo: PostgresAssetRepository, tenant: UUID, observation_id: UUID
) -> None:
    """A serial saying A and a MAC saying B is a conflict for a merge to settle, not
    something resolve should average out. The stronger anchor wins and the disagreement
    stays visible: the MAC is absent from `matched_on`."""
    by_serial = repo.upsert_from_anchors(tenant, [SERIAL], observation_id)
    repo.upsert_from_anchors(tenant, [MAC], observation_id)

    resolution = repo.resolve(tenant, [SERIAL, MAC])

    assert resolution.asset_id == by_serial
    assert resolution.matched_on == ["serial"]


def test_anchors_are_scoped_to_a_tenant(
    repo: PostgresAssetRepository, tenant: UUID, observation_id: UUID
) -> None:
    repo.upsert_from_anchors(tenant, [SERIAL], observation_id)

    assert repo.resolve(uuid4(), [SERIAL]).asset_id is None


# ------------------------------------------------------------------------ upsert


def test_upsert_from_anchors_is_idempotent(
    repo: PostgresAssetRepository, autocommit_conn: Connection, tenant: UUID, observation_id: UUID
) -> None:
    """A retried ingestion must not fork the asset graph or duplicate its identifiers."""
    first = repo.upsert_from_anchors(tenant, [SERIAL, MAC, HOSTNAME, IP], observation_id)
    second = repo.upsert_from_anchors(tenant, [SERIAL, MAC, HOSTNAME, IP], observation_id)

    assert first == second
    assert identifiers_of(autocommit_conn, first) == [
        ("hostname", HOSTNAME.value),
        ("ip", IP.value),
        ("mac", MAC.value),
        ("serial", SERIAL.value),
    ]


def test_upsert_links_the_asserting_observation(
    repo: PostgresAssetRepository, autocommit_conn: Connection, tenant: UUID, observation_id: UUID
) -> None:
    """Provenance: every identifier points at the observation that asserted it. This is the
    asset↔observation link, made from this side because `observation` is append-only."""
    asset_id = repo.upsert_from_anchors(tenant, [SERIAL], observation_id)

    rows = autocommit_conn.execute(
        "select observation_id from asset_identifier where asset_id = %s", (asset_id,)
    ).fetchall()
    assert [UUID(str(row[0])) for row in rows] == [observation_id]


def test_upsert_grows_an_asset_as_new_anchors_are_learned(
    repo: PostgresAssetRepository, autocommit_conn: Connection, tenant: UUID, observation_id: UUID
) -> None:
    """ARP sees a MAC; a later credentialed read adds the serial. Same asset, more identity."""
    from_arp = repo.upsert_from_anchors(tenant, [MAC, IP], observation_id)
    with_serial = repo.upsert_from_anchors(tenant, [MAC, SERIAL], observation_id)

    assert with_serial == from_arp
    assert {kind for kind, _ in identifiers_of(autocommit_conn, from_arp)} == {
        "mac",
        "ip",
        "serial",
    }


def test_a_strong_anchor_is_never_re_pointed_at_another_asset(
    repo: PostgresAssetRepository, tenant: UUID, observation_id: UUID
) -> None:
    """Two assets cannot claim one serial. Stealing the anchor would rewrite identity
    silently; raising leaves the conflict for a merge to settle deliberately."""
    first = repo.upsert_from_anchors(tenant, [SERIAL], observation_id)
    second = repo.upsert_from_anchors(tenant, [OTHER_SERIAL], observation_id)

    # An observation claiming both serials would have to steal one of them.
    with pytest.raises(ConflictError, match="already identifies asset"):
        repo.upsert_from_anchors(tenant, [SERIAL, OTHER_SERIAL], observation_id)

    # ... and the failed attempt changed nothing: both anchors still point where they did.
    assert repo.resolve(tenant, [SERIAL]).asset_id == first
    assert repo.resolve(tenant, [OTHER_SERIAL]).asset_id == second


def test_upsert_without_anchors_is_refused(
    repo: PostgresAssetRepository, tenant: UUID, observation_id: UUID
) -> None:
    """An asset with no way to recognise it again is not an asset."""
    with pytest.raises(ValidationError, match="empty anchor set"):
        repo.upsert_from_anchors(tenant, [], observation_id)


def test_get_returns_the_asset_view(
    repo: PostgresAssetRepository, tenant: UUID, observation_id: UUID
) -> None:
    asset_id = repo.upsert_from_anchors(tenant, [SERIAL], observation_id)

    view = repo.get(tenant, asset_id)

    assert view is not None
    assert view.id == asset_id
    assert view.tenant_id == tenant
    assert view.status == "active"
    assert view.asset_class == "unknown"  # nothing has classified it yet


def test_get_does_not_cross_tenants(
    repo: PostgresAssetRepository, tenant: UUID, observation_id: UUID
) -> None:
    asset_id = repo.upsert_from_anchors(tenant, [SERIAL], observation_id)

    assert repo.get(uuid4(), asset_id) is None


# ------------------------------------------------------------------------ merges


def test_a_merge_marks_the_asset_merged_and_records_the_event(
    repo: PostgresAssetRepository, autocommit_conn: Connection, tenant: UUID, observation_id: UUID
) -> None:
    survivor = repo.upsert_from_anchors(tenant, [SERIAL], observation_id)
    merged = repo.upsert_from_anchors(tenant, [OTHER_SERIAL], observation_id)

    merge_id = repo.record_merge(
        MergeRequest(survivor_id=survivor, merged_id=merged, derivation="deterministic")
    )

    merged_view = repo.get(tenant, merged)
    assert merged_view is not None
    assert merged_view.status == "merged"
    events = merge_events(autocommit_conn, tenant)
    assert len(events) == 1
    assert events[0][0] == "merge"
    assert UUID(str(events[0][1])) == survivor
    assert merge_id is not None


def test_resolving_a_merged_assets_anchor_yields_the_survivor(
    repo: PostgresAssetRepository, tenant: UUID, observation_id: UUID
) -> None:
    """A merged asset is never deleted, so its anchors still exist — and must lead to the
    asset that survived, not to the one that was absorbed."""
    survivor = repo.upsert_from_anchors(tenant, [SERIAL], observation_id)
    merged = repo.upsert_from_anchors(tenant, [OTHER_SERIAL], observation_id)
    repo.record_merge(
        MergeRequest(survivor_id=survivor, merged_id=merged, derivation="deterministic")
    )

    assert repo.resolve(tenant, [OTHER_SERIAL]).asset_id == survivor


def test_a_merge_and_its_reversal_leave_the_asset_active_with_both_events_recorded(
    repo: PostgresAssetRepository, autocommit_conn: Connection, tenant: UUID, observation_id: UUID
) -> None:
    """The DoD case, and the reason merges are safe to make: reversal restores the asset
    and *adds* an event — the original merge is still there, because the table is
    append-only (AGENTS.md §3)."""
    survivor = repo.upsert_from_anchors(tenant, [SERIAL], observation_id)
    merged = repo.upsert_from_anchors(tenant, [OTHER_SERIAL], observation_id)
    merge_id = repo.record_merge(
        MergeRequest(survivor_id=survivor, merged_id=merged, derivation="deterministic")
    )

    reversal_id = repo.reverse_merge(merge_id, rationale="operator: different chassis")

    restored = repo.get(tenant, merged)
    assert restored is not None
    assert restored.status == "active"

    events = merge_events(autocommit_conn, tenant)
    assert [str(event[0]) for event in events] == ["merge", "reversal"]
    assert UUID(str(events[1][3])) == merge_id  # reverses_id points at the merge
    assert events[1][5] == "operator: different chassis"
    assert reversal_id != merge_id

    # And the asset resolves independently again.
    assert repo.resolve(tenant, [OTHER_SERIAL]).asset_id == merged


def test_a_reversed_merge_cannot_be_reversed_twice(
    repo: PostgresAssetRepository, tenant: UUID, observation_id: UUID
) -> None:
    survivor = repo.upsert_from_anchors(tenant, [SERIAL], observation_id)
    merged = repo.upsert_from_anchors(tenant, [OTHER_SERIAL], observation_id)
    merge_id = repo.record_merge(
        MergeRequest(survivor_id=survivor, merged_id=merged, derivation="deterministic")
    )
    repo.reverse_merge(merge_id)

    with pytest.raises(ConflictError, match="already been reversed"):
        repo.reverse_merge(merge_id)


def test_reversing_something_that_is_not_a_merge_is_refused(
    repo: PostgresAssetRepository, tenant: UUID, observation_id: UUID
) -> None:
    survivor = repo.upsert_from_anchors(tenant, [SERIAL], observation_id)
    merged = repo.upsert_from_anchors(tenant, [OTHER_SERIAL], observation_id)
    merge_id = repo.record_merge(
        MergeRequest(survivor_id=survivor, merged_id=merged, derivation="deterministic")
    )
    reversal_id = repo.reverse_merge(merge_id)

    with pytest.raises(ValidationError, match="not a merge"):
        repo.reverse_merge(reversal_id)

    with pytest.raises(NotFoundError):
        repo.reverse_merge(uuid4())


def test_an_llm_proposed_merge_without_a_rationale_is_rejected(
    repo: PostgresAssetRepository, autocommit_conn: Connection, tenant: UUID, observation_id: UUID
) -> None:
    """Belt and suspenders with the `merge_llm_has_rationale` CHECK: the adapter refuses
    before the database is touched, so the rule holds even if the constraint is ever
    relaxed (AGENTS.md §2.8). Nothing produces `llm_proposed` yet — this guard is here
    before the generator that will need it (M3)."""
    survivor = repo.upsert_from_anchors(tenant, [SERIAL], observation_id)
    merged = repo.upsert_from_anchors(tenant, [OTHER_SERIAL], observation_id)

    with pytest.raises(ValidationError, match="requires a rationale"):
        repo.record_merge(
            MergeRequest(survivor_id=survivor, merged_id=merged, derivation="llm_proposed")
        )

    assert merge_events(autocommit_conn, tenant) == []
    still_active = repo.get(tenant, merged)
    assert still_active is not None
    assert still_active.status == "active"


def test_an_llm_proposed_merge_with_a_rationale_is_accepted(
    repo: PostgresAssetRepository, autocommit_conn: Connection, tenant: UUID, observation_id: UUID
) -> None:
    """The rule is "cite your reasoning", not "never propose"."""
    survivor = repo.upsert_from_anchors(tenant, [SERIAL], observation_id)
    merged = repo.upsert_from_anchors(tenant, [OTHER_SERIAL], observation_id)

    repo.record_merge(
        MergeRequest(
            survivor_id=survivor,
            merged_id=merged,
            derivation="llm_proposed",
            rationale="same chassis serial prefix and identical firmware banner",
            confidence=0.8,
            model_version="local-model-0.1",
        )
    )

    events = merge_events(autocommit_conn, tenant)
    assert events[0][4] == "llm_proposed"
    assert events[0][5] is not None


def test_self_merge_and_double_merge_are_refused(
    repo: PostgresAssetRepository, tenant: UUID, observation_id: UUID
) -> None:
    survivor = repo.upsert_from_anchors(tenant, [SERIAL], observation_id)
    merged = repo.upsert_from_anchors(tenant, [OTHER_SERIAL], observation_id)

    with pytest.raises(ValidationError, match="merged into itself"):
        repo.record_merge(
            MergeRequest(survivor_id=survivor, merged_id=survivor, derivation="deterministic")
        )

    repo.record_merge(
        MergeRequest(survivor_id=survivor, merged_id=merged, derivation="deterministic")
    )
    with pytest.raises(ConflictError, match="already merged"):
        repo.record_merge(
            MergeRequest(survivor_id=survivor, merged_id=merged, derivation="deterministic")
        )


def test_a_cross_tenant_merge_is_refused(
    repo: PostgresAssetRepository, tenant: UUID, observation_id: UUID
) -> None:
    """Two tenants' assets are never the same device, whatever the anchors say."""
    ours = repo.upsert_from_anchors(tenant, [SERIAL], observation_id)
    theirs = repo.upsert_from_anchors(uuid4(), [OTHER_SERIAL], observation_id)

    with pytest.raises(ValidationError, match="different tenants"):
        repo.record_merge(
            MergeRequest(survivor_id=ours, merged_id=theirs, derivation="deterministic")
        )


def test_merging_an_unknown_asset_is_refused(
    repo: PostgresAssetRepository, tenant: UUID, observation_id: UUID
) -> None:
    survivor = repo.upsert_from_anchors(tenant, [SERIAL], observation_id)

    with pytest.raises(NotFoundError):
        repo.record_merge(
            MergeRequest(survivor_id=survivor, merged_id=uuid4(), derivation="deterministic")
        )


# -------------------------------------------------------------- current software


def component(name: str, version: str | None, cpe: str | None = None) -> SoftwareComponent:
    return SoftwareComponent(
        cpe=cpe,
        name=name,
        version=version,
        version_source=VersionSource.PACKAGE_MANAGER,
        confidence=0.95,
    )


def current_software(conn: Connection, asset_id: UUID) -> list[tuple[str, str | None]]:
    rows = conn.execute(
        "select name, version from software_component "
        "where asset_id = %s and is_current order by name",
        (asset_id,),
    ).fetchall()
    return [(str(row[0]), row[1]) for row in rows]


def test_set_current_software_projects_the_current_set(
    repo: PostgresAssetRepository, autocommit_conn: Connection, tenant: UUID, observation_id: UUID
) -> None:
    asset_id = repo.upsert_from_anchors(tenant, [SERIAL], observation_id)

    repo.set_current_software(asset_id, [component("openssl", "3.0.2"), component("nginx", "1.22")])

    assert current_software(autocommit_conn, asset_id) == [("nginx", "1.22"), ("openssl", "3.0.2")]


def test_set_current_software_is_idempotent(
    repo: PostgresAssetRepository, autocommit_conn: Connection, tenant: UUID, observation_id: UUID
) -> None:
    asset_id = repo.upsert_from_anchors(tenant, [SERIAL], observation_id)
    components = [component("openssl", "3.0.2")]

    repo.set_current_software(asset_id, components)
    repo.set_current_software(asset_id, components)

    assert current_software(autocommit_conn, asset_id) == [("openssl", "3.0.2")]


def test_a_replaced_component_is_retired_not_deleted(
    repo: PostgresAssetRepository, autocommit_conn: Connection, tenant: UUID, observation_id: UUID
) -> None:
    """ "What was installed on date X?" has to stay answerable, so the old row survives with
    `is_current = false` (AGENTS.md §3)."""
    asset_id = repo.upsert_from_anchors(tenant, [SERIAL], observation_id)

    repo.set_current_software(asset_id, [component("openssl", "3.0.2")])
    repo.set_current_software(asset_id, [component("openssl", "3.0.13")])

    assert current_software(autocommit_conn, asset_id) == [("openssl", "3.0.13")]
    rows = autocommit_conn.execute(
        "select version, is_current from software_component where asset_id = %s order by version",
        (asset_id,),
    ).fetchall()
    assert [(str(row[0]), bool(row[1])) for row in rows] == [
        ("3.0.13", True),
        ("3.0.2", False),
    ]


def test_software_for_an_unknown_asset_is_refused(repo: PostgresAssetRepository) -> None:
    with pytest.raises(NotFoundError):
        repo.set_current_software(uuid4(), [component("openssl", "3.0.2")])


# --------------------------------------------------------------------- conformance


def test_the_adapter_satisfies_the_port(autocommit_conn: Connection) -> None:
    repository: AssetRepository = PostgresAssetRepository(autocommit_conn)

    assert callable(repository.resolve)
    assert callable(repository.upsert_from_anchors)
    assert callable(repository.set_current_software)
    assert callable(repository.record_merge)
    assert callable(repository.reverse_merge)


# ------------------------------------------------- locator-only sightings (mDNS)


def test_a_locator_only_sighting_is_not_recreated_on_every_run(
    repo: PostgresAssetRepository, tenant: UUID, observation_id: UUID
) -> None:
    """An mDNS record carries a hostname and an address and nothing else. Resolution
    rightly refuses to identify a device from those — but the upsert must still be
    idempotent, or every sweep would mint another asset for the same sighting and inflate
    the graph exactly where this product claims to reduce noise."""
    first = repo.upsert_from_anchors(tenant, [HOSTNAME, IP], observation_id)
    second = repo.upsert_from_anchors(tenant, [HOSTNAME, IP], observation_id)

    assert first == second


def test_a_locator_only_sighting_never_joins_an_identified_asset(
    repo: PostgresAssetRepository, tenant: UUID, observation_id: UUID
) -> None:
    """Reuse is idempotency, never identity: a hostname and an IP cannot pull a sighting
    into an asset we have actually identified. That would be a merge — reversible and
    recorded — and this is neither (AGENTS.md §3)."""
    identified = repo.upsert_from_anchors(tenant, [MAC, HOSTNAME, IP], observation_id)

    candidate = repo.upsert_from_anchors(tenant, [HOSTNAME, IP], observation_id)

    assert candidate != identified


def test_a_partially_matching_locator_set_is_a_new_candidate(
    repo: PostgresAssetRepository, tenant: UUID, observation_id: UUID
) -> None:
    """Every locator has to match. A device that kept its name but changed address is not
    demonstrably the same device, and passive evidence cannot settle it."""
    first = repo.upsert_from_anchors(tenant, [HOSTNAME, IP], observation_id)

    moved = repo.upsert_from_anchors(
        tenant,
        [HOSTNAME, AnchorObservation(kind="ip", value="10.10.5.99", confidence=0.9)],
        observation_id,
    )

    assert moved != first
