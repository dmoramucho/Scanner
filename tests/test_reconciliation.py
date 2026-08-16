"""The matching rules and the four categories — pure, no database.

The correctness-critical file of P11. The whole value of the diff is that its shadow-IT
number is *trustworthy*, so the assertions that matter most are the ones proving an
unresolved case can never inflate it. A false "shadow IT!" that the CISO disproves in the
first demo burns trust in the entire system (m2-design §3).
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from domain.models import (
    AssetAnchorSet,
    ManagedRecordSnapshot,
    ManagedSourceKind,
    ManagementState,
    MatchStrength,
    ShadowItDiff,
)
from engine.reconciliation import (
    SHADOW_IT_STRONG_CONFIDENCE,
    SHADOW_IT_WEAK_CONFIDENCE,
    normalize_hostname,
    reconcile,
    squash_hostname,
)

TENANT = UUID("11111111-1111-1111-1111-111111111111")
NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)


def asset(
    *,
    serials: tuple[str, ...] = (),
    macs: tuple[str, ...] = (),
    hostnames: tuple[str, ...] = (),
    asset_id: UUID | None = None,
) -> AssetAnchorSet:
    return AssetAnchorSet(
        asset_id=asset_id or uuid4(),
        serials=frozenset(serials),
        macs=frozenset(macs),
        hostnames=frozenset(hostnames),
    )


def record(
    *,
    serial: str | None = None,
    mac: str | None = None,
    hostname: str | None = None,
    external_id: str = "CMDB-0001",
) -> ManagedRecordSnapshot:
    return ManagedRecordSnapshot(
        record_id=uuid4(),
        external_id=external_id,
        source=ManagedSourceKind.CMDB,
        serial=serial,
        mac=mac,
        hostname=hostname,
    )


def diff_of(records: list[ManagedRecordSnapshot], assets: list[AssetAnchorSet]) -> ShadowItDiff:
    return reconcile(records, assets).diff(TENANT, computed_at=NOW)


# ------------------------------------------------------------------ strong match


def test_a_shared_serial_links_the_record_to_the_asset() -> None:
    server = asset(serials=("SN-ABC-1234",), hostnames=("srv-app-03",))
    result = reconcile([record(serial="SN-ABC-1234")], [server])

    assert len(result.links) == 1
    link = result.links[0]
    assert link.asset_id == server.asset_id
    assert link.strength is MatchStrength.STRONG
    assert link.matched_on == ["serial"]
    assert result.states[server.asset_id] is ManagementState.MANAGED


def test_a_shared_mac_links_just_as_confidently() -> None:
    camera = asset(macs=("00:40:8c:9d:1e:2f",))
    result = reconcile([record(mac="00:40:8C:9D:1E:2F")], [camera])  # case differs

    assert result.links[0].strength is MatchStrength.STRONG
    assert result.states[camera.asset_id] is ManagementState.MANAGED


def test_serials_compare_case_insensitively() -> None:
    """The same serial is upper-case on the label the CMDB was typed from and lower-case in
    whatever the device reported."""
    server = asset(serials=("sn-abc-1234",))

    result = reconcile([record(serial="SN-ABC-1234")], [server])

    assert result.links[0].asset_id == server.asset_id


def test_a_matched_asset_appears_in_the_matched_category() -> None:
    server = asset(serials=("SN-1",))
    diff = diff_of([record(serial="SN-1")], [server])

    assert diff.counts == {"matched": 1, "unmanaged": 0, "stale": 0, "ambiguous": 0}
    assert diff.matched[0].asset_id == server.asset_id
    assert diff.shadow_it_count == 0


# --------------------------------------------------------------------- shadow IT


def test_an_asset_no_record_matches_is_shadow_it() -> None:
    """The headline finding: it is on the network and nobody registered it."""
    rogue = asset(serials=("SN-ROGUE",), macs=("aa:bb:cc:dd:ee:ff",))

    diff = diff_of([record(serial="SN-KNOWN")], [rogue])

    assert diff.shadow_it_count == 1
    finding = diff.unmanaged[0]
    assert finding.asset_id == rogue.asset_id
    assert finding.confidence == SHADOW_IT_STRONG_CONFIDENCE
    assert "serial or MAC" in finding.reason


def test_shadow_it_is_softer_when_we_could_only_look_it_up_by_name() -> None:
    """Still a finding, but the CMDB might simply spell it differently — the confidence
    says so rather than the number quietly overstating (m2-design §4)."""
    by_name_only = asset(hostnames=("mystery-box",))

    diff = diff_of([record(hostname="something-else")], [by_name_only])

    assert diff.shadow_it_count == 1
    assert diff.unmanaged[0].confidence == SHADOW_IT_WEAK_CONFIDENCE


def test_management_state_agrees_with_the_headline_count() -> None:
    """There is no path that marks an asset unmanaged without listing it as shadow IT, or
    the reverse — the field and the number are derived from the same conclusion."""
    rogue = asset(macs=("aa:bb:cc:dd:ee:ff",))
    known = asset(serials=("SN-1",))

    result = reconcile([record(serial="SN-1")], [rogue, known])
    diff = result.diff(TENANT, computed_at=NOW)

    unmanaged_ids = {
        asset_id for asset_id, state in result.states.items() if state is ManagementState.UNMANAGED
    }
    assert unmanaged_ids == {finding.asset_id for finding in diff.unmanaged}


# ------------------------------------------------------------------------- stale


def test_a_record_with_no_asset_is_stale_not_an_error() -> None:
    """The device may be switched off rather than gone — a candidate for the CMDB owner."""
    diff = diff_of([record(serial="SN-DECOMMISSIONED", external_id="CMDB-9")], [])

    assert diff.counts["stale"] == 1
    assert diff.stale[0].external_id == "CMDB-9"
    assert diff.stale[0].asset_id is None  # a stale record creates no asset
    assert "switched off" in diff.stale[0].reason


def test_stale_records_do_not_affect_the_shadow_it_count() -> None:
    rogue = asset(macs=("aa:bb:cc:dd:ee:ff",))

    diff = diff_of([record(serial="SN-GONE"), record(serial="SN-ALSO-GONE")], [rogue])

    assert diff.counts["stale"] == 2
    assert diff.shadow_it_count == 1


# ------------------------------------------- THE SAFETY-CRITICAL ASSERTIONS


def test_an_ambiguous_case_is_never_counted_as_shadow_it() -> None:
    """The assertion this whole module exists to satisfy.

    Two assets answer to the same name and the CMDB row gives only that name. We cannot
    tell which one it describes — so *neither* is called shadow IT, both resolve to
    `unknown`, and the operator gets a review queue instead of a false accusation
    (m2-design §3, §4).
    """
    first = asset(hostnames=("srv-app-03",))
    second = asset(hostnames=("srv-app-03",))

    result = reconcile([record(hostname="SRV-APP-03")], [first, second])
    diff = result.diff(TENANT, computed_at=NOW)

    assert diff.shadow_it_count == 0
    assert diff.unmanaged == []
    assert {finding.asset_id for finding in diff.ambiguous if finding.asset_id} == {
        first.asset_id,
        second.asset_id,
    }
    assert result.states[first.asset_id] is ManagementState.UNKNOWN
    assert result.states[second.asset_id] is ManagementState.UNKNOWN


def test_no_ambiguous_asset_ever_appears_in_the_unmanaged_list() -> None:
    """Stated as an invariant over a deliberately messy estate rather than one case: every
    way of being unresolved is checked at once, and the two lists must not intersect."""
    twin_a = asset(hostnames=("srv-app-03",))
    twin_b = asset(hostnames=("srv-app-03",))
    squashed = asset(hostnames=("srv-app-04",))
    conflicted = asset(serials=("SN-CONFLICT",))
    other_side = asset(macs=("11:22:33:44:55:66",))
    address_only = asset()
    genuinely_rogue = asset(serials=("SN-ROGUE",))

    records = [
        record(hostname="srv-app-03", external_id="CMDB-1"),  # two candidates
        record(hostname="srvapp04", external_id="CMDB-2"),  # squash-only
        record(serial="SN-CONFLICT", mac="11:22:33:44:55:66", external_id="CMDB-3"),  # disagree
    ]
    assets = [twin_a, twin_b, squashed, conflicted, other_side, address_only, genuinely_rogue]

    result = reconcile(records, assets)
    diff = result.diff(TENANT, computed_at=NOW)

    ambiguous_ids = {finding.asset_id for finding in diff.ambiguous if finding.asset_id}
    unmanaged_ids = {finding.asset_id for finding in diff.unmanaged}

    assert ambiguous_ids & unmanaged_ids == set()
    assert unmanaged_ids == {genuinely_rogue.asset_id}  # only the defensible one
    assert diff.shadow_it_count == 1
    for asset_id in ambiguous_ids:
        assert result.states[asset_id] is ManagementState.UNKNOWN


def test_strong_anchors_that_disagree_are_ambiguous_not_a_guess() -> None:
    """A record whose serial names one asset and whose MAC names another is a data-quality
    problem in the CMDB. Picking a winner would be inventing a fact (AGENTS.md §2.8)."""
    by_serial = asset(serials=("SN-CONFLICT",))
    by_mac = asset(macs=("11:22:33:44:55:66",))

    diff = diff_of([record(serial="SN-CONFLICT", mac="11:22:33:44:55:66")], [by_serial, by_mac])

    assert diff.shadow_it_count == 0
    assert diff.counts["ambiguous"] == 3  # the record, plus both candidate assets
    assert "disagree" in diff.ambiguous[0].reason
    assert sorted(diff.ambiguous[0].candidate_asset_ids) == sorted(
        [by_serial.asset_id, by_mac.asset_id]
    )


def test_an_asset_with_no_comparable_anchor_is_ambiguous_not_shadow_it() -> None:
    """An asset known only by its address cannot be looked up in a CMDB at all, so calling
    it unmanaged would be a claim about a test we never ran. IP is a locator, never an
    identity (AGENTS.md §3)."""
    address_only = asset()

    result = reconcile([], [address_only])
    diff = result.diff(TENANT, computed_at=NOW)

    assert diff.shadow_it_count == 0
    assert diff.counts["ambiguous"] == 1
    assert "cannot be looked up" in diff.ambiguous[0].reason
    assert result.states[address_only.asset_id] is ManagementState.UNKNOWN


def test_the_ambiguous_queue_carries_its_candidates_for_a_later_proposer() -> None:
    """The LLM seam (m2-design §3): the findings an M3 proposer would reason over already
    name the assets in question. Nothing here calls a model."""
    first = asset(hostnames=("srv-app-03",))
    second = asset(hostnames=("srv-app-03",))

    diff = diff_of([record(hostname="srv-app-03")], [first, second])

    record_finding = next(f for f in diff.ambiguous if f.record_id is not None)
    assert sorted(record_finding.candidate_asset_ids) == sorted([first.asset_id, second.asset_id])


def test_the_ambiguous_rate_is_measurable() -> None:
    """The number the runbook asks an operator to measure: it is the signal for whether
    deterministic matching suffices on this estate (m2-design §5)."""
    twin_a = asset(hostnames=("dup",))
    twin_b = asset(hostnames=("dup",))
    clean = asset(serials=("SN-1",))

    diff = diff_of([record(hostname="dup"), record(serial="SN-1")], [twin_a, twin_b, clean])

    assert diff.ambiguous_rate == pytest.approx(2 / 3)


# ---------------------------------------------------------- hostname handling


@pytest.mark.parametrize(
    ("cmdb_name", "discovered_name", "should_link"),
    [
        ("SRV-APP-03", "srv-app-03", True),  # case only
        ("srv-app-03.corp.local", "srv-app-03", True),  # DNS domain suffix
        ("srv-app-03.", "srv-app-03", True),  # trailing FQDN dot
        ("SRV-APP-03.CORP.LOCAL", "srv-app-03.corp.local", True),  # both
        ("srvapp03", "srv-app-03", False),  # punctuation removed — ambiguous, not a link
        ("srv-app-04", "srv-app-03", False),  # a different machine
    ],
)
def test_hostname_matching_follows_the_documented_rules(
    cmdb_name: str, discovered_name: str, should_link: bool
) -> None:
    """Case and domain suffix are safe to normalise silently — a location is not a name.
    Deleting punctuation is not, because `a-b1` and `ab-1` squash identically (ADR-0009)."""
    server = asset(hostnames=(discovered_name,))

    result = reconcile([record(hostname=cmdb_name)], [server])

    assert bool(result.links) is should_link
    if should_link:
        assert result.links[0].strength is MatchStrength.WEAK  # a name is never strong
        assert result.states[server.asset_id] is ManagementState.MANAGED


def test_a_squash_only_similarity_is_ambiguous_rather_than_shadow_it() -> None:
    """`srvapp03` in the CMDB, `srv-app-03` on the network: probably the same machine, and
    "probably" is not something this layer is allowed to conclude — but it is emphatically
    not evidence that nobody manages it."""
    server = asset(hostnames=("srv-app-03",))

    result = reconcile([record(hostname="srvapp03")], [server])
    diff = result.diff(TENANT, computed_at=NOW)

    assert diff.shadow_it_count == 0
    assert diff.counts["ambiguous"] == 2  # the record and the candidate asset
    assert result.states[server.asset_id] is ManagementState.UNKNOWN


def test_hostname_normalisation_is_directly_testable() -> None:
    assert normalize_hostname("SRV-APP-03.corp.local.") == "srv-app-03"
    assert squash_hostname("SRV-APP-03.corp.local") == "srvapp03"


def test_a_strong_anchor_beats_a_hostname_that_points_elsewhere() -> None:
    """Anchor priority, as the entity resolution defines it: a serial settles the question
    and a name does not get a vote (AGENTS.md §3)."""
    right = asset(serials=("SN-1",), hostnames=("renamed-host",))
    decoy = asset(hostnames=("old-host",))

    result = reconcile([record(serial="SN-1", hostname="old-host")], [right, decoy])

    assert result.links[0].asset_id == right.asset_id
    assert result.links[0].strength is MatchStrength.STRONG
    assert result.states[decoy.asset_id] is ManagementState.UNMANAGED  # nothing claimed it


# ----------------------------------------------------------------- stability


def test_recomputing_over_unchanged_state_gives_the_same_answer() -> None:
    """A diff that drifted between runs would be impossible to act on."""
    assets = [
        asset(serials=("SN-1",)),
        asset(macs=("aa:bb:cc:dd:ee:ff",)),
        asset(hostnames=("dup",)),
        asset(hostnames=("dup",)),
    ]
    records = [record(serial="SN-1"), record(hostname="dup"), record(serial="SN-GONE")]

    first = reconcile(records, assets).diff(TENANT, computed_at=NOW)
    second = reconcile(records, assets).diff(TENANT, computed_at=NOW)

    assert first.counts == second.counts
    assert {f.asset_id for f in first.unmanaged} == {f.asset_id for f in second.unmanaged}
    assert first.model_dump() == second.model_dump()


def test_an_empty_estate_produces_an_empty_diff() -> None:
    diff = diff_of([], [])

    assert diff.counts == {"matched": 0, "unmanaged": 0, "stale": 0, "ambiguous": 0}
    assert diff.ambiguous_rate == 0.0


def test_every_asset_lands_in_exactly_one_category() -> None:
    """No asset is counted twice, and none is silently omitted — the diff is a partition of
    the estate, which is what makes its totals mean anything."""
    assets = [
        asset(serials=("SN-1",)),
        asset(macs=("aa:bb:cc:dd:ee:ff",)),
        asset(hostnames=("dup",)),
        asset(hostnames=("dup",)),
        asset(),
    ]
    records = [record(serial="SN-1"), record(hostname="dup")]

    diff = diff_of(records, assets)

    reported = [
        finding.asset_id
        for finding in (*diff.matched, *diff.unmanaged, *diff.ambiguous)
        if finding.asset_id
    ]
    assert sorted(reported) == sorted(a.asset_id for a in assets)
    assert len(reported) == len(set(reported))
