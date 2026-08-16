"""Deterministic correlation: version ranges, confidence derivation, KEV, and failures.

The correctness-critical file of P14 and of M3's Half A. Everything the LLM reasons about in
Half B stands on these matches, so two properties carry the file:

* **A version outside a CVE's affected range never produces a match.** A spurious match is a
  false positive that discredits the tool and a fiction for the model to reason about.
* **`confidence_state` is derived, never guessed.** `package_manager` means the device's own
  package database said so; `banner` means a service advertised a string that a backported
  fix may have left stale. That flag is the whole point of the stratification.

Fakes throughout: no feed, no network, no database (AGENTS.md §43).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from domain.errors import DependencyError, ValidationError
from domain.models import (
    ComponentSnapshot,
    ConfidenceState,
    CpeMatch,
    CveRecord,
    EpssScore,
    FeedFetchReport,
    VersionSource,
    VulnerabilityMatchInput,
    VulnerabilityMatchRecord,
)
from engine.correlation import VulnerabilityCorrelator, derive_confidence_state
from engine.cpe import RangeVerdict

TENANT = UUID("11111111-1111-1111-1111-111111111111")
NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)

APACHE_2452 = "cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*"
APACHE_ANY = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
NGINX_ANY = "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"


# --------------------------------------------------------------------------- fakes


def cve(
    cve_id: str = "CVE-2024-27316",
    *,
    matches: Sequence[CpeMatch] | None = None,
) -> CveRecord:
    return CveRecord(
        cve_id=cve_id,
        description="a flaw",
        cvss_score=7.5,
        cpe_matches=list(matches) if matches is not None else [CpeMatch(criteria=APACHE_ANY)],
        fetched_at=NOW,
        raw_record_ref=f"nvd:{cve_id}",
    )


def component(
    *,
    cpe: str | None = None,
    version: str | None = "2.4.52",
    version_source: VersionSource = VersionSource.PACKAGE_MANAGER,
) -> ComponentSnapshot:
    """A component whose CPE and reported version agree, unless a test says otherwise.

    They agree by default because that is the real-world case, and a helper that let them
    drift would test a situation that does not occur while hiding the one that does.
    """
    if cpe is None:
        cpe = f"cpe:2.3:a:apache:http_server:{version or '*'}:*:*:*:*:*:*:*"
    return ComponentSnapshot(
        component_id=uuid4(),
        asset_id=uuid4(),
        tenant_id=TENANT,
        cpe=cpe,
        name="apache2",
        version=version,
        version_source=version_source,
    )


class FakeFeed:
    def __init__(
        self, records: Sequence[CveRecord] = (), *, raises: Exception | None = None
    ) -> None:
        self.records = list(records)
        self.raises = raises
        self.queried: list[str] = []

    def cves_for_cpe(self, cpe: str) -> Sequence[CveRecord]:
        self.queried.append(cpe)
        if self.raises is not None:
            raise self.raises
        return self.records

    def cve(self, cve_id: str) -> CveRecord | None:  # pragma: no cover — unused here
        return next((record for record in self.records if record.cve_id == cve_id), None)

    def fetch_report(self) -> FeedFetchReport:
        return FeedFetchReport()


class FakeKev:
    def __init__(
        self, exploited: set[str] | None = None, *, raises: Exception | None = None
    ) -> None:
        self.exploited = exploited or set()
        self.raises = raises
        self.asked: list[str] = []

    def is_known_exploited(self, cve_id: str) -> bool:
        self.asked.append(cve_id)
        if self.raises is not None:
            raise self.raises
        return cve_id in self.exploited

    def entry(self, cve_id: str) -> None:  # pragma: no cover — unused here
        return None

    def refresh(self) -> FeedFetchReport:  # pragma: no cover
        return FeedFetchReport()

    def fetch_report(self) -> FeedFetchReport:
        return FeedFetchReport()


class FakeEpss:
    def __init__(
        self, scores: dict[str, float] | None = None, *, raises: Exception | None = None
    ) -> None:
        self.scores = scores or {}
        self.raises = raises

    def score_for(self, cve_id: str) -> EpssScore | None:
        if self.raises is not None:
            raise self.raises
        value = self.scores.get(cve_id)
        if value is None:
            return None
        return EpssScore(cve_id=cve_id, score=value, percentile=0.5, fetched_at=NOW)

    def refresh(self) -> FeedFetchReport:  # pragma: no cover
        return FeedFetchReport()

    def fetch_report(self) -> FeedFetchReport:
        return FeedFetchReport()


class FakeStore:
    def __init__(self, components: Sequence[ComponentSnapshot] = ()) -> None:
        self.components = list(components)
        self.recorded: list[VulnerabilityMatchInput] = []
        self.seen: set[tuple[str, str]] = set()

    def components_with_cpe(self, tenant_id: UUID) -> Sequence[ComponentSnapshot]:
        return self.components

    def record_match(self, match: VulnerabilityMatchInput) -> VulnerabilityMatchRecord:
        self.recorded.append(match)
        key = (match.cve_id, match.matched_cpe)
        created = key not in self.seen
        self.seen.add(key)
        return VulnerabilityMatchRecord(match_id=uuid4(), created=created)


def correlator(
    feed: FakeFeed,
    *,
    kev: FakeKev | None = None,
    epss: FakeEpss | None = None,
    store: FakeStore | None = None,
) -> tuple[VulnerabilityCorrelator, FakeStore]:
    resolved_store = store or FakeStore()
    return (
        VulnerabilityCorrelator(feed, kev or FakeKev(), epss or FakeEpss(), resolved_store),
        resolved_store,
    )


# ------------------------------------------------- THE VERSION-RANGE BOUNDARY TEST


@pytest.mark.parametrize(
    ("version", "should_match"),
    [
        ("2.4.0", True),  # exactly the lower bound, which is *including*
        ("2.4.1", True),  # just inside
        ("2.4.57", True),  # the last affected version
        ("2.4.58", False),  # exactly the upper bound, which is *excluding*
        ("2.4.59", False),  # just outside
        ("2.3.99", False),  # below the range entirely
        ("2.4.10", True),  # numeric ordering: 10 > 9, which a lexical compare gets wrong
        ("2.4.6", True),  # …and 6 < 57, which a lexical compare also gets wrong
    ],
)
def test_a_version_outside_the_affected_range_never_matches(
    version: str, should_match: bool
) -> None:
    """The correctness-critical assertion of P14.

    NVD publishes `versionStartIncluding: 2.4.0, versionEndExcluding: 2.4.58`, and those
    boundary semantics are exact: 2.4.0 *is* affected, 2.4.58 is *not*. A CVE matched to a
    version it does not affect is a false positive that discredits the tool; the same
    mistake in the other direction hides a real vulnerability (AGENTS.md §4.9).

    The 2.4.6 and 2.4.10 cases are here because a lexical comparison — the obvious wrong
    implementation — puts "2.4.6" after "2.4.57" and "2.4.10" before "2.4.9".
    """
    affected = cve(
        matches=[
            CpeMatch(
                criteria=APACHE_ANY,
                version_start_including="2.4.0",
                version_end_excluding="2.4.58",
            )
        ]
    )
    engine, store = correlator(FakeFeed([affected]))

    outcome = engine.correlate([component(version=version)])

    assert (outcome.matches == 1) is should_match
    assert (len(store.recorded) == 1) is should_match
    if not should_match:
        assert outcome.filtered_out_of_range == 1
        assert store.recorded == []  # nothing was written at all


def test_an_excluding_lower_bound_excludes_its_own_value() -> None:
    """`versionStartExcluding: 2.4.0` means 2.4.0 itself is *not* affected — the mirror of
    the upper-bound case, and just as easy to get backwards."""
    affected = cve(matches=[CpeMatch(criteria=APACHE_ANY, version_start_excluding="2.4.0")])
    engine, _ = correlator(FakeFeed([affected]))

    assert engine.correlate([component(version="2.4.0")]).matches == 0
    assert engine.correlate([component(version="2.4.1")]).matches == 1


def test_an_including_upper_bound_includes_its_own_value() -> None:
    affected = cve(matches=[CpeMatch(criteria=APACHE_ANY, version_end_including="2.4.52")])
    engine, _ = correlator(FakeFeed([affected]))

    assert engine.correlate([component(version="2.4.52")]).matches == 1
    assert engine.correlate([component(version="2.4.53")]).matches == 0


def test_a_criterion_pinned_to_one_version_matches_only_that_version() -> None:
    """NVD also publishes criteria with a concrete version and no bounds. That means exactly
    one affected version, not "this and everything after"."""
    affected = cve(matches=[CpeMatch(criteria=APACHE_2452)])
    engine, _ = correlator(FakeFeed([affected]))

    assert engine.correlate([component(version="2.4.52")]).matches == 1
    assert engine.correlate([component(version="2.4.53")]).matches == 0
    assert engine.correlate([component(version="2.4.51")]).matches == 0


def test_a_criterion_with_no_version_and_no_bounds_affects_every_version() -> None:
    """NVD does publish these, and it does mean it: the whole product is affected."""
    affected = cve(matches=[CpeMatch(criteria=APACHE_ANY)])
    engine, _ = correlator(FakeFeed([affected]))

    assert engine.correlate([component(version="1.0")]).matches == 1
    assert engine.correlate([component(version="99.0")]).matches == 1


def test_a_different_product_never_matches_however_the_versions_line_up() -> None:
    """The identity check comes before the version check: an nginx CVE is not an Apache
    finding, whatever the numbers say."""
    nginx_cve = cve(matches=[CpeMatch(criteria=NGINX_ANY, version_end_excluding="2.4.58")])
    engine, store = correlator(FakeFeed([nginx_cve]))

    outcome = engine.correlate([component(version="2.4.52")])

    assert outcome.matches == 0
    assert store.recorded == []


def test_a_criterion_marked_not_vulnerable_is_not_a_match() -> None:
    """NVD marks some criteria as the *platform* a vulnerable component runs on. Matching on
    those would report the operating system as vulnerable to the application's CVE."""
    platform_only = cve(matches=[CpeMatch(criteria=APACHE_ANY, vulnerable=False)])
    engine, _ = correlator(FakeFeed([platform_only]))

    assert engine.correlate([component()]).matches == 0


# ------------------------------------------- THE CONFIDENCE-STATE DERIVATION TEST


@pytest.mark.parametrize(
    ("version_source", "expected"),
    [
        (VersionSource.PACKAGE_MANAGER, ConfidenceState.CONFIRMED),
        (VersionSource.VENDOR_API, ConfidenceState.CONFIRMED),
        (VersionSource.BANNER, ConfidenceState.PROBABLE),
    ],
)
def test_confidence_state_is_derived_from_the_version_source(
    version_source: VersionSource, expected: ConfidenceState
) -> None:
    """The other correctness-critical assertion (dossier contract, AGENTS.md §3).

    A package database says what is *installed* — ground truth, so `confirmed`. A vendor API
    is the manufacturer saying the same thing about its own firmware. A banner says what a
    service *claims*, and a distribution that backported the fix serves the old version
    string forever — so `probable`, which is what stops that backport from becoming a false
    positive downstream.
    """
    engine, store = correlator(FakeFeed([cve()]))

    engine.correlate([component(version_source=version_source)])

    assert len(store.recorded) == 1
    assert store.recorded[0].confidence_state is expected
    assert store.recorded[0].version_source is version_source


def test_verified_exploitable_is_never_produced_by_correlation() -> None:
    """It is reserved for a later `check` step that actually demonstrates exploitability.
    Correlation has demonstrated nothing of the sort (m3-design §2)."""
    engine, store = correlator(
        FakeFeed([cve("CVE-2024-1"), cve("CVE-2024-2"), cve("CVE-2024-3")]),
        kev=FakeKev({"CVE-2024-1", "CVE-2024-2", "CVE-2024-3"}),
        epss=FakeEpss({"CVE-2024-1": 0.9}),
    )

    for source in VersionSource:
        engine.correlate([component(version_source=source)])

    assert store.recorded
    for match in store.recorded:
        assert match.confidence_state is not ConfidenceState.VERIFIED_EXPLOITABLE


def test_the_derivation_function_is_directly_testable() -> None:
    assert derive_confidence_state(VersionSource.PACKAGE_MANAGER) is ConfidenceState.CONFIRMED
    assert derive_confidence_state(VersionSource.VENDOR_API) is ConfidenceState.CONFIRMED
    assert derive_confidence_state(VersionSource.BANNER) is ConfidenceState.PROBABLE


def test_an_undecidable_version_comparison_is_never_confirmed() -> None:
    """A refinement beyond the source alone, and the reason it exists: "confirmed" has to
    mean we checked. A match kept despite an unparseable version stays visible — hiding it
    would be the false negative — but it does not claim a certainty nobody established
    (ADR-0012)."""
    assert (
        derive_confidence_state(VersionSource.PACKAGE_MANAGER, RangeVerdict.INCONCLUSIVE)
        is ConfidenceState.PROBABLE
    )

    affected = cve(matches=[CpeMatch(criteria=APACHE_ANY, version_end_excluding="2.4.58")])
    engine, store = correlator(FakeFeed([affected]))

    outcome = engine.correlate(
        [
            component(
                cpe="cpe:2.3:a:apache:http_server:unknown:*:*:*:*:*:*:*",
                version="unknown",
                version_source=VersionSource.PACKAGE_MANAGER,
            )
        ]
    )

    assert outcome.matches == 1  # kept — an unreadable version is not evidence of safety
    assert outcome.inconclusive_versions == 1
    assert store.recorded[0].confidence_state is ConfidenceState.PROBABLE


def test_every_match_is_marked_deterministic() -> None:
    """No model decides that a vulnerability exists (AGENTS.md §2.8, §4.8). The database
    CHECK says so too; this asserts the value that reaches it."""
    engine, store = correlator(FakeFeed([cve()]))

    engine.correlate([component()])

    assert store.recorded[0].derivation == "deterministic"


# ------------------------------------------------------------------ KEV and EPSS


def test_a_kev_listed_cve_is_flagged_even_on_a_probable_match() -> None:
    """The override (dossier contract §7): a banner-inferred match is still `probable` — the
    KEV flag does not launder weak version evidence — but the flag travels with it so no
    view can quietly drop an actively-exploited finding."""
    engine, store = correlator(FakeFeed([cve("CVE-2021-44228")]), kev=FakeKev({"CVE-2021-44228"}))

    outcome = engine.correlate([component(version_source=VersionSource.BANNER)])

    match = store.recorded[0]
    assert match.kev is True
    assert match.confidence_state is ConfidenceState.PROBABLE  # not upgraded by KEV
    assert outcome.kev_matches == 1


def test_a_cve_not_in_kev_is_flagged_false() -> None:
    engine, store = correlator(FakeFeed([cve()]), kev=FakeKev(set()))

    engine.correlate([component()])

    assert store.recorded[0].kev is False


def test_the_epss_score_is_carried_onto_the_match() -> None:
    engine, store = correlator(
        FakeFeed([cve("CVE-2021-44228")]), epss=FakeEpss({"CVE-2021-44228": 0.94366})
    )

    engine.correlate([component()])

    assert store.recorded[0].epss == pytest.approx(0.94366)


def test_a_cve_with_no_epss_score_still_produces_a_valid_match() -> None:
    """FIRST has not scored every CVE. A missing score is a missing gradient, not a missing
    vulnerability."""
    engine, store = correlator(FakeFeed([cve()]), epss=FakeEpss({}))

    outcome = engine.correlate([component()])

    assert outcome.matches == 1
    assert store.recorded[0].epss is None


# ------------------------------------------- FAILURE IS NEVER A CLEAN RESULT


def test_a_feed_failure_does_not_produce_a_clean_component() -> None:
    """The false-negative path P12 and P13 closed, arriving one layer later. A component
    whose lookup failed must never be recorded as having no vulnerabilities."""
    engine, store = correlator(FakeFeed(raises=DependencyError("NVD down", retryable=True)))

    outcome = engine.correlate([component()])

    assert outcome.matches == 0
    assert outcome.correlated == 0  # emphatically not "correlated, and clean"
    assert outcome.failed == 1
    assert outcome.complete is False
    assert store.recorded == []


def test_a_kev_failure_does_not_produce_matches_flagged_not_exploited() -> None:
    """A match written with `kev=false` because CISA was unreachable is an actively-exploited
    vulnerability silently de-prioritised (ADR-0011)."""
    engine, store = correlator(
        FakeFeed([cve()]), kev=FakeKev(raises=DependencyError("CISA down", retryable=True))
    )

    outcome = engine.correlate([component()])

    assert outcome.failed == 1
    assert store.recorded == []  # nothing half-written


def test_an_epss_failure_also_fails_the_component() -> None:
    engine, store = correlator(
        FakeFeed([cve()]), epss=FakeEpss(raises=DependencyError("FIRST down", retryable=True))
    )

    assert engine.correlate([component()]).failed == 1
    assert store.recorded == []


def test_one_failed_component_does_not_cost_the_others() -> None:
    """Same per-target shape as the sweep's denial and the scanner's breaker trip."""

    class SelectiveFeed(FakeFeed):
        def cves_for_cpe(self, cpe: str) -> Sequence[CveRecord]:
            self.queried.append(cpe)
            if "nginx" in cpe:
                raise DependencyError("NVD down", retryable=True)
            return [cve()]

    engine, store = correlator(SelectiveFeed())

    outcome = engine.correlate(
        [component(), component(cpe="cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*")]
    )

    assert outcome.failed == 1
    assert outcome.correlated == 1
    assert len(store.recorded) == 1


def test_an_incomplete_run_says_so() -> None:
    engine, _ = correlator(FakeFeed(raises=DependencyError("down", retryable=True)))

    assert engine.correlate([component()]).complete is False
    engine, _ = correlator(FakeFeed([cve()]))
    assert engine.correlate([component()]).complete is True


def test_a_component_with_no_matching_cves_is_a_real_clean_result() -> None:
    """The other side of the same coin: an empty answer from a *working* feed means this
    component genuinely has no known vulnerabilities."""
    engine, store = correlator(FakeFeed([]))

    outcome = engine.correlate([component()])

    assert outcome.matches == 0
    assert outcome.correlated == 1  # checked, and clean
    assert outcome.complete is True
    assert store.recorded == []


def test_a_component_whose_cpe_does_not_parse_is_skipped_and_counted() -> None:
    feed = FakeFeed([cve()])
    engine, store = correlator(feed)

    outcome = engine.correlate([component(cpe="not-a-cpe")])

    assert outcome.skipped_components == ("not-a-cpe",)
    assert feed.queried == []  # nothing was looked up
    assert store.recorded == []


# ------------------------------------------------------------------ idempotency


def test_re_correlating_produces_the_same_matches_without_duplicating() -> None:
    store = FakeStore()
    engine, _ = correlator(FakeFeed([cve()]), store=store)
    device = component()

    first = engine.correlate([device])
    second = engine.correlate([device])

    assert first.new_matches == 1
    assert second.new_matches == 0  # the store's unique key arbitrated
    assert second.matches == 1
    assert len({(m.cve_id, m.matched_cpe) for m in store.recorded}) == 1


def test_the_match_records_the_criterion_that_matched_not_our_own_cpe() -> None:
    """`matched_cpe` is the CVE's criterion, which is what makes the match auditable: it is
    the thing NVD said was affected."""
    affected = cve(
        matches=[
            CpeMatch(criteria=APACHE_ANY, version_end_excluding="2.4.58"),
            CpeMatch(criteria=NGINX_ANY),
        ]
    )
    engine, store = correlator(FakeFeed([affected]))

    engine.correlate([component()])

    assert store.recorded[0].matched_cpe == APACHE_ANY


def test_the_outcome_totals_add_up() -> None:
    engine, _ = correlator(
        FakeFeed([cve("CVE-2024-1"), cve("CVE-2024-2")]), kev=FakeKev({"CVE-2024-1"})
    )

    outcome = engine.correlate(
        [
            component(version_source=VersionSource.PACKAGE_MANAGER),
            component(version_source=VersionSource.BANNER),
        ]
    )

    assert outcome.components == 2
    assert outcome.matches == 4  # two CVEs against two components
    assert outcome.confirmed + outcome.probable == outcome.matches
    assert outcome.kev_matches == 2


def test_a_component_without_a_version_is_matched_conservatively() -> None:
    """No version at all: a ranged CVE cannot be decided, so the match is kept and marked
    `probable` rather than dropped."""
    ranged = cve(matches=[CpeMatch(criteria=APACHE_ANY, version_end_excluding="2.4.58")])
    engine, store = correlator(FakeFeed([ranged]))

    outcome = engine.correlate(
        [component(cpe=APACHE_ANY, version=None, version_source=VersionSource.PACKAGE_MANAGER)]
    )

    assert outcome.matches == 1
    assert store.recorded[0].confidence_state is ConfidenceState.PROBABLE


def test_the_correlator_refuses_a_cross_tenant_component() -> None:
    """The tenant on the match is the component's own, so a store handed a foreign component
    cannot smear one tenant's findings onto another."""
    engine, store = correlator(FakeFeed([cve()]))
    foreign = component()

    engine.correlate([foreign])

    assert store.recorded[0].tenant_id == foreign.tenant_id
    assert store.recorded[0].asset_id == foreign.asset_id


def test_an_empty_estate_correlates_to_nothing() -> None:
    engine, store = correlator(FakeFeed([cve()]))

    outcome = engine.correlate([])

    assert outcome.components == 0
    assert outcome.complete is True
    assert store.recorded == []


def test_a_validation_error_from_the_feed_fails_the_component_not_the_run() -> None:
    """A malformed feed response is a `ValidationError`, which is still a `DomainError` and
    still must not read as "this component is clean"."""
    engine, store = correlator(FakeFeed(raises=ValidationError("NVD returned nonsense")))

    outcome = engine.correlate([component()])

    assert outcome.failed == 1
    assert outcome.complete is False
    assert store.recorded == []
