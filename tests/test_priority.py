"""Priority: the band, and the reason it can give for itself.

This is where the product decides what an analyst looks at first, so the tests are about two
things and not one. The band has to be *right* — KEV on top, probable never at the top until
somebody verifies it — and it has to be *explainable*: every match carries the rule id that
produced it and a sentence naming the evidence. An unexplainable priority is the exact
failure this product displaces (ux-design §2), so "there is a reason, and it mentions the
actual numbers" is asserted as hard as the band itself.
"""

from __future__ import annotations

import pytest

from domain.models import ConfidenceState, Priority
from engine.priority import (
    CRITICAL_CVSS,
    ELEVATED_EPSS,
    FALLBACK_RULE,
    HIGH_CVSS,
    HIGH_EPSS,
    KEV_FLOOR,
    RULES,
    PriorityInputs,
    derive_priority,
    rule_ids,
)

CVE = "CVE-2023-25690"


def inputs(**overrides: object) -> PriorityInputs:
    fields: dict[str, object] = {
        "cve_id": CVE,
        "confidence_state": ConfidenceState.CONFIRMED,
        "kev": False,
        "epss": None,
        "cvss_score": None,
    }
    fields.update(overrides)
    return PriorityInputs(**fields)  # type: ignore[arg-type]


# ------------------------------------------------------------------ KEV outranks everything


@pytest.mark.parametrize(
    "state",
    [ConfidenceState.CONFIRMED, ConfidenceState.PROBABLE, ConfidenceState.VERIFIED_EXPLOITABLE],
)
def test_a_kev_match_is_top_band_whatever_the_version_evidence(state: ConfidenceState) -> None:
    """CISA says this is being exploited *now*. How we identified the version changes how
    urgently we should verify it, not whether it belongs at the top (ux-design §3.1)."""
    decision = derive_priority(inputs(confidence_state=state, kev=True))

    assert decision.priority is Priority.P1


@pytest.mark.parametrize(("epss", "cvss"), [(None, None), (0.0, 0.0), (0.00001, 1.0), (None, 2.3)])
def test_a_kev_match_stays_top_band_even_with_the_weakest_scores(
    epss: float | None, cvss: float | None
) -> None:
    """A low EPSS on a KEV-listed CVE is a contradiction in the data, not permission to
    de-prioritise it. Observed exploitation outranks a model's estimate of exploitation."""
    decision = derive_priority(
        inputs(confidence_state=ConfidenceState.PROBABLE, kev=True, epss=epss, cvss_score=cvss)
    )

    assert decision.priority is Priority.P1
    assert decision.rule_id == "kev-actively-exploited"


def test_no_rule_can_put_a_kev_finding_below_the_floor() -> None:
    """The safety assertion of this file, stated over the rules themselves rather than over
    a sample.

    Every rule in the table is evaluated against a KEV match, and none of them may yield a
    band worse than the floor. This is what makes the floor a property of the module instead
    of a property of the current ordering — a rule inserted in the wrong place two years
    from now fails here (AGENTS.md §4.9).
    """
    bands = [Priority.P1, Priority.P2, Priority.P3, Priority.P4]
    floor_index = bands.index(KEV_FLOOR)

    for state in ConfidenceState:
        for epss in (None, 0.0, 0.005, 0.05, 0.5, 1.0):
            for cvss in (None, 0.0, 3.1, 7.5, 9.9, 10.0):
                decision = derive_priority(
                    inputs(confidence_state=state, kev=True, epss=epss, cvss_score=cvss)
                )
                assert bands.index(decision.priority) <= floor_index, (
                    f"a KEV match reached {decision.priority} via {decision.rule_id}"
                )


def test_the_floor_fires_when_the_rules_would_have_gone_lower() -> None:
    """The clamp is belt-and-braces over rule ordering, and it says so when it acts — the
    reason names the rule it overrode, so nobody has to guess why a band moved."""
    from engine.priority import PriorityDecision, _floored

    decision = _floored(
        inputs(kev=True), PriorityDecision(Priority.P4, "some-future-rule", "because")
    )

    assert decision.priority is KEV_FLOOR
    assert decision.rule_id == "kev-floor"
    assert "some-future-rule" in decision.reason
    assert "known-exploited" in decision.reason


# --------------------------------------------------- probable never reaches the top band


@pytest.mark.parametrize(
    ("epss", "cvss"),
    [(0.99, 10.0), (0.5, 9.9), (0.11, 9.0), (None, 10.0), (0.9, None)],
)
def test_a_probable_non_kev_match_never_reaches_the_top_band(
    epss: float | None, cvss: float | None
) -> None:
    """A banner-inferred version may already be patched — a distribution that backported the
    fix serves the old version string forever. Sending an analyst to patch that is how a
    scanner loses their trust, so `probable` is a *verification* queue until somebody logs
    in (ux-design §2, AGENTS.md §3)."""
    decision = derive_priority(
        inputs(confidence_state=ConfidenceState.PROBABLE, epss=epss, cvss_score=cvss)
    )

    assert decision.priority is not Priority.P1
    assert "verify" in decision.reason.lower() or "queue" in decision.reason.lower()


def test_a_probable_match_with_high_epss_is_still_worth_scheduling() -> None:
    """The other half: `probable` is not `ignore`. Something likely to be exploited that we
    have not verified is exactly what the "needs verification" queue is for."""
    decision = derive_priority(inputs(confidence_state=ConfidenceState.PROBABLE, epss=0.42))

    assert decision.priority is Priority.P2
    assert decision.rule_id == "probable-high-epss"


def test_the_same_evidence_confirmed_outranks_probable() -> None:
    """The single comparison the confidence stratification exists to make."""
    evidence = {"epss": 0.42, "cvss_score": 9.8}

    confirmed = derive_priority(inputs(confidence_state=ConfidenceState.CONFIRMED, **evidence))
    probable = derive_priority(inputs(confidence_state=ConfidenceState.PROBABLE, **evidence))

    assert confirmed.priority is Priority.P1
    assert probable.priority is Priority.P2


# ------------------------------------------------------------------------ the bands


@pytest.mark.parametrize(
    ("case", "expected", "rule"),
    [
        (
            {"confidence_state": ConfidenceState.VERIFIED_EXPLOITABLE},
            Priority.P1,
            "verified-exploitable",
        ),
        ({"kev": True}, Priority.P1, "kev-actively-exploited"),
        ({"epss": HIGH_EPSS}, Priority.P1, "actionable-high-epss"),
        ({"cvss_score": CRITICAL_CVSS}, Priority.P2, "actionable-critical-cvss"),
        ({"epss": ELEVATED_EPSS}, Priority.P2, "actionable-elevated-epss"),
        ({"cvss_score": HIGH_CVSS}, Priority.P2, "actionable-high-cvss"),
        ({"cvss_score": 5.0}, Priority.P3, "actionable-moderate"),
        ({"epss": 0.001}, Priority.P3, "actionable-moderate"),
        ({}, Priority.P3, "actionable-moderate"),
        (
            {"confidence_state": ConfidenceState.PROBABLE, "cvss_score": 8.0},
            Priority.P3,
            "probable-severe-unverified",
        ),
        (
            {"confidence_state": ConfidenceState.PROBABLE, "cvss_score": 4.0},
            Priority.P4,
            "probable-unverified",
        ),
    ],
)
def test_each_band_comes_from_the_rule_that_names_it(
    case: dict[str, object], expected: Priority, rule: str
) -> None:
    """The whole table, one row at a time. Reading this parametrisation should tell you the
    policy without reading the module — which is the point of rules over a formula."""
    decision = derive_priority(inputs(**case))

    assert decision.priority is expected
    assert decision.rule_id == rule


@pytest.mark.parametrize("threshold", [HIGH_EPSS, ELEVATED_EPSS])
def test_an_epss_threshold_is_inclusive_at_its_boundary(threshold: float) -> None:
    """`>=`, not `>`. A CVE sitting exactly on the published line belongs on the urgent side
    of it — the thresholds are cuts in a continuum, and rounding down at the boundary would
    make the band depend on floating-point luck."""
    at = derive_priority(inputs(epss=threshold))
    below = derive_priority(inputs(epss=threshold - 0.000001))

    assert at.priority != below.priority or at.rule_id != below.rule_id


@pytest.mark.parametrize("threshold", [CRITICAL_CVSS, HIGH_CVSS])
def test_a_cvss_threshold_is_inclusive_at_its_boundary(threshold: float) -> None:
    """CVSS 9.0 is critical and 7.0 is high in the standard's own rating scale — the
    boundaries are theirs, and this pins that we read them the same way."""
    assert (
        derive_priority(inputs(cvss_score=threshold)).rule_id
        != derive_priority(inputs(cvss_score=threshold - 0.1)).rule_id
    )


# ------------------------------------------------------------- absence is not a low score


def test_a_missing_epss_is_not_treated_as_a_low_epss() -> None:
    """FIRST not having scored a CVE says nothing about it. Treating silence as 0.0 would
    quietly push everything newly published to the bottom of the worklist — the sort of
    false negative this codebase keeps refusing to introduce (AGENTS.md §67)."""
    unscored = derive_priority(inputs(cvss_score=9.5, epss=None))
    scored_low = derive_priority(inputs(cvss_score=9.5, epss=0.0))

    assert unscored.priority is scored_low.priority is Priority.P2
    assert "EPSS" not in unscored.reason  # it did not claim to know one


def test_a_match_with_no_published_evidence_lands_in_the_bottom_band_with_a_reason() -> None:
    """ "We know very little about this one" is a real state, and it belongs at the bottom of
    a worklist rather than missing from it."""
    decision = derive_priority(
        inputs(confidence_state=ConfidenceState.PROBABLE, epss=None, cvss_score=None)
    )

    assert decision.priority is Priority.P4
    assert decision.reason


# ------------------------------------------------------- every priority explains itself


def test_every_decision_carries_a_rule_id_and_a_reason() -> None:
    """The property that makes the band trustworthy. Exhaustive over the input space rather
    than sampled: there is no combination of evidence that yields a band with no
    explanation, because the interface has nothing else to show (ux-design §2)."""
    known = set(rule_ids())

    for state in ConfidenceState:
        for kev in (True, False):
            for epss in (None, 0.0, 0.005, 0.2, 1.0):
                for cvss in (None, 0.0, 4.0, 7.0, 9.9):
                    decision = derive_priority(
                        inputs(confidence_state=state, kev=kev, epss=epss, cvss_score=cvss)
                    )
                    assert decision.rule_id in known
                    assert len(decision.reason) > 40, decision
                    assert CVE in decision.reason


def test_the_reason_quotes_the_evidence_that_produced_the_band() -> None:
    """Not a template sentence: the numbers in the reason are the numbers that decided it,
    so an analyst who disagrees can see exactly what they are disagreeing with."""
    decision = derive_priority(inputs(epss=0.42, cvss_score=9.8))

    assert "42%" in decision.reason
    assert "10%" in decision.reason  # the threshold it cleared
    assert "package database" in decision.reason  # and the version evidence behind it


def test_a_kev_reason_names_cisa() -> None:
    """The analyst should never have to ask why something is at the top."""
    decision = derive_priority(inputs(kev=True))

    assert "CISA" in decision.reason
    assert CVE in decision.reason


def test_rule_ids_are_unique() -> None:
    """They are stored on every match and will end up in a UI legend and in queries; two
    rules sharing an id would make a stored priority ambiguous about its own cause."""
    ids = [rule.rule_id for rule in RULES] + [FALLBACK_RULE.rule_id]

    assert len(ids) == len(set(ids))


def test_every_rule_id_is_slug_shaped() -> None:
    for rule_id in rule_ids():
        assert rule_id == rule_id.lower()
        assert " " not in rule_id


# ------------------------------------------------------------------------ determinism


def test_recomputation_over_unchanged_inputs_is_stable() -> None:
    """Idempotent by construction — a pure function of five values. Asserted because the
    correlator re-derives the band on every run, and a priority that drifted between runs
    would churn a worklist an analyst is trying to work through."""
    case = inputs(confidence_state=ConfidenceState.PROBABLE, kev=False, epss=0.05, cvss_score=8.1)

    first = derive_priority(case)
    again = [derive_priority(case) for _ in range(25)]

    assert all(decision == first for decision in again)


def test_the_bands_are_ordered_by_urgency_not_by_declaration() -> None:
    """A sanity check on the enum itself: P1 sorts before P4 wherever the UI sorts on it."""
    assert sorted([Priority.P4, Priority.P1, Priority.P3, Priority.P2]) == [
        Priority.P1,
        Priority.P2,
        Priority.P3,
        Priority.P4,
    ]
