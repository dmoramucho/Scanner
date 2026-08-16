"""Priority: an ordered list of rules, and the reason the winning one gives.

This module decides what an analyst looks at first, which makes it the product's most
consequential twenty lines. It is written as a **list of named rules, evaluated in order,
first match wins** — not a weighted score — for one reason: the analyst has to be able to
see *why* something is P1, and "0.87" is not a why (ux-design §2; the competitor's failure
this product exists to displace is exactly an unexplainable number).

Three properties follow from that shape:

**Every priority carries its own explanation.** `derive_priority` returns the band, the id
of the rule that produced it, and a sentence naming the actual evidence and the actual
threshold. Both are stored on the match, so the interface shows the reason without
re-deriving anything and without knowing these rules exist.

**Every threshold is somebody else's published number.** EPSS ≥ 0.10 is FIRST's commonly
cited operational cut for "likely to be exploited"; CVSS 9.0 and 7.0 are the v3 standard's
own critical/high boundaries. Nothing here is a number I chose because it felt right, which
is what makes the bands defensible to a CISO who disagrees with one (ADR-0015).

**KEV outranks everything, and cannot be argued down.** A CVE in CISA's catalog is being
exploited *now*; it is P1 whatever the version evidence says, and `KEV_FLOOR` makes it
impossible for any rule — or any later adjustment — to put it below P2. That mirrors the
same rule in the insight generator and in the database (dossier contract §7).

Pure and total: same inputs, same band, every time. No clock, no I/O, no model.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Final

from domain.models import ConfidenceState, Priority

#: FIRST publishes EPSS as the probability a CVE is exploited in the next 30 days. 0.10 is
#: the threshold most operational guidance uses for "act on this"; 0.01 already puts a CVE
#: in the top few percent of everything scored, so it is the "elevated" line.
HIGH_EPSS: Final = 0.10
ELEVATED_EPSS: Final = 0.01

#: CVSS v3 severity boundaries, from the standard's own rating scale — not invented here.
CRITICAL_CVSS: Final = 9.0
HIGH_CVSS: Final = 7.0

#: A KEV finding can never be worse than this, whatever else is true about it. Enforced as a
#: clamp rather than trusted to rule ordering, so a future rule inserted in the wrong place
#: cannot bury an actively-exploited vulnerability (ux-design §3.1, AGENTS.md §4.9).
KEV_FLOOR: Final = Priority.P2

#: Version evidence good enough to act on without logging in first. `probable` is a *work
#: queue* — a backported fix leaves the old banner in place — so it never reaches P1 on its
#: own (ux-design §2, AGENTS.md §3).
ACTIONABLE_STATES: Final = frozenset(
    {ConfidenceState.CONFIRMED, ConfidenceState.VERIFIED_EXPLOITABLE}
)

_BAND_ORDER: Final = (Priority.P1, Priority.P2, Priority.P3, Priority.P4)


@dataclass(frozen=True, slots=True)
class PriorityInputs:
    """Everything a band may be derived from. Deliberately four fields.

    If prioritisation ever needs a fifth, that is a product decision that belongs in the ADR
    and in this signature — not a term quietly added to a formula.
    """

    cve_id: str
    confidence_state: ConfidenceState
    kev: bool = False
    epss: float | None = None
    cvss_score: float | None = None

    @property
    def actionable(self) -> bool:
        """Is the version evidence strong enough to act on without verifying first?"""
        return self.confidence_state in ACTIONABLE_STATES

    def epss_at_least(self, threshold: float) -> bool:
        """An absent EPSS is *not* a low EPSS. FIRST not having scored a CVE says nothing
        about it, and treating silence as a low probability would quietly de-prioritise
        everything new (AGENTS.md §67)."""
        return self.epss is not None and self.epss >= threshold

    def cvss_at_least(self, threshold: float) -> bool:
        return self.cvss_score is not None and self.cvss_score >= threshold


@dataclass(frozen=True, slots=True)
class PriorityRule:
    """One legible rule: when it applies, what band it gives, and how it explains itself."""

    rule_id: str
    priority: Priority
    applies: Callable[[PriorityInputs], bool]
    explain: Callable[[PriorityInputs], str]


@dataclass(frozen=True, slots=True)
class PriorityDecision:
    """A band and the reason for it. Both are persisted; neither is re-derived downstream."""

    priority: Priority
    rule_id: str
    reason: str


def _confidence(inputs: PriorityInputs) -> str:
    """How the version was established, in the words an analyst uses."""
    return {
        ConfidenceState.CONFIRMED: "the installed version is confirmed from the device's "
        "own package database",
        ConfidenceState.VERIFIED_EXPLOITABLE: "exploitability has been verified on this asset",
        ConfidenceState.PROBABLE: "the version is inferred from a banner and may already be "
        "patched by a backport",
    }[inputs.confidence_state]


#: **The rules, in order. First match wins.** Read top to bottom: that is the whole policy.
#:
#: Ordering is the design. Exploitation evidence outranks severity, because a CVSS 9.8 that
#: nobody exploits is a worse use of an afternoon than a CVSS 6.5 that is being used today.
#: And confirmed outranks probable at every severity, because sending an analyst to patch a
#: backported package is how a scanner loses their trust (ux-design §2).
RULES: Final[tuple[PriorityRule, ...]] = (
    PriorityRule(
        rule_id="verified-exploitable",
        priority=Priority.P1,
        applies=lambda i: i.confidence_state is ConfidenceState.VERIFIED_EXPLOITABLE,
        explain=lambda i: (
            f"Exploitability of {i.cve_id} has been verified on this asset — the strongest "
            f"evidence the system produces."
        ),
    ),
    PriorityRule(
        rule_id="kev-actively-exploited",
        priority=Priority.P1,
        applies=lambda i: i.kev,
        explain=lambda i: (
            f"CISA lists {i.cve_id} as known exploited — attackers are using it now, so it "
            f"is P1 regardless of how the version was identified."
        ),
    ),
    PriorityRule(
        rule_id="actionable-high-epss",
        priority=Priority.P1,
        applies=lambda i: i.actionable and i.epss_at_least(HIGH_EPSS),
        explain=lambda i: (
            f"EPSS puts exploitation of {i.cve_id} at {i.epss:.0%} in the next 30 days "
            f"(at or above the {HIGH_EPSS:.0%} threshold), and {_confidence(i)}."
        ),
    ),
    PriorityRule(
        rule_id="actionable-critical-cvss",
        priority=Priority.P2,
        applies=lambda i: i.actionable and i.cvss_at_least(CRITICAL_CVSS),
        explain=lambda i: (
            f"CVSS rates {i.cve_id} critical at {i.cvss_score}, and {_confidence(i)}. No "
            f"exploitation has been observed in the wild, so it is scheduled rather than "
            f"dropped on the analyst today."
        ),
    ),
    PriorityRule(
        rule_id="actionable-elevated-epss",
        priority=Priority.P2,
        applies=lambda i: i.actionable and i.epss_at_least(ELEVATED_EPSS),
        explain=lambda i: (
            f"EPSS puts exploitation of {i.cve_id} at {i.epss:.1%} in the next 30 days "
            f"(above the {ELEVATED_EPSS:.0%} elevated line), and {_confidence(i)}."
        ),
    ),
    PriorityRule(
        rule_id="actionable-high-cvss",
        priority=Priority.P2,
        applies=lambda i: i.actionable and i.cvss_at_least(HIGH_CVSS),
        explain=lambda i: f"CVSS rates {i.cve_id} high at {i.cvss_score}, and {_confidence(i)}.",
    ),
    PriorityRule(
        rule_id="probable-high-epss",
        priority=Priority.P2,
        applies=lambda i: i.epss_at_least(HIGH_EPSS),
        explain=lambda i: (
            f"EPSS puts exploitation of {i.cve_id} at {i.epss:.0%} in the next 30 days, but "
            f"{_confidence(i)}. Verify the installed version by logging in — this cannot be "
            f"P1 until it is confirmed."
        ),
    ),
    PriorityRule(
        rule_id="actionable-moderate",
        priority=Priority.P3,
        applies=lambda i: i.actionable,
        explain=lambda i: (
            f"{_confidence(i).capitalize()}, but {i.cve_id} is neither severe nor likely to "
            f"be exploited on the published evidence."
        ),
    ),
    PriorityRule(
        rule_id="probable-severe-unverified",
        priority=Priority.P3,
        applies=lambda i: i.cvss_at_least(HIGH_CVSS) or i.epss_at_least(ELEVATED_EPSS),
        explain=lambda i: (
            f"{i.cve_id} would matter if it is really installed, but {_confidence(i)}. It "
            f"belongs in the verification queue rather than the patch queue."
        ),
    ),
    PriorityRule(
        rule_id="probable-unverified",
        priority=Priority.P4,
        applies=lambda i: i.confidence_state is ConfidenceState.PROBABLE,
        explain=lambda i: (
            f"{_confidence(i).capitalize()}, and {i.cve_id} is neither severe nor likely to "
            f"be exploited. Informational until something else changes."
        ),
    ),
)

#: The band for a match no rule claims: nothing severe, nothing exploited, nothing certain.
#: A default rather than an exception, because "we know very little about this one" is a
#: real state and it should be visible at the bottom of a worklist, not missing from it.
FALLBACK_RULE: Final = PriorityRule(
    rule_id="insufficient-signal",
    priority=Priority.P4,
    applies=lambda _i: True,
    explain=lambda i: (
        f"Neither CVSS nor EPSS is published for {i.cve_id} and it is not known to be "
        f"exploited, so there is nothing yet to raise it on."
    ),
)


def derive_priority(inputs: PriorityInputs) -> PriorityDecision:
    """The band for one match, with the rule and the sentence that produced it.

    Deterministic and total: every input produces a decision, the same one every time, and
    the reason names the evidence rather than describing the arithmetic.
    """
    for rule in RULES:
        if rule.applies(inputs):
            return _floored(
                inputs, PriorityDecision(rule.priority, rule.rule_id, rule.explain(inputs))
            )
    return _floored(
        inputs,
        PriorityDecision(
            FALLBACK_RULE.priority, FALLBACK_RULE.rule_id, FALLBACK_RULE.explain(inputs)
        ),
    )


def _floored(inputs: PriorityInputs, decision: PriorityDecision) -> PriorityDecision:
    """Apply the KEV floor, and say so if it changed anything.

    Belt and braces over rule ordering. The KEV rule already returns P1, so this should
    never fire — and it is here precisely because "should never fire" is what a rule
    inserted in the wrong place two years from now will quietly disprove (AGENTS.md §4.9).
    """
    if not inputs.kev or not _worse_than(decision.priority, KEV_FLOOR):
        return decision
    return PriorityDecision(
        priority=KEV_FLOOR,
        rule_id="kev-floor",
        reason=(
            f"Raised to {KEV_FLOOR.value.upper()}: {inputs.cve_id} is in CISA's known-exploited "
            f"catalog, which no other rule may put below {KEV_FLOOR.value.upper()} "
            f"(rule '{decision.rule_id}' would have given {decision.priority.value.upper()})."
        ),
    )


def _worse_than(candidate: Priority, floor: Priority) -> bool:
    """Is this band lower down the worklist than the floor allows?"""
    return _BAND_ORDER.index(candidate) > _BAND_ORDER.index(floor)


def rule_ids() -> tuple[str, ...]:
    """Every rule id this module can emit. Used by the store's CHECK and by the UI legend."""
    return (*(rule.rule_id for rule in (*RULES, FALLBACK_RULE)), "kev-floor")


__all__: Sequence[str] = [
    "ACTIONABLE_STATES",
    "CRITICAL_CVSS",
    "ELEVATED_EPSS",
    "FALLBACK_RULE",
    "HIGH_CVSS",
    "HIGH_EPSS",
    "KEV_FLOOR",
    "RULES",
    "PriorityDecision",
    "PriorityInputs",
    "PriorityRule",
    "derive_priority",
    "rule_ids",
]
