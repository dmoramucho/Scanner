"""Deterministic correlation: component → CVE → KEV → EPSS → `vulnerability_match`.

The last step with no model in it, and the foundation everything in Half B stands on
(m3-design §1). If a match here is wrong, every insight reasoning about it is reasoning
about a fiction — so this module is written to be *checkable* rather than clever.

Four rules, in the order they matter:

1. **CVE knowledge comes only from the feed.** No model, no inference, no memory. An LLM's
   CVE knowledge is stale and hallucinated CVE ids are its characteristic failure
   (AGENTS.md §4.8), so nothing in this package may import one —
   `tests/test_adapter_boundaries.py` fails if that changes.

2. **The feed proposes; this module disposes.** NVD's `cpeName` query returns CVEs for a
   *product*, broadly. Every criterion it returns is re-checked locally against the
   component's actual version, and only the ones that genuinely apply become matches. A CVE
   matched to a version it does not affect is a false positive that discredits the tool.

3. **`confidence_state` is derived, never guessed.** A package database says what is
   installed (`confirmed`); a banner says what a service claims, and a distribution that
   backported the fix serves the old version string forever (`probable`). That single flag
   is what keeps a backport from becoming a false positive downstream (AGENTS.md §3).
   `verified_exploitable` is never produced here — it belongs to a later `check` step that
   actually demonstrates exploitability.

4. **A failed lookup is never a clean result.** If the feed, KEV or EPSS cannot answer, that
   component's correlation fails and says so. Recording "no vulnerabilities" for a component
   whose lookup failed would be the false negative P12 and P13 exist to prevent, arriving
   one layer later (AGENTS.md §67, §4.9).

KEV needs a word of its own. It is the override that keeps a finding visible regardless of
confidence (dossier contract §7): a `probable` match that is KEV-listed is still a
`probable` match — the flag does not launder the version evidence — but the `kev` boolean
travels with it so no view can quietly drop it. And because a KEV outage would silently
produce matches with `kev=false`, a KEV failure aborts the component rather than defaulting.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from uuid import UUID

from domain.errors import DomainError
from domain.models import (
    ComponentSnapshot,
    ConfidenceState,
    CpeMatch,
    CveRecord,
    Priority,
    VersionSource,
    VulnerabilityMatchInput,
)
from domain.ports import EpssSource, KevSource, VulnerabilityFeed, VulnerabilityMatchStore
from engine.cpe import RangeVerdict, parse_cpe, version_in_range
from engine.priority import PriorityInputs, derive_priority

#: Version evidence good enough to call a match `confirmed`. Both are the device or its
#: manufacturer stating what is installed, rather than a service advertising a string.
GROUND_TRUTH_SOURCES = frozenset({VersionSource.PACKAGE_MANAGER, VersionSource.VENDOR_API})


@dataclass(frozen=True, slots=True)
class CorrelationOutcome:
    """What a correlation run did, with every non-match accounted for.

    `failed_components` is the field that matters: a run with failures produced an
    *incomplete* picture, and a caller that treats its output as "everything we know" needs
    to see that rather than infer it from a silence.
    """

    components: int = 0
    correlated: int = 0
    matches: int = 0
    new_matches: int = 0
    kev_matches: int = 0
    #: Matches that landed in the top band — the number an operator actually reacts to.
    p1_matches: int = 0
    confirmed: int = 0
    probable: int = 0
    #: CVEs the feed returned whose version range excluded this component. Counted because
    #: it is the number that shows the version check is doing something.
    filtered_out_of_range: int = 0
    #: Matches kept despite an undecidable version comparison, and downgraded for it.
    inconclusive_versions: int = 0
    skipped_components: tuple[str, ...] = ()
    failed_components: tuple[str, ...] = ()

    @property
    def failed(self) -> int:
        return len(self.failed_components)

    @property
    def complete(self) -> bool:
        """True when every component was correlated. False means the picture has holes and
        the caller must not read an absence of matches as an absence of vulnerabilities."""
        return not self.failed_components


class VulnerabilityCorrelator:
    """Joins components to CVEs, deterministically."""

    def __init__(
        self,
        feed: VulnerabilityFeed,
        kev: KevSource,
        epss: EpssSource,
        store: VulnerabilityMatchStore,
    ) -> None:
        self._feed = feed
        self._kev = kev
        self._epss = epss
        self._store = store

    def run(self, tenant_id: UUID, *, run_id: UUID | None = None) -> CorrelationOutcome:
        """Correlate every component that has a CPE."""
        return self.correlate(self._store.components_with_cpe(tenant_id), run_id=run_id)

    def correlate(
        self, components: Iterable[ComponentSnapshot], *, run_id: UUID | None = None
    ) -> CorrelationOutcome:
        """Correlate the given components. One failure never costs the others."""
        state = _RunState()

        for component in components:
            state.components += 1
            parsed = parse_cpe(component.cpe)
            if parsed is None:
                # A component whose CPE does not parse cannot be looked up. Counted, not
                # silently passed over.
                state.skipped.append(component.cpe)
                continue

            try:
                self._correlate_one(component, run_id, state)
            except DomainError:
                # A feed, KEV or EPSS failure. This component's picture is incomplete and
                # the outcome says so; the rest of the estate still gets correlated.
                state.failed.append(str(component.component_id))
                continue

            state.correlated += 1

        return state.outcome()

    def _correlate_one(
        self, component: ComponentSnapshot, run_id: UUID | None, state: _RunState
    ) -> None:
        """One component, end to end. Every lookup failure propagates rather than emptying."""
        # Raises on a feed failure — an empty list here always means "the feed knows of no
        # CVEs for this CPE", never "we could not ask" (ADR-0010).
        candidates = self._feed.cves_for_cpe(component.cpe)

        for cve in candidates:
            matched = self._matching_criterion(component, cve, state)
            if matched is None:
                continue
            criterion, verdict = matched

            # Raises on a KEV failure rather than defaulting to False, because a match
            # recorded with `kev=false` because CISA was unreachable is an actively-exploited
            # vulnerability silently de-prioritised (ADR-0011).
            kev = self._kev.is_known_exploited(cve.cve_id)
            score = self._epss.score_for(cve.cve_id)

            confidence = derive_confidence_state(component.version_source, verdict)
            epss = score.score if score is not None else None

            # The band and the sentence behind it, derived here from evidence that is all
            # already in hand — and stored, so the interface never re-derives a priority or
            # invents an explanation for one (ux-design §2, ADR-0015).
            band = derive_priority(
                PriorityInputs(
                    cve_id=cve.cve_id,
                    confidence_state=confidence,
                    kev=kev,
                    epss=epss,
                    cvss_score=cve.cvss_score,
                )
            )

            record = self._store.record_match(
                VulnerabilityMatchInput(
                    tenant_id=component.tenant_id,
                    asset_id=component.asset_id,
                    component_id=component.component_id,
                    cve_id=cve.cve_id,
                    matched_cpe=criterion.criteria,
                    version_source=component.version_source,
                    confidence_state=confidence,
                    kev=kev,
                    epss=epss,
                    # Carried from the feed record, never computed here: a CVE with no
                    # published score keeps `None` rather than a substituted zero.
                    cvss_score=cve.cvss_score,
                    cvss_vector=cve.cvss_vector,
                    cvss_version=cve.cvss_version,
                    priority=band.priority,
                    priority_rule=band.rule_id,
                    priority_reason=band.reason,
                    run_id=run_id,
                )
            )

            state.matches += 1
            state.new_matches += int(record.created)
            state.kev_matches += int(kev)
            state.p1 += int(band.priority is Priority.P1)
            if confidence is ConfidenceState.CONFIRMED:
                state.confirmed += 1
            else:
                state.probable += 1
            if verdict is RangeVerdict.INCONCLUSIVE:
                state.inconclusive += 1

    def _matching_criterion(
        self, component: ComponentSnapshot, cve: CveRecord, state: _RunState
    ) -> tuple[CpeMatch, RangeVerdict] | None:
        """The CVE criterion that genuinely applies to this component, if any.

        This is where the feed's broad answer is narrowed to the truth. A criterion applies
        when it names the same product *and* the component's version falls inside its
        affected range. Between two criteria that both apply, a decisive verdict beats an
        inconclusive one — we would rather report the match we can defend.
        """
        component_cpe = parse_cpe(component.cpe)
        if component_cpe is None:  # pragma: no cover — the caller parsed it already
            return None

        # Which version do we compare? The CPE's, when it carries one: NVD expresses its
        # ranges in CPE-space versions, and that is the field they are comparable with. When
        # the CPE is wildcarded — common for a CPE assembled from a package name — the
        # component's own reported version is the only thing we have.
        version = component_cpe.version if component_cpe.has_concrete_version else component.version

        fallback: tuple[CpeMatch, RangeVerdict] | None = None

        for criterion in cve.cpe_matches:
            if not criterion.vulnerable:
                # NVD marks some criteria as the platform a vulnerable component runs on
                # rather than the vulnerable thing itself.
                continue
            criterion_cpe = parse_cpe(criterion.criteria)
            if criterion_cpe is None or criterion_cpe.identity != component_cpe.identity:
                continue

            verdict = self._verdict_for(version, criterion, criterion_cpe.version)
            if verdict is RangeVerdict.IN_RANGE:
                return criterion, verdict
            if verdict is RangeVerdict.INCONCLUSIVE and fallback is None:
                fallback = (criterion, verdict)
            elif verdict is RangeVerdict.OUT_OF_RANGE:
                state.filtered += 1

        return fallback

    def _verdict_for(
        self, component_version: str | None, criterion: CpeMatch, criterion_version: str
    ) -> RangeVerdict:
        """Does this component's version fall inside what the criterion covers?

        Two shapes, because NVD publishes both: a criterion pinned to one version, and a
        wildcard criterion carrying the range in its sibling bounds.
        """
        if criterion_version not in {"*", "-", ""} and not criterion.has_bounds:
            # Pinned to a single version: only that exact version is affected.
            return version_in_range(
                component_version,
                start_including=criterion_version,
                end_including=criterion_version,
            )

        return version_in_range(
            component_version,
            start_including=criterion.version_start_including,
            start_excluding=criterion.version_start_excluding,
            end_including=criterion.version_end_including,
            end_excluding=criterion.version_end_excluding,
        )


def derive_confidence_state(
    version_source: VersionSource, verdict: RangeVerdict = RangeVerdict.IN_RANGE
) -> ConfidenceState:
    """How much this match's version evidence is worth (dossier contract, AGENTS.md §3).

    `package_manager` and `vendor_api` are the device or its manufacturer stating what is
    installed — ground truth, so `confirmed`. `banner` is what a service advertises, and a
    backported fix leaves the old string in place, so `probable`.

    One refinement beyond the source alone: a match kept despite an *undecidable* version
    comparison is `probable` whatever its source, because "confirmed" has to mean we
    checked. The finding stays visible — hiding it would be the false negative — but it does
    not claim a certainty nobody established (ADR-0012).

    `verified_exploitable` is never returned: it belongs to a later `check` step.
    """
    if verdict is RangeVerdict.INCONCLUSIVE:
        return ConfidenceState.PROBABLE
    if version_source in GROUND_TRUTH_SOURCES:
        return ConfidenceState.CONFIRMED
    return ConfidenceState.PROBABLE


@dataclass
class _RunState:
    """Mutable bookkeeping; frozen into an outcome at the end."""

    components: int = 0
    correlated: int = 0
    matches: int = 0
    new_matches: int = 0
    kev_matches: int = 0
    p1: int = 0
    confirmed: int = 0
    probable: int = 0
    filtered: int = 0
    inconclusive: int = 0
    skipped: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)

    def outcome(self) -> CorrelationOutcome:
        return CorrelationOutcome(
            components=self.components,
            correlated=self.correlated,
            matches=self.matches,
            new_matches=self.new_matches,
            kev_matches=self.kev_matches,
            p1_matches=self.p1,
            confirmed=self.confirmed,
            probable=self.probable,
            filtered_out_of_range=self.filtered,
            inconclusive_versions=self.inconclusive,
            skipped_components=tuple(self.skipped),
            failed_components=tuple(self.failed),
        )


__all__: Sequence[str] = [
    "GROUND_TRUTH_SOURCES",
    "CorrelationOutcome",
    "VulnerabilityCorrelator",
    "derive_confidence_state",
]
