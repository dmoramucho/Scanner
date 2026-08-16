"""The insight pipeline: match → dossier → advisory → snapshot → model → proposal.

Five steps, and the order of the middle three is the audit trail. The dossier is assembled
and redacted, the advisory is retrieved, the two are frozen into a `TriageDossier`, and
**the snapshot is written before the model is called**. So whatever the model then does —
answer well, answer badly, time out — there is a durable record of exactly what it was
given (dossier contract §2, §8.1). An insight whose evidence cannot be reproduced is not
auditable, and auditability is the entire claim this system makes about its AI.

Nothing here decides anything about the vulnerability. The match arrived from
`engine/correlation.py`, deterministic and already written; this pipeline attaches an
opinion to it and never edits it (AGENTS.md §2.8).

Every failure is contained to one match and named:

* **No advisory** — P15 could find no text to ground on, so no insight is produced. The
  finding stays exactly as visible as the correlator left it. This is the system refusing to
  reason rather than reasoning from memory (AGENTS.md §4.8).
* **Ungrounded** — the model cited nothing that resolves. Refused, counted.
* **Refused** — the model broke a rule: a KEV-hiding recommendation, a foreign CVE id, an
  unparseable reply. Refused, counted.
* **Failed** — the model or a source was unreachable. Retryable, counted, and never
  recorded as "we looked at this and had nothing to say" (AGENTS.md §67).

In every one of those, the deterministic finding survives untouched. That is the whole
design: the AI can only ever *add* a recommendation, and its absence costs nothing.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID, uuid4

from domain.errors import DependencyError, GroundingError, NotFoundError, ValidationError
from domain.models import (
    InsightRecord,
    MatchForTriage,
    TriageDossier,
)
from domain.ports import AdvisoryRetriever, InsightGenerator, TriageStore
from engine.dossier import DossierAssembler


@dataclass(frozen=True, slots=True)
class TriageOutcome:
    """What a triage run did, with every non-insight accounted for.

    A run that produced three insights out of ten matches is not a run that found seven
    clean components — it is a run that declined to speak about seven, for reasons that are
    each counted here.
    """

    matches: int = 0
    insights: int = 0
    kev_locked: int = 0
    #: No advisory text existed, so there was nothing to ground on.
    skipped_no_advisory: int = 0
    #: The model cited nothing that resolved to the advisory or the dossier.
    ungrounded: int = 0
    #: The model broke a containment rule and its answer was thrown away.
    refused: int = 0
    #: A source or the model itself could not be reached. Retryable.
    failed: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        """True when nothing failed. False means retry, not "nothing to say"."""
        return not self.failed


class TriagePipeline:
    """Turns deterministic matches into reviewable, grounded proposals."""

    def __init__(
        self,
        assembler: DossierAssembler,
        retriever: AdvisoryRetriever,
        generator: InsightGenerator,
        store: TriageStore,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        new_id: Callable[[], UUID] = uuid4,
    ) -> None:
        self._assembler = assembler
        self._retriever = retriever
        self._generator = generator
        self._store = store
        self._clock = clock
        self._new_id = new_id

    def run(self, tenant_id: UUID, *, limit: int = 100) -> TriageOutcome:
        """Triage the matches that have no insight yet. One failure never costs the rest."""
        state = _RunState()
        for candidate in self._store.pending_matches(tenant_id, limit=limit):
            state.matches += 1
            self._triage_one(candidate, state)
        return state.outcome()

    def triage(self, candidate: MatchForTriage) -> InsightRecord | None:
        """Triage one match. Returns None when there was nothing to ground on.

        Raises everything else — `GroundingError`, `ValidationError`, `DependencyError` —
        because a single-match caller is entitled to the reason. `run()` catches them and
        counts them instead.
        """
        triage = self.assemble(candidate)
        self._store.record_snapshot(triage)
        insight = self._generator.generate(triage)
        return self._store.record_insight(insight)

    def assemble(self, candidate: MatchForTriage) -> TriageDossier:
        """Build the exact input the model will see: redacted dossier + advisory + match.

        Raises `NotFoundError` when no advisory text can be sourced. That is P15 refusing to
        hand over hollow grounding, and it must stay an exception here rather than becoming
        an empty string — the model would happily reason over one (ADR-0013).
        """
        asset = self._assembler.assemble(candidate.tenant_id, candidate.asset_id)
        advisory = self._retriever.fetch(candidate.match.cve_id, candidate.match.matched_cpe)
        return TriageDossier(
            triage_id=self._new_id(),
            match=candidate.match,
            advisory=advisory,
            asset=asset,
        )

    # ------------------------------------------------------------------ one match

    def _triage_one(self, candidate: MatchForTriage, state: _RunState) -> None:
        """One match, with every failure named and contained."""
        try:
            record = self.triage(candidate)
        except NotFoundError:
            # No advisory text, or no such asset. Either way there is nothing to reason
            # over, and reasoning anyway is the failure mode this whole milestone avoids.
            state.no_advisory += 1
            return
        except GroundingError:
            state.ungrounded += 1
            return
        except ValidationError:
            # A containment rule refused the model's answer. The finding is untouched.
            state.refused += 1
            return
        except DependencyError:
            state.failed.append(str(candidate.match_id))
            return

        if record is not None:
            state.insights += 1
            state.kev_locked += int(candidate.match.kev)


@dataclass
class _RunState:
    matches: int = 0
    insights: int = 0
    kev_locked: int = 0
    no_advisory: int = 0
    ungrounded: int = 0
    refused: int = 0
    failed: list[str] = field(default_factory=list)

    def outcome(self) -> TriageOutcome:
        return TriageOutcome(
            matches=self.matches,
            insights=self.insights,
            kev_locked=self.kev_locked,
            skipped_no_advisory=self.no_advisory,
            ungrounded=self.ungrounded,
            refused=self.refused,
            failed=tuple(self.failed),
        )


__all__: Sequence[str] = [
    "TriageOutcome",
    "TriagePipeline",
]
