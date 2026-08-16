"""The insight pipeline: what gets written, in what order, and what happens when it fails.

The property this file exists for is the ordering one: **the snapshot is written before the
model is called**. Everything else in M3 can be re-derived; what a model was given at 03:00
last Tuesday cannot. If the snapshot were written after a successful generation, every
failed or refused insight would leave no record that the model was ever asked (dossier
contract §2, §8.1).

The rest is containment. An advisory that could not be sourced, an ungrounded answer, a
refused answer, an unreachable model: each is counted, each is confined to one match, and
none of them touch the deterministic finding underneath.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from adapters.llm.generator import ContainedInsightGenerator
from adapters.llm.prompt import build_user_prompt
from domain.errors import DependencyError, NotFoundError
from domain.models import (
    AdvisoryEvidence,
    AssetClass,
    AssetView,
    Identifier,
    InsightProposal,
    InsightRecord,
    InsightReviewState,
    ManagementState,
    MatchForTriage,
    ModelCompletion,
    ObservationSnapshot,
    SoftwareComponent,
    TriageDossier,
)
from engine.dossier import DossierAssembler
from engine.triage import TriagePipeline
from tests.builders import CVE, advisory, match, observation
from tests.test_insight_generator import GOOD_ANSWER, ScriptedModel

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
TENANT = UUID("11111111-1111-1111-1111-111111111111")
ASSET = UUID("22222222-2222-2222-2222-222222222222")


class FakeSource:
    def asset(self, tenant_id: UUID, asset_id: UUID) -> AssetView | None:
        if asset_id != ASSET:
            return None
        return AssetView(
            id=ASSET,
            tenant_id=TENANT,
            asset_class=AssetClass.SERVER,
            management_state=ManagementState.UNMANAGED,
            identification_confidence=0.9,
            status="active",
        )

    def identifiers(self, tenant_id: UUID, asset_id: UUID) -> list[Identifier]:
        return [Identifier(kind="mac", value="00:11:22:33:44:55", confidence=1.0)]

    def software(self, tenant_id: UUID, asset_id: UUID) -> list[SoftwareComponent]:
        return []

    def observations(
        self, tenant_id: UUID, asset_id: UUID, *, limit: int = 500
    ) -> list[ObservationSnapshot]:
        return [observation("network", {"reachability": "internet_facing"})]

    def managed_by(self, tenant_id: UUID, asset_id: UUID) -> list[str]:
        return []


class FakeRetriever:
    def __init__(
        self, evidence: AdvisoryEvidence | None = None, *, raises: Exception | None = None
    ) -> None:
        self.evidence = evidence if evidence is not None else advisory()
        self.raises = raises
        self.calls: list[tuple[str, str]] = []

    def fetch(self, cve_id: str, matched_cpe: str) -> AdvisoryEvidence:
        self.calls.append((cve_id, matched_cpe))
        if self.raises is not None:
            raise self.raises
        return self.evidence


class FakeStore:
    """Records the order of writes, which is the thing under test."""

    def __init__(self, pending: Sequence[MatchForTriage] = ()) -> None:
        self.pending = list(pending)
        self.snapshots: list[TriageDossier] = []
        self.insights: list[InsightProposal] = []
        self.writes: list[str] = []

    def pending_matches(self, tenant_id: UUID, *, limit: int = 100) -> Sequence[MatchForTriage]:
        return self.pending

    def record_snapshot(self, triage: TriageDossier) -> UUID:
        self.snapshots.append(triage)
        self.writes.append("snapshot")
        return triage.triage_id

    def record_insight(self, insight: InsightProposal) -> InsightRecord:
        self.insights.append(insight)
        self.writes.append("insight")
        return InsightRecord(
            insight_id=insight.insight_id, triage_id=insight.triage_id, created=True
        )

    def review_insight(
        self, insight_id: UUID, *, state: InsightReviewState, reviewer: str
    ) -> InsightProposal:  # pragma: no cover — the store's own tests cover review
        raise NotImplementedError

    def insight(self, insight_id: UUID) -> InsightProposal | None:  # pragma: no cover
        return None

    def snapshot(self, triage_id: UUID) -> TriageDossier | None:  # pragma: no cover
        return None


class RecordingModel(ScriptedModel):
    """A model that reports when it was called, so ordering can be asserted."""

    def __init__(self, store: FakeStore, reply: object = None) -> None:
        super().__init__(reply)
        self._store = store

    def complete(self, *, system: str, user: str) -> ModelCompletion:
        self._store.writes.append("model")
        return super().complete(system=system, user=user)


def candidate(**overrides: object) -> MatchForTriage:
    return MatchForTriage(
        match_id=uuid4(), tenant_id=TENANT, asset_id=ASSET, match=match(**overrides)
    )


def pipeline(
    store: FakeStore,
    *,
    retriever: FakeRetriever | None = None,
    model: ScriptedModel | None = None,
) -> TriagePipeline:
    return TriagePipeline(
        DossierAssembler(FakeSource(), clock=lambda: NOW, new_id=uuid4),
        retriever if retriever is not None else FakeRetriever(),
        ContainedInsightGenerator(model if model is not None else RecordingModel(store)),
        store,
        clock=lambda: NOW,
        new_id=uuid4,
    )


# ------------------------------------------------------------------ the ordering rule


def test_the_snapshot_is_written_before_the_model_is_called() -> None:
    """The property this file exists for.

    Everything else in the system can be re-derived from evidence. What a model was handed
    at 03:00 last Tuesday cannot — so it is written down first, and it is written down even
    when what follows fails (contract §8.1).
    """
    store = FakeStore()

    pipeline(store).triage(candidate())

    assert store.writes == ["snapshot", "model", "insight"]


def test_a_refused_answer_still_leaves_the_evidence_behind() -> None:
    """A model that broke a rule is exactly the case somebody will want to audit. The
    snapshot survives the refusal; the insight does not exist."""
    store = FakeStore([candidate(kev=True)])
    lowering = dict(GOOD_ANSWER, recommendation="lower_priority")

    outcome = pipeline(store, model=RecordingModel(store, lowering)).run(TENANT)

    assert outcome.refused == 1
    assert outcome.insights == 0
    assert len(store.snapshots) == 1  # the evidence is retained
    assert store.insights == []


def test_the_snapshot_is_exactly_what_the_model_was_given() -> None:
    """The retained snapshot reconstructs the prompt: it is the *input* to a pure function.

    Substring equality does not hold, and deliberately: the prompt builder sanitises the
    advisory a second time on the way out, which also breaks apart the `[[source: …]]`
    headers P15 emitted. That is anti-forgery outranking idempotence — an advisory able to
    survive one sanitising pass with intact markers could attribute its own words to NVD —
    and it costs only the brackets around an attribution the model can still read.
    """
    store = FakeStore()
    model = RecordingModel(store)

    pipeline(store, model=model).triage(candidate())

    snapshot = store.snapshots[0]
    _system, user = model.calls[0]
    assert build_user_prompt(snapshot) == user  # the snapshot regenerates the prompt exactly
    assert "allow a HTTP Request Smuggling attack" in user
    assert snapshot.match.cve_id in user
    assert store.insights[0].triage_id == snapshot.triage_id


# --------------------------------------------------------------------- containment


def test_a_cve_with_no_advisory_produces_no_insight_and_is_counted() -> None:
    """P15 refusing to hand over hollow grounding, arriving one layer up. The pipeline does
    not reason without an advisory — that is the whole point of the retriever existing
    (AGENTS.md §4.8)."""
    store = FakeStore([candidate()])
    retriever = FakeRetriever(raises=NotFoundError("no advisory text for CVE-2023-25690"))

    outcome = pipeline(store, retriever=retriever).run(TENANT)

    assert outcome.skipped_no_advisory == 1
    assert outcome.insights == 0
    assert store.snapshots == []
    assert store.insights == []
    assert outcome.complete  # not a failure — an honest absence


def test_an_ungrounded_answer_is_counted_and_persists_nothing() -> None:
    store = FakeStore([candidate()])
    model = RecordingModel(store, dict(GOOD_ANSWER, cited_sources=[]))

    outcome = pipeline(store, model=model).run(TENANT)

    assert outcome.ungrounded == 1
    assert store.insights == []


def test_an_unreachable_model_is_a_failure_not_an_empty_result() -> None:
    """A run that could not ask is not a run that found nothing to say. `complete` is False
    so the caller retries rather than reading silence as agreement (AGENTS.md §67)."""
    store = FakeStore([candidate()])
    model = ScriptedModel(raises=DependencyError("model unreachable", retryable=True))

    outcome = pipeline(store, model=model).run(TENANT)

    assert outcome.failed
    assert not outcome.complete
    assert outcome.insights == 0


def test_one_bad_match_never_costs_the_others() -> None:
    store = FakeStore([candidate(), candidate(cve_id="CVE-2024-0001"), candidate()])
    replies = [dict(GOOD_ANSWER), dict(GOOD_ANSWER, cited_sources=[]), dict(GOOD_ANSWER)]

    class Sequenced(RecordingModel):
        def complete(self, *, system: str, user: str) -> ModelCompletion:
            self._store.writes.append("model")
            return ModelCompletion(text=json.dumps(replies.pop(0)), model_version="local")

    outcome = pipeline(store, model=Sequenced(store)).run(TENANT)

    assert outcome.matches == 3
    assert outcome.insights == 2
    assert outcome.ungrounded == 1


def test_a_kev_match_is_counted_as_locked_visible() -> None:
    store = FakeStore([candidate(kev=True)])

    outcome = pipeline(store).run(TENANT)

    assert outcome.insights == 1
    assert outcome.kev_locked == 1
    assert store.insights[0].kev_locked_visible is True


def test_an_empty_run_is_complete() -> None:
    outcome = pipeline(FakeStore()).run(TENANT)

    assert outcome.matches == 0
    assert outcome.complete


def test_the_pipeline_reasons_only_about_the_cve_of_the_match_it_was_given() -> None:
    """The retriever is asked for exactly the match's CVE and CPE. There is no other route
    into the advisory, so there is no other route into CVE knowledge."""
    store = FakeStore()
    retriever = FakeRetriever()

    pipeline(store, retriever=retriever).triage(candidate())

    assert retriever.calls == [(CVE, store.snapshots[0].match.matched_cpe)]


def test_an_asset_that_does_not_exist_is_skipped_not_invented() -> None:
    store = FakeStore(
        [MatchForTriage(match_id=uuid4(), tenant_id=TENANT, asset_id=uuid4(), match=match())]
    )

    outcome = pipeline(store).run(TENANT)

    assert outcome.skipped_no_advisory == 1
    assert store.snapshots == []


def test_the_triage_dossier_is_immutable() -> None:
    """Contract §6: the snapshot behind an insight is a frozen record, not a working copy."""
    store = FakeStore()

    pipeline(store).triage(candidate())

    with pytest.raises(ValueError, match="frozen"):
        store.snapshots[0].match = match()  # type: ignore[misc]
