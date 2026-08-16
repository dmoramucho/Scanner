"""The insight path against the real store: the backstops, and the audit trail.

The generator already refuses an ungrounded insight and a KEV-hiding one. This file asserts
that the *database* refuses them too — belt and braces, as m3-design §3 asks for. The Python
guard is the one that gives a clear error; the constraint is the one that survives a
refactor, a new caller, or somebody writing SQL by hand at 02:00.

Also here: that the retained snapshot is genuinely immutable (the append-only trigger), and
that a human review records who and when and cannot run backwards.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest

from adapters.postgres.triage_store import PostgresDossierSource, PostgresTriageStore
from domain.errors import NotFoundError, ValidationError
from domain.models import (
    AssetClass,
    CitedSource,
    Derivation,
    InsightProposal,
    InsightReview,
    ManagementState,
    ReviewOutcome,
    TriageDossier,
)
from tests.builders import CVE, asset_dossier, triage_dossier

pytestmark = pytest.mark.integration

Connection = psycopg.Connection[tuple[Any, ...]]

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)


@pytest.fixture
def tenant() -> UUID:
    return uuid4()


def seed_asset(conn: Connection, tenant_id: UUID) -> UUID:
    row = conn.execute(
        """
        insert into asset (tenant_id, asset_class, management_state,
                           identification_confidence, first_seen_at, last_seen_at)
        values (%s, 'server', 'unmanaged', 0.9, %s, %s) returning id
        """,
        (tenant_id, NOW, NOW),
    ).fetchone()
    assert row is not None
    asset_id: UUID = row[0]
    return asset_id


def snapshot_for(conn: Connection, tenant_id: UUID, *, kev: bool = False) -> TriageDossier:
    asset_id = seed_asset(conn, tenant_id)
    return triage_dossier(kev=kev, asset=asset_dossier(tenant_id=tenant_id, asset_id=asset_id))


def proposal(triage: TriageDossier, **overrides: object) -> InsightProposal:
    fields: dict[str, Any] = {
        "insight_id": uuid4(),
        "triage_id": triage.triage_id,
        "recommendation": "raise_priority",
        "rationale": "The affected path is reachable from the internet.",
        "cited_sources": [CitedSource(kind="advisory", ref=CVE, quote="Request Smuggling")],
        "confidence": 0.8,
        "model_version": "llama3.3:70b",
        "kev_locked_visible": triage.match.kev,
    }
    fields.update(overrides)
    return InsightProposal(**fields)


# ------------------------------------------------------------- the database backstops


def test_the_database_refuses_an_ungrounded_insight(conn: Connection, tenant: UUID) -> None:
    """Safety-critical, at the last layer. The generator raises `GroundingError` long before
    this — but Python can be refactored and a constraint cannot be talked around. An insight
    citing nothing is a claim with nothing behind it (contract §7)."""
    triage = snapshot_for(conn, tenant)
    store = PostgresTriageStore(conn)
    store.record_snapshot(triage)

    with pytest.raises(psycopg.errors.CheckViolation) as raised:
        conn.execute(
            """
            insert into insight (tenant_id, triage_id, recommendation, rationale,
                                 cited_sources, confidence, model_version)
            values (%s, %s, 'maintain', 'trust me', '[]'::jsonb, 0.9, 'local')
            """,
            (tenant, triage.triage_id),
        )

    assert "insight_must_be_grounded" in str(raised.value)


def test_the_database_refuses_an_insight_that_hides_a_kev_finding(
    conn: Connection, tenant: UUID
) -> None:
    """Safety-critical, at the last layer. CISA says this is being exploited right now; the
    schema will not store a row that argues it down the page (contract §7)."""
    triage = snapshot_for(conn, tenant, kev=True)
    store = PostgresTriageStore(conn)
    store.record_snapshot(triage)

    with pytest.raises(psycopg.errors.CheckViolation) as raised:
        conn.execute(
            """
            insert into insight (tenant_id, triage_id, recommendation, rationale,
                                 cited_sources, confidence, model_version, kev_locked_visible)
            values (%s, %s, 'lower_priority', 'not exploitable here',
                    '[{"kind":"advisory","ref":"CVE-2023-25690"}]'::jsonb, 0.9, 'local', true)
            """,
            (tenant, triage.triage_id),
        )

    assert "insight_kev_not_hidden" in str(raised.value)


def test_the_database_refuses_an_insight_claiming_to_be_deterministic(
    conn: Connection, tenant: UUID
) -> None:
    """The mirror of `vulnerability_match`'s constraint. That table cannot hold a model's
    opinion; this one cannot pretend to be anything else (AGENTS.md §2.2)."""
    triage = snapshot_for(conn, tenant)
    PostgresTriageStore(conn).record_snapshot(triage)

    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """
            insert into insight (tenant_id, triage_id, recommendation, rationale,
                                 cited_sources, confidence, model_version, derivation)
            values (%s, %s, 'maintain', 'because',
                    '[{"kind":"advisory","ref":"x"}]'::jsonb, 0.5, 'local', 'deterministic')
            """,
            (tenant, triage.triage_id),
        )


def test_a_reviewed_insight_must_name_its_reviewer(conn: Connection, tenant: UUID) -> None:
    """ "A human accepted it" has to mean a specific human (AGENTS.md §2.8)."""
    triage = snapshot_for(conn, tenant)
    store = PostgresTriageStore(conn)
    store.record_snapshot(triage)
    store.record_insight(proposal(triage))

    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "update insight set state = 'accepted' where triage_id = %s", (triage.triage_id,)
        )


# --------------------------------------------------------------- the retained snapshot


def test_the_snapshot_is_immutable(conn: Connection, tenant: UUID) -> None:
    """The append-only trigger, same as `observation` and `audit_log`. An insight whose
    evidence can be rewritten afterwards proves nothing (contract §2)."""
    triage = snapshot_for(conn, tenant)
    PostgresTriageStore(conn).record_snapshot(triage)

    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute(
            "update triage_snapshot set cve_id = 'CVE-1999-0001' where id = %s",
            (triage.triage_id,),
        )


def test_the_snapshot_cannot_be_deleted(conn: Connection, tenant: UUID) -> None:
    triage = snapshot_for(conn, tenant)
    PostgresTriageStore(conn).record_snapshot(triage)

    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("delete from triage_snapshot where id = %s", (triage.triage_id,))


def test_the_snapshot_round_trips_exactly(conn: Connection, tenant: UUID) -> None:
    """What the model saw, reconstructable field for field."""
    triage = snapshot_for(conn, tenant)
    store = PostgresTriageStore(conn)

    store.record_snapshot(triage)
    restored = store.snapshot(triage.triage_id)

    assert restored is not None
    assert restored.model_dump(mode="json") == triage.model_dump(mode="json")


def test_an_insight_without_its_snapshot_is_refused(conn: Connection, tenant: UUID) -> None:
    """Evidence first, always. An insight with no retained snapshot cannot be audited, so it
    is not written (contract §8.1)."""
    triage = triage_dossier()

    with pytest.raises(NotFoundError):
        PostgresTriageStore(conn).record_insight(proposal(triage))


# ------------------------------------------------------------------- the happy path


def test_a_grounded_insight_persists_as_a_proposal(conn: Connection, tenant: UUID) -> None:
    triage = snapshot_for(conn, tenant)
    store = PostgresTriageStore(conn)
    store.record_snapshot(triage)

    record = store.record_insight(proposal(triage))
    stored = store.insight(record.insight_id)

    assert stored is not None
    assert stored.state == "proposed"
    assert stored.derivation is Derivation.LLM_GENERATED
    assert stored.recommendation == "raise_priority"
    assert stored.cited_sources[0].ref == CVE
    assert stored.cited_sources[0].quote == "Request Smuggling"


def test_the_adapter_refuses_an_ungrounded_insight_by_name(conn: Connection, tenant: UUID) -> None:
    """The same rule one layer up, so the failure says what it is rather than surfacing as
    an integrity error."""
    triage = snapshot_for(conn, tenant)
    store = PostgresTriageStore(conn)
    store.record_snapshot(triage)

    with pytest.raises(ValidationError, match="ungrounded"):
        store.record_insight(proposal(triage, cited_sources=[]))


def test_the_adapter_refuses_a_kev_hiding_insight_by_name(conn: Connection, tenant: UUID) -> None:
    triage = snapshot_for(conn, tenant, kev=True)
    store = PostgresTriageStore(conn)
    store.record_snapshot(triage)

    with pytest.raises(ValidationError, match="KEV"):
        store.record_insight(proposal(triage, recommendation="lower_priority"))


# ----------------------------------------------------------------- the human in the loop


def test_a_human_review_is_recorded_with_who_and_when(conn: Connection, tenant: UUID) -> None:
    """The state exists so a person owns the decision. `proposed → human_reviewed →
    accepted`, each step naming the reviewer (AGENTS.md §2.8)."""
    triage = snapshot_for(conn, tenant)
    store = PostgresTriageStore(conn)
    store.record_snapshot(triage)
    record = store.record_insight(proposal(triage))

    reviewed = store.review_insight(
        InsightReview(
            insight_id=record.insight_id,
            outcome=ReviewOutcome.REJECTED,
            reviewer="dmora",
            rationale="The affected module is not loaded on this host.",
        )
    )
    accepted = store.review_insight(
        InsightReview(
            insight_id=record.insight_id, outcome=ReviewOutcome.ACCEPTED, reviewer="dmora"
        )
    )

    assert reviewed.state == "human_reviewed"
    assert accepted.state == "accepted"
    row = conn.execute(
        "select reviewed_by, reviewed_at from insight where id = %s", (record.insight_id,)
    ).fetchone()
    assert row is not None
    assert row[0] == "dmora"
    assert row[1] is not None


def test_a_review_cannot_run_backwards(conn: Connection, tenant: UUID) -> None:
    """Re-reviewing backwards would quietly erase a decision somebody made."""
    triage = snapshot_for(conn, tenant)
    store = PostgresTriageStore(conn)
    store.record_snapshot(triage)
    record = store.record_insight(proposal(triage))
    store.review_insight(
        InsightReview(
            insight_id=record.insight_id, outcome=ReviewOutcome.ACCEPTED, reviewer="dmora"
        )
    )

    with pytest.raises(ValidationError, match="forward-only"):
        store.review_insight(
            InsightReview(
                insight_id=record.insight_id,
                outcome=ReviewOutcome.REJECTED,
                reviewer="someone-else",
            )
        )


def test_a_review_must_name_a_reviewer(conn: Connection, tenant: UUID) -> None:
    triage = snapshot_for(conn, tenant)
    store = PostgresTriageStore(conn)
    store.record_snapshot(triage)
    record = store.record_insight(proposal(triage))

    with pytest.raises(ValidationError):
        store.review_insight(
            InsightReview(
                insight_id=record.insight_id, outcome=ReviewOutcome.ACCEPTED, reviewer="   "
            )
        )


def test_reviewing_an_insight_that_does_not_exist_raises(conn: Connection) -> None:
    with pytest.raises(NotFoundError):
        PostgresTriageStore(conn).review_insight(
            InsightReview(insight_id=uuid4(), outcome=ReviewOutcome.ACCEPTED, reviewer="dmora")
        )


# ------------------------------------------------------------------ reading the estate


def test_pending_matches_are_kev_first(conn: Connection, tenant: UUID) -> None:
    """If a run is cut short, it is cut short after the findings that matter most."""
    asset_id = seed_asset(conn, tenant)
    for cve, kev, epss in (("CVE-2024-0001", False, 0.9), ("CVE-2024-0002", True, 0.1)):
        conn.execute(
            """
            insert into vulnerability_match (tenant_id, asset_id, cve_id, matched_cpe,
                version_source, confidence_state, kev, epss, derivation,
                priority, priority_rule, priority_reason)
            values (%s, %s, %s, 'cpe:2.3:a:v:p:1:*:*:*:*:*:*:*', 'package_manager',
                    'confirmed', %s, %s, 'deterministic',
                    'p1', 'kev-actively-exploited', 'seeded for this test')
            """,
            (tenant, asset_id, cve, kev, epss),
        )

    pending = PostgresTriageStore(conn).pending_matches(tenant)

    assert [entry.match.cve_id for entry in pending] == ["CVE-2024-0002", "CVE-2024-0001"]
    assert pending[0].match.kev is True
    assert pending[0].match.provenance.derivation == "deterministic"


def test_the_dossier_source_reads_only_within_the_tenant(conn: Connection, tenant: UUID) -> None:
    asset_id = seed_asset(conn, tenant)
    source = PostgresDossierSource(conn)

    assert source.asset(tenant, asset_id) is not None
    assert source.asset(uuid4(), asset_id) is None


def test_the_dossier_source_returns_the_asset_as_the_contract_expects(
    conn: Connection, tenant: UUID
) -> None:
    asset_id = seed_asset(conn, tenant)

    asset = PostgresDossierSource(conn).asset(tenant, asset_id)

    assert asset is not None
    assert asset.asset_class is AssetClass.SERVER
    assert asset.management_state is ManagementState.UNMANAGED


# --------------------------------------------------------------- the review history


def test_a_review_writes_an_immutable_event(conn: Connection, tenant: UUID) -> None:
    """The current-state columns are the summary an analyst's list view reads; this is the
    record of what actually happened. Same discipline as `asset_merge_event`
    (data-model §4)."""
    triage = snapshot_for(conn, tenant)
    store = PostgresTriageStore(conn)
    store.record_snapshot(triage)
    record = store.record_insight(proposal(triage))

    store.review_insight(
        InsightReview(
            insight_id=record.insight_id,
            outcome=ReviewOutcome.ACCEPTED,
            reviewer="dmora",
            rationale="Agreed — the host is internet-facing.",
        )
    )
    history = store.review_history(record.insight_id)

    assert len(history) == 1
    assert history[0].kind == "accept"
    assert history[0].from_state == "proposed"
    assert history[0].to_state == "accepted"
    assert history[0].reviewer == "dmora"
    assert history[0].rationale == "Agreed — the host is internet-facing."
    assert history[0].occurred_at is not None


def test_the_review_event_table_refuses_update_and_delete(conn: Connection, tenant: UUID) -> None:
    """A review history that can be edited afterwards is not a history."""
    triage = snapshot_for(conn, tenant)
    store = PostgresTriageStore(conn)
    store.record_snapshot(triage)
    record = store.record_insight(proposal(triage))
    store.review_insight(
        InsightReview(
            insight_id=record.insight_id, outcome=ReviewOutcome.ACCEPTED, reviewer="dmora"
        )
    )

    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("update insight_review_event set reviewer = 'someone else'")


def test_a_review_event_cannot_be_deleted(conn: Connection, tenant: UUID) -> None:
    triage = snapshot_for(conn, tenant)
    store = PostgresTriageStore(conn)
    store.record_snapshot(triage)
    record = store.record_insight(proposal(triage))
    store.review_insight(
        InsightReview(
            insight_id=record.insight_id, outcome=ReviewOutcome.ACCEPTED, reviewer="dmora"
        )
    )

    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("delete from insight_review_event")


def test_the_history_reads_back_in_order(conn: Connection, tenant: UUID) -> None:
    triage = snapshot_for(conn, tenant)
    store = PostgresTriageStore(conn)
    store.record_snapshot(triage)
    record = store.record_insight(proposal(triage))

    store.review_insight(
        InsightReview(
            insight_id=record.insight_id,
            outcome=ReviewOutcome.ADJUSTED,
            reviewer="ana",
            recommendation="maintain",
            rationale="Right finding, wrong urgency.",
        )
    )
    store.review_insight(
        InsightReview(
            insight_id=record.insight_id, outcome=ReviewOutcome.ACCEPTED, reviewer="dmora"
        )
    )

    history = store.review_history(record.insight_id)

    assert [event.kind for event in history] == ["adjust", "accept"]
    assert [event.reviewer for event in history] == ["ana", "dmora"]
    assert history[0].recommendation == "maintain"


def test_the_projection_and_the_event_commit_together(conn: Connection, tenant: UUID) -> None:
    """One transaction, like the merge path. A current-state column that can disagree with
    its own event log is worse than not having the column."""
    triage = snapshot_for(conn, tenant)
    store = PostgresTriageStore(conn)
    store.record_snapshot(triage)
    record = store.record_insight(proposal(triage))

    store.review_insight(
        InsightReview(
            insight_id=record.insight_id,
            outcome=ReviewOutcome.REJECTED,
            reviewer="dmora",
            rationale="Not reachable from the network this sits on.",
        )
    )

    row = conn.execute(
        "select state, review_outcome, reviewed_by from insight where id = %s",
        (record.insight_id,),
    ).fetchone()
    history = store.review_history(record.insight_id)

    assert row is not None
    # A rejection is reviewed-and-not-accepted: the contract's lifecycle cannot say that on
    # its own, so the outcome column says it instead (ADR-0015).
    assert row[0] == "human_reviewed"
    assert row[1] == "rejected"
    assert row[2] == "dmora"
    assert [event.kind for event in history] == ["reject"]


def test_an_adjustment_records_the_analysts_own_recommendation(
    conn: Connection, tenant: UUID
) -> None:
    """The model's `recommendation` is evidence of what it said and is never overwritten;
    the human's call lands beside it."""
    triage = snapshot_for(conn, tenant)
    store = PostgresTriageStore(conn)
    store.record_snapshot(triage)
    record = store.record_insight(proposal(triage, recommendation="raise_priority"))

    store.review_insight(
        InsightReview(
            insight_id=record.insight_id,
            outcome=ReviewOutcome.ADJUSTED,
            reviewer="ana",
            recommendation="maintain",
        )
    )

    row = conn.execute(
        "select recommendation, analyst_recommendation from insight where id = %s",
        (record.insight_id,),
    ).fetchone()

    assert row is not None
    assert row[0] == "raise_priority"  # the model's, untouched
    assert row[1] == "maintain"  # the analyst's, recorded


def test_an_adjustment_that_adjusts_nothing_is_refused(conn: Connection, tenant: UUID) -> None:
    triage = snapshot_for(conn, tenant)
    store = PostgresTriageStore(conn)
    store.record_snapshot(triage)
    record = store.record_insight(proposal(triage))

    with pytest.raises(ValidationError, match="analyst's recommendation"):
        store.review_insight(
            InsightReview(
                insight_id=record.insight_id, outcome=ReviewOutcome.ADJUSTED, reviewer="ana"
            )
        )


def test_the_analyst_cannot_bury_a_kev_finding_either(conn: Connection, tenant: UUID) -> None:
    """The UX is explicit: neither the AI nor the analyst gets to hide an actively-exploited
    finding. The same rule as the model's, and the DB CHECK
    `insight_analyst_kev_not_hidden` says it too."""
    triage = snapshot_for(conn, tenant, kev=True)
    store = PostgresTriageStore(conn)
    store.record_snapshot(triage)
    record = store.record_insight(proposal(triage))

    with pytest.raises(ValidationError, match="KEV"):
        store.review_insight(
            InsightReview(
                insight_id=record.insight_id,
                outcome=ReviewOutcome.ADJUSTED,
                reviewer="ana",
                recommendation="lower_priority",
            )
        )

    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "update insight set analyst_recommendation = 'lower_priority' where id = %s",
            (record.insight_id,),
        )


def test_a_match_stores_its_cvss_and_its_priority_reason(conn: Connection, tenant: UUID) -> None:
    """What the interface reads: the score NVD published, the band, and the sentence that
    explains the band — none of it re-derived at read time (ux-design §2)."""
    asset_id = seed_asset(conn, tenant)
    conn.execute(
        """
        insert into vulnerability_match (tenant_id, asset_id, cve_id, matched_cpe,
            version_source, confidence_state, kev, epss, cvss_score, cvss_vector,
            cvss_version, priority, priority_rule, priority_reason, derivation)
        values (%s, %s, 'CVE-2023-25690', 'cpe:2.3:a:v:p:1:*:*:*:*:*:*:*', 'package_manager',
                'confirmed', true, 0.42, 9.8, 'CVSS:3.1/AV:N', '3.1',
                'p1', 'kev-actively-exploited', 'CISA lists it as known exploited.',
                'deterministic')
        """,
        (tenant, asset_id),
    )

    row = conn.execute(
        "select cvss_score, cvss_version, priority, priority_rule, priority_reason "
        "from vulnerability_match where tenant_id = %s",
        (tenant,),
    ).fetchone()

    assert row is not None
    assert row[0] == 9.8
    assert row[1] == "3.1"
    assert row[2] == "p1"
    assert row[3] == "kev-actively-exploited"
    assert row[4]


def test_the_database_refuses_a_priority_with_no_explanation(
    conn: Connection, tenant: UUID
) -> None:
    """The constraint that keeps the band trustworthy. A priority nobody can explain is the
    competitor's failure this product displaces — the schema will not store one."""
    asset_id = seed_asset(conn, tenant)

    with pytest.raises(psycopg.errors.CheckViolation) as raised:
        conn.execute(
            """
            insert into vulnerability_match (tenant_id, asset_id, cve_id, matched_cpe,
                version_source, confidence_state, priority, priority_rule, priority_reason)
            values (%s, %s, 'CVE-2023-25690', 'cpe:2.3:a:v:p:1:*:*:*:*:*:*:*',
                    'package_manager', 'confirmed', 'p1', 'kev-actively-exploited', '  ')
            """,
            (tenant, asset_id),
        )

    assert "vuln_match_priority_explained" in str(raised.value)
