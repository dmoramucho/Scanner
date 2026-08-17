"""The one write, and the rules it re-enforces when the frontend is not there.

This file exists for a single sentence in m4-design §1: **the frontend never decides
security.** A UI will disable the control that would bury a KEV finding — and that disabled
button is a convenience, not a guarantee. Every test below skips the frontend entirely and
speaks to the API the way an attacker, a script, or a developer with the console open would.

The security-critical assertion is `test_the_api_refuses_to_bury_a_kev_finding_...`: a
request crafted to lower a KEV-listed finding is refused by the API, independently of any
client state, and the store and the database refuse it again behind that.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import AbstractContextManager
from datetime import UTC, datetime
from typing import Any, get_type_hints
from uuid import UUID, uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import sql

from adapters.postgres.triage_store import PostgresTriageStore
from api.app import create_app
from api.security import read_connection, write_connection
from config.settings import AppConfig
from domain.models import InsightReview, ReviewOutcome
from tests.integration.estate import api_config, seed_asset

pytestmark = pytest.mark.integration

Connection = psycopg.Connection[tuple[Any, ...]]
NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)

REVIEW = "/api/insights/{insight_id}/review"


def seed_insight(
    conn: Connection,
    tenant: UUID,
    *,
    kev: bool,
    recommendation: str = "raise_priority",
    hostname: str = "camera-01",
) -> UUID:
    """One insight in `proposed`, with the snapshot behind it."""
    asset_id = seed_asset(conn, tenant, hostname=hostname)
    snapshot = conn.execute(
        """
        insert into triage_snapshot (tenant_id, asset_id, cve_id, snapshot, content_hash,
                                     assembler_version)
        values (%s, %s, 'CVE-2023-25690', '{"schema_version": 1}'::jsonb, sha256(%s), '1.0.0')
        returning id
        """,
        (tenant, asset_id, uuid4().bytes),
    ).fetchone()
    assert snapshot is not None

    row = conn.execute(
        """
        insert into insight (tenant_id, triage_id, recommendation, rationale, cited_sources,
                             confidence, model_version, kev_locked_visible)
        values (%s, %s, %s, 'The affected path is reachable from the internet.',
                '[{"kind":"advisory","ref":"CVE-2023-25690"}]'::jsonb, 0.8,
                'llama3.3:70b', %s)
        returning id
        """,
        (tenant, snapshot[0], recommendation, kev),
    ).fetchone()
    assert row is not None
    insight_id: UUID = row[0]
    return insight_id


@pytest.fixture
def tenant() -> UUID:
    return uuid4()


@pytest.fixture
def config(tenant: UUID, migrated_database: str) -> AppConfig:
    return api_config(tenant, migrated_database)


@pytest.fixture
def client(config: AppConfig, conn: Connection) -> Iterator[TestClient]:
    """Reads and the write both run on the test transaction, so everything rolls back.

    Both dependencies are overridden separately — which is itself the point: the app has two
    connection seams, and only one of them can write.
    """
    app = create_app(config)
    app.dependency_overrides[read_connection] = lambda: conn
    app.dependency_overrides[write_connection] = lambda: conn
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def history_rows(conn: Connection, insight_id: UUID) -> list[tuple[Any, ...]]:
    return conn.execute(
        "select kind, from_state, to_state, reviewer, recommendation, rationale "
        "from insight_review_event where insight_id = %s order by occurred_at, id",
        (insight_id,),
    ).fetchall()


# ================================================ security-critical: the KEV floor via HTTP


def test_the_api_refuses_to_bury_a_kev_finding_even_when_the_frontend_is_bypassed(
    client: TestClient, conn: Connection, tenant: UUID
) -> None:
    """**The assertion this file exists for.**

    A UI will disable the control that lowers a KEV-listed finding. This request never went
    near a UI: it is a hand-built POST asking the API directly to record `lower_priority` on
    a finding CISA says is being exploited right now. The API refuses it — a clean 422, no
    state change, and nothing written to the append-only history.

    That is "the frontend never decides security" made concrete (m4-design §1, AGENTS.md
    §2.8): the control lives here, so bypassing the client buys an attacker nothing.
    """
    insight_id = seed_insight(conn, tenant, kev=True)

    response = client.post(
        REVIEW.format(insight_id=insight_id),
        json={
            "outcome": "adjusted",
            "recommendation": "lower_priority",
            "rationale": "Not exploitable in our configuration.",
        },
    )

    assert response.status_code == 422
    assert response.json()["error"] == "invalid_request"
    assert "KEV" in response.json()["detail"]

    # Nothing moved, and nothing was written: a refusal is not a partial success.
    row = conn.execute(
        "select state, review_outcome, analyst_recommendation from insight where id = %s",
        (insight_id,),
    ).fetchone()
    assert row is not None
    assert row[0] == "proposed"
    assert row[1] is None
    assert row[2] is None
    assert history_rows(conn, insight_id) == []


@pytest.mark.parametrize("outcome", ["accepted", "rejected", "adjusted"])
def test_no_outcome_can_carry_a_kev_lowering_recommendation(
    client: TestClient, conn: Connection, tenant: UUID, outcome: str
) -> None:
    """The refusal is about the *recommendation*, not the button that carried it. Wrapping
    `lower_priority` in an accept or a reject changes nothing."""
    insight_id = seed_insight(conn, tenant, kev=True)

    response = client.post(
        REVIEW.format(insight_id=insight_id),
        json={"outcome": outcome, "recommendation": "lower_priority"},
    )

    assert response.status_code == 422
    assert history_rows(conn, insight_id) == []


def test_a_kev_finding_can_still_be_accepted_and_raised(
    client: TestClient, conn: Connection, tenant: UUID
) -> None:
    """The other half of the rule. KEV locks a finding *visible*; it does not freeze the
    analyst out of deciding. Only the direction that hides it is refused."""
    insight_id = seed_insight(conn, tenant, kev=True)

    accepted = client.post(REVIEW.format(insight_id=insight_id), json={"outcome": "accepted"})
    assert accepted.status_code == 200
    assert accepted.json()["state"] == "accepted"
    assert accepted.json()["kev_locked_visible"] is True

    raised = seed_insight(conn, tenant, kev=True, hostname="camera-02")
    response = client.post(
        REVIEW.format(insight_id=raised),
        json={"outcome": "adjusted", "recommendation": "raise_priority"},
    )
    assert response.status_code == 200


def test_a_non_kev_finding_may_be_lowered(
    client: TestClient, conn: Connection, tenant: UUID
) -> None:
    """A triage tool has to let an analyst say "this one matters less". The floor applies to
    KEV findings, and only to them."""
    insight_id = seed_insight(conn, tenant, kev=False)

    response = client.post(
        REVIEW.format(insight_id=insight_id),
        json={"outcome": "adjusted", "recommendation": "lower_priority"},
    )

    assert response.status_code == 200
    assert response.json()["history"][0]["recommendation"] == "lower_priority"


def test_the_database_refuses_a_kev_lowering_written_around_the_api(
    conn: Connection, tenant: UUID
) -> None:
    """The last of the three layers, asserted on its own.

    If the API check were removed and the store's check with it, this is what would still
    stop an actively-exploited finding being argued down the page (P17's
    `insight_analyst_kev_not_hidden`).
    """
    insight_id = seed_insight(conn, tenant, kev=True)

    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            "update insight set analyst_recommendation = 'lower_priority' where id = %s",
            (insight_id,),
        )


# ===================================================== security-critical: tenant scope


def test_a_caller_cannot_review_another_tenants_insight(
    client: TestClient, conn: Connection
) -> None:
    """404, not 403 — the same answer as an insight that does not exist, so an id cannot be
    probed for existence (ADR-0016)."""
    other = uuid4()
    insight_id = seed_insight(conn, other, kev=False, hostname="not-ours")

    response = client.post(REVIEW.format(insight_id=insight_id), json={"outcome": "accepted"})

    assert response.status_code == 404
    assert response.json()["detail"] == "the requested resource was not found"
    assert history_rows(conn, insight_id) == []
    row = conn.execute("select state from insight where id = %s", (insight_id,)).fetchone()
    assert row is not None
    assert row[0] == "proposed"  # untouched


def test_reviewing_an_insight_that_does_not_exist_is_the_same_404(client: TestClient) -> None:
    response = client.post(REVIEW.format(insight_id=uuid4()), json={"outcome": "accepted"})

    assert response.status_code == 404
    assert response.json()["detail"] == "the requested resource was not found"


# ============================================================ the event and the state


def test_a_decision_writes_the_state_and_its_immutable_event(
    client: TestClient, conn: Connection, tenant: UUID
) -> None:
    """The projection and the history, together — the P17 discipline reaching HTTP. There is
    no path that records a decision without recording who made it."""
    insight_id = seed_insight(conn, tenant, kev=False)

    response = client.post(
        REVIEW.format(insight_id=insight_id),
        json={"outcome": "rejected", "rationale": "The affected module is not loaded."},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "human_reviewed"

    events = history_rows(conn, insight_id)
    assert len(events) == 1
    kind, from_state, to_state, reviewer, _recommendation, rationale = events[0]
    assert (kind, from_state, to_state) == ("reject", "proposed", "human_reviewed")
    assert reviewer == "local-operator"
    assert rationale == "The affected module is not loaded."

    row = conn.execute(
        "select state, review_outcome, reviewed_by, reviewed_at from insight where id = %s",
        (insight_id,),
    ).fetchone()
    assert row is not None
    assert row[0] == "human_reviewed"
    assert row[1] == "rejected"
    assert row[2] == "local-operator"
    assert row[3] is not None


def test_the_review_event_is_immutable(client: TestClient, conn: Connection, tenant: UUID) -> None:
    """An audit trail that can be edited afterwards is not an audit trail."""
    insight_id = seed_insight(conn, tenant, kev=False)
    client.post(REVIEW.format(insight_id=insight_id), json={"outcome": "accepted"})

    with pytest.raises(psycopg.errors.RaiseException):
        conn.execute("update insight_review_event set reviewer = 'mallory'")


def test_a_refused_decision_leaves_no_partial_write(
    client: TestClient, conn: Connection, tenant: UUID
) -> None:
    """The state update and the event commit together, so a refusal cannot leave one of
    them behind."""
    insight_id = seed_insight(conn, tenant, kev=True)

    client.post(
        REVIEW.format(insight_id=insight_id),
        json={"outcome": "adjusted", "recommendation": "lower_priority"},
    )

    row = conn.execute(
        "select state, reviewed_by from insight where id = %s", (insight_id,)
    ).fetchone()
    assert row is not None
    assert (row[0], row[1]) == ("proposed", None)
    assert history_rows(conn, insight_id) == []


def test_the_history_accumulates_in_order(
    client: TestClient, conn: Connection, tenant: UUID
) -> None:
    """`proposed → human_reviewed → accepted`, each step its own entry."""
    insight_id = seed_insight(conn, tenant, kev=False)

    client.post(
        REVIEW.format(insight_id=insight_id),
        json={"outcome": "adjusted", "recommendation": "maintain"},
    )
    final = client.post(REVIEW.format(insight_id=insight_id), json={"outcome": "accepted"})

    assert final.status_code == 200
    assert [event["kind"] for event in final.json()["history"]] == ["adjust", "accept"]
    assert [event["to_state"] for event in final.json()["history"]] == [
        "human_reviewed",
        "accepted",
    ]


def test_an_adjustment_records_the_analysts_recommendation_beside_the_models(
    client: TestClient, conn: Connection, tenant: UUID
) -> None:
    """The model's output is evidence of what it said and is never overwritten."""
    insight_id = seed_insight(conn, tenant, kev=False, recommendation="raise_priority")

    response = client.post(
        REVIEW.format(insight_id=insight_id),
        json={"outcome": "adjusted", "recommendation": "maintain"},
    )

    assert response.json()["recommendation"] == "raise_priority"  # the model's, untouched
    row = conn.execute(
        "select analyst_recommendation from insight where id = %s", (insight_id,)
    ).fetchone()
    assert row is not None
    assert row[0] == "maintain"


# ==================================================================== state transitions


def test_a_backwards_transition_is_a_conflict(
    client: TestClient, conn: Connection, tenant: UUID
) -> None:
    """Well-formed, and it conflicts with a decision a human already made — 409, not 422.
    Re-reviewing backwards would quietly erase that decision."""
    insight_id = seed_insight(conn, tenant, kev=False)
    client.post(REVIEW.format(insight_id=insight_id), json={"outcome": "accepted"})

    response = client.post(REVIEW.format(insight_id=insight_id), json={"outcome": "rejected"})

    assert response.status_code == 409
    assert response.json()["error"] == "conflict"
    assert len(history_rows(conn, insight_id)) == 1


def test_an_adjustment_must_say_what_it_adjusts(
    client: TestClient, conn: Connection, tenant: UUID
) -> None:
    """An "adjustment" that adjusts nothing is a state change wearing the wrong label."""
    insight_id = seed_insight(conn, tenant, kev=False)

    response = client.post(REVIEW.format(insight_id=insight_id), json={"outcome": "adjusted"})

    assert response.status_code == 422
    assert history_rows(conn, insight_id) == []


# ========================================================================= idempotency


def test_an_identical_decision_resubmitted_writes_no_second_event(
    client: TestClient, conn: Connection, tenant: UUID
) -> None:
    """A double-clicked button, or a client that never saw the first response.

    The state is already what the request asks for, so the second call returns it and writes
    nothing. The history says a human decided once, because a human did (ADR-0017).
    """
    insight_id = seed_insight(conn, tenant, kev=False)
    body = {"outcome": "accepted"}

    first = client.post(REVIEW.format(insight_id=insight_id), json=body)
    second = client.post(REVIEW.format(insight_id=insight_id), json=body)
    third = client.post(REVIEW.format(insight_id=insight_id), json=body)

    assert first.status_code == second.status_code == third.status_code == 200
    assert first.json()["state"] == third.json()["state"] == "accepted"
    assert len(history_rows(conn, insight_id)) == 1
    assert len(third.json()["history"]) == 1


def test_a_repeated_adjustment_with_a_different_recommendation_is_recorded(
    client: TestClient, conn: Connection, tenant: UUID
) -> None:
    """Idempotency is about *identical* decisions. Changing your mind within the same state
    is a new decision and belongs in the history."""
    insight_id = seed_insight(conn, tenant, kev=False)

    client.post(
        REVIEW.format(insight_id=insight_id),
        json={"outcome": "adjusted", "recommendation": "maintain"},
    )
    client.post(
        REVIEW.format(insight_id=insight_id),
        json={"outcome": "adjusted", "recommendation": "raise_priority"},
    )

    assert len(history_rows(conn, insight_id)) == 2


# =============================================================== untrusted input (§68)


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"outcome": "approved"},
        {"outcome": "accepted", "recommendation": "delete_the_finding"},
        {"outcome": "accepted", "state": "accepted"},
        {"outcome": "accepted", "reviewer": "someone-else"},
        {"outcome": "accepted", "rationale": "x" * 5000},
        {"outcome": ["accepted"]},
        {"outcome": None},
    ],
)
def test_a_malformed_decision_is_422_and_changes_nothing(
    client: TestClient, conn: Connection, tenant: UUID, body: dict[str, Any]
) -> None:
    """Every shape a caller can get wrong: a bounded 422, no state change, no event, and no
    value reaching a query."""
    insight_id = seed_insight(conn, tenant, kev=False)

    response = client.post(REVIEW.format(insight_id=insight_id), json=body)

    assert response.status_code == 422, body
    assert "Traceback" not in response.text
    assert history_rows(conn, insight_id) == []


def test_a_caller_cannot_sign_a_review_with_someone_elses_name(
    client: TestClient, conn: Connection, tenant: UUID
) -> None:
    """Who decided is server-side, like the tenant.

    With no authentication, a `reviewer` field in the body would let anyone attribute a
    decision to a named colleague — in an append-only history that cannot be corrected. The
    field is refused outright rather than ignored (ADR-0017).
    """
    insight_id = seed_insight(conn, tenant, kev=False)

    refused = client.post(
        REVIEW.format(insight_id=insight_id),
        json={"outcome": "accepted", "reviewer": "alice"},
    )
    assert refused.status_code == 422

    client.post(REVIEW.format(insight_id=insight_id), json={"outcome": "accepted"})
    assert history_rows(conn, insight_id)[0][3] == "local-operator"


def test_a_malformed_insight_id_is_422(client: TestClient) -> None:
    response = client.post("/api/insights/not-a-uuid/review", json={"outcome": "accepted"})

    assert response.status_code == 422
    assert "Traceback" not in response.text


def test_the_review_endpoint_is_refused_from_a_non_loopback_client(
    config: AppConfig, conn: Connection, tenant: UUID
) -> None:
    """The write is behind the same gate as everything else — and it is the one that
    matters most, because it changes state (m4-design §5)."""
    insight_id = seed_insight(conn, tenant, kev=False)
    app = create_app(config)
    app.dependency_overrides[read_connection] = lambda: conn
    app.dependency_overrides[write_connection] = lambda: conn

    with TestClient(app, client=("203.0.113.9", 51234)) as remote:
        response = remote.post(REVIEW.format(insight_id=insight_id), json={"outcome": "accepted"})

    assert response.status_code == 403
    assert history_rows(conn, insight_id) == []


# ============================================================ the read path is unchanged


def test_a_failure_writing_the_event_rolls_back_the_state_change(
    conn: Connection, tenant: UUID
) -> None:
    """Never a state change without its event, proven by breaking the event.

    The two writes share a transaction, so a failure on the second must undo the first. A
    projection that survived while its history did not would be a decision nobody can trace
    — which is the exact failure the append-only log exists to prevent (data-model §4).
    """
    insight_id = seed_insight(conn, tenant, kev=False)

    class EventWritesFail:
        """The real connection, except that the event insert raises."""

        def __init__(self, wrapped: Connection) -> None:
            self._wrapped = wrapped

        def execute(
            self,
            query: str | bytes | sql.SQL | sql.Composed,
            params: Sequence[Any] | Mapping[str, Any] | None = None,
        ) -> psycopg.Cursor[tuple[Any, ...]]:
            if "insight_review_event" in str(query):
                raise psycopg.errors.DiskFull("simulated failure writing the event")
            return self._wrapped.execute(query, params)

        def transaction(self) -> AbstractContextManager[psycopg.Transaction]:
            return self._wrapped.transaction()

    store = PostgresTriageStore(EventWritesFail(conn))  # type: ignore[arg-type]

    with pytest.raises(psycopg.errors.DiskFull):
        store.review_insight(
            tenant,
            InsightReview(
                insight_id=insight_id, outcome=ReviewOutcome.ACCEPTED, reviewer="local-operator"
            ),
        )

    row = conn.execute(
        "select state, reviewed_by from insight where id = %s", (insight_id,)
    ).fetchone()
    assert row is not None
    assert (row[0], row[1]) == ("proposed", None)
    assert history_rows(conn, insight_id) == []


def test_the_write_route_is_wired_to_the_write_connection(config: AppConfig) -> None:
    """Structural, because a test that overrides both connections cannot see the difference.

    `review_store` must depend on `write_connection` and nothing else — that is what keeps
    the write capability attached to one route rather than to the app (ADR-0017).
    """
    from api.security import review_store, write_connection

    # `get_type_hints` rather than `inspect.signature`: the module uses postponed
    # annotations, so the `Depends(...)` marker only exists once the hints are resolved.
    hints = get_type_hints(review_store, include_extras=True)
    dependencies = [
        metadata.dependency
        for hint in hints.values()
        for metadata in getattr(hint, "__metadata__", ())
        if hasattr(metadata, "dependency")
    ]

    assert dependencies == [write_connection]


def test_the_read_endpoints_still_run_on_a_read_only_connection(config: AppConfig) -> None:
    """P19 grants the write capability to one route, not to the app.

    Asserted on the real dependencies: the read connection still refuses a mutation, and the
    write connection is a *different* one. A future handler that wants to write has to ask
    for it visibly (ADR-0017).
    """
    reads = read_connection(config)
    read_conn = next(iter(reads))
    try:
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            read_conn.execute("delete from insight")
    finally:
        read_conn.close()

    writes = write_connection(config)
    write_conn = next(iter(writes))
    try:
        assert write_conn.read_only is not True
    finally:
        write_conn.close()


def test_a_reviewed_insight_leaves_the_review_queue(
    client: TestClient, conn: Connection, tenant: UUID
) -> None:
    """The loop closing: the queue on the landing surface is insights still in `proposed`,
    so a decision removes one from it (ux-design §3.1)."""
    insight_id = seed_insight(conn, tenant, kev=False)
    assert len(client.get("/api/worklist").json()["review_queue"]) == 1

    client.post(REVIEW.format(insight_id=insight_id), json={"outcome": "accepted"})

    assert client.get("/api/worklist").json()["review_queue"] == []
