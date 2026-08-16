"""The ingestion write path: idempotent by index, hashed by the sink (ports.md §5)."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest

from adapters.postgres.observation_sink import PostgresObservationSink, canonical_payload
from domain.errors import ValidationError
from domain.models import ObservationInput
from domain.ports import ObservationSink

pytestmark = pytest.mark.integration

Connection = psycopg.Connection[tuple[Any, ...]]

NOW = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)


@pytest.fixture
def tenant() -> UUID:
    return uuid4()


@pytest.fixture
def sink(autocommit_conn: Connection) -> PostgresObservationSink:
    return PostgresObservationSink(autocommit_conn)


def observation(
    tenant: UUID,
    run_id: UUID,
    *,
    payload: dict[str, Any] | None = None,
    source_identifier: str | None = "10.10.5.7",
    observed_at: datetime = NOW,
) -> ObservationInput:
    return ObservationInput(
        tenant_id=tenant,
        run_id=run_id,
        asset_id=None,
        observation_type="identity",
        payload=payload if payload is not None else {"ip": "10.10.5.7", "mac": "aa:bb:cc:dd:ee:ff"},
        source="arp",
        source_type="passive",
        source_identifier=source_identifier,
        collector="passive-collector",
        collector_version="0.1.0",
        collection_method="arp_table",
        version_source=None,
        confidence=0.9,
        observed_at=observed_at,
        collected_at=NOW,
        raw_record_ref=None,
    )


def stored_rows(conn: Connection, tenant: UUID) -> list[tuple[Any, ...]]:
    return conn.execute(
        "select id, content_hash, payload, run_id from observation where tenant_id = %s",
        (tenant,),
    ).fetchall()


# ------------------------------------------------------------------- idempotency


def test_a_retry_within_a_run_lands_once(
    sink: PostgresObservationSink, autocommit_conn: Connection, tenant: UUID
) -> None:
    """The DoD case: the same fixture ingested twice yields exactly one observation."""
    run_id = uuid4()

    first = sink.record(observation(tenant, run_id))
    second = sink.record(observation(tenant, run_id))

    assert first.created is True
    assert second.created is False
    assert second.observation_id == first.observation_id
    assert len(stored_rows(autocommit_conn, tenant)) == 1


def test_the_same_observation_in_a_later_run_is_new_evidence(
    sink: PostgresObservationSink, autocommit_conn: Connection, tenant: UUID
) -> None:
    """Re-observation is evidence with its own provenance, not a duplicate to discard
    (AGENTS.md §3)."""
    first = sink.record(observation(tenant, uuid4()))
    second = sink.record(observation(tenant, uuid4()))

    assert first.created is True
    assert second.created is True
    assert first.observation_id != second.observation_id
    assert len(stored_rows(autocommit_conn, tenant)) == 2


def test_key_order_does_not_change_the_hash(
    sink: PostgresObservationSink, autocommit_conn: Connection, tenant: UUID
) -> None:
    """Canonicalisation is why two callers that built the same payload differently still
    deduplicate — the sink owns the hash so they cannot get this wrong."""
    run_id = uuid4()

    first = sink.record(observation(tenant, run_id, payload={"a": 1, "b": [2, 3]}))
    second = sink.record(observation(tenant, run_id, payload={"b": [2, 3], "a": 1}))

    assert second.created is False
    assert second.observation_id == first.observation_id


def test_a_different_payload_is_a_different_observation(
    sink: PostgresObservationSink, tenant: UUID
) -> None:
    run_id = uuid4()

    first = sink.record(observation(tenant, run_id, payload={"ip": "10.10.5.7"}))
    second = sink.record(observation(tenant, run_id, payload={"ip": "10.10.5.8"}))

    assert second.created is True
    assert first.observation_id != second.observation_id


def test_a_null_source_identifier_still_deduplicates(
    sink: PostgresObservationSink, tenant: UUID
) -> None:
    """The dedup index keys on `coalesce(source_identifier, '')`; the lookup after a
    conflict has to use the same coalesce or a retry would look like a lost row."""
    run_id = uuid4()

    first = sink.record(observation(tenant, run_id, source_identifier=None))
    second = sink.record(observation(tenant, run_id, source_identifier=None))

    assert second.created is False
    assert second.observation_id == first.observation_id


def test_record_batch_is_per_item_idempotent_and_ordered(
    sink: PostgresObservationSink, autocommit_conn: Connection, tenant: UUID
) -> None:
    run_id = uuid4()
    first = observation(tenant, run_id, payload={"ip": "10.10.5.7"})
    duplicate = observation(tenant, run_id, payload={"ip": "10.10.5.7"})
    other = observation(tenant, run_id, payload={"ip": "10.10.5.8"})

    results = sink.record_batch([first, duplicate, other])

    assert [result.created for result in results] == [True, False, True]
    assert results[0].observation_id == results[1].observation_id
    assert len(stored_rows(autocommit_conn, tenant)) == 2


# ------------------------------------------------------------------- the hash


def test_the_sink_stores_sha256_of_the_canonical_payload(
    sink: PostgresObservationSink, autocommit_conn: Connection, tenant: UUID
) -> None:
    """Tamper-evidence is only worth something if the hash is reproducible from the row."""
    payload = {"ip": "10.10.5.7", "mac": "aa:bb:cc:dd:ee:ff"}

    sink.record(observation(tenant, uuid4(), payload=payload))

    _, stored_hash, stored_payload, _ = stored_rows(autocommit_conn, tenant)[0]
    expected = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).digest()
    assert bytes(stored_hash) == expected
    assert stored_payload == payload


def test_canonical_payload_is_stable_and_minimal() -> None:
    assert canonical_payload({"b": 1, "a": [1, 2]}) == '{"a":[1,2],"b":1}'


# ------------------------------------------------------------------- validation


def test_a_naive_timestamp_is_rejected(sink: PostgresObservationSink, tenant: UUID) -> None:
    """UTC-aware or nothing: guessing a zone would corrupt the history spine silently."""
    naive = observation(tenant, uuid4(), observed_at=datetime(2026, 8, 13, 12, 0))  # noqa: DTZ001

    with pytest.raises(ValidationError, match="timezone-aware"):
        sink.record(naive)


def test_an_unserialisable_payload_is_rejected(sink: PostgresObservationSink, tenant: UUID) -> None:
    with pytest.raises(ValidationError, match="JSON-serialisable"):
        sink.record(observation(tenant, uuid4(), payload={"when": datetime.now(UTC)}))


def test_a_nan_payload_is_rejected(sink: PostgresObservationSink, tenant: UUID) -> None:
    """NaN is not JSON and jsonb would refuse it — fail in the adapter with a domain error
    rather than at the driver."""
    with pytest.raises(ValidationError):
        sink.record(observation(tenant, uuid4(), payload={"confidence": float("nan")}))


# ------------------------------------------------------------------ conformance


def test_the_adapter_satisfies_the_port(autocommit_conn: Connection) -> None:
    sink: ObservationSink = PostgresObservationSink(autocommit_conn)

    assert callable(sink.record)
    assert callable(sink.record_batch)
