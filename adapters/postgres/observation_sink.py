"""Postgres-backed `ObservationSink` — the one write path into the history spine.

Three properties the contract puts here rather than in the caller (ports.md §5):

* **The sink computes `content_hash` itself.** Callers cannot get it wrong, and two
  callers that serialise the same payload differently still collide correctly, because
  the hash is taken over a canonical form (sorted keys, no insignificant whitespace).
* **Idempotency is the database's job.** The write is a single `INSERT … ON CONFLICT DO
  NOTHING` against the `observation_dedup` unique index — never check-then-insert
  (AGENTS.md §62), which has a race between the check and the insert.
* **A repeat within a run is a no-op; the same content in a *later* run is a new row.**
  `run_id` is part of the dedup key: re-observation is additional evidence with its own
  provenance, not a duplicate to discard (AGENTS.md §3).

Note on the `ON CONFLICT` variant: the usual `DO UPDATE … RETURNING` trick for learning
whether a row was inserted is unavailable here by design — `observation` carries the
`forbid_mutation()` trigger, so any `UPDATE` against it is refused. `DO NOTHING` plus a
lookup of the existing id is the correct shape for an append-only table.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from datetime import datetime
from typing import Any, Final
from uuid import UUID

import psycopg

from domain.errors import ValidationError
from domain.models import ObservationInput, ObservationRecord

Connection = psycopg.Connection[tuple[Any, ...]]

_INSERT_SQL: Final = """
    insert into observation (
        tenant_id, asset_id, observation_type, payload,
        source, source_type, source_identifier,
        collector, collector_version, collection_method,
        version_source, confidence, content_hash, raw_record_ref,
        observed_at, collected_at, run_id
    ) values (
        %(tenant_id)s, %(asset_id)s, %(observation_type)s, %(payload)s::jsonb,
        %(source)s, %(source_type)s, %(source_identifier)s,
        %(collector)s, %(collector_version)s, %(collection_method)s,
        %(version_source)s, %(confidence)s, %(content_hash)s, %(raw_record_ref)s,
        %(observed_at)s, %(collected_at)s, %(run_id)s
    )
    on conflict (tenant_id, run_id, coalesce(source_identifier, ''), observation_type, content_hash)
    do nothing
    returning id
"""

_EXISTING_SQL: Final = """
    select id from observation
    where tenant_id = %(tenant_id)s
      and run_id = %(run_id)s
      and coalesce(source_identifier, '') = coalesce(%(source_identifier)s, '')
      and observation_type = %(observation_type)s
      and content_hash = %(content_hash)s
"""


def canonical_payload(payload: dict[str, Any]) -> str:
    """The exact bytes the hash is taken over.

    Sorted keys and no insignificant whitespace, so two semantically identical payloads
    hash identically regardless of how the caller built the dict. `allow_nan=False`
    because NaN/Infinity are not JSON and `jsonb` would reject them anyway — better to
    fail in the adapter with a domain error than at the database with a driver error.
    """
    try:
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        )
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"observation payload is not JSON-serialisable: {exc}") from exc


def content_hash(payload: dict[str, Any]) -> bytes:
    """sha256 of the canonical payload — tamper-evidence and the dedup discriminator."""
    return hashlib.sha256(canonical_payload(payload).encode("utf-8")).digest()


def _require_utc_aware(name: str, value: datetime) -> None:
    """Timestamps are UTC and explicit. A naive datetime is ambiguous, and guessing a zone
    would silently corrupt the history spine (AGENTS.md §5)."""
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValidationError(f"{name} must be timezone-aware (UTC); got a naive datetime")


class PostgresObservationSink:
    """`ObservationSink` over the append-only `observation` table.

    Transaction handling is the caller's: with an autocommit connection each observation
    is durable as it lands; inside a transaction, a batch is all-or-nothing. The sink does
    not decide that for you, because the right unit of work belongs to the ingestion flow.
    """

    def __init__(self, conn: Connection) -> None:
        self._conn = conn

    def record(self, obs: ObservationInput) -> ObservationRecord:
        """Idempotent write. Returns `created=False` when the row was already present."""
        params = self._params(obs)

        inserted = self._conn.execute(_INSERT_SQL, params).fetchone()
        if inserted is not None:
            return ObservationRecord(observation_id=UUID(str(inserted[0])), created=True)

        # The insert was refused by the unique index, so the row exists: read its id.
        # This is not a check-then-insert — the insert already happened and lost the race.
        existing = self._conn.execute(_EXISTING_SQL, params).fetchone()
        if existing is None:  # pragma: no cover — only reachable if the index changed
            raise ValidationError(
                "observation insert conflicted but no matching row was found; the dedup "
                "key and the observation_dedup index have diverged"
            )
        return ObservationRecord(observation_id=UUID(str(existing[0])), created=False)

    def record_batch(self, batch: Sequence[ObservationInput]) -> list[ObservationRecord]:
        """Per-item idempotency, results in input order.

        A straightforward loop: batching this into one round trip is an optimisation with
        no measurement behind it yet (AGENTS.md §4.11), and the per-item semantics have to
        survive it.
        """
        return [self.record(obs) for obs in batch]

    def _params(self, obs: ObservationInput) -> dict[str, Any]:
        _require_utc_aware("observed_at", obs.observed_at)
        _require_utc_aware("collected_at", obs.collected_at)
        return {
            "tenant_id": obs.tenant_id,
            "asset_id": obs.asset_id,
            "observation_type": obs.observation_type,
            "payload": canonical_payload(obs.payload),
            "source": obs.source,
            "source_type": obs.source_type,
            "source_identifier": obs.source_identifier,
            "collector": obs.collector,
            "collector_version": obs.collector_version,
            "collection_method": obs.collection_method,
            "version_source": obs.version_source.value if obs.version_source else None,
            "confidence": obs.confidence,
            "content_hash": content_hash(obs.payload),
            "raw_record_ref": obs.raw_record_ref,
            "observed_at": obs.observed_at,
            "collected_at": obs.collected_at,
            "run_id": obs.run_id,
        }
