"""Postgres-backed `ManagedRecordSink` — idempotent writes into `managed_record`.

The table and its `(tenant_id, source, external_id)` unique key already exist (migration
`0001_expand`), so this is a write path, not a schema change (m2-design §7).

Two decisions worth naming:

* **Re-import refreshes rather than duplicates.** A CMDB row's contents legitimately change
  between exports — a device gets a new owner, a serial gets corrected — and the latest
  export is the current statement of what is believed. So the conflict resolution is
  `DO UPDATE`, not `DO NOTHING`, and `created=False` tells the caller it was already known.
* **The unique index arbitrates, never a preceding lookup** (AGENTS.md §62). Two concurrent
  imports of the same export cannot produce two rows.

Unlike `observation`, `managed_record` is not append-only: it is a *projection* of an
external system's current state, and its history lives in that system. The rows this writes
carry provenance — which export, taken when — so a record can always be traced to the file
that asserted it.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any, Final
from uuid import UUID

import psycopg

from domain.errors import ValidationError
from domain.models import ManagedRecordInput, ManagedRecordResult

Connection = psycopg.Connection[tuple[Any, ...]]

#: `xmax = 0` is true only for a row this statement inserted; a row it updated carries the
#: updating transaction's id. It is the standard way to tell an upsert's two outcomes apart
#: in one round trip.
_UPSERT_SQL: Final = """
    insert into managed_record (
        tenant_id, source, external_id, payload, observed_at
    ) values (
        %(tenant_id)s, %(source)s, %(external_id)s, %(payload)s::jsonb, %(observed_at)s
    )
    on conflict (tenant_id, source, external_id) do update set
        payload = excluded.payload,
        observed_at = excluded.observed_at,
        ingested_at = now()
    returning id, (xmax = 0) as created
"""


class PostgresManagedRecordSink:
    """`ManagedRecordSink` over the existing `managed_record` table."""

    def __init__(self, conn: Connection) -> None:
        self._conn = conn

    def record(self, entry: ManagedRecordInput) -> ManagedRecordResult:
        """Insert or refresh one record. `created=False` means it was already known."""
        row = self._conn.execute(_UPSERT_SQL, self._params(entry)).fetchone()
        if row is None:  # pragma: no cover — an upsert with DO UPDATE always returns a row
            raise ValidationError(
                f"managed_record upsert for {entry.external_id!r} returned no row"
            )
        return ManagedRecordResult(record_id=UUID(str(row[0])), created=bool(row[1]))

    def record_batch(self, batch: Sequence[ManagedRecordInput]) -> list[ManagedRecordResult]:
        """Per-item idempotency, results in input order."""
        return [self.record(entry) for entry in batch]

    def _params(self, entry: ManagedRecordInput) -> dict[str, Any]:
        if entry.observed_at.tzinfo is None:
            raise ValidationError("observed_at must be timezone-aware (UTC)")

        # The identity fields and the extras become the payload. `source_ref` travels with
        # them: a record whose truth is "someone said so" has to say which file said it.
        payload = {
            "hostname": entry.hostname,
            "serial": entry.serial,
            "mac": entry.mac,
            "ip": entry.ip,
            "owner": entry.owner,
            "source_ref": entry.source_ref,
            "attributes": dict(entry.attributes),
        }
        return {
            "tenant_id": entry.tenant_id,
            "source": entry.source.value,
            "external_id": entry.external_id,
            "payload": json.dumps(payload, sort_keys=True, ensure_ascii=False),
            "observed_at": entry.observed_at,
        }
