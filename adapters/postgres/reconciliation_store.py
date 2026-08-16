"""Postgres-backed `ReconciliationStore` — both sides of the diff, and its two projections.

Reads are deliberately narrow: an asset comes back as the set of anchors it can be matched
on, and a managed record as the three identity fields the CMDB carried. The diff never sees
a whole row, because matching is about identity and nothing else.

Writes are the two current-state projections m2-design §4 describes: which asset a record
describes (`managed_record.asset_id`), and what the diff concluded about each asset
(`asset.management_state`). Neither is append-only history — both are conclusions that
change as evidence changes, and the evidence itself stays in `observation` and
`managed_record`.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Final
from uuid import UUID

import psycopg

from domain.models import AssetAnchorSet, ManagedRecordSnapshot, ManagedSourceKind, ManagementState

Connection = psycopg.Connection[tuple[Any, ...]]

#: Active assets only: a merged asset is not a device, it is history pointing at its
#: survivor (AGENTS.md §3). Counting one as shadow IT would double-count a device.
_ASSET_ANCHORS_SQL: Final = """
    select a.id,
           coalesce(array_agg(i.value) filter (where i.kind = 'serial'), '{}') as serials,
           coalesce(array_agg(i.value) filter (where i.kind = 'mac'), '{}') as macs,
           coalesce(array_agg(i.value) filter (where i.kind = 'hostname'), '{}') as hostnames
    from asset a
    left join asset_identifier i on i.asset_id = a.id and i.tenant_id = a.tenant_id
    where a.tenant_id = %(tenant_id)s and a.status = 'active'
    group by a.id
"""

_MANAGED_RECORDS_SQL: Final = """
    select id, external_id, source,
           payload ->> 'serial' as serial,
           payload ->> 'mac' as mac,
           payload ->> 'hostname' as hostname
    from managed_record
    where tenant_id = %(tenant_id)s
    order by external_id
"""

_LINK_SQL: Final = "update managed_record set asset_id = %(asset_id)s where id = %(record_id)s"

_STATE_SQL: Final = """
    update asset set management_state = %(state)s, updated_at = now()
    where id = %(asset_id)s
"""


class PostgresReconciliationStore:
    """`ReconciliationStore` over `asset`, `asset_identifier` and `managed_record`."""

    def __init__(self, conn: Connection) -> None:
        self._conn = conn

    def asset_anchors(self, tenant_id: UUID) -> Sequence[AssetAnchorSet]:
        rows = self._conn.execute(_ASSET_ANCHORS_SQL, {"tenant_id": tenant_id}).fetchall()
        return [
            AssetAnchorSet(
                asset_id=UUID(str(row[0])),
                serials=frozenset(str(value) for value in row[1] if value),
                macs=frozenset(str(value) for value in row[2] if value),
                hostnames=frozenset(str(value) for value in row[3] if value),
            )
            for row in rows
        ]

    def managed_records(self, tenant_id: UUID) -> Sequence[ManagedRecordSnapshot]:
        rows = self._conn.execute(_MANAGED_RECORDS_SQL, {"tenant_id": tenant_id}).fetchall()
        return [
            ManagedRecordSnapshot(
                record_id=UUID(str(row[0])),
                external_id=str(row[1]),
                source=ManagedSourceKind(str(row[2])),
                serial=_text_or_none(row[3]),
                mac=_text_or_none(row[4]),
                hostname=_text_or_none(row[5]),
            )
            for row in rows
        ]

    def link_record(self, record_id: UUID, asset_id: UUID | None) -> None:
        self._conn.execute(_LINK_SQL, {"record_id": record_id, "asset_id": asset_id})

    def set_management_state(self, asset_id: UUID, state: ManagementState) -> None:
        self._conn.execute(_STATE_SQL, {"asset_id": asset_id, "state": state.value})


def _text_or_none(value: object) -> str | None:
    """`payload ->> 'serial'` gives SQL NULL for both a missing key and a JSON null."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None
