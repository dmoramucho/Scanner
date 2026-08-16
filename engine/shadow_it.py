"""Running the reconciliation and writing back what it concluded.

Thin, like the managed import: load both sides through the port, run the deterministic
matching in `engine.reconciliation`, persist the two projections, return the diff. The
judgment is all in the matching; this is the part that makes it durable.

Writing back is what turns the diff from a report into a property of the inventory: an
asset's `management_state` is what the last reconciliation concluded, and a record's
`asset_id` is which device it describes. Both are recomputed from scratch each run — a link
that was right last month and is wrong now is cleared rather than defended.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from domain.models import ShadowItDiff
from domain.ports import ReconciliationStore
from engine.reconciliation import reconcile


class ShadowItReconciler:
    """Computes the bidirectional diff for a tenant and projects its conclusions."""

    def __init__(self, store: ReconciliationStore) -> None:
        self._store = store

    def run(self, tenant_id: UUID, *, computed_at: datetime | None = None) -> ShadowItDiff:
        """Reconcile, persist, and return the diff.

        Idempotent by construction: the matching is a pure function of the current state,
        and both writes are assignments rather than accumulations, so recomputing over
        unchanged data changes nothing.
        """
        assets = self._store.asset_anchors(tenant_id)
        records = self._store.managed_records(tenant_id)

        result = reconcile(records, assets)

        linked_records = {link.record_id: link.asset_id for link in result.links}
        for record in records:
            # Every record is written, including the ones that did not match: clearing a
            # stale link is as important as setting a new one.
            self._store.link_record(record.record_id, linked_records.get(record.record_id))

        for asset_id, state in result.states.items():
            self._store.set_management_state(asset_id, state)

        return result.diff(tenant_id, computed_at=computed_at or datetime.now(UTC))
