"""Importing an authoritative inventory into the store.

Thin by design: a `ManagedSource` yields records, a `ManagedRecordSink` writes them
idempotently, and this counts what happened. M2 adds a source of records and the diff; it
does not add a new write path or touch the spine (m2-design §7).

The counting is the substance. An import that quietly loses rows would corrupt the P11 diff
in its most dangerous direction — a managed device missing from `managed_record` reads as
shadow IT — so the outcome accounts for every row the source read, including the ones it
refused and why (AGENTS.md §4.4).
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from domain.errors import ValidationError
from domain.models import SkippedRow
from domain.ports import ManagedRecordSink, ManagedSource


@dataclass(frozen=True, slots=True)
class ManagedImportOutcome:
    """What an import did, row for row.

    `rows_read == imported + refreshed + skipped` always holds; `balanced` asserts it, and a
    caller that sees `False` is looking at a bug rather than at a quirky export.
    """

    source_ref: str
    rows_read: int = 0
    imported: int = 0  # records new to the store
    refreshed: int = 0  # records that already existed and were updated
    defanged_cells: int = 0  # cells that looked like spreadsheet formulas (ADR-0008)
    skipped: tuple[SkippedRow, ...] = ()

    @property
    def skipped_count(self) -> int:
        return len(self.skipped)

    @property
    def records(self) -> int:
        """Records now in the store from this import."""
        return self.imported + self.refreshed

    @property
    def skip_reasons(self) -> dict[str, int]:
        """Skip counts by reason — what an operator takes back to the CMDB owner."""
        counts: dict[str, int] = {}
        for row in self.skipped:
            counts[row.reason.value] = counts.get(row.reason.value, 0) + 1
        return counts

    @property
    def balanced(self) -> bool:
        return self.rows_read == self.records + self.skipped_count


class ManagedImport:
    """Runs one authoritative source into the store."""

    def __init__(self, source: ManagedSource, sink: ManagedRecordSink) -> None:
        self._source = source
        self._sink = sink

    def run(self, tenant_id: UUID) -> ManagedImportOutcome:
        """Import every usable record, and report everything that was not one."""
        imported = 0
        refreshed = 0

        for entry in self._source.records(tenant_id):
            if entry.tenant_id != tenant_id:
                raise ValidationError(
                    f"managed record tenant {entry.tenant_id} does not match the import "
                    f"tenant {tenant_id}"
                )
            result = self._sink.record(entry)
            if result.created:
                imported += 1
            else:
                refreshed += 1

        report = self._source.read_report()
        return ManagedImportOutcome(
            source_ref=report.source_ref,
            rows_read=report.rows_read,
            imported=imported,
            refreshed=refreshed,
            defanged_cells=report.defanged_cells,
            skipped=tuple(report.skipped),
        )
