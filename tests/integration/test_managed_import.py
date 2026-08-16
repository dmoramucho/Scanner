"""Importing a CMDB export into the real store: idempotent, provenance-complete.

The adapter's parsing and sanitisation are covered hermetically in `tests/test_cmdb_csv.py`.
This file asserts the property that only the database can prove — that re-importing the same
export lands once, arbitrated by the `(tenant_id, source, external_id)` unique key that has
been in the schema since migration `0001_expand` (m2-design §7).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest

from adapters.managed.cmdb_csv import ColumnMapping, CsvCmdbSource
from adapters.postgres.managed_record_sink import PostgresManagedRecordSink
from domain.errors import ValidationError
from domain.models import ManagedRecordInput, SkipReason, SourceReadReport
from engine.managed_import import ManagedImport

pytestmark = pytest.mark.integration

Connection = psycopg.Connection[tuple[Any, ...]]

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "cmdb"
EXPORTED_AT = datetime(2026, 8, 14, 9, 0, tzinfo=UTC)

MAPPING = ColumnMapping(
    external_id="Asset ID",
    hostname="Device Name",
    serial="S/N",
    mac="MAC Address",
    ip="IP",
    owner="Owner",
    extras={"site": "Site"},
)


@pytest.fixture
def tenant() -> UUID:
    return uuid4()


def importer(
    conn: Connection, name: str = "clean.csv", *, observed_at: datetime = EXPORTED_AT
) -> ManagedImport:
    return ManagedImport(
        CsvCmdbSource(FIXTURES / name, MAPPING, observed_at=observed_at),
        PostgresManagedRecordSink(conn),
    )


def stored(conn: Connection, tenant: UUID) -> list[tuple[str, Any]]:
    rows = conn.execute(
        """
        select external_id, payload, source, observed_at from managed_record
        where tenant_id = %s order by external_id
        """,
        (tenant,),
    ).fetchall()
    return [(str(row[0]), row[1]) for row in rows]


def test_an_export_lands_as_managed_records(autocommit_conn: Connection, tenant: UUID) -> None:
    outcome = importer(autocommit_conn).run(tenant)

    assert outcome.imported == 3
    assert outcome.refreshed == 0
    assert outcome.balanced
    records = stored(autocommit_conn, tenant)
    assert [external_id for external_id, _ in records] == ["CMDB-0001", "CMDB-0002", "CMDB-0003"]


def test_records_carry_their_provenance(autocommit_conn: Connection, tenant: UUID) -> None:
    """A record whose truth is "someone said so" has to say which file said it, and as of
    when the export was taken — not when we happened to read it (AGENTS.md §2.2)."""
    importer(autocommit_conn).run(tenant)

    row = autocommit_conn.execute(
        """
        select source, payload, observed_at, ingested_at from managed_record
        where tenant_id = %s and external_id = 'CMDB-0001'
        """,
        (tenant,),
    ).fetchone()
    assert row is not None
    source, payload, observed_at, ingested_at = row
    assert source == "cmdb"
    assert payload["source_ref"] == "clean.csv"
    assert payload["serial"] == "SN-ABC-1234"
    assert payload["mac"] == "aa:bb:cc:dd:ee:ff"
    assert payload["attributes"] == {"site": "HQ"}
    assert observed_at == EXPORTED_AT
    assert ingested_at >= observed_at  # read after it was exported


def test_re_importing_the_same_export_lands_once(autocommit_conn: Connection, tenant: UUID) -> None:
    """Idempotency is the unique index doing the work, not a preceding lookup
    (AGENTS.md §62)."""
    first = importer(autocommit_conn).run(tenant)
    second = importer(autocommit_conn).run(tenant)

    assert first.imported == 3
    assert second.imported == 0
    assert second.refreshed == 3  # already known, and refreshed rather than duplicated
    assert len(stored(autocommit_conn, tenant)) == 3


def test_a_later_export_refreshes_what_changed(autocommit_conn: Connection, tenant: UUID) -> None:
    """A CMDB row's contents legitimately change between exports — a device gets a new
    owner — and the latest export is the current statement of what is believed."""
    importer(autocommit_conn).run(tenant)

    updated = FIXTURES / "clean-updated.csv"
    updated.write_text(
        (FIXTURES / "clean.csv").read_text().replace("alice@corp.internal", "bob@corp.internal"),
        encoding="utf-8",
    )
    later = EXPORTED_AT + timedelta(days=7)
    try:
        outcome = ManagedImport(
            CsvCmdbSource(updated, MAPPING, observed_at=later),
            PostgresManagedRecordSink(autocommit_conn),
        ).run(tenant)
    finally:
        updated.unlink()

    assert outcome.refreshed == 3
    row = autocommit_conn.execute(
        """
        select payload, observed_at from managed_record
        where tenant_id = %s and external_id = 'CMDB-0001'
        """,
        (tenant,),
    ).fetchone()
    assert row is not None
    assert row[0]["owner"] == "bob@corp.internal"
    assert row[0]["source_ref"] == "clean-updated.csv"
    assert row[1] == later
    assert len(stored(autocommit_conn, tenant)) == 3  # still three devices


def test_imports_are_scoped_to_a_tenant(autocommit_conn: Connection, tenant: UUID) -> None:
    """The same CMDB row for two tenants is two records: `external_id` is only unique within
    a tenant, and the diff must never cross that line (AGENTS.md §5)."""
    other = uuid4()

    importer(autocommit_conn).run(tenant)
    importer(autocommit_conn).run(other)

    assert len(stored(autocommit_conn, tenant)) == 3
    assert len(stored(autocommit_conn, other)) == 3


def test_a_messy_export_imports_what_it_can_and_accounts_for_the_rest(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    """One bad line in a 4000-row export must not cost the other 3999 — and every refusal is
    counted, because a row lost silently would read as shadow IT in the P11 diff."""
    outcome = importer(autocommit_conn, "messy.csv").run(tenant)

    assert outcome.imported == 3
    assert outcome.skipped_count == 5
    assert outcome.balanced
    assert outcome.skip_reasons == {
        SkipReason.BLANK.value: 1,
        SkipReason.NO_IDENTITY.value: 2,
        SkipReason.NO_EXTERNAL_ID.value: 1,
        SkipReason.DUPLICATE_EXTERNAL_ID.value: 1,
    }
    assert outcome.defanged_cells > 0


def test_a_defanged_cell_is_stored_defanged(autocommit_conn: Connection, tenant: UUID) -> None:
    """The value in the database is the safe one: whatever report is built on this table
    later cannot re-animate a formula the CMDB carried (ADR-0008)."""
    importer(autocommit_conn, "messy.csv").run(tenant)

    rows = autocommit_conn.execute(
        "select payload from managed_record where tenant_id = %s", (tenant,)
    ).fetchall()

    for (payload,) in rows:
        for value in payload.values():
            if isinstance(value, str):
                assert not value.startswith(("=", "+", "-", "@"))


def test_an_import_refuses_a_record_for_another_tenant(
    autocommit_conn: Connection, tenant: UUID
) -> None:
    """A cross-tenant write is worse than a refused import."""

    class ForeignSource:
        def records(self, tenant_id: UUID) -> list[ManagedRecordInput]:
            reader = CsvCmdbSource(FIXTURES / "clean.csv", MAPPING, observed_at=EXPORTED_AT)
            return [
                record.model_copy(update={"tenant_id": uuid4()})
                for record in reader.records(uuid4())
            ]

        def read_report(self) -> SourceReadReport:
            return SourceReadReport(source_ref="foreign.csv")

    engine = ManagedImport(ForeignSource(), PostgresManagedRecordSink(autocommit_conn))

    with pytest.raises(ValidationError, match="does not match the import tenant"):
        engine.run(tenant)


def test_csv_and_xlsx_land_identical_records(autocommit_conn: Connection, tenant: UUID) -> None:
    other = uuid4()

    importer(autocommit_conn, "clean.csv").run(tenant)
    importer(autocommit_conn, "clean.xlsx").run(other)

    from_csv = [payload for _, payload in stored(autocommit_conn, tenant)]
    from_xlsx = [payload for _, payload in stored(autocommit_conn, other)]

    def without_source(payloads: list[Any]) -> list[Any]:
        return [{k: v for k, v in payload.items() if k != "source_ref"} for payload in payloads]

    assert without_source(from_csv) == without_source(from_xlsx)
