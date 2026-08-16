"""Parser tests — no database needed. Parsers are where untrusted text enters the system.

Two things are asserted throughout: the good lines become records with the right
provenance-shaping fields, and the bad lines are *skipped with a reason*, never coerced
into a plausible-looking record. A parser that guesses is a parser that invents assets.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from adapters.collector.parsers import (
    ARP_CONFIDENCE,
    DHCP_CONFIDENCE,
    MDNS_CONFIDENCE,
    parse_arp_table,
    parse_dhcp_leases,
    parse_mdns,
)
from adapters.collector.records import to_observation_input

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "passive"

CAPTURED_AT = datetime(2026, 8, 13, 12, 0, tzinfo=UTC)


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


# ------------------------------------------------------------------------------ ARP


def test_arp_table_parses_resolved_entries() -> None:
    parsed = parse_arp_table(fixture("arp_table.txt"), observed_at=CAPTURED_AT)

    assert [str(record.target) for record in parsed.records] == [
        "10.10.5.7",
        "10.10.5.20",
        "10.10.5.31",
        "192.168.99.14",
    ]
    first = parsed.records[0]
    assert first.mac == "aa:bb:cc:dd:ee:ff"
    assert first.source == "arp"
    assert first.source_type == "passive"
    assert first.collection_method == "arp_table"
    assert first.confidence == ARP_CONFIDENCE
    assert first.observed_at == CAPTURED_AT
    assert first.attributes["interface"] == "eth0"


def test_arp_table_keeps_out_of_scope_addresses_for_the_engine_to_judge() -> None:
    """The parser does not enforce scope — the engine does (AGENTS.md §2.5). A parser that
    quietly dropped foreign addresses would make the scope gate untestable."""
    parsed = parse_arp_table(fixture("arp_table.txt"), observed_at=CAPTURED_AT)

    assert "192.168.99.14" in {str(record.target) for record in parsed.records}


def test_arp_table_skips_unusable_lines_with_reasons() -> None:
    parsed = parse_arp_table(fixture("arp_table.txt"), observed_at=CAPTURED_AT)

    reasons = [skip.reason for skip in parsed.skipped]
    assert any("unrecognised" in reason for reason in reasons)  # prose line
    assert any("not a MAC" in reason for reason in reasons)  # zz:zz:...
    assert all(skip.lineno > 0 for skip in parsed.skipped)


def test_arp_skips_do_not_echo_the_offending_text() -> None:
    """Untrusted input never travels in a diagnostic (AGENTS.md §2.9)."""
    parsed = parse_arp_table(fixture("arp_table.txt"), observed_at=CAPTURED_AT)

    for skip in parsed.skipped:
        assert "zz:zz" not in skip.reason
        assert "this is not an arp entry" not in skip.reason


def test_bsd_arp_output_is_understood_too() -> None:
    parsed = parse_arp_table(fixture("arp_bsd.txt"), observed_at=CAPTURED_AT)

    assert [str(record.target) for record in parsed.records] == ["10.10.5.7", "10.10.0.1"]
    # BSD prints single-digit octets; padding them is not optional if we want to match
    # the same device seen through `ip neigh`.
    assert parsed.records[1].mac == "0a:0b:0c:01:02:03"


def test_incomplete_arp_entries_are_not_devices() -> None:
    parsed = parse_arp_table("10.10.5.99 dev eth0 lladdr  INCOMPLETE", observed_at=CAPTURED_AT)

    assert parsed.records == ()
    assert len(parsed.skipped) == 1


# ----------------------------------------------------------------------------- DHCP


def test_dhcp_leases_parses_active_leases_only() -> None:
    parsed = parse_dhcp_leases(fixture("dhcpd.leases"))

    assert [str(record.target) for record in parsed.records] == [
        "10.10.5.20",
        "10.10.5.31",
        "192.168.99.14",
    ]  # the 'free' lease and the malformed block are absent


def test_dhcp_lease_uses_its_own_start_time_not_the_capture_time() -> None:
    """A stale lease must date itself honestly — otherwise a device that left last week
    looks freshly seen (AGENTS.md §5, distinguished timestamps)."""
    parsed = parse_dhcp_leases(fixture("dhcpd.leases"))

    assert parsed.records[0].observed_at == datetime(2026, 8, 13, 10, 15, 22, tzinfo=UTC)
    assert parsed.records[1].observed_at == datetime(2026, 8, 13, 9, 2, tzinfo=UTC)


def test_dhcp_lease_carries_mac_hostname_and_source_metadata() -> None:
    record = parse_dhcp_leases(fixture("dhcpd.leases")).records[0]

    assert record.mac == "aa:bb:cc:00:11:22"
    assert record.hostname == "printer-3f"
    assert record.source == "dhcp"
    assert record.source_type == "authoritative"
    assert record.collection_method == "dhcp_lease_file"
    assert record.confidence == DHCP_CONFIDENCE
    assert record.attributes["binding_state"] == "active"
    assert record.attributes["lease_ends"] == "2026/08/14 10:15:22"


def test_dhcp_lease_with_an_unparseable_address_is_skipped() -> None:
    parsed = parse_dhcp_leases(fixture("dhcpd.leases"))

    assert any("does not parse as an IP" in skip.reason for skip in parsed.skipped)


def test_unterminated_dhcp_lease_block_is_reported() -> None:
    parsed = parse_dhcp_leases("lease 10.10.5.20 {\n  binding state active;\n")

    assert parsed.records == ()
    assert any("unterminated" in skip.reason for skip in parsed.skipped)


# ----------------------------------------------------------------------------- mDNS


def test_mdns_parses_resolved_records() -> None:
    parsed = parse_mdns(fixture("avahi_browse.txt"), observed_at=CAPTURED_AT)

    assert [str(record.target) for record in parsed.records] == [
        "10.10.5.20",
        "10.10.5.31",
        "192.168.99.14",
    ]
    printer = parsed.records[0]
    assert printer.hostname == "printer-3f.local"
    assert printer.attributes["service_type"] == "_ipp._tcp"
    assert printer.attributes["service_name"] == "Brother HL-L2350DW"  # \032 unescaped
    assert printer.attributes["port"] == "631"
    assert printer.confidence == MDNS_CONFIDENCE
    assert printer.source_type == "passive"


def test_mdns_skips_unresolved_and_malformed_records() -> None:
    parsed = parse_mdns(fixture("avahi_browse.txt"), observed_at=CAPTURED_AT)

    reasons = [skip.reason for skip in parsed.skipped]
    assert any("not a resolved" in reason for reason in reasons)  # the '+' line
    assert any("too few fields" in reason for reason in reasons)
    assert any("does not parse as an IP" in reason for reason in reasons)  # 999.1.1.1


@pytest.mark.parametrize("hostname", ["evil host.local", "hôst.local", "a" * 300])
def test_mdns_refuses_a_hostname_that_is_not_a_hostname(hostname: str) -> None:
    """A device names itself; we do not have to believe it. An unacceptable name becomes
    None rather than a sanitised guess — the sighting itself is still real."""
    line = f'=;eth0;IPv4;Svc;_http._tcp;local;{hostname};10.10.5.60;80;"x=1"'

    record = parse_mdns(line, observed_at=CAPTURED_AT).records[0]

    assert record.hostname is None
    assert str(record.target) == "10.10.5.60"


def test_mdns_record_with_an_injected_delimiter_is_refused_entirely() -> None:
    """A device-supplied name containing the field separator shifts every later field. The
    parser must not fall for the shift and read `drop` as an address — it refuses the
    record instead of assembling a plausible wrong one (AGENTS.md §2.9)."""
    line = '=;eth0;IPv4;Svc;_http._tcp;local;host;drop;10.10.5.60;80;"x=1"'

    parsed = parse_mdns(line, observed_at=CAPTURED_AT)

    assert parsed.records == ()
    assert [skip.reason for skip in parsed.skipped] == ["address does not parse as an IP"]


# ------------------------------------------------------------- record → observation


def test_observation_input_is_provenance_complete() -> None:
    """Every provenance field the contract names is populated by the mapping — there is no
    path that produces a provenance-less observation (AGENTS.md §2.2)."""
    record = parse_arp_table(fixture("arp_table.txt"), observed_at=CAPTURED_AT).records[0]
    collected_at = datetime(2026, 8, 13, 12, 0, 5, tzinfo=UTC)

    observation = to_observation_input(
        record,
        tenant_id=uuid4(),
        run_id=uuid4(),
        collector="passive-collector",
        collector_version="0.1.0",
        collected_at=collected_at,
    )

    assert observation.source == "arp"
    assert observation.source_type == "passive"
    assert observation.collector == "passive-collector"
    assert observation.collector_version == "0.1.0"
    assert observation.collection_method == "arp_table"
    assert observation.confidence == ARP_CONFIDENCE
    assert observation.observed_at == CAPTURED_AT
    assert observation.collected_at == collected_at
    assert observation.source_identifier == "10.10.5.7"
    assert observation.observation_type == "identity"
    assert observation.asset_id is None  # passive sightings precede entity resolution
    assert observation.version_source is None  # a sighting says nothing about versions
    assert observation.payload["ip"] == "10.10.5.7"
    assert observation.payload["mac"] == "aa:bb:cc:dd:ee:ff"
