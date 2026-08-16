"""VLAN labels: inferred from the operator's map, marked as inferred, never guessed.

Two properties carry this file. **A label always says it was inferred** — there is no switch
to ask, so the mapping describes how the network was *designed*, and a device with a static
address from another range makes it wrong without anything looking wrong. And **an address
outside every mapped range is unknown**: no nearest match, no default VLAN. The same honesty
as the ambiguous category in reconciliation — "we don't know" is an answer (ADR-0015).
"""

from __future__ import annotations

from datetime import UTC, datetime
from ipaddress import ip_address

import pytest

from config.settings import ConfigError, load_config
from domain.errors import ValidationError
from engine.segments import (
    INFERRED_CONFIDENCE,
    INFERRED_SOURCE,
    INFERRED_SOURCE_TYPE,
    MAX_LABEL_CHARS,
    SubnetVlanMap,
)

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)

MAPPING = {
    "10.0.60.0/24": "VLAN 60 (IoT)",
    "10.0.10.0/24": "VLAN 10 (Servers)",
    "10.0.0.0/8": "Corporate (unsegmented)",
    "192.168.4.0/22": "VLAN 400 (Guest)",
    "2001:db8:cafe::/48": "VLAN 60 (IoT v6)",
}


def vlan_map() -> SubnetVlanMap:
    return SubnetVlanMap.from_mapping(MAPPING)


# ------------------------------------------------------------------- inside the ranges


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("10.0.60.14", "VLAN 60 (IoT)"),
        ("10.0.60.255", "VLAN 60 (IoT)"),
        ("10.0.10.4", "VLAN 10 (Servers)"),
        ("10.0.99.7", "Corporate (unsegmented)"),  # inside the /8 but no more specific rule
        ("192.168.5.30", "VLAN 400 (Guest)"),
        ("2001:db8:cafe::1", "VLAN 60 (IoT v6)"),
    ],
)
def test_an_address_inside_a_mapped_range_gets_that_label(address: str, expected: str) -> None:
    assert vlan_map().label_for(address) == expected


def test_the_most_specific_mapping_wins() -> None:
    """Longest prefix, as in any routing table. An operator who maps a /24 inside a mapped
    /8 means the /24 — the general rule is the fallback, not the answer."""
    engine = vlan_map()

    assert engine.label_for("10.0.60.14") == "VLAN 60 (IoT)"
    assert engine.label_for("10.0.200.14") == "Corporate (unsegmented)"


def test_the_label_carries_an_inferred_marker() -> None:
    """The property the UI depends on. There is no SNMP access to the switches, so this is
    a derivation from a design document — and it must be impossible to render it as a
    measured fact (AGENTS.md §3)."""
    observed = vlan_map().observed_label(ip_address("10.0.60.14"), at=NOW)

    assert observed is not None
    assert observed.value == "VLAN 60 (IoT)"
    assert observed.provenance.source_type == INFERRED_SOURCE_TYPE
    assert observed.provenance.source == INFERRED_SOURCE
    assert observed.provenance.confidence == INFERRED_CONFIDENCE
    assert observed.provenance.confidence < 1.0  # never presented as certain
    assert observed.provenance.raw_record_ref == "vlan-map:10.0.60.0/24"  # which rule matched


# --------------------------------------------------------------- outside every range


@pytest.mark.parametrize(
    "address", ["172.16.4.9", "8.8.8.8", "192.168.99.1", "2001:db8:beef::1", "127.0.0.1"]
)
def test_an_address_outside_every_mapped_range_is_unknown(address: str) -> None:
    """Not a guess, not a nearest match, not "probably the default VLAN". Telling an analyst
    a camera is on an isolated segment when nobody established that is worse than telling
    them we do not know."""
    engine = vlan_map()

    assert engine.label_for(address) is None
    assert engine.observed_label(address, at=NOW) is None


def test_an_empty_map_labels_nothing() -> None:
    """The default deployment: no mapping configured, every asset's segment unknown. Valid,
    and honest."""
    engine = SubnetVlanMap()

    assert len(engine) == 0
    assert engine.label_for("10.0.60.14") is None


def test_an_unparseable_address_is_unknown_rather_than_an_error() -> None:
    """Addresses reach this from stored identifiers. A malformed one is a data problem to
    surface elsewhere, not a reason to fail assembling a dossier."""
    assert vlan_map().label_for("not-an-ip") is None


def test_an_ipv4_address_never_matches_an_ipv6_rule() -> None:
    assert SubnetVlanMap.from_mapping({"::/0": "everything v6"}).label_for("10.0.60.1") is None


# ----------------------------------------------------------- a bad mapping fails loudly


@pytest.mark.parametrize(
    ("mapping", "fragment"),
    [
        ({"10.0.60.0/33": "VLAN 60"}, "CIDR"),
        ({"not-a-network": "VLAN 60"}, "CIDR"),
        ({"10.0.60.5/24": "VLAN 60"}, "CIDR"),  # a host where a network belongs
        ({"10.0.60.0/24": ""}, "empty label"),
        ({"10.0.60.0/24": "   "}, "empty label"),
        ({"10.0.60.0/24": "x" * (MAX_LABEL_CHARS + 1)}, "longer than"),
    ],
)
def test_a_malformed_mapping_is_refused_with_a_reason(
    mapping: dict[str, str], fragment: str
) -> None:
    """A mapping an operator got wrong would mislabel devices silently for months. `10.0.60.5/24`
    is called out specifically: quietly rounding a host address to its network would hide the
    mistake rather than surface it."""
    with pytest.raises(ValidationError) as raised:
        SubnetVlanMap.from_mapping(mapping)

    assert fragment in str(raised.value)


def test_the_same_network_mapped_twice_is_refused() -> None:
    """Two labels for one range is an operator asking two different questions of the same
    device; there is no defensible way to pick one."""
    with pytest.raises(ValidationError, match="more than once"):
        SubnetVlanMap.from_json('{"10.0.60.0/24": "IoT", "10.0.60.0/24 ": "Cameras"}')


@pytest.mark.parametrize("document", ["not json", "[]", '"a string"', "42"])
def test_a_mapping_that_is_not_a_json_object_is_refused(document: str) -> None:
    with pytest.raises(ValidationError):
        SubnetVlanMap.from_json(document)


def test_an_absent_mapping_is_an_empty_map_not_an_error() -> None:
    assert len(SubnetVlanMap.from_json("")) == 0
    assert len(SubnetVlanMap.from_json("   ")) == 0


# --------------------------------------------------------------- validated at startup


def base_env() -> dict[str, str]:
    return {
        "SCANNER_ENV": "dev",
        "SCANNER_DATABASE_URL": "postgresql://u:p@localhost:5433/scanner",
        "SCANNER_RAW_STORE_ENDPOINT_URL": "http://localhost:9000",
        "SCANNER_RAW_STORE_BUCKET": "raw",
        "SCANNER_RAW_STORE_ACCESS_KEY_ID": "key",
        "SCANNER_RAW_STORE_SECRET_ACCESS_KEY": "secret",
        "SCANNER_SECRETS_ENDPOINT_URL": "http://localhost:4566",
    }


def test_a_valid_mapping_loads_at_startup() -> None:
    config = load_config(base_env() | {"SCANNER_VLAN_MAP": '{"10.0.60.0/24": "VLAN 60 (IoT)"}'})

    assert config.vlan_map.label_for("10.0.60.9") == "VLAN 60 (IoT)"


def test_no_mapping_configured_is_valid_and_labels_nothing() -> None:
    config = load_config(base_env())

    assert len(config.vlan_map) == 0


def test_a_malformed_mapping_fails_the_process_at_startup() -> None:
    """Loud, at boot, not at first use. A mapping nobody validated would otherwise mislabel
    every asset it touched until somebody noticed a camera filed under Servers
    (AGENTS.md §6)."""
    with pytest.raises(ConfigError) as raised:
        load_config(base_env() | {"SCANNER_VLAN_MAP": '{"10.0.60.0/33": "VLAN 60"}'})

    assert "SCANNER_VLAN_MAP" in str(raised.value)


def test_a_mapping_file_is_read_and_validated(tmp_path: object) -> None:
    from pathlib import Path

    assert isinstance(tmp_path, Path)
    path = tmp_path / "vlans.json"
    path.write_text('{"10.0.10.0/24": "VLAN 10 (Servers)"}', encoding="utf-8")

    config = load_config(base_env() | {"SCANNER_VLAN_MAP_FILE": str(path)})

    assert config.vlan_map.label_for("10.0.10.5") == "VLAN 10 (Servers)"


def test_an_unreadable_mapping_file_fails_at_startup() -> None:
    with pytest.raises(ConfigError, match="could not be read"):
        load_config(base_env() | {"SCANNER_VLAN_MAP_FILE": "/nonexistent/vlans.json"})


def test_configuring_both_a_file_and_an_inline_mapping_is_refused() -> None:
    """Two mappings cannot both be the mapping, and silently preferring one would make the
    other look applied."""
    with pytest.raises(ConfigError, match="not both"):
        load_config(
            base_env()
            | {"SCANNER_VLAN_MAP": '{"10.0.60.0/24": "IoT"}', "SCANNER_VLAN_MAP_FILE": "vlans.json"}
        )
