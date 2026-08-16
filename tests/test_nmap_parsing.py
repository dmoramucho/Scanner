"""Parsing recorded nmap XML and normalizing it into observations.

Fixture-driven, so CI needs neither the nmap binary nor a network (AGENTS.md §43,
m1-design §4). The fixtures are shaped exactly like real `-oX` output, including the
`<!DOCTYPE nmaprun>` nmap emits.

Two themes run through these tests. First, **nmap's output is untrusted**: it is XML
describing what an unknown device said, so entity tricks are refused and hostile-looking
fields are cleaned or dropped rather than believed. Second, **a failure is never an empty
success**: every way a scan can fail raises a specific domain error, because "no ports
found" and "the scanner never ran" must never be the same value (AGENTS.md §67).
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from adapters.scanner.nmap import (
    COLLECTOR_NAME,
    NmapActiveScanner,
    parse_scan_xml,
)
from domain.errors import DependencyError, ValidationError
from domain.models import ScanProfile, VersionSource
from domain.ports import ActiveScanner

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "nmap"

TENANT = UUID("11111111-1111-1111-1111-111111111111")
CAMERA = ip_address("10.10.5.31")
SERVER = ip_address("10.10.5.7")
ABSENT = ip_address("10.10.5.99")
RUN_ID = UUID("22222222-2222-2222-2222-222222222222")
CLOCK_AT = datetime(2026, 8, 13, 12, 5, tzinfo=UTC)


def fixture(name: str) -> str:
    return (FIXTURES / f"{name}.xml").read_text(encoding="utf-8")


Runner = Callable[[Sequence[str], float], "subprocess.CompletedProcess[str]"]


def fake_runner(
    stdout: str = "", *, returncode: int = 0, stderr: str = "", raises: Exception | None = None
) -> Runner:
    """A `CommandRunner` that replays a recording instead of executing anything."""

    def run(command: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
        if raises is not None:
            raise raises
        return subprocess.CompletedProcess(list(command), returncode, stdout, stderr)

    return run


def scanner(**kwargs: object) -> NmapActiveScanner:
    return NmapActiveScanner(RUN_ID, clock=lambda: CLOCK_AT, **kwargs)  # type: ignore[arg-type]


# ------------------------------------------------------------------------- parsing


def test_open_ports_are_parsed_and_closed_ones_are_not() -> None:
    parsed = parse_scan_xml(fixture("open_ports"))

    assert parsed.host_up is True
    assert [(port.port, port.protocol) for port in parsed.ports] == [
        (80, "tcp"),
        (443, "tcp"),
        (554, "tcp"),
    ]  # the closed telnet port is absent — a closed port is not a finding here
    assert [port.service for port in parsed.ports] == ["http", "https", "rtsp"]


def test_the_mac_and_hostname_are_picked_up_as_identity() -> None:
    parsed = parse_scan_xml(fixture("open_ports"))

    assert parsed.mac == "00:40:8c:9d:1e:2f"  # lower-cased to match the passive collector
    assert parsed.vendor == "Axis Communications AB"
    assert parsed.hostname == "cam-lobby-01.local"


def test_service_versions_are_parsed_with_their_certainty() -> None:
    parsed = parse_scan_xml(fixture("service_versions"))

    by_port = {port.port: port for port in parsed.ports}
    assert by_port[22].product == "OpenSSH"
    assert by_port[22].version == "8.9p1 Ubuntu 3ubuntu0.6"
    assert by_port[22].confidence == 1.0  # nmap conf="10", probed
    assert by_port[80].product == "Apache httpd"
    assert by_port[80].version == "2.4.52"
    assert by_port[5432].confidence == 0.3  # conf="3", a table guess, not a probe
    assert by_port[5432].has_version is False


def test_observed_at_comes_from_nmap_not_from_our_clock() -> None:
    """The scan's own timestamps are the observation time; ours is the collection time."""
    parsed = parse_scan_xml(fixture("open_ports"))

    assert parsed.observed_at == datetime(2026, 8, 13, 12, 0, 36, tzinfo=UTC)


def test_a_run_that_reached_no_host_is_a_result_not_an_error() -> None:
    parsed = parse_scan_xml(fixture("host_down"))

    assert parsed.host_up is False
    assert parsed.ports == []


def test_an_explicitly_down_host_is_reported_down() -> None:
    parsed = parse_scan_xml(fixture("host_down_reported"))

    assert parsed.host_up is False


# ---------------------------------------------------------------- untrusted input


def test_external_entities_are_refused() -> None:
    """XXE: nmap's output describes what an untrusted device said, and this file would read
    /etc/passwd into a service name. The parser refuses the document outright."""
    with pytest.raises(ValidationError, match="could not be parsed"):
        parse_scan_xml(fixture("xxe"))


def test_hostile_banner_text_is_cleaned_not_trusted() -> None:
    """A device chooses its own banner. Control characters are stripped and the value is
    length-capped, so a banner cannot smuggle newlines into a log or unbounded text into
    the store (AGENTS.md §2.9)."""
    parsed = parse_scan_xml(fixture("hostile_banner"))

    product = parsed.ports[0].product
    assert product is not None
    assert "\t" not in product
    assert "\n" not in product
    assert len(product) <= 200
    # The text itself is preserved rather than silently rewritten — it is evidence.
    assert "alert(1)" in (parsed.ports[0].version or "")


@pytest.mark.parametrize("bad", ["99999", "notanumber"])
def test_ports_outside_the_valid_range_are_dropped(bad: str) -> None:
    parsed = parse_scan_xml(fixture("hostile_banner"))

    assert bad not in {str(port.port) for port in parsed.ports}


def test_an_unexpected_protocol_is_dropped() -> None:
    """`sctp` is a protocol the observation contract does not carry; recording it as tcp
    would be a lie."""
    parsed = parse_scan_xml(fixture("hostile_banner"))

    assert {port.protocol for port in parsed.ports} <= {"tcp", "udp"}


@pytest.mark.parametrize(
    ("xml_text", "match"),
    [
        ("", "no XML output"),
        ("   \n ", "no XML output"),
        ("<html><body>not nmap</body></html>", "unexpected root element"),
        ("<nmaprun><host>", "could not be parsed"),
    ],
)
def test_unparseable_output_raises_rather_than_returning_nothing(xml_text: str, match: str) -> None:
    with pytest.raises(ValidationError, match=match):
        parse_scan_xml(xml_text)


def test_truncated_output_raises() -> None:
    """A killed nmap leaves a half-written document; treating it as "no ports" would turn a
    crash into a clean bill of health."""
    with pytest.raises(ValidationError):
        parse_scan_xml(fixture("truncated"))


# ------------------------------------------------------------------ normalization


def test_scan_produces_provenance_complete_observations() -> None:
    result = scanner(runner=fake_runner(fixture("open_ports"))).scan(
        TENANT, CAMERA, ScanProfile.GENTLE
    )

    assert result.host_up is True
    assert result.observations
    for observation in result.observations:
        assert observation.tenant_id == TENANT
        assert observation.run_id == RUN_ID
        assert observation.source == "nmap"
        assert observation.source_type == "active_scan"
        assert observation.collector == COLLECTOR_NAME
        assert observation.collector_version
        assert observation.collection_method == "nmap_gentle"
        assert observation.source_identifier == "10.10.5.31"
        assert observation.observed_at.tzinfo is not None
        assert observation.collected_at == CLOCK_AT
        assert observation.asset_id is None  # resolution is the engine's job


def test_open_ports_are_normalized_into_an_observation() -> None:
    result = scanner(runner=fake_runner(fixture("open_ports"))).scan(
        TENANT, CAMERA, ScanProfile.GENTLE
    )

    ports = next(obs for obs in result.observations if obs.observation_type == "open_ports")
    assert ports.payload["ip"] == "10.10.5.31"
    assert [entry["port"] for entry in ports.payload["ports"]] == [80, 443, 554]
    assert ports.version_source is None  # an open port says nothing about a version


def test_version_signals_are_marked_as_banner_inferred() -> None:
    """The whole point of `version_source`: an uncredentialed scan reads banners, and a
    backported package will lie to it. Saying `banner` is what keeps that from becoming a
    false positive in M3 (AGENTS.md §3)."""
    result = scanner(runner=fake_runner(fixture("service_versions"))).scan(
        TENANT, SERVER, ScanProfile.STANDARD
    )

    software = next(obs for obs in result.observations if obs.observation_type == "software")
    assert software.version_source is VersionSource.BANNER
    components = {entry["name"]: entry for entry in software.payload["components"]}
    assert components["OpenSSH"]["version"] == "8.9p1 Ubuntu 3ubuntu0.6"
    assert components["Apache httpd"]["version"] == "2.4.52"
    assert components["Apache httpd"]["cpe"] is None  # CPE mapping is M3, not a guess here
    assert "postgresql" not in components  # no version detected, so no component claimed


def test_a_scan_with_no_version_signals_produces_no_software_observation() -> None:
    result = scanner(runner=fake_runner(fixture("open_ports"))).scan(
        TENANT, CAMERA, ScanProfile.GENTLE
    )

    assert not [obs for obs in result.observations if obs.observation_type == "software"]


def test_identity_and_anchors_come_from_the_mac_the_scan_saw() -> None:
    """A MAC from the same segment is a strong anchor — the same one the passive collector
    produces, in the same canonical form, so both sources resolve to one asset."""
    result = scanner(runner=fake_runner(fixture("open_ports"))).scan(
        TENANT, CAMERA, ScanProfile.GENTLE
    )

    identity = next(obs for obs in result.observations if obs.observation_type == "identity")
    assert identity.payload["mac"] == "00:40:8c:9d:1e:2f"
    assert identity.payload["mac_vendor"] == "Axis Communications AB"

    assert [(anchor.kind, anchor.value) for anchor in result.anchors] == [
        ("mac", "00:40:8c:9d:1e:2f"),
        ("hostname", "cam-lobby-01.local"),
    ]


def test_a_host_that_is_down_yields_a_result_with_no_observations() -> None:
    """Explicitly a finding — "checked, not there" — and distinguishable from a failure,
    which raises."""
    result = scanner(runner=fake_runner(fixture("host_down"))).scan(
        TENANT, ABSENT, ScanProfile.GENTLE
    )

    assert result.host_up is False
    assert result.observations == []
    assert result.anchors == []
    assert result.target == "10.10.5.99"
    assert result.profile is ScanProfile.GENTLE


def test_the_result_records_when_the_scan_ran() -> None:
    result = scanner(runner=fake_runner(fixture("open_ports"))).scan(
        TENANT, CAMERA, ScanProfile.GENTLE
    )

    assert result.started_at == CLOCK_AT
    assert result.finished_at == CLOCK_AT


# ----------------------------------------------------------------- failure modes


def test_a_missing_nmap_binary_is_a_permanent_dependency_error() -> None:
    scan = scanner(runner=fake_runner(raises=FileNotFoundError("nmap"))).scan

    with pytest.raises(DependencyError, match="not found") as exc_info:
        scan(TENANT, CAMERA, ScanProfile.GENTLE)

    assert exc_info.value.retryable is False  # retrying will not install nmap


def test_a_non_zero_exit_raises_rather_than_returning_an_empty_result() -> None:
    """The failure this test exists for: nmap refusing to run (no root for `-sS`, say) and
    the caller recording "no open ports" for a device that was never scanned."""
    scan = scanner(
        runner=fake_runner("", returncode=1, stderr="You requested a scan type which requires root")
    ).scan

    with pytest.raises(DependencyError, match="exited 1") as exc_info:
        scan(TENANT, CAMERA, ScanProfile.GENTLE)

    assert "requires root" in str(exc_info.value)
    assert exc_info.value.retryable is False


def test_a_timeout_is_retryable() -> None:
    scan = scanner(
        runner=fake_runner(raises=subprocess.TimeoutExpired(cmd="nmap", timeout=900))
    ).scan

    with pytest.raises(DependencyError, match="timed out") as exc_info:
        scan(TENANT, CAMERA, ScanProfile.GENTLE)

    assert exc_info.value.retryable is True  # a slow network may well succeed next time


def test_an_os_error_launching_nmap_is_a_dependency_error() -> None:
    scan = scanner(runner=fake_runner(raises=PermissionError("permission denied"))).scan

    with pytest.raises(DependencyError, match="could not execute"):
        scan(TENANT, CAMERA, ScanProfile.GENTLE)


def test_malformed_output_from_a_successful_exit_still_raises() -> None:
    """Exit code 0 is not proof the output is usable."""
    scan = scanner(runner=fake_runner(fixture("truncated"))).scan

    with pytest.raises(ValidationError):
        scan(TENANT, CAMERA, ScanProfile.GENTLE)


def test_an_invalid_target_never_reaches_the_runner() -> None:
    """The command is built — and validated — before anything is executed."""
    executed: list[Sequence[str]] = []

    def recording_runner(
        command: Sequence[str], timeout: float
    ) -> subprocess.CompletedProcess[str]:
        executed.append(command)
        return subprocess.CompletedProcess(list(command), 0, "", "")

    # The annotation says `IPAddress`; the test deliberately violates it, because a type is
    # not a runtime guarantee at a boundary and the validation must hold anyway.
    hostile: object = "10.10.5.31; id"
    with pytest.raises(ValidationError):
        scanner(runner=recording_runner).scan(TENANT, hostile, ScanProfile.GENTLE)  # type: ignore[arg-type]

    assert executed == []


# ------------------------------------------------------------------ conformance


def test_the_adapter_satisfies_the_port() -> None:
    active: ActiveScanner = NmapActiveScanner(uuid4())

    assert callable(active.scan)
