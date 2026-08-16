"""Parsers for passive capture formats: ARP tables, DHCP leases, mDNS browse output.

Pure functions: text in, `PassiveRecord`s out. No sockets, no subprocesses, no database —
which is what makes the collector read-only by construction (AGENTS.md §2.4) and makes it
extractable behind an outbound boundary later without touching this code.

Every input here is untrusted (AGENTS.md §2.9): a device chooses its own mDNS name, and a
lease file is written by a daemon parsing device-supplied hostnames. So parsing is
allow-list shaped — an address must parse as an IP, a MAC must match the canonical form, a
hostname must look like a hostname — and anything else is skipped with a reason and a line
number, never coerced and never echoed back.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address

from adapters.collector.records import PassiveRecord, SkippedLine
from domain.models import IPAddress

#: How much a sighting from each source is worth. ARP is the device answering on the
#: wire; a DHCP lease is a server's record, which can outlive the device; mDNS is the
#: device describing itself, which is the easiest of the three to get wrong or to spoof.
ARP_CONFIDENCE = 0.9
DHCP_CONFIDENCE = 0.8
MDNS_CONFIDENCE = 0.6

_MAC_RE = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")

# `ip neigh`: "10.10.5.7 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
_IP_NEIGH_RE = re.compile(
    r"^(?P<ip>\S+)\s+dev\s+(?P<dev>\S+)\s+lladdr\s+(?P<mac>\S+)\s+(?P<state>[A-Z]+)\s*$"
)
# BSD/macOS `arp -an`: "? (10.10.5.7) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]"
_ARP_AN_RE = re.compile(
    r"^\S*\s*\((?P<ip>[^)]+)\)\s+at\s+(?P<mac>[0-9a-fA-F:]+)\s+on\s+(?P<dev>\S+)"
)
# ISC dhcpd.leases: "starts 4 2026/08/13 10:15:22;"
_LEASE_TIME_RE = re.compile(r"^(?P<key>starts|ends)\s+\d\s+(?P<stamp>[\d/]+\s[\d:]+);$")

#: ARP states that mean "we have no confirmed mapping" — not evidence of a device.
_UNRESOLVED_ARP_STATES = frozenset({"INCOMPLETE", "FAILED"})


@dataclass(frozen=True, slots=True)
class ParsedCapture:
    """What a parser makes of a capture: the records, and what it refused."""

    records: tuple[PassiveRecord, ...]
    skipped: tuple[SkippedLine, ...]


def _normalize_mac(raw: str) -> str | None:
    """Canonical lower-case colon form, or None if it is not a MAC.

    Accepts the `-` and `.` separators other tools emit, and pads the single-digit octets
    BSD `arp` prints (`a:b:c:1:2:3`), because dropping a real device over formatting would
    be a silent false negative.
    """
    candidate = raw.strip().lower().replace("-", ":").replace(".", ":")
    parts = candidate.split(":")
    if len(parts) == 6 and all(0 < len(part) <= 2 for part in parts):
        candidate = ":".join(part.zfill(2) for part in parts)
    return candidate if _MAC_RE.match(candidate) else None


def _parse_ip(raw: str) -> IPAddress | None:
    try:
        return ip_address(raw.strip())
    except ValueError:
        return None


def _clean_hostname(raw: str | None) -> str | None:
    """A hostname we are willing to store, or None. Never a coerced approximation."""
    if raw is None:
        return None
    candidate = raw.strip().strip('"')
    return candidate if _HOSTNAME_RE.match(candidate) else None


def _significant_lines(text: str) -> Iterator[tuple[int, str]]:
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if line and not line.startswith("#"):
            yield lineno, line


def parse_arp_table(text: str, *, observed_at: datetime) -> ParsedCapture:
    """Parse `ip neigh` (Linux) or `arp -an` (BSD/macOS) output.

    Both shapes are accepted because both boxes exist on a real network. The ARP table has
    no timestamps, so `observed_at` is the moment the table was captured — passed in, not
    guessed from the clock, so the caller owns the claim.
    """
    records: list[PassiveRecord] = []
    skipped: list[SkippedLine] = []

    for lineno, line in _significant_lines(text):
        match = _IP_NEIGH_RE.match(line) or _ARP_AN_RE.match(line)
        if match is None:
            skipped.append(SkippedLine(lineno, "unrecognised ARP entry format"))
            continue

        groups = match.groupdict()
        if groups.get("state", "") in _UNRESOLVED_ARP_STATES:
            skipped.append(SkippedLine(lineno, "unresolved ARP entry (no confirmed MAC)"))
            continue

        target = _parse_ip(groups["ip"])
        if target is None:
            skipped.append(SkippedLine(lineno, "address does not parse as an IP"))
            continue

        mac = _normalize_mac(groups["mac"])
        if mac is None:
            skipped.append(SkippedLine(lineno, "hardware address is not a MAC"))
            continue

        records.append(
            PassiveRecord(
                target=target,
                source="arp",
                source_type="passive",
                collection_method="arp_table",
                confidence=ARP_CONFIDENCE,
                observed_at=observed_at,
                mac=mac,
                attributes={"interface": groups["dev"]} if groups.get("dev") else {},
            )
        )

    return ParsedCapture(tuple(records), tuple(skipped))


def _parse_lease_timestamp(stamp: str) -> datetime | None:
    """ISC dhcpd writes lease times in UTC unless configured otherwise; we read them as
    UTC rather than as "whatever this host's timezone is"."""
    try:
        return datetime.strptime(stamp, "%Y/%m/%d %H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None


def parse_dhcp_leases(text: str) -> ParsedCapture:
    """Parse an ISC `dhcpd.leases` file.

    Only `binding state active` leases become records: a free or abandoned lease is the
    absence of a device, and `observed_at` comes from the lease's own `starts` time, so a
    stale lease dates itself honestly instead of looking freshly seen.
    """
    records: list[PassiveRecord] = []
    skipped: list[SkippedLine] = []

    lease_ip: IPAddress | None = None
    lease_start: int | None = None
    fields: dict[str, str] = {}

    for lineno, line in _significant_lines(text):
        if line.startswith("lease ") and line.endswith("{"):
            lease_ip = _parse_ip(line[len("lease ") : -1].strip())
            lease_start = lineno
            fields = {}
            if lease_ip is None:
                skipped.append(SkippedLine(lineno, "lease address does not parse as an IP"))
            continue

        if line == "}":
            if lease_ip is not None:
                record = _lease_record(lease_ip, fields)
                if record is None:
                    skipped.append(
                        SkippedLine(lease_start or lineno, "lease is not active or has no start")
                    )
                else:
                    records.append(record)
            lease_ip, lease_start, fields = None, None, {}
            continue

        if lease_ip is None:
            continue

        statement = line.removesuffix(";")
        for key, prefix in (
            ("mac", "hardware ethernet "),
            ("hostname", "client-hostname "),
            ("state", "binding state "),
        ):
            if statement.startswith(prefix):
                fields[key] = statement[len(prefix) :].strip()
        time_match = _LEASE_TIME_RE.match(line)
        if time_match is not None:
            fields[time_match.group("key")] = time_match.group("stamp")

    if lease_ip is not None:
        skipped.append(SkippedLine(lease_start or 0, "unterminated lease block"))

    return ParsedCapture(tuple(records), tuple(skipped))


def _lease_record(target: IPAddress, fields: dict[str, str]) -> PassiveRecord | None:
    if fields.get("state") != "active":
        return None
    starts = _parse_lease_timestamp(fields.get("starts", ""))
    if starts is None:
        return None

    attributes = {"binding_state": "active"}
    if "ends" in fields:
        attributes["lease_ends"] = fields["ends"]

    return PassiveRecord(
        target=target,
        source="dhcp",
        source_type="authoritative",
        collection_method="dhcp_lease_file",
        confidence=DHCP_CONFIDENCE,
        observed_at=starts,
        mac=_normalize_mac(fields.get("mac", "")),
        hostname=_clean_hostname(fields.get("hostname")),
        attributes=attributes,
    )


def parse_mdns(text: str, *, observed_at: datetime) -> ParsedCapture:
    """Parse `avahi-browse -p` output, resolved (`=`) records only.

    An unresolved (`+`) line has no address, so there is nothing to attribute a sighting
    to. Everything an mDNS record claims is device-supplied, which is why this is the
    lowest-confidence source and why the service name is stored as an attribute rather
    than treated as identity.
    """
    records: list[PassiveRecord] = []
    skipped: list[SkippedLine] = []

    for lineno, line in _significant_lines(text):
        fields = line.split(";")
        if fields[0] != "=":
            skipped.append(SkippedLine(lineno, "not a resolved mDNS record"))
            continue
        if len(fields) < 9:
            skipped.append(SkippedLine(lineno, "resolved mDNS record has too few fields"))
            continue

        target = _parse_ip(fields[7])
        if target is None:
            skipped.append(SkippedLine(lineno, "address does not parse as an IP"))
            continue

        attributes = {
            "interface": fields[1],
            "protocol": fields[2],
            "service_name": fields[3].replace("\\032", " "),
            "service_type": fields[4],
            "port": fields[8],
        }
        records.append(
            PassiveRecord(
                target=target,
                source="mdns",
                source_type="passive",
                collection_method="mdns_browse",
                confidence=MDNS_CONFIDENCE,
                observed_at=observed_at,
                hostname=_clean_hostname(fields[6]),
                attributes={key: value for key, value in attributes.items() if value},
            )
        )

    return ParsedCapture(tuple(records), tuple(skipped))
