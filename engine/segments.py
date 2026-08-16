"""Subnet → VLAN labels: operator-configured, always inferred, never guessed.

The UX shows a device's network segment, and knowing that a camera sits on the IoT VLAN is
most of what "is this exposure serious?" means. We have no way to *measure* it — there is no
SNMP access to the switches — so the label is derived from the asset's IP against a mapping
the operator supplies (`10.0.60.0/24 → "VLAN 60 (IoT)"`), the same configurable-mapping
pattern as the CMDB columns.

Two rules follow, and they are the whole module:

**It is inferred, and it says so.** Every label carries provenance with
`source_type = "inferred"` and a confidence below 1.0, so it can never be rendered as a
measured fact. The operator's mapping describes how the network was *designed*; a device
with a static address from another range, or a VLAN renumbered last quarter, makes it wrong
without anything looking wrong. That gap is the reason for the marker (AGENTS.md §3).

**An address outside every mapped range is unknown, not guessed.** No nearest-match, no
"probably the default VLAN". The same honesty as the ambiguous category in shadow-IT
reconciliation: *we do not know* is a real answer, and the alternative is telling an analyst
a camera is isolated when nobody established that (ADR-0009, ADR-0015).

Longest prefix wins, as it does in every routing table: an operator who maps a /24 inside a
mapped /16 means the /24.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from typing import Final

from domain.errors import ValidationError
from domain.models import Derivation, IPAddress, Observed, Provenance

#: The provenance this module stamps on every label it produces. `source_type` is the marker
#: that matters: an interface may render an inferred value differently, but it can only do
#: that if the value says what it is.
INFERRED_SOURCE: Final = "subnet_vlan_map"
INFERRED_SOURCE_TYPE: Final = "inferred"
INFERRED_METHOD: Final = "subnet_containment"

#: Deliberately below 1.0 and deliberately a constant. It reflects the *kind* of evidence —
#: a design document, not a measurement — rather than anything about a particular device, and
#: pretending to a per-asset number here would be false precision.
INFERRED_CONFIDENCE: Final = 0.6

#: A label is a short human string for a UI badge, not a description.
MAX_LABEL_CHARS: Final = 80

#: More than this is a configuration mistake, and scanning a list this long per asset is a
#: cost nobody asked for.
MAX_RULES: Final = 2_000

Network = IPv4Network | IPv6Network


@dataclass(frozen=True, slots=True)
class SegmentRule:
    """One operator-supplied mapping: a network, and what to call it."""

    network: Network
    label: str


class SubnetVlanMap:
    """An operator's subnet → VLAN mapping. Empty is a valid map: everything is unknown."""

    def __init__(self, rules: Iterable[SegmentRule] = ()) -> None:
        # Longest prefix first, so the most specific mapping wins without a search.
        self._rules = tuple(sorted(rules, key=lambda rule: rule.network.prefixlen, reverse=True))

    def __len__(self) -> int:
        return len(self._rules)

    @property
    def rules(self) -> tuple[SegmentRule, ...]:
        return self._rules

    @classmethod
    def from_mapping(cls, raw: Mapping[str, str]) -> SubnetVlanMap:
        """Build from `{cidr: label}`, or raise.

        Every failure is loud: a malformed CIDR, a blank label, a host address written where
        a network belongs, the same network mapped twice. A mapping an operator got wrong is
        a mapping that would mislabel devices silently for months (AGENTS.md §6).
        """
        if len(raw) > MAX_RULES:
            raise ValidationError(
                f"the subnet→VLAN mapping has {len(raw)} entries; the limit is {MAX_RULES}"
            )

        rules: list[SegmentRule] = []
        seen: set[str] = set()
        for cidr, label in raw.items():
            network = _parsed_network(cidr)
            text = _parsed_label(label, cidr)
            key = str(network)
            if key in seen:
                raise ValidationError(f"subnet→VLAN mapping lists {key} more than once")
            seen.add(key)
            rules.append(SegmentRule(network=network, label=text))
        return cls(rules)

    @classmethod
    def from_json(cls, document: str) -> SubnetVlanMap:
        """Build from a JSON object of `{cidr: label}`."""
        text = document.strip()
        if not text:
            return cls()
        try:
            parsed: object = json.loads(text)
        except ValueError as exc:
            raise ValidationError(f"the subnet→VLAN mapping is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ValidationError("the subnet→VLAN mapping must be a JSON object of cidr → label")
        return cls.from_mapping({str(key): str(value) for key, value in parsed.items()})

    def label_for(self, address: IPAddress | str) -> str | None:
        """The label for this address, or None when no mapped range contains it.

        None is the answer, not a failure: an address outside every mapped range is a device
        on a segment nobody described, and saying so is more useful than a guess.
        """
        try:
            target = ip_address(address) if isinstance(address, str) else address
        except ValueError:
            return None
        for rule in self._rules:
            if target.version == rule.network.version and target in rule.network:
                return rule.label
        return None

    def observed_label(self, address: IPAddress | str, *, at: datetime) -> Observed[str] | None:
        """The label with its provenance attached, or None.

        The provenance is the point: `source_type = "inferred"` travels with the value into
        the dossier, into the retained snapshot, and into whatever the interface renders, so
        nothing downstream can present it as a measured fact.
        """
        label = self.label_for(address)
        if label is None:
            return None
        return Observed(
            value=label,
            provenance=Provenance(
                source=INFERRED_SOURCE,
                source_type=INFERRED_SOURCE_TYPE,
                collector="dossier-assembler",
                collector_version="1.0.0",
                collection_method=INFERRED_METHOD,
                observed_at=at,
                collected_at=at,
                confidence=INFERRED_CONFIDENCE,
                # The *mapping* is applied deterministically; what is uncertain is whether
                # the mapping still describes the network. Hence `inferred` above.
                derivation=Derivation.DETERMINISTIC,
                raw_record_ref=f"vlan-map:{self._matched_network(address)}",
            ),
        )

    def _matched_network(self, address: IPAddress | str) -> str:
        try:
            target = ip_address(address) if isinstance(address, str) else address
        except ValueError:  # pragma: no cover — the caller matched it a moment ago
            return "unknown"
        for rule in self._rules:
            if target.version == rule.network.version and target in rule.network:
                return str(rule.network)
        return "unknown"  # pragma: no cover — likewise


def _parsed_network(cidr: str) -> Network:
    candidate = cidr.strip()
    try:
        # `strict=True`: `10.0.60.5/24` is an operator writing a host where a network
        # belongs, and quietly rounding it to 10.0.60.0/24 would hide the mistake.
        return ip_network(candidate, strict=True)
    except ValueError as exc:
        raise ValidationError(
            f"subnet→VLAN mapping key {candidate[:60]!r} is not a network in CIDR notation: {exc}"
        ) from exc


def _parsed_label(label: str, cidr: str) -> str:
    text = " ".join(str(label).split())
    if not text:
        raise ValidationError(f"subnet→VLAN mapping for {cidr} has an empty label")
    if len(text) > MAX_LABEL_CHARS:
        raise ValidationError(
            f"subnet→VLAN label for {cidr} is longer than {MAX_LABEL_CHARS} characters"
        )
    if any(char in text for char in "\n\r\t"):  # pragma: no cover — collapsed above
        raise ValidationError(f"subnet→VLAN label for {cidr} contains control characters")
    return text


__all__: Sequence[str] = [
    "INFERRED_CONFIDENCE",
    "INFERRED_METHOD",
    "INFERRED_SOURCE",
    "INFERRED_SOURCE_TYPE",
    "MAX_LABEL_CHARS",
    "MAX_RULES",
    "SegmentRule",
    "SubnetVlanMap",
]
