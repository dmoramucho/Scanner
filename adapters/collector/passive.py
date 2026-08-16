"""The passive collector.

Passive discovery is what AGENTS.md §7 asks for before anything is probed: reading the
network's own records — the ARP table, the DHCP server's leases, the mDNS names devices
announce — tells us a fragile camera exists without sending it a single packet. Nothing
here contacts a device, so §2.4 (read-only against target infrastructure) holds by
construction rather than by discipline.

**Shape, for the boundary that comes later.** For M0 this runs in-process. Its inputs are
`Capture` objects (text plus the moment of capture) and its output is `ObservationInput`
objects; it opens no connection, reads no file, and calls no command. Extracting it to a
separate process behind mTLS is therefore a transport change around this API, not a
rewrite of it — and live packet capture is a thin wrapper that produces `Capture`s, which
is why it is deferred rather than designed around.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Final, Literal
from uuid import UUID

from adapters.collector.parsers import (
    ParsedCapture,
    parse_arp_table,
    parse_dhcp_leases,
    parse_mdns,
)
from adapters.collector.records import PassiveRecord, SkippedLine, to_observation_input
from domain.errors import ValidationError
from domain.models import IPAddress, ObservationInput

COLLECTOR_NAME: Final = "passive-collector"
COLLECTOR_VERSION: Final = "0.1.0"

CaptureKind = Literal["arp", "dhcp", "mdns"]


@dataclass(frozen=True, slots=True)
class Capture:
    """One raw capture to parse.

    `observed_at` is when the capture was taken. It is required even for DHCP (which
    carries its own timestamps) because a format that *sometimes* has a time still needs a
    fallback that is a fact rather than a default — the caller knows when it read the file;
    the parser does not.
    """

    kind: CaptureKind
    text: str
    observed_at: datetime


@dataclass(frozen=True, slots=True)
class CollectionResult:
    """Candidate observations, each with the target they concern, plus what was refused.

    The target travels alongside the observation because scope enforcement happens in the
    engine, not here: the collector's job is to say what it saw, the engine's job is to
    decide what may be acted on (AGENTS.md §2.5).
    """

    candidates: tuple[tuple[IPAddress, ObservationInput], ...] = ()
    skipped: tuple[SkippedLine, ...] = ()
    sources: tuple[str, ...] = field(default_factory=tuple)


class PassiveCollector:
    """Turns captures into provenance-complete observations.

    `collected_at` is supplied per call rather than read from the clock, so the timestamp
    is the caller's fact and the whole pipeline stays deterministic under test — the four
    distinguished timestamps (`observed_at` / `collected_at` / `ingested_at` /
    `processed_at`) only stay meaningful if nobody quietly invents one.
    """

    def __init__(self, *, name: str = COLLECTOR_NAME, version: str = COLLECTOR_VERSION) -> None:
        self._name = name
        self._version = version

    def collect(
        self,
        *,
        tenant_id: UUID,
        run_id: UUID,
        captures: Sequence[Capture],
        collected_at: datetime,
    ) -> CollectionResult:
        """Parse every capture and attach provenance. Raises `ValidationError` on a
        timestamp we would otherwise have to guess at."""
        _require_utc_aware("collected_at", collected_at)

        candidates: list[tuple[IPAddress, ObservationInput]] = []
        skipped: list[SkippedLine] = []
        sources: list[str] = []

        for capture in captures:
            _require_utc_aware(f"{capture.kind} capture observed_at", capture.observed_at)
            parsed = self._parse(capture)
            skipped.extend(parsed.skipped)
            for record in parsed.records:
                candidates.append(
                    (record.target, self._to_observation(record, tenant_id, run_id, collected_at))
                )
            if parsed.records:
                sources.append(capture.kind)

        return CollectionResult(tuple(candidates), tuple(skipped), tuple(sources))

    def _parse(self, capture: Capture) -> ParsedCapture:
        if capture.kind == "arp":
            return parse_arp_table(capture.text, observed_at=capture.observed_at)
        if capture.kind == "dhcp":
            return parse_dhcp_leases(capture.text)
        if capture.kind == "mdns":
            return parse_mdns(capture.text, observed_at=capture.observed_at)
        raise ValidationError(f"unknown capture kind: {capture.kind!r}")

    def _to_observation(
        self, record: PassiveRecord, tenant_id: UUID, run_id: UUID, collected_at: datetime
    ) -> ObservationInput:
        return to_observation_input(
            record,
            tenant_id=tenant_id,
            run_id=run_id,
            collector=self._name,
            collector_version=self._version,
            collected_at=collected_at,
        )


def _require_utc_aware(name: str, value: datetime) -> None:
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValidationError(f"{name} must be timezone-aware (UTC); got a naive datetime")
