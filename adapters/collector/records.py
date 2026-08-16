"""The collector's intermediate representation, and its mapping to `ObservationInput`.

A `PassiveRecord` is one normalized sighting: this address, seen this way, at this time.
Parsers produce them; `to_observation_input` attaches the provenance envelope that makes
them observations (AGENTS.md §2.2). Nothing here touches a network, a device, or a
database.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from domain.models import IPAddress, ObservationInput

#: Passive sightings assert identity anchors (address ↔ MAC ↔ name), not software state.
OBSERVATION_TYPE = "identity"


@dataclass(frozen=True, slots=True)
class PassiveRecord:
    """One sighting, normalized. Immutable: a parse result is evidence, not a draft."""

    target: IPAddress
    source: str  # 'arp' | 'dhcp' | 'mdns'
    source_type: str  # 'passive' | 'authoritative'
    collection_method: str  # 'arp_table' | 'dhcp_lease_file' | 'mdns_browse'
    confidence: float
    observed_at: datetime  # UTC — when the *source* saw it
    mac: str | None = None
    hostname: str | None = None
    attributes: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class SkippedLine:
    """A line the parser refused. Carries the reason and the line number, never the line:
    parser input is untrusted (AGENTS.md §2.9) and echoing it into logs or dossiers is how
    untrusted text ends up somewhere it is trusted."""

    lineno: int
    reason: str


def to_observation_input(
    record: PassiveRecord,
    *,
    tenant_id: UUID,
    run_id: UUID,
    collector: str,
    collector_version: str,
    collected_at: datetime,
) -> ObservationInput:
    """Attach the provenance envelope. Every field the contract requires is populated
    here; there is no path that produces a provenance-less observation.

    `asset_id` is None on purpose — passive sightings arrive before entity resolution
    (ports.md §5). `version_source` is None because a passive sighting says nothing about
    software versions, and `raw_record_ref` stays None until the raw-capture store is
    wired (that is a later slice, not a silently dropped field).
    """
    payload: dict[str, object] = {
        "ip": str(record.target),
        "mac": record.mac,
        "hostname": record.hostname,
        **{f"attr_{key}": value for key, value in sorted(record.attributes.items())},
    }
    return ObservationInput(
        tenant_id=tenant_id,
        run_id=run_id,
        asset_id=None,
        observation_type=OBSERVATION_TYPE,
        payload=payload,
        source=record.source,
        source_type=record.source_type,
        source_identifier=str(record.target),
        collector=collector,
        collector_version=collector_version,
        collection_method=record.collection_method,
        version_source=None,
        confidence=record.confidence,
        observed_at=record.observed_at,
        collected_at=collected_at,
        raw_record_ref=None,
    )
