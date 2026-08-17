"""What the API returns, stated explicitly.

Every response is an explicit model rather than a domain object serialised by default. That
is the difference between "these fields are public" and "these fields have not been made
private yet": a field added to a domain model later cannot appear in a response without
somebody adding it here, on purpose (m4-design §1).

The shapes follow the surfaces in `ux-design.md`, not the tables. This is a
backend-for-frontend: the worklist response is the Triage Home payload, the asset response
is the Asset Analysis payload, and neither is a projection of a row.

Two things are deliberately absent from every model below: observation payloads, and
anything a `Secret` ever touched. Asset facts arrive through the redacted dossier, and the
timeline carries provenance only.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from domain.models import (
    AssetClass,
    AssetDossier,
    AssetPage,
    ConfidenceState,
    InsightSummary,
    ManagementState,
    Priority,
    Reachability,
    TimelineEntry,
    VersionSource,
    WorklistFinding,
    WorklistSummary,
)


class FindingOut(BaseModel):
    """One finding, with everything the UI needs to render its badges and its reason."""

    model_config = ConfigDict(frozen=True)

    match_id: UUID
    asset_id: UUID
    asset_label: str | None
    asset_class: AssetClass
    management_state: ManagementState
    cve_id: str
    matched_cpe: str
    #: The band and *why* — carried, never re-derived here. An interface that recomputed
    #: priority would be a second implementation of the policy (ADR-0015).
    priority: Priority
    priority_rule: str
    priority_reason: str
    confidence_state: ConfidenceState
    version_source: VersionSource
    kev: bool
    epss: float | None
    cvss_score: float | None
    cvss_version: str | None
    matched_at: datetime
    has_insight: bool

    @classmethod
    def of(cls, finding: WorklistFinding) -> FindingOut:
        return cls(**finding.model_dump())


class InsightQueueItemOut(BaseModel):
    """An insight awaiting a human. The AI's output is always marked as the AI's."""

    model_config = ConfigDict(frozen=True, protected_namespaces=())

    insight_id: UUID
    asset_id: UUID
    asset_label: str | None
    cve_id: str
    recommendation: Literal["raise_priority", "lower_priority", "maintain"]
    confidence: float
    state: Literal["proposed", "human_reviewed", "accepted"]
    kev_locked_visible: bool
    model_version: str
    created_at: datetime
    #: Constant, and present in the payload on purpose: the UI must never have to infer
    #: which parts of a screen are model-generated (ux-design §2).
    derivation: Literal["llm_generated"] = "llm_generated"

    @classmethod
    def of(cls, summary: InsightSummary) -> InsightQueueItemOut:
        return cls(
            insight_id=summary.insight_id,
            asset_id=summary.asset_id,
            asset_label=summary.asset_label,
            cve_id=summary.cve_id,
            recommendation=summary.recommendation,
            confidence=summary.confidence,
            state=summary.state,
            kev_locked_visible=summary.kev_locked_visible,
            model_version=summary.model_version,
            created_at=summary.created_at,
        )


class SummaryOut(BaseModel):
    """The glanceable counts. `unknown` management is reported separately from shadow IT,
    because conflating them is the overclaim the reconciliation refuses to make (ADR-0009)."""

    model_config = ConfigDict(frozen=True)

    kev_findings: int
    p1_findings: int
    needs_verification: int
    proposed_insights: int
    shadow_it_assets: int
    unknown_management_assets: int
    total_findings: int

    @classmethod
    def of(cls, summary: WorklistSummary) -> SummaryOut:
        return cls(**summary.model_dump())


class WorklistOut(BaseModel):
    """The Triage Home payload: one request, the whole surface (ux-design §3.1)."""

    model_config = ConfigDict(frozen=True)

    summary: SummaryOut
    findings: list[FindingOut]
    needs_verification: list[FindingOut]
    review_queue: list[InsightQueueItemOut]


class AssetRowOut(BaseModel):
    """One row of the inventory table (ux-design §3.2)."""

    model_config = ConfigDict(frozen=True)

    asset_id: UUID
    label: str | None
    asset_class: AssetClass
    management_state: ManagementState
    identification_confidence: float
    confirmed_findings: int
    probable_findings: int
    kev_findings: int
    highest_priority: Priority | None
    last_seen_at: datetime | None


class AssetListOut(BaseModel):
    model_config = ConfigDict(frozen=True)

    items: list[AssetRowOut]
    total: int
    limit: int
    offset: int

    @classmethod
    def of(cls, page: AssetPage) -> AssetListOut:
        return cls(
            items=[AssetRowOut(**item.model_dump()) for item in page.items],
            total=page.total,
            limit=page.limit,
            offset=page.offset,
        )


class ProvenanceOut(BaseModel):
    """Where a value came from. Present on everything observed, because a fact the analyst
    cannot trace is a fact they have to take on faith (dossier contract §8.2)."""

    model_config = ConfigDict(frozen=True)

    source: str
    source_type: str
    collector: str
    collection_method: str
    confidence: float
    observed_at: datetime
    derivation: str


class ObservedValueOut(BaseModel):
    """A value with its provenance — and, for anything derived rather than measured, the
    marker that says so. `source_type == "inferred"` is what keeps the P17 VLAN label from
    being rendered as ground truth (ADR-0015)."""

    model_config = ConfigDict(frozen=True)

    value: str
    inferred: bool
    provenance: ProvenanceOut


class OpenPortOut(BaseModel):
    model_config = ConfigDict(frozen=True)

    port: int
    protocol: Literal["tcp", "udp"]
    service: str | None


class SoftwareOut(BaseModel):
    """A component, always with how its version was established (AGENTS.md §3)."""

    model_config = ConfigDict(frozen=True)

    name: str
    cpe: str | None
    version: str | None
    version_source: VersionSource
    confidence: float


class IdentifierOut(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["mac", "serial", "cert_fingerprint", "hostname", "ip"]
    value: str
    confidence: float


class SecurityFlagOut(BaseModel):
    """A derived, config-safe flag. Never the configuration it came from (contract §4)."""

    model_config = ConfigDict(frozen=True)

    key: str
    value: str


class ExposureOut(BaseModel):
    model_config = ConfigDict(frozen=True)

    reachability: Reachability
    #: Null means *unknown* — no mapped subnet contained this asset's address. Never a
    #: guessed VLAN (ADR-0015).
    network_segment: ObservedValueOut | None
    open_ports: list[OpenPortOut]


class TimelineEntryOut(BaseModel):
    """One sighting: who, how, when. No payload — by construction, not by filtering."""

    model_config = ConfigDict(frozen=True)

    observation_id: UUID
    observation_type: str
    source: str
    source_type: str
    collector: str
    collection_method: str
    confidence: float
    observed_at: datetime

    @classmethod
    def of(cls, entry: TimelineEntry) -> TimelineEntryOut:
        return cls(
            observation_id=entry.observation_id,
            observation_type=entry.observation_type,
            source=entry.source,
            source_type=entry.source_type,
            collector=entry.collector,
            collection_method=entry.collection_method,
            confidence=entry.confidence,
            observed_at=entry.observed_at,
        )


class AssetDetailOut(BaseModel):
    """The Asset Analysis payload (ux-design §3.3).

    Assembled from the **redacted dossier**, not from observations: identity, exposure,
    software and context all arrive having passed the contract's allowlist and its refusal
    sweep. That is why this model can be read as a list of what the API serves rather than
    as a list of what it remembered to strip.
    """

    model_config = ConfigDict(frozen=True)

    asset_id: UUID
    label: str | None
    asset_class: AssetClass
    management_state: ManagementState
    #: Empty means nothing manages this asset — the shadow-IT signal (ADR-0009).
    managed_by: list[str]
    identification_confidence: float
    identifiers: list[IdentifierOut]
    exposure: ExposureOut
    software: list[SoftwareOut]
    security_flags: list[SecurityFlagOut]
    findings: list[FindingOut]
    timeline: list[TimelineEntryOut]
    assembled_at: datetime
    assembler_version: str


class AssetQuery(BaseModel):
    """The inventory's query string, validated before it is anywhere near a query.

    `extra="forbid"`: an unexpected parameter is a 422, not something quietly ignored. A
    caller who thinks they filtered and did not is worse off than one who was told
    (AGENTS.md §68).
    """

    model_config = ConfigDict(extra="forbid")

    asset_class: AssetClass | None = None
    management_state: ManagementState | None = None
    has_kev: bool | None = None
    q: Annotated[str, Field(max_length=120)] | None = None
    limit: Annotated[int, Field(ge=1, le=200)] = 50
    offset: Annotated[int, Field(ge=0, le=100_000)] = 0


class WorklistQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")

    limit: Annotated[int, Field(ge=1, le=200)] = 50


class ErrorOut(BaseModel):
    """The only error shape this API emits.

    No stack trace, no SQL, no exception class. A client is told what kind of failure it was
    and the id it was logged under, and nothing about the machinery behind it (§2.10).
    """

    model_config = ConfigDict(frozen=True)

    error: str  # a stable machine-readable code
    detail: str  # a safe, human-readable sentence
    request_id: str


def observed_out(value: object, provenance: object) -> ObservedValueOut | None:
    """Render an `Observed[...]` from the dossier, carrying its inferred marker."""
    from domain.models import Provenance  # local: keeps the schema module import-light

    if value is None or not isinstance(provenance, Provenance):
        return None
    return ObservedValueOut(
        value=str(value),
        # The one derived-vs-measured distinction the UI must never lose (ADR-0015).
        inferred=provenance.source_type == "inferred",
        provenance=ProvenanceOut(
            source=provenance.source,
            source_type=provenance.source_type,
            collector=provenance.collector,
            collection_method=provenance.collection_method,
            confidence=provenance.confidence,
            observed_at=provenance.observed_at,
            derivation=provenance.derivation.value,
        ),
    )


def asset_detail_out(
    dossier: AssetDossier,
    *,
    label: str | None,
    findings: Sequence[WorklistFinding],
    timeline: Sequence[TimelineEntry],
) -> AssetDetailOut:
    """Map a redacted dossier plus its findings into the Asset Analysis payload."""
    context = dossier.context
    flags = getattr(context, "security_flags", [])

    return AssetDetailOut(
        asset_id=dossier.asset_id,
        label=label,
        asset_class=dossier.asset_class,
        management_state=dossier.management.state.value,
        managed_by=list(dossier.management.known_to),
        identification_confidence=dossier.identification_confidence,
        identifiers=[
            IdentifierOut(kind=item.kind, value=item.value, confidence=item.confidence)
            for item in dossier.identifiers
        ],
        exposure=ExposureOut(
            reachability=dossier.exposure.reachability.value,
            network_segment=(
                observed_out(
                    dossier.exposure.network_segment_label.value,
                    dossier.exposure.network_segment_label.provenance,
                )
                if dossier.exposure.network_segment_label is not None
                else None
            ),
            open_ports=[
                OpenPortOut(port=port.port, protocol=port.protocol, service=port.service)
                for port in dossier.exposure.open_ports
            ],
        ),
        software=[
            SoftwareOut(
                name=component.name,
                cpe=component.cpe,
                version=component.version,
                version_source=component.version_source,
                confidence=component.confidence,
            )
            for component in dossier.software
        ],
        security_flags=[SecurityFlagOut(key=flag.key, value=flag.value) for flag in flags],
        findings=[FindingOut.of(finding) for finding in findings],
        timeline=[TimelineEntryOut.of(entry) for entry in timeline],
        assembled_at=dossier.assembled_at,
        assembler_version=dossier.assembler_version,
    )
