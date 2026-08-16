"""Domain models: the asset-dossier contract plus the port operation types.

Sources of truth, lifted verbatim in shape:
  * `docs/data/asset-dossier-contract.md` §3 (vocabulary + provenance), §5 (dossier),
    §6 (triage dossier), §7 (insight proposal).
  * `docs/architecture/ports.md` §3, §5, §6 (the operation types the ports exchange).

Pure domain: stdlib + pydantic only, no infrastructure imports (AGENTS.md §2.1).

Semantic rules that live *outside* these models on purpose — the contracts assign them
to the adapter, and duplicating them here would change where the error surfaces:
  * `InsightProposal.cited_sources == []` is rejected by `InsightGenerator` with
    `GroundingError` (ports.md §8), not by field validation.
  * A `MergeRequest` with `derivation == 'llm_proposed'` and no `rationale` is rejected
    by `AssetRepository.record_merge` (ports.md §6).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# §3 — shared vocabulary and the provenance primitive
# ---------------------------------------------------------------------------


class Derivation(StrEnum):
    """How a fact came to exist. Carried on every asserted fact (AGENTS.md §2.2)."""

    DETERMINISTIC = "deterministic"  # rules / exact match
    LLM_PROPOSED = "llm_proposed"  # LLM candidate, not yet materialised as fact
    LLM_GENERATED = "llm_generated"  # LLM-produced content (e.g. an insight)


class VersionSource(StrEnum):
    """Why the OS backport false-positive is avoidable (AGENTS.md §3)."""

    PACKAGE_MANAGER = "package_manager"  # credentialed ground truth (dpkg/rpm)
    VENDOR_API = "vendor_api"  # e.g. Axis VAPIX firmware readout
    BANNER = "banner"  # inferred from banner/header — treat as candidate


class Reachability(StrEnum):
    INTERNET_FACING = "internet_facing"
    INTERNAL_ONLY = "internal_only"
    ISOLATED_SEGMENT = "isolated_segment"
    UNKNOWN = "unknown"


class ManagementState(StrEnum):
    MANAGED = "managed"  # known to AD/MDM/EDR/vCenter
    UNMANAGED = "unmanaged"  # seen on the network, unknown to IAM — the shadow-IT signal
    UNKNOWN = "unknown"


class AssetClass(StrEnum):
    SERVER = "server"
    EMBEDDED = "embedded"  # cameras, IoT, VoIP, UPS — firmware is the version unit
    APPLICATION = "application"
    NETWORK_DEVICE = "network_device"
    UNKNOWN = "unknown"


Confidence = Annotated[float, Field(ge=0.0, le=1.0)]

IPAddress = IPv4Address | IPv6Address


class Provenance(BaseModel):
    """Attached to every observed value in the dossier. Lets the LLM's citations
    trace back to a real observation, and makes the insight auditable."""

    model_config = ConfigDict(frozen=True)

    source: str  # e.g. "nmap", "ad_ldap", "vapix", "snmp"
    source_type: str  # e.g. "active_scan", "authoritative", "credentialed"
    collector: str
    collector_version: str
    collection_method: str
    observed_at: datetime  # UTC — when the source observed it
    collected_at: datetime  # UTC — when we collected it
    confidence: Confidence
    derivation: Derivation = Derivation.DETERMINISTIC
    raw_record_ref: str | None = None  # pointer to the raw record; never the raw blob


class Observed[T](BaseModel):
    """A value plus where it came from. The dossier is mostly Observed[...] fields."""

    value: T
    provenance: Provenance


# ---------------------------------------------------------------------------
# §5 — shared blocks
# ---------------------------------------------------------------------------


class Identifier(BaseModel):
    kind: Literal["mac", "serial", "cert_fingerprint", "hostname", "ip"]
    value: str
    confidence: Confidence


class SoftwareComponent(BaseModel):
    """The crux for vulnerability reasoning."""

    cpe: str | None  # None when we couldn't map to a CPE
    name: str
    version: str | None
    version_source: VersionSource  # gates false-positive handling downstream
    confidence: Confidence


class OpenPort(BaseModel):
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"]
    service: str | None  # normalized service name, not a raw banner
    provenance: Provenance


class ExposureBlock(BaseModel):
    reachability: Observed[Reachability]
    network_segment_label: Observed[str] | None = None
    open_ports: list[OpenPort] = Field(default_factory=list)


class ManagementBlock(BaseModel):
    state: Observed[ManagementState]
    known_to: list[str] = Field(default_factory=list)  # ["ad", "mdm"]; empty ⇒ shadow-IT


# ---------------------------------------------------------------------------
# §5 — per-type context (discriminated union)
# ---------------------------------------------------------------------------


class SecurityFlag(BaseModel):
    """A derived, config-safe boolean/enum. Never the underlying config."""

    key: str  # e.g. "telnet_enabled", "smb_signing"
    value: str
    provenance: Provenance


class ServerContext(BaseModel):
    """Context axis: configuration & exposure. Credentialed = rich."""

    asset_class: Literal[AssetClass.SERVER] = AssetClass.SERVER
    os_name: Observed[str] | None = None
    os_version: Observed[str] | None = None  # package-manager truth when credentialed
    running_services: list[Observed[str]] = Field(default_factory=list)
    security_flags: list[SecurityFlag] = Field(default_factory=list)


class EmbeddedContext(BaseModel):
    """Context axis: deployment & network. Firmware is the version unit; often no
    package manager."""

    asset_class: Literal[AssetClass.EMBEDDED] = AssetClass.EMBEDDED
    vendor: Observed[str] | None = None
    model: Observed[str] | None = None
    device_family: Observed[str] | None = None  # e.g. "ip_camera", "voip_phone"
    firmware_version: Observed[str] | None = None  # the real CPE unit for these devices
    limited_shell: bool = False  # BusyBox etc. — no dpkg/rpm available
    security_flags: list[SecurityFlag] = Field(default_factory=list)


class ApplicationContext(BaseModel):
    """Context axis: architecture."""

    asset_class: Literal[AssetClass.APPLICATION] = AssetClass.APPLICATION
    app_name: Observed[str] | None = None
    stack_components: list[SoftwareComponent] = Field(default_factory=list)
    behind_reverse_proxy: Observed[bool] | None = None
    behind_waf: Observed[bool] | None = None


class GenericContext(BaseModel):
    """Fallback for network_device / unknown — kept minimal on purpose."""

    asset_class: Literal[AssetClass.NETWORK_DEVICE, AssetClass.UNKNOWN]
    vendor: Observed[str] | None = None
    model: Observed[str] | None = None
    firmware_version: Observed[str] | None = None


AssetContext = Annotated[
    ServerContext | EmbeddedContext | ApplicationContext | GenericContext,
    Field(discriminator="asset_class"),
]


# ---------------------------------------------------------------------------
# §5 — the dossier
# ---------------------------------------------------------------------------


class AssetDossier(BaseModel):
    model_config = ConfigDict(frozen=True)  # a dossier is a snapshot; immutable once assembled

    schema_version: Literal[1] = 1
    dossier_id: UUID
    asset_id: UUID
    tenant_id: UUID

    assembled_at: datetime  # UTC
    assembler_version: str

    asset_class: AssetClass
    identifiers: list[Identifier]
    software: list[SoftwareComponent] = Field(default_factory=list)
    exposure: ExposureBlock
    management: ManagementBlock
    context: AssetContext

    identification_confidence: Confidence  # overall: how sure are we this is one real asset?


# ---------------------------------------------------------------------------
# §6 — the triage dossier (input to the insight flow)
# ---------------------------------------------------------------------------


class VulnerabilityMatch(BaseModel):
    """The deterministic match. The LLM never decides this — it reasons about relevance."""

    cve_id: str
    matched_cpe: str
    version_source: VersionSource
    confidence_state: Literal["confirmed", "probable", "verified_exploitable"]
    kev: bool  # actively exploited — override, always visible
    epss: Annotated[float, Field(ge=0.0, le=1.0)] | None = None
    provenance: Provenance


class AdvisoryEvidence(BaseModel):
    """Grounding material. Cited by the insight; supplied via RAG, not recalled."""

    advisory_id: str  # e.g. GHSA / CVE record id
    advisory_source: str  # where the text was fetched from
    advisory_text: str  # the real text — the LLM quotes/cites this, not memory
    fix_diff_ref: str | None = None  # pointer to the commit/changelog that fixed it
    fix_touched_summary: str | None = None  # derived: which feature/area the fix changed


class TriageDossier(BaseModel):
    # retained immutably as lineage for the insight it produces
    model_config = ConfigDict(frozen=True)

    schema_version: Literal[1] = 1
    triage_id: UUID
    match: VulnerabilityMatch
    advisory: AdvisoryEvidence
    asset: AssetDossier


# ---------------------------------------------------------------------------
# §7 — the insight proposal (output — closes the audit loop)
# ---------------------------------------------------------------------------


class CitedSource(BaseModel):
    """Every claim must ground in something real."""

    kind: Literal["advisory", "dossier_field"]
    ref: str  # advisory_id, or a dotted path into the dossier
    quote: str | None = None  # short supporting excerpt, if applicable


class InsightProposal(BaseModel):
    # `model_version` is a contract field name, not a pydantic namespace clash.
    model_config = ConfigDict(protected_namespaces=())

    schema_version: Literal[1] = 1
    insight_id: UUID
    triage_id: UUID  # ties back to the exact snapshot the model saw

    recommendation: Literal["raise_priority", "lower_priority", "maintain"]
    rationale: str
    cited_sources: list[CitedSource]  # empty list ⇒ reject the insight; ungrounded is invalid
    confidence: Confidence

    derivation: Literal[Derivation.LLM_GENERATED] = Derivation.LLM_GENERATED
    model_version: str
    state: Literal["proposed", "human_reviewed", "accepted"] = "proposed"
    kev_locked_visible: bool = False  # true ⇒ recommendation cannot hide this finding


# ---------------------------------------------------------------------------
# ports.md §3 — ScopeAuthority operation types
# ---------------------------------------------------------------------------


class ScopeDecision(BaseModel):
    allowed: bool
    target: str
    matched_authorization_id: UUID | None = None
    reason: str  # human-readable, for the audit trail


# ---------------------------------------------------------------------------
# ports.md §5 — ObservationSink operation types
# ---------------------------------------------------------------------------


class ObservationInput(BaseModel):
    tenant_id: UUID
    run_id: UUID
    asset_id: UUID | None  # may be None before entity resolution
    observation_type: str  # 'open_ports'|'software'|'firmware'|'identity'|...
    payload: dict[str, Any]  # normalized; NEVER secret-bearing
    source: str
    source_type: str
    source_identifier: str | None
    collector: str
    collector_version: str
    collection_method: str
    version_source: VersionSource | None
    confidence: Confidence
    observed_at: datetime  # UTC
    collected_at: datetime  # UTC
    raw_record_ref: str | None = None


class ObservationRecord(BaseModel):
    observation_id: UUID
    created: bool  # False ⇒ idempotent no-op


# ---------------------------------------------------------------------------
# ports.md §6 — AssetRepository operation types
# ---------------------------------------------------------------------------


class AnchorObservation(BaseModel):
    kind: Literal["mac", "serial", "cert_fingerprint", "hostname", "ip"]
    value: str
    confidence: Confidence


class AssetResolution(BaseModel):
    asset_id: UUID | None  # None ⇒ no confident match (new-asset candidate)
    confidence: Confidence
    matched_on: list[str]  # anchor kinds that matched


class AssetView(BaseModel):
    id: UUID
    tenant_id: UUID
    asset_class: AssetClass
    management_state: ManagementState
    identification_confidence: Confidence
    status: Literal["active", "merged"]


class MergeRequest(BaseModel):
    # `model_version` is a contract field name, not a pydantic namespace clash.
    model_config = ConfigDict(protected_namespaces=())

    survivor_id: UUID
    merged_id: UUID
    derivation: Literal["deterministic", "llm_proposed"]
    rationale: str | None = None  # required when derivation == 'llm_proposed'
    confidence: Confidence | None = None
    model_version: str | None = None


# ---------------------------------------------------------------------------
# m1-design §1 — ActiveScanner operation types
# ---------------------------------------------------------------------------


class ScanProfile(StrEnum):
    """*Intent*, not a bag of nmap options. The translation from intent to flags lives in
    the scanning adapter and nowhere else (m1-design §2).

    `GENTLE` is the one that keeps fragile embedded stacks alive (AGENTS.md §2.7): the
    engine selects it for anything fingerprinted as embedded, and the adapter is obliged to
    honour it. A caller cannot ask for "gentle but with a bit more" — that is the point of
    an enum of two values.
    """

    GENTLE = "gentle"  # cameras, VoIP, printers, UPS, badge readers — anything embedded
    STANDARD = "standard"  # servers and other robust hosts


class ScanResult(BaseModel):
    """What an active scan learned, already shaped for the existing spine.

    `observations` are `ObservationInput`s the existing `ObservationSink` records
    unchanged, carrying `version_source='banner'` on anything version-shaped: an active
    scan infers versions from banners, and never has package-manager ground truth
    (AGENTS.md §3). `anchors` are the identity signals the scan saw — a MAC when the
    scanner is on the same segment — for the engine to hand to entity resolution.

    `host_up=False` with no observations is a *result*, not a failure: the host was
    checked and was not there. A failure raises instead (m1-design §1, AGENTS.md §67).
    """

    target: str
    profile: ScanProfile
    host_up: bool
    observations: list[ObservationInput] = Field(default_factory=list)
    anchors: list[AnchorObservation] = Field(default_factory=list)
    started_at: datetime  # UTC — when the scan of this target began
    finished_at: datetime  # UTC


# ---------------------------------------------------------------------------
# m1-design §1 — CredentialedInspector / InspectorRegistry operation types
# ---------------------------------------------------------------------------


class DeviceFingerprint(BaseModel):
    """Capability signals about a device — never a brand.

    The registry picks an inspector from what a device *can do* (it speaks SSH; a
    manufacturer API answered), not from what it is called. That is what keeps a new
    vendor to a new adapter instead of an `if brand == …` branch spreading through the
    core (m1-design §1).

    Everything here comes from normalization work already done: OUI lookup, service
    banners, mDNS advertisements, prior observations.
    """

    target: str
    open_ports: tuple[int, ...] = ()
    service_banners: tuple[str, ...] = ()  # e.g. ("SSH-2.0-OpenSSH_8.9p1",)
    mdns_services: tuple[str, ...] = ()
    mac_vendor: str | None = None  # a signal about capability, not a selector
    #: Opaque handle into the vault. No credential path ⇒ no credentialed inspection, and
    #: the device keeps `version_source='banner'` (m1-design §1).
    credential_ref: str | None = None
    username: str | None = None


class InspectionResult(BaseModel):
    """Ground truth read from a device we could authenticate to.

    `observations` are `ObservationInput`s the existing `ObservationSink` records
    unchanged, carrying `version_source='package_manager'` (a package database is what the
    device itself says is installed) or `'vendor_api'` for a manufacturer readout. That is
    the flag that ends the OS-backport false positive: a banner claiming `Apache/2.4.52`
    can be wrong about patching, `dpkg` cannot (AGENTS.md §3).

    Nothing here ever carries a credential: the secret reaches the transport and stops
    there (AGENTS.md §2.10).
    """

    target: str
    inspector: str  # which adapter produced this, for provenance
    observations: list[ObservationInput] = Field(default_factory=list)
    components: list[SoftwareComponent] = Field(default_factory=list)
    anchors: list[AnchorObservation] = Field(default_factory=list)
    started_at: datetime  # UTC
    finished_at: datetime  # UTC


# ---------------------------------------------------------------------------
# m2-design §2 — ManagedSource operation types
# ---------------------------------------------------------------------------


class ManagedSourceKind(StrEnum):
    """Where an authoritative record came from.

    The values match the `managed_record.source` CHECK constraint in migration
    `0001_expand`: adding one means a migration, which is the right amount of friction for
    a column the shadow-IT diff is computed from.
    """

    AD = "ad"
    MDM = "mdm"
    EDR = "edr"
    VCENTER = "vcenter"
    CMDB = "cmdb"


class ManagedRecordInput(BaseModel):
    """One row of an authoritative inventory, normalized.

    This is the other half of the shadow-IT diff: `observation` says what is on the
    network, `managed_record` says what the organization believes it owns, and the
    interesting part is where they disagree (m2-design §1).

    The identity fields are the anchors the reconciliation in P11 will match on, in the
    same priority the entity resolution already uses (`serial › mac › hostname`). They are
    optional individually because real CMDB rows are patchy — but a row with none of them
    is unusable, and the adapter refuses it rather than storing a record nothing can ever
    be matched to.

    `attributes` carries the other mapped columns as free text. Nothing secret-bearing
    belongs here: a CMDB export should not contain credentials, and if one does, it is not
    this model's job to be the place they land (AGENTS.md §2.10).
    """

    tenant_id: UUID
    source: ManagedSourceKind
    external_id: str  # the authoritative system's own record id
    hostname: str | None = None
    serial: str | None = None
    mac: str | None = None
    ip: str | None = None
    owner: str | None = None
    attributes: dict[str, str] = Field(default_factory=dict)
    #: Which export this came from — a filename, an API endpoint, an import id. Provenance
    #: for a record whose truth is entirely a matter of who said so (AGENTS.md §2.2).
    source_ref: str
    observed_at: datetime  # UTC — when the export was taken, not when we read it

    @property
    def has_identity(self) -> bool:
        """Is there anything here the diff could ever match on?"""
        return any((self.serial, self.mac, self.hostname, self.ip))


class SkipReason(StrEnum):
    """Why a row of an authoritative export did not become a record.

    An enum rather than free text because these get counted and compared across imports:
    "your export has 340 rows with no serial" is a conversation with the CMDB owner, and it
    only happens if the reasons aggregate.
    """

    BLANK = "blank"  # nothing in the row at all
    NO_EXTERNAL_ID = "no_external_id"  # nothing to key idempotency on
    NO_IDENTITY = "no_identity"  # no serial, MAC, hostname or IP — unmatchable
    DUPLICATE_EXTERNAL_ID = "duplicate_external_id"  # the same id twice in one file
    OVERSIZED = "oversized"  # a cell far past any plausible field length
    MALFORMED = "malformed"  # the row did not parse


class SkippedRow(BaseModel):
    """A refused row: where it was and why. Never the row's content — it is untrusted text
    and a diagnostic is not the place for it (AGENTS.md §2.9)."""

    row_number: int
    reason: SkipReason
    column: str | None = None


class SourceReadReport(BaseModel):
    """What a read of an authoritative source did, including everything it refused.

    Every row is accounted for: `rows_read == records_yielded + len(skipped)`. That
    invariant is the point — an import that quietly loses rows would corrupt the shadow-IT
    diff in the most dangerous direction, by making a managed device look unmanaged.
    """

    source_ref: str
    rows_read: int = 0
    records_yielded: int = 0
    skipped: list[SkippedRow] = Field(default_factory=list)
    #: Cells that looked like spreadsheet formulas and were neutralised (ADR-0008).
    defanged_cells: int = 0

    @property
    def skipped_count(self) -> int:
        return len(self.skipped)

    @property
    def reasons(self) -> dict[str, int]:
        """Skip counts by reason — the summary an operator acts on."""
        counts: dict[str, int] = {}
        for row in self.skipped:
            counts[row.reason.value] = counts.get(row.reason.value, 0) + 1
        return counts

    @property
    def balanced(self) -> bool:
        """Every row read is either a record or an accounted-for skip."""
        return self.rows_read == self.records_yielded + self.skipped_count


class ManagedRecordResult(BaseModel):
    """The outcome of writing one authoritative record."""

    record_id: UUID
    created: bool  # False ⇒ the record was already known and has been refreshed
