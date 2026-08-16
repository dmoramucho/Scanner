# Asset Dossier Contract

`docs/data/asset-dossier-contract.md` · schema_version: `1`

The **asset dossier** is the typed, redacted context object that the LLM reasons over — for vulnerability insight, entity-resolution proposals, and unknown-device fingerprinting. It is the single interface between the deterministic core and any AI capability.

This document is the source of truth for the contract. The Pydantic models below are code-ready: lift them into `domain/dossier/` or drive a build prompt from them. They are pure domain types — no infrastructure imports (AGENTS.md §2.1).

---

## 1. Purpose and the two boundaries

The dossier exists to enforce two boundaries at once:

1. **The token / cost boundary.** The LLM reasons over a curated view, never a raw dump of every observation. Assembly decides what is *relevant*, not what *exists*.
2. **The minimisation / redaction boundary.** Secrets and sensitive operational data are stripped *before* assembly. **What is not in the dossier never reaches the model.** This is the enforcement point for AGENTS.md §2.10 and §4.10.

The contract is an **allowlist, not a denylist** (§4 below). Only explicitly-contracted fields are assembled; any observation field not named in this contract is excluded by default. This fails closed: a new raw field added upstream never silently leaks into a prompt.

---

## 2. Position in the architecture

The dossier is **derived, read-only, and assembled on demand** — it is not the store and not a source of truth (AGENTS.md §3, raw/normalized/derived split). It is projected from the asset's observations and resolved facts at the moment of reasoning.

One consequence matters for lineage: the exact `TriageDossier` (§5) that produced a given insight is **retained immutably** alongside that insight. You must be able to reconstruct *what the model saw* when it made a claim (AGENTS.md §3 immutability, master-doc lineage). The live dossier is ephemeral; the snapshot that backs a persisted insight is not.

```
observations + resolved facts  ──assemble──▶  AssetDossier (ephemeral, redacted)
                                                      │
                                          + advisory + fix diff + match
                                                      ▼
                                              TriageDossier ──▶ LLM ──▶ InsightProposal
                                                      │                      │
                                              retained snapshot ◀────────────┘ (lineage)
```

---

## 3. Shared vocabulary and the provenance primitive

```python
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


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
    raw_record_ref: str | None = (
        None  # pointer to the raw record; never the raw secret-bearing blob
    )


class Observed[T](BaseModel):
    """A value plus where it came from. The dossier is mostly Observed[...] fields."""

    value: T
    provenance: Provenance
```

---

## 4. The redaction contract

Assembly is an **allowlist**. Fields fall into exactly three buckets:

**Included** (identity, exposure, and version signals the LLM needs to reason about relevance):
- Identity anchors: MAC, serial, cert fingerprint, hostname, device model/vendor.
- Network exposure: reachability class, network-segment *label*, open ports + normalized service names.
- Software: identified components as CPE + version + `version_source` + confidence.
- Management state and which source classes know the asset.

**Masked / summarised** (sensitive in raw form, but the *derived signal* is safe and useful):
- Configuration → **not** the raw config; only a summarised set of security-relevant flags (e.g. `telnet_enabled: true`, `tls_min_version: "1.0"`, `default_credential_present: true`). The assembler derives these; it never passes the config file.
- Logs → never the log; only derived facts already extracted upstream.
- Network-segment identifier → a stable label, not raw topology detail beyond what the reasoning needs.

**Excluded entirely** (never assembled, under any asset class):
- Credentials, private keys, API tokens, auth headers, session identifiers.
- Raw configuration or log contents.
- End-user PII and any record of *who* accessed or operated the device.
- Anything not named in this contract (the default-exclude rule).

> The assembler is the only component allowed to read secret-bearing observations, and it is structurally incapable of emitting them into a dossier — it maps to the contracted fields and drops the rest. Treat a dossier that contains an excluded field as a P0 defect (AGENTS.md §75-style invariant: secrets never reach an LLM).

---

## 5. The base dossier and per-type extensions

```python
# ---- shared blocks -----------------------------------------------------------


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
    known_to: list[str] = Field(
        default_factory=list
    )  # e.g. ["ad", "mdm"]; empty ⇒ shadow-IT signal


# ---- per-type context (discriminated union) ----------------------------------


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
    """Context axis: deployment & network. Firmware is the version unit; often no package manager."""

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


# ---- the dossier -------------------------------------------------------------


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
```

---

## 6. The triage dossier (input to the insight flow)

The star flow. A deterministic CVE match fires; the assembler bundles the (redacted) asset dossier with the **real advisory** and the **fix diff**, both fetched via RAG — never the LLM's memory (AGENTS.md §4.8). The fix diff is the reachability signal: it says which feature the patch touched, so the LLM can ask "is that feature active/exposed on this asset?".

```python
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
    model_config = ConfigDict(
        frozen=True
    )  # retained immutably as lineage for the insight it produces

    schema_version: Literal[1] = 1
    triage_id: UUID
    match: VulnerabilityMatch
    advisory: AdvisoryEvidence
    asset: AssetDossier
```

---

## 7. The insight proposal (output — closes the audit loop)

Included here because the contract is only complete end-to-end. The LLM's output is **advisory, cited, and reversible** (AGENTS.md §2.8, §4.9). It never suppresses a finding; it recommends, and a human confirms for consequential cases. KEV matches stay visible regardless of what the insight says.

```python
class CitedSource(BaseModel):
    """Every claim must ground in something real."""

    kind: Literal["advisory", "dossier_field"]
    ref: str  # advisory_id, or a dotted path into the dossier
    quote: str | None = None  # short supporting excerpt, if applicable


class InsightProposal(BaseModel):
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
```

---

## 8. Assembly and lineage rules

1. **Assemble, don't store as truth.** The `AssetDossier` is projected from observations at reasoning time. Only the `TriageDossier` snapshot behind a persisted `InsightProposal` is retained, and it is immutable.
2. **Provenance is mandatory on observed values.** An `Observed[...]` without provenance is an assembly bug. The LLM may only cite what carries provenance.
3. **Redaction is allowlist and fail-closed** (§4). Unknown fields are dropped, not passed.
4. **Grounding is enforced structurally.** `advisory_text` is populated by the retrieval adapter; the insight generator has no path to CVE knowledge except the `AdvisoryEvidence` it is handed. An `InsightProposal` with empty `cited_sources` is rejected before persistence.
5. **KEV is sticky.** If `match.kev` is true, `kev_locked_visible` is set and no `lower_priority` recommendation can remove the finding from the default view.
6. **Deterministic wins conflicts.** Nothing in the dossier or the insight overrides a hard anchor or the deterministic match (AGENTS.md §2.8).

---

## 9. Next step

The dossier is assembled *from* the store. The next data artifact is the **store schema** the projection reads: `asset`, `identifier`, `observation`, `software_component`, `vulnerability_match`, `managed_record`, `scope_authorization`, plus the `insight` + retained `triage_snapshot` tables — with the provenance columns from §3 as first-class, and the `tenant_id` discipline from AGENTS.md §5. Every field in this contract must have a home there (or be derivable from one).
