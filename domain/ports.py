"""The six seams between the deterministic domain and the outside world.

Source of truth: `docs/architecture/ports.md` §3–§8. Ports are defined in the domain;
adapters implement them structurally (AGENTS.md §2.1). None of these definitions may
import an infrastructure package — if one needs to, the abstraction is in the wrong layer.

Three of them are where a rule stops being prose and becomes an enforced contract:
`ScopeAuthority` (deny-by-default, AGENTS.md §2.5), `SecretsPort` (never logged, §2.10),
`InsightGenerator` (grounded and non-suppressing, §2.8 / §4.8–4.9).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Protocol
from uuid import UUID

from domain.models import (
    AdvisoryEvidence,
    AnchorObservation,
    AssetResolution,
    AssetView,
    DeviceFingerprint,
    InsightProposal,
    InspectionResult,
    IPAddress,
    ManagedRecordInput,
    ManagedRecordResult,
    MergeRequest,
    ObservationInput,
    ObservationRecord,
    ScanProfile,
    ScanResult,
    ScopeDecision,
    SoftwareComponent,
    SourceReadReport,
    TriageDossier,
)
from domain.secret import Secret


class ScopeAuthority(Protocol):
    """The engine's pre-flight (safety-critical). Deny-by-default: if no *active*
    authorization contains the target, the decision is `allowed=False`."""

    def authorize(self, tenant_id: UUID, target: IPAddress) -> ScopeDecision:
        """Deny-by-default. Backed by `scope_authorization` + the SP-GiST containment index
        (`cidr >>= target`). Records the decision to the audit log."""
        ...

    def require_authorized(self, tenant_id: UUID, target: IPAddress) -> None:
        """Convenience wrapper: raises ScopeViolation on deny. Use at the point of emission
        so a forgotten check fails closed rather than open."""
        ...


class SecretsPort(Protocol):
    """Credential resolution within the perimeter. `ref` is an opaque handle stored in
    config/DB — never the secret itself."""

    def resolve(self, tenant_id: UUID, ref: str) -> Secret:
        """Return the secret for an opaque reference. Raises SecretAccessError on failure.
        The returned value is a redacting `Secret`; never log or serialise its revealed value."""
        ...


class ObservationSink(Protocol):
    """The one write path into the append-only `observation` spine. The sink computes
    `content_hash` itself so callers cannot get it wrong."""

    def record(self, obs: ObservationInput) -> ObservationRecord:
        """Idempotent write. Computes content_hash internally. Raises ValidationError on
        malformed input."""
        ...

    def record_batch(self, batch: Sequence[ObservationInput]) -> list[ObservationRecord]:
        """Batch variant; per-item idempotency, results in input order."""
        ...


class AssetRepository(Protocol):
    """Entity resolution + current-state. Deterministic anchors win; merges are
    transactional and reversible."""

    def resolve(self, tenant_id: UUID, anchors: Sequence[AnchorObservation]) -> AssetResolution:
        """Match observed anchors to an asset. Strong anchors first; deterministic only."""
        ...

    def get(self, tenant_id: UUID, asset_id: UUID) -> AssetView | None: ...

    def upsert_from_anchors(
        self, tenant_id: UUID, anchors: Sequence[AnchorObservation], observation_id: UUID
    ) -> UUID:
        """Get-or-create by strong anchors, idempotent. Links the asserting observation."""
        ...

    def set_current_software(self, asset_id: UUID, components: Sequence[SoftwareComponent]) -> None:
        """Project current-state software; history remains in `observation`."""
        ...

    def record_merge(self, req: MergeRequest) -> UUID:
        """Append a merge event and mark the merged asset 'merged' → survivor, in one
        transaction. LLM-proposed merges without a rationale are rejected."""
        ...

    def reverse_merge(self, merge_id: UUID, *, rationale: str | None = None) -> UUID:
        """Append a reversal event and restore the merged asset to 'active', in one
        transaction. Merges are always reversible (AGENTS.md §3)."""
        ...


class ActiveScanner(Protocol):
    """Uncredentialed reachability and service/version detection (m1-design §1).

    The port speaks in **profiles and normalized results, never in scanner flags**. That
    is not stylistic: it is what makes "embedded devices get the gentle treatment" a
    property the engine can enforce and a test can assert, instead of a string of options
    that any caller could quietly extend. The translation from `ScanProfile` to actual
    flags lives in the adapter and nowhere else (AGENTS.md §2.7).

    The scope gate runs before this, unchanged: `require_authorized` before any packet.
    """

    def scan(self, tenant_id: UUID, target: IPAddress, profile: ScanProfile) -> ScanResult:
        """Scan one target under the given profile and return normalized observations.

        A host that is not there returns `host_up=False` with no observations — a result.
        A scan that could not be *performed* raises instead: `DependencyError` when the
        scanner binary is missing, fails, or times out, and `ValidationError` when its
        output cannot be trusted. An empty success is never used to mean "something went
        wrong" (AGENTS.md §67).
        """
        ...


class CredentialedInspector(Protocol):
    """Ground truth read from a device we can authenticate to (m1-design §1, §3).

    Brand-agnostic by construction: this is one seam, and the vendor specifics live in
    adapters chosen by `InspectorRegistry`. What every implementation owes:

    * **Read-only, absolutely.** An inspector reads; it never configures. No command that
      writes device or system state, ever, whatever the provocation (AGENTS.md §2.4).
    * **The credential is resolved through `SecretsPort` and stays a `Secret`.** The raw
      value reaches the transport and nothing else — not a log line, not an exception
      message, not an observation payload (AGENTS.md §2.10).
    * **Device output is untrusted input.** It is parsed and validated into normalized
      components before it becomes an observation; never executed, never trusted as a
      filename or a query (AGENTS.md §2.9).
    """

    def inspect(self, tenant_id: UUID, target: IPAddress, credential_ref: str) -> InspectionResult:
        """Read what the device says is installed on it.

        Raises `SecretAccessError` when the credential cannot be resolved, and
        `DependencyError` when the device cannot be reached or refuses the credential —
        `retryable=True` for a device that may simply be busy, `False` for a credential
        that will not work next time either. Raises `ValidationError` when the device's
        output cannot be trusted. An empty result is never used to signal a failure
        (AGENTS.md §67).
        """
        ...


class InspectorRegistry(Protocol):
    """Chooses the inspector for a device from its capabilities — not its brand.

    Returns `None` when there is no credentialed path, which is a legitimate answer: the
    device stays uncredentialed and its observations keep `version_source='banner'`
    (m1-design §1). Adding a vendor-API inspector later is a registration, not a change
    to any caller.
    """

    def for_device(self, fingerprint: DeviceFingerprint) -> CredentialedInspector | None:
        """The inspector that can read this device, or None if we have no way in."""
        ...


class ManagedSource(Protocol):
    """An authoritative inventory: what the organization believes it owns (m2-design §2).

    The CMDB, AD, MDM, EDR — anything whose answer to "is this device ours?" is a matter of
    record rather than of observation. M2 ships one adapter (a CSV/Excel export); the rest
    are future adapters behind this same port.

    Rows from these sources are **untrusted input** (AGENTS.md §2.9). A CMDB export is a
    file a person edited, and it will contain blank rows, malformed cells, and — because
    spreadsheets are programs — cells that are formulas. An implementation validates and
    sanitizes before yielding, and it yields only rows that could actually be matched.
    """

    def records(self, tenant_id: UUID) -> Iterable[ManagedRecordInput]:
        """Yield the normalized records this source knows about.

        Rows that cannot be used are skipped rather than raised on — one bad line in a
        4000-row export must not cost the other 3999 — but they are never dropped silently:
        `read_report()` accounts for every one.
        """
        ...

    def read_report(self) -> SourceReadReport:
        """What the last read did, including every row it refused and why.

        Call after consuming `records()`. This exists because "never silently drop a row"
        (AGENTS.md §4.4) is only enforceable if the count reaches the caller — a source that
        could quietly discard half an export while looking successful is exactly the failure
        this port is meant to preclude.
        """
        ...


class ManagedRecordSink(Protocol):
    """The write path into `managed_record`. Idempotent, like the observation spine.

    Re-importing the same export lands once: the store's `(tenant_id, source, external_id)`
    unique key arbitrates, never a check-then-insert (AGENTS.md §62). A record that already
    exists is *refreshed* rather than duplicated — a CMDB row's contents legitimately change
    between exports, and the latest export is the current statement of what is believed.
    """

    def record(self, entry: ManagedRecordInput) -> ManagedRecordResult:
        """Insert or refresh one record. `created=False` means it was already known."""
        ...

    def record_batch(self, batch: Sequence[ManagedRecordInput]) -> list[ManagedRecordResult]:
        """Batch variant; per-item idempotency, results in input order."""
        ...


class HealthProbe(Protocol):
    """Is this device still answering? The circuit breaker's only sense organ.

    Required by the engine-side safety mechanism in m1-design §2: a health check before
    and after touching each device, so that a device which stops responding aborts *its*
    scan rather than being probed further. The probe itself emits a packet, so the engine
    calls it only after `ScopeAuthority.require_authorized` — a health check is not exempt
    from the gate (AGENTS.md §2.5).

    An adapter implements this with something cheap and gentle: an ICMP echo, or a TCP
    connect to a port already known open. It is the lightest touch in the system.
    """

    def is_responsive(self, target: IPAddress) -> bool:
        """True if the device answered. False means silence, which the breaker reads as
        distress when it follows a scan.

        Returns a verdict; it does not raise for a device that simply did not answer. It
        raises only when the probe itself could not be performed — which the engine treats
        as a reason not to scan, never as "assume it is fine".
        """
        ...


class AdvisoryRetriever(Protocol):
    """RAG grounding: the real advisory text and fix diff for a match — never the
    model's memory (AGENTS.md §4.8)."""

    def fetch(self, cve_id: str, matched_cpe: str) -> AdvisoryEvidence:
        """Fetch advisory text + fix-diff reference from an external source (NVD/GHSA/commit).
        Raises DependencyError(retryable=...) on failure. Returns AdvisoryEvidence (contract §6)."""
        ...


class InsightGenerator(Protocol):
    """The LLM boundary (strict). Reads only the already-redacted `TriageDossier`; its
    output is grounded, advisory, and non-suppressing."""

    def generate(self, triage: TriageDossier) -> InsightProposal:
        """Produce a grounded, advisory InsightProposal. Raises GroundingError if the model
        output cites nothing; raises ValidationError on a KEV-hiding recommendation. Never
        suppresses a finding; never uses out-of-band CVE knowledge."""
        ...
