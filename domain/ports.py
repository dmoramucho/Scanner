"""The six seams between the deterministic domain and the outside world.

Source of truth: `docs/architecture/ports.md` §3–§8. Ports are defined in the domain;
adapters implement them structurally (AGENTS.md §2.1). None of these definitions may
import an infrastructure package — if one needs to, the abstraction is in the wrong layer.

Three of them are where a rule stops being prose and becomes an enforced contract:
`ScopeAuthority` (deny-by-default, AGENTS.md §2.5), `SecretsPort` (never logged, §2.10),
`InsightGenerator` (grounded and non-suppressing, §2.8 / §4.8–4.9).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol
from uuid import UUID

from domain.models import (
    AdvisoryEvidence,
    AnchorObservation,
    AssetResolution,
    AssetView,
    InsightProposal,
    IPAddress,
    MergeRequest,
    ObservationInput,
    ObservationRecord,
    ScopeDecision,
    SoftwareComponent,
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
