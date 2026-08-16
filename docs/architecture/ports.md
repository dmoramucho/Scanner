# Port Contracts

`docs/architecture/ports.md`

The six seams between the deterministic domain and the outside world. **Ports are defined in the domain; adapters implement them** (AGENTS.md §2.1). These `Protocol` definitions contain no infrastructure imports — that is the whole point. The Postgres driver, the vault client, the RAG retriever, and the LLM client all live in the adapter layer and are structurally matched to the shapes below.

Types written in `CamelCase` and not defined here are imported from the dossier contract (`AdvisoryEvidence`, `TriageDossier`, `InsightProposal`, `SoftwareComponent`, `VersionSource`, `AssetClass`, `ManagementState`, `Confidence`) or the store.

Several ports are where a rule stops being prose and becomes an enforced contract: `ScopeAuthority` (deny-by-default, §2.5), `SecretsPort` (never logged, §2.10), `InsightGenerator` (grounded and non-suppressing, §2.8 / §4.8–4.9). Read those three contracts closely.

---

## 1. The error contract

Ports raise a small, shared hierarchy. The one distinction that drives retry behaviour (AGENTS.md §6, §27, §67) is `DependencyError.retryable`.

```python
class DomainError(Exception):
    """Base for all domain-level errors."""


class ValidationError(DomainError):
    """Input failed validation at a boundary."""


class NotFoundError(DomainError):
    """A referenced entity does not exist."""


class ConflictError(DomainError):
    """A uniqueness/idempotency constraint was violated in a way the caller must handle."""


class ScopeViolation(DomainError):
    """A target fell outside authorized scope. Safety-critical — never swallowed."""


class GroundingError(DomainError):
    """An insight was produced without citations. Rejected before it can be persisted."""


class SecretAccessError(DomainError):
    """A secret could not be resolved."""


class DependencyError(DomainError):
    """An external dependency failed. `retryable` separates temporary from permanent."""

    def __init__(self, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.retryable = retryable
```

---

## 2. The `Secret` primitive

`SecretsPort` returns this, not a bare `str`. Its `repr`/`str` redact, so a secret can never land in a log line, a stack trace, or a dossier by accident. The raw value is reachable only through an explicit `reveal()` — which greppably marks every place a secret is actually used.

```python
class Secret:
    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        """The ONLY path to the raw value. Never pass the result to a logger or an LLM."""
        return self._value

    def __repr__(self) -> str:
        return "Secret(***redacted***)"

    __str__ = __repr__
```

---

## 3. `ScopeAuthority` — the engine's pre-flight (safety-critical)

Backs the allowlist enforced in the engine (AGENTS.md §2.5). **Deny-by-default:** if no *active* authorization contains the target, the decision is `allowed=False`. The engine MUST call `authorize` before emitting any packet to a target, and an `allowed=False` decision aborts that target. Every decision is auditable (writes `audit_log`).

```python
from ipaddress import IPv4Address, IPv6Address
from uuid import UUID
from pydantic import BaseModel

IPAddress = IPv4Address | IPv6Address


class ScopeDecision(BaseModel):
    allowed: bool
    target: str
    matched_authorization_id: UUID | None = None
    reason: str  # human-readable, for the audit trail


class ScopeAuthority(Protocol):
    def authorize(self, tenant_id: UUID, target: IPAddress) -> ScopeDecision:
        """Deny-by-default. Backed by `scope_authorization` + the SP-GiST containment index
        (`cidr >>= target`). Records the decision to the audit log."""
        ...

    def require_authorized(self, tenant_id: UUID, target: IPAddress) -> None:
        """Convenience wrapper: raises ScopeViolation on deny. Use at the point of emission
        so a forgotten check fails closed rather than open."""
        ...
```

---

## 4. `SecretsPort` — credential resolution within the perimeter

The collector resolves credentials locally against the vault (AGENTS.md §2.10); the control plane never holds them. `ref` is an opaque handle stored in config/DB — never the secret itself.

```python
class SecretsPort(Protocol):
    def resolve(self, tenant_id: UUID, ref: str) -> Secret:
        """Return the secret for an opaque reference. Raises SecretAccessError on failure.
        The returned value is a redacting `Secret`; never log or serialise its revealed value."""
        ...
```

---

## 5. `ObservationSink` — idempotent ingestion

The one write path into the append-only `observation` spine. **The sink computes `content_hash` itself** (sha256 of the canonicalised payload) so callers cannot get it wrong, and dedups on `(tenant_id, run_id, source_identifier, observation_type, content_hash)` — a retried write lands once (`created=False`); a genuinely new observation in a later run is a new row. `payload` is contractually **normalized and non-secret-bearing** (redaction is the collector's job, upstream).

```python
from collections.abc import Sequence
from datetime import datetime
from typing import Any


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


class ObservationSink(Protocol):
    def record(self, obs: ObservationInput) -> ObservationRecord:
        """Idempotent write. Computes content_hash internally. Raises ValidationError on
        malformed input."""
        ...

    def record_batch(self, batch: Sequence[ObservationInput]) -> list[ObservationRecord]:
        """Batch variant; per-item idempotency, results in input order."""
        ...
```

---

## 6. `AssetRepository` — entity resolution + current-state

Reads resolve observed anchors to a real asset; writes materialise current state and record reversible merges. **Deterministic anchors win** — `resolve` matches strong anchors first (`serial › cert_fingerprint › mac`) and never returns an LLM-proposed identity as a hard match (AGENTS.md §2.8). Merge and reversal are **transactional**: the append-only event and the `asset.status`/`merged_into` change commit together, or not at all.

```python
from typing import Literal


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
    survivor_id: UUID
    merged_id: UUID
    derivation: Literal["deterministic", "llm_proposed"]
    rationale: str | None = None  # required when derivation == 'llm_proposed'
    confidence: Confidence | None = None
    model_version: str | None = None


class AssetRepository(Protocol):
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
```

---

## 7. `AdvisoryRetriever` — RAG grounding

Supplies the *real* advisory text and fix diff for a match. **Never the model's memory** (AGENTS.md §4.8) — this port is the only path by which CVE knowledge enters insight generation.

```python
class AdvisoryRetriever(Protocol):
    def fetch(self, cve_id: str, matched_cpe: str) -> AdvisoryEvidence:
        """Fetch advisory text + fix-diff reference from an external source (NVD/GHSA/commit).
        Raises DependencyError(retryable=...) on failure. Returns AdvisoryEvidence (contract §6)."""
        ...
```

---

## 8. `InsightGenerator` — the LLM boundary (strict)

Where the AI enters, under contract. It reads **only** the `TriageDossier` (already redacted, already carrying its `AdvisoryEvidence`); it has no other route to CVE knowledge. Its output is **grounded, advisory, and non-suppressing**:

- If the model returns an insight with no `cited_sources`, the generator raises `GroundingError` — an ungrounded insight is never persisted.
- If `triage.match.kev` is true, it sets `kev_locked_visible=True` and must not recommend `lower_priority`. The DB rejects a violation too (`insight_kev_not_hidden`); the generator fails earlier and louder.
- `derivation` is always `llm_generated`; it never decides the match, and it never closes a finding — a human confirms consequential cases (`state` starts `proposed`).
- The implementing adapter uses a local/self-hosted model for sensitive content (AGENTS.md §2.10); the port guarantees the contract regardless of which model backs it.

```python
class InsightGenerator(Protocol):
    def generate(self, triage: TriageDossier) -> InsightProposal:
        """Produce a grounded, advisory InsightProposal. Raises GroundingError if the model
        output cites nothing; raises ValidationError on a KEV-hiding recommendation. Never
        suppresses a finding; never uses out-of-band CVE knowledge."""
        ...
```

---

## 9. Adapter map (M0) and consistency notes

| Port | M0 adapter | Called by | Guarantee it must honour |
|------|-----------|-----------|--------------------------|
| `ScopeAuthority` | Postgres (`scope_authorization` + SP-GiST) | the engine, pre-emission | deny-by-default; audited |
| `SecretsPort` | vault inside the perimeter | the collector | never returns a non-redacting value |
| `ObservationSink` | Postgres (`observation`, `ON CONFLICT`) | ingestion | idempotent per run; computes its own hash |
| `AssetRepository` | Postgres (`asset`/`asset_identifier`/`asset_merge_event`) | ingestion + ER | transactional merge/reversal; deterministic resolve |
| `AdvisoryRetriever` | RAG over NVD/GHSA + commit fetch | insight path | real text only, never memory |
| `InsightGenerator` | local/self-hosted LLM client | insight path | grounded, non-suppressing |

Cross-cutting: the two idempotent ports (`ObservationSink`, `AssetRepository.upsert_from_anchors`) must use unique-constraint + `ON CONFLICT`, never check-then-insert (AGENTS.md §62). The two transactional operations (`record_merge`, `reverse_merge`) commit the event and the state change atomically. None of these Protocol definitions may import an infrastructure package — if one needs to, the abstraction is in the wrong layer (AGENTS.md §73).

---

## 10. Next step

The domain now has its data contracts, its store, and its seams. The last artifact before implementation is the **M0 build-prompt series (P-continuation)** for Cursor / Claude Code, in dependency order:

1. **P·scaffold** — repo layout, `domain/` vs `adapters/` boundaries, the six Protocols above, the error hierarchy, tooling (uv/ruff/mypy/pytest), docker-compose + LocalStack + MinIO.
2. **P·scope+collector** — `ScopeAuthority` adapter + the engine pre-flight (deny-by-default, with negative tests), the outbound collector shell, passive sweep (ARP/DHCP/mDNS).
3. **P·ingestion** — `ObservationSink` adapter + migration `0001_expand`, idempotent write path.
4. **P·resolution** — `AssetRepository` adapter, anchor-based resolution into `asset`, reversible merges.

Each prompt ends at a runnable, tested slice, committed before the next — matching your existing P-series discipline.
