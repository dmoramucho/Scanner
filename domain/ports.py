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
    AdvisoryDocument,
    AdvisoryEvidence,
    AnchorObservation,
    AssetAnchorSet,
    AssetResolution,
    AssetView,
    ComponentSnapshot,
    CveQueryCacheEntry,
    CveRecord,
    DeviceFingerprint,
    EpssScore,
    FeedFetchReport,
    FeedSnapshot,
    Identifier,
    InsightProposal,
    InsightRecord,
    InsightReview,
    InsightReviewEvent,
    InspectionResult,
    IPAddress,
    KevEntry,
    ManagedRecordInput,
    ManagedRecordResult,
    ManagedRecordSnapshot,
    ManagementState,
    MatchForTriage,
    MergeRequest,
    ModelCompletion,
    ObservationInput,
    ObservationRecord,
    ObservationSnapshot,
    ScanProfile,
    ScanResult,
    ScopeDecision,
    SoftwareComponent,
    SourceReadReport,
    TriageDossier,
    VulnerabilityMatchInput,
    VulnerabilityMatchRecord,
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


class VulnerabilityFeed(Protocol):
    """Where CVE knowledge comes from — and the only place it may come from.

    The core never learns that this is NVD (m3-design §2). More importantly, it never
    learns CVE facts from a model: an LLM's CVE knowledge is stale and hallucinated CVE ids
    are its most characteristic failure (AGENTS.md §4.8). Every match the correlator makes
    traces back through this port to a feed that actually said so.

    **An empty answer and a failure are different things.** `cves_for_cpe` returning an
    empty sequence means the feed knows of no CVEs for that CPE — a real finding. A feed
    that could not be reached raises `DependencyError` instead, because a silent empty here
    would later read as "this component is clean" (AGENTS.md §67).
    """

    def cves_for_cpe(self, cpe: str) -> Sequence[CveRecord]:
        """Every CVE the feed associates with this CPE.

        Raises `ValidationError` for a CPE that is not a CPE, and `DependencyError` when
        the feed fails — `retryable=True` for a timeout, a 429, or a 5xx, `False` for
        something that will fail identically next time.
        """
        ...

    def cve(self, cve_id: str) -> CveRecord | None:
        """One CVE by id, or None if the feed does not know it."""
        ...

    def fetch_report(self) -> FeedFetchReport:
        """What the fetches since construction did, including records refused and why.

        Call after fetching. As with `ManagedSource.read_report`, this exists so that
        "never silently drop a record" is verifiable by the caller rather than promised by
        the adapter (AGENTS.md §4.4).
        """
        ...


class CveCache(Protocol):
    """The local persistence of what a feed told us — the raw/normalized split applied to
    an external source (AGENTS.md §3, m3-design §2).

    It exists so we do not re-ask NVD for something it already answered: NVD is slow and
    rate-limited, and a correlation run over a few hundred components would otherwise take
    hours and risk a ban.

    Note it is **not tenant-scoped**. A CVE is a fact about software in the world, identical
    for every tenant; scoping it per tenant would multiply the fetching by the number of
    tenants for no gain. Nothing tenant-specific is stored here — the conclusions about
    *our* devices live in `vulnerability_match`, which is tenant-scoped.
    """

    def query_entry(self, source: str, cpe: str) -> CveQueryCacheEntry | None:
        """What we last asked this feed about this CPE, or None if we never have.

        The distinction this method exists for: a stored entry with no CVE ids means the
        feed said "none", which is an answer worth caching. `None` means we never asked.
        """
        ...

    def records(self, source: str, cve_ids: Sequence[str]) -> Sequence[CveRecord]:
        """The cached records for these ids, in whatever order the store returns them."""
        ...

    def store(self, records: Sequence[CveRecord]) -> int:
        """Persist normalized records, idempotently. Returns how many were new."""
        ...

    def store_query(self, entry: CveQueryCacheEntry) -> None:
        """Record that we asked about a CPE, and what came back — including nothing."""
        ...


class KevSource(Protocol):
    """Is this CVE being exploited in the wild? (CISA KEV, m3-design §2.)

    The most consequential boolean in the product. A `True` promotes a finding past every
    other consideration; a `False` lets it be ranked normally. Which is why the third
    outcome must never be silently folded into the second:

    **A lookup that could not be performed raises.** If a failed catalog fetch returned
    `False`, an actively-exploited vulnerability would be quietly de-prioritised — the worst
    false negative this system could produce (AGENTS.md §4.9). "Not listed" and "we could
    not check" are different answers and this port keeps them different.
    """

    def is_known_exploited(self, cve_id: str) -> bool:
        """True if CISA lists this CVE as exploited in the wild.

        Raises `DependencyError` when the catalog cannot be loaded — never `False`.
        """
        ...

    def entry(self, cve_id: str) -> KevEntry | None:
        """The catalog entry, with its dates and ransomware flag, or None if not listed."""
        ...

    def refresh(self) -> FeedFetchReport:
        """Reload the catalog now, whatever the cache says. For a scheduler or an operator."""
        ...

    def fetch_report(self) -> FeedFetchReport:
        """What the loads since construction did, including entries refused and why."""
        ...


class EpssSource(Protocol):
    """How likely is this CVE to be exploited? (EPSS, m3-design §2.)

    Same discipline as `KevSource`, one step softer in consequence: `None` means FIRST has
    not scored this CVE, which is a real answer about a real absence. A snapshot that could
    not be fetched raises instead, because "no score" and "we do not know" would otherwise
    rank identically.
    """

    def score_for(self, cve_id: str) -> EpssScore | None:
        """The EPSS score, or None if FIRST has no score for this CVE.

        Raises `DependencyError` when the snapshot cannot be loaded — never `None`.
        """
        ...

    def refresh(self) -> FeedFetchReport:
        """Reload the current snapshot now, whatever the cache says."""
        ...

    def fetch_report(self) -> FeedFetchReport:
        """What the loads since construction did, including rows refused and why."""
        ...


class KevCache(Protocol):
    """Local persistence of the KEV catalog.

    `snapshot` is the load marker: `None` means the catalog has never been loaded, which is
    why a lookup against an empty cache must fetch rather than answer "not listed".
    """

    def snapshot(self, source: str) -> FeedSnapshot | None: ...

    def entry(self, source: str, cve_id: str) -> KevEntry | None: ...

    def replace(self, source: str, entries: Sequence[KevEntry], snapshot: FeedSnapshot) -> int:
        """Swap the whole catalog for this one, atomically. Returns how many entries landed.

        Replacement rather than accumulation because CISA does remove entries, and a
        catalog we only ever added to would keep asserting an exploitation that CISA has
        withdrawn.
        """
        ...


class EpssCache(Protocol):
    """Local persistence of an EPSS snapshot. Same shape, same load-marker discipline."""

    def snapshot(self, source: str) -> FeedSnapshot | None: ...

    def score(self, source: str, cve_id: str) -> EpssScore | None: ...

    def replace(self, source: str, scores: Sequence[EpssScore], snapshot: FeedSnapshot) -> int:
        """Swap the whole snapshot for this one, atomically. Returns how many scores landed."""
        ...


class VulnerabilityMatchStore(Protocol):
    """Both ends of correlation: the components to check, and the matches it concludes.

    Reads return components reduced to what correlation needs — what the software is, and
    how well we know its version. Writes are idempotent through the store's own unique key,
    never a check-then-insert (AGENTS.md §62), because a re-correlation is routine: feeds
    change, components change, and a run must be safe to repeat.
    """

    def components_with_cpe(self, tenant_id: UUID) -> Sequence[ComponentSnapshot]:
        """Every current component that has a CPE to look up.

        Components without a CPE are not returned: there is nothing to correlate them
        against, and inventing one would be guessing at identity (m3-design §2).
        """
        ...

    def record_match(self, match: VulnerabilityMatchInput) -> VulnerabilityMatchRecord:
        """Insert or refresh one match. `created=False` means it was already known.

        Refresh rather than duplicate: a CVE's KEV status and EPSS score change, and the
        latest correlation is the current statement of what we believe.
        """
        ...


class ReconciliationStore(Protocol):
    """Both sides of the shadow-IT diff, and the two projections it writes back.

    Separate from `AssetRepository` on purpose: entity resolution answers "which asset is
    this observation about?", while this answers "which assets and records exist, and what
    do we now believe about who manages them?". Folding the second into the first would
    give the ER contract a reporting surface it has no business carrying (ADR-0006 noted the
    same boundary from the other side).

    The reads return anchor sets rather than whole rows: matching needs identity and nothing
    else, and a port that handed out everything would invite the diff to reason about fields
    it has no business seeing.
    """

    def asset_anchors(self, tenant_id: UUID) -> Sequence[AssetAnchorSet]:
        """Every *active* asset, reduced to what it can be matched on. Merged assets are
        excluded — they are not devices, they are history (AGENTS.md §3)."""
        ...

    def managed_records(self, tenant_id: UUID) -> Sequence[ManagedRecordSnapshot]:
        """Every authoritative record, reduced to what it can be matched on."""
        ...

    def link_record(self, record_id: UUID, asset_id: UUID | None) -> None:
        """Point a record at the asset it describes, or clear the link.

        Clearing matters: a link that was right last month and is wrong now must be
        removable, or the diff would be stuck defending a stale match.
        """
        ...

    def set_management_state(self, asset_id: UUID, state: ManagementState) -> None:
        """Project what the diff concluded onto the asset. `unknown` is a real answer."""
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
        Raises DependencyError(retryable=...) on failure. Returns AdvisoryEvidence (contract §6).

        Three outcomes, and keeping them apart is the whole contract (P15, ADR-0013):

        * **Evidence.** `advisory_text` is non-empty, real, fetched text with its source
          recorded. This is the only channel by which CVE knowledge may enter insight
          generation.
        * **`NotFoundError`.** The sources were reachable and had no advisory text for this
          CVE. There is nothing to ground on, so the generator must refuse rather than
          reason from memory — never an `AdvisoryEvidence` with an empty `advisory_text`,
          which would look like valid grounding.
        * **`DependencyError(retryable=…)`.** A source could not be reached. Ask again;
          this is not "there is no advisory" (AGENTS.md §67).
        """
        ...


class AdvisoryDocumentCache(Protocol):
    """Fetched reference documents, cached by URL.

    Cache-first for the same reason as `CveCache`: a retrieval run should not re-download a
    patch it already holds, and re-asking a reference that has already 404'd is noise
    somebody else has to serve. Stores sanitized text, never raw bytes (ADR-0013).
    """

    def document(self, url: str) -> AdvisoryDocument | None:
        """The cached document for this URL, or None if it was never fetched.

        `None` means "never asked". A document with `status=unavailable` means "asked, and
        there was nothing there" — a different answer, and one worth keeping.
        """
        ...

    def store(self, document: AdvisoryDocument) -> None:
        """Cache a fetched document, replacing any previous fetch of the same URL."""
        ...


class InsightGenerator(Protocol):
    """The LLM boundary (strict). Reads only the already-redacted `TriageDossier`; its
    output is grounded, advisory, and non-suppressing."""

    def generate(self, triage: TriageDossier) -> InsightProposal:
        """Produce a grounded, advisory InsightProposal. Raises GroundingError if the model
        output cites nothing; raises ValidationError on a KEV-hiding recommendation. Never
        suppresses a finding; never uses out-of-band CVE knowledge."""
        ...


class DossierSource(Protocol):
    """Everything the dossier assembler is allowed to read.

    A read port rather than a repository: the assembler projects an *allowlist* out of what
    this returns (dossier contract §4), and keeping the read narrow is half of that. What
    comes back is deliberately raw — observation payloads as collectors wrote them — because
    the redaction has to happen in one auditable place rather than being assumed at each
    query.
    """

    def asset(self, tenant_id: UUID, asset_id: UUID) -> AssetView | None:
        """The asset itself, or None. Tenant-scoped: an asset is never read cross-tenant."""
        ...

    def identifiers(self, tenant_id: UUID, asset_id: UUID) -> Sequence[Identifier]:
        """The identity anchors, which the contract includes verbatim."""
        ...

    def software(self, tenant_id: UUID, asset_id: UUID) -> Sequence[SoftwareComponent]:
        """Current components — the crux of vulnerability reasoning."""
        ...

    def observations(
        self, tenant_id: UUID, asset_id: UUID, *, limit: int = 500
    ) -> Sequence[ObservationSnapshot]:
        """Recent observations, newest first. Payloads are untrusted and un-redacted."""
        ...

    def managed_by(self, tenant_id: UUID, asset_id: UUID) -> Sequence[str]:
        """Which managed-source classes know this asset (`["ad", "mdm"]`).

        Empty is the shadow-IT signal, and it is context the insight is entitled to: a
        vulnerability on a device nobody manages is a different problem (m3-design §3).
        """
        ...


class TriageStore(Protocol):
    """Persistence for the insight path: the immutable snapshot, then the proposal.

    The order is the contract. The snapshot is written *first* and never changes, so what
    the model was given is always reconstructable — an insight whose evidence cannot be
    reproduced is not auditable, and this system's whole claim is that it is (dossier
    contract §2, §8).
    """

    def pending_matches(self, tenant_id: UUID, *, limit: int = 100) -> Sequence[MatchForTriage]:
        """Deterministic matches with no insight yet, KEV and highest-confidence first."""
        ...

    def record_snapshot(self, triage: TriageDossier) -> UUID:
        """Persist exactly what the model will see. Immutable once written."""
        ...

    def record_insight(self, insight: InsightProposal) -> InsightRecord:
        """Persist a validated proposal. The database refuses an ungrounded one
        (`insight_must_be_grounded`) and a KEV-hiding one (`insight_kev_not_hidden`) — the
        generator has already refused both, and this is the backstop."""
        ...

    def review_insight(self, review: InsightReview) -> InsightProposal:
        """Record one human decision: the current-state update *and* the history event, in
        one transaction.

        Forward only through `proposed → human_reviewed → accepted`. The insight is advisory
        until a human says otherwise, which is the point of the state existing at all
        (AGENTS.md §2.8). Both writes commit together, like the merge path — a projection
        that can disagree with its own history is worse than no projection.
        """
        ...

    def review_history(self, insight_id: UUID) -> Sequence[InsightReviewEvent]:
        """Every review decision on this insight, oldest first. Append-only, so this is the
        record and the columns on `insight` are the summary (data-model §4)."""
        ...

    def insight(self, insight_id: UUID) -> InsightProposal | None: ...

    def snapshot(self, triage_id: UUID) -> TriageDossier | None:
        """The retained snapshot behind an insight — what the model actually saw."""
        ...


class ModelClient(Protocol):
    """The model seam, kept as small as a seam can be.

    One method, two strings in, text out. Everything that makes the insight trustworthy —
    the prompt, the parsing, the grounding checks, the KEV rule — lives above this and is
    therefore testable without a model (AGENTS.md §43). The implementing adapter runs a
    **local or self-hosted** model, because the dossier is corporate asset data and it does
    not leave the perimeter (AGENTS.md §2.10, ADR-0014).
    """

    def complete(self, *, system: str, user: str) -> ModelCompletion:
        """Run one completion. Raises `DependencyError(retryable=…)` if the model is
        unreachable — never a fabricated or empty completion (AGENTS.md §67)."""
        ...
