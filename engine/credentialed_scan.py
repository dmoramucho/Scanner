"""Credentialed inspection, wired into the same spine everything else feeds.

This is where the moat gets sharper (m1-design §6). Passive discovery says a device exists.
An active scan reads its banners and *infers* versions. Logging in and reading the package
database is the device telling us what is actually installed — `version_source =
'package_manager'` instead of `'banner'`, which is the difference between "Apache 2.4.52 is
vulnerable" and "Apache 2.4.52 with the fix backported is not" (AGENTS.md §3).

The rules are the ones already established, reused rather than re-invented:

* **Scope first, unchanged.** An inspector opens a TCP connection to a real device and
  authenticates to it. That is emission, and it goes through `require_authorized` exactly
  like a scan does (AGENTS.md §2.5). A denied device is never connected to.
* **No credentialed path is a normal answer.** `InspectorRegistry.for_device` returning
  `None` means the device stays uncredentialed, keeps its banner-inferred versions, and is
  skipped without an error (m1-design §1).
* **A failed inspection is counted, never silent, and never fatal to the run.** The same
  per-target shape as the passive sweep's denial and the active scan's breaker trip.
* **The spine and the ER are untouched.** Observations go through the existing
  `ObservationSink`; assets come from the existing `upsert_from_anchors`; current software
  is projected with the existing `set_current_software`. M1 adds sources; it does not add
  write paths (m1-design §6).

One consequence worth stating plainly: `set_current_software` replaces the current set for
an asset, so a credentialed read supersedes whatever was current before it — which is the
point, and its trade-off is recorded in ADR-0006.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from ipaddress import ip_address
from uuid import UUID

from domain.errors import DomainError, ScopeViolation, ValidationError
from domain.models import AnchorObservation, DeviceFingerprint, InspectionResult
from domain.ports import AssetRepository, InspectorRegistry, ObservationSink, ScopeAuthority

#: A device we authenticated to and read is the strongest statement we can make about where
#: an observation came from — we were there, as ourselves.
ADDRESS_ANCHOR_CONFIDENCE = 0.9


@dataclass(frozen=True, slots=True)
class CredentialedOutcome:
    """What a credentialed run did, with every non-inspection made explicit.

    Same shape and same discipline as `SweepOutcome` and `ActiveScanOutcome`: a device that
    was denied, skipped, or failed is reported as such, so a run that inspected nothing
    cannot be mistaken for an estate with nothing to inspect.
    """

    inspected: int = 0
    denied: int = 0
    skipped_no_path: int = 0
    failed: int = 0
    recorded: int = 0  # observations newly written
    duplicates: int = 0  # observations the sink already had
    components: int = 0  # current-state components projected onto assets
    denied_targets: tuple[str, ...] = ()
    skipped_targets: tuple[str, ...] = ()
    failed_targets: tuple[str, ...] = ()
    asset_ids: frozenset[UUID] = field(default_factory=frozenset)

    @property
    def assets(self) -> int:
        return len(self.asset_ids)


class CredentialedInspectionEngine:
    """Scope-gated credentialed inspection, feeding the existing store."""

    def __init__(
        self,
        scope: ScopeAuthority,
        registry: InspectorRegistry,
        sink: ObservationSink,
        assets: AssetRepository,
    ) -> None:
        self._scope = scope
        self._registry = registry
        self._sink = sink
        self._assets = assets

    def run(self, tenant_id: UUID, candidates: Iterable[DeviceFingerprint]) -> CredentialedOutcome:
        """Inspect every candidate we have a way into, and record what we learn."""
        state = _RunState()

        for fingerprint in candidates:
            self._process(tenant_id, fingerprint, state)

        return state.outcome()

    def _process(self, tenant_id: UUID, fingerprint: DeviceFingerprint, state: _RunState) -> None:
        try:
            target = ip_address(fingerprint.target)
        except ValueError:
            # A fingerprint whose address does not parse is a data problem, not a device
            # problem. It is counted and skipped rather than allowed to abort the run.
            state.failed.append(fingerprint.target)
            return

        address = str(target)

        # 1. Scope, before a connection is opened. Authenticating to a device is emission.
        try:
            self._scope.require_authorized(tenant_id, target)
        except ScopeViolation:
            state.denied.append(address)
            return

        # 2. Capability, not brand. No inspector is a legitimate outcome.
        inspector = self._registry.for_device(fingerprint)
        if inspector is None or not fingerprint.credential_ref:
            state.skipped.append(address)
            return

        # 3. The inspection itself. Every domain error is this device's problem alone.
        try:
            result = inspector.inspect(tenant_id, target, fingerprint.credential_ref)
        except DomainError:
            # DependencyError (refused, rejected credential, timeout), ValidationError
            # (unreadable output), SecretAccessError (vault could not resolve it) — all of
            # them mean "we did not read this device", which is recorded, not swallowed.
            state.failed.append(address)
            return

        self._ingest(tenant_id, address, result, state)
        state.inspected += 1

    def _ingest(
        self, tenant_id: UUID, address: str, result: InspectionResult, state: _RunState
    ) -> None:
        """Existing sink, existing entity resolution, existing current-state projection."""
        asserting_observation: UUID | None = None

        for observation in result.observations:
            if observation.tenant_id != tenant_id:
                raise ValidationError(
                    f"inspection observation tenant {observation.tenant_id} does not match "
                    f"the run tenant {tenant_id}"
                )
            record = self._sink.record(observation)
            if record.created:
                state.recorded += 1
            else:
                state.duplicates += 1
            if asserting_observation is None:
                asserting_observation = record.observation_id

        if asserting_observation is None:
            return

        asset_id = self._assets.upsert_from_anchors(
            tenant_id, _anchors_for(result, address), asserting_observation
        )
        state.asset_ids.add(asset_id)

        if result.components:
            # The payoff: this asset's current software is now what the device itself
            # reports, with `version_source='package_manager'`. Anything previously current
            # and absent here is retired — never deleted — and the observations behind it
            # remain in the append-only spine (ADR-0006).
            self._assets.set_current_software(asset_id, result.components)
            state.components += len(result.components)


def _anchors_for(result: InspectionResult, address: str) -> Sequence[AnchorObservation]:
    """The inspector's anchors, plus the address we authenticated to.

    The address is the one thing this engine knows for certain, and without it a device
    whose hostname we could not read would have nothing for entity resolution to key on.
    """
    anchors = list(result.anchors)
    if not any(anchor.kind == "ip" and anchor.value == address for anchor in anchors):
        anchors.append(
            AnchorObservation(kind="ip", value=address, confidence=ADDRESS_ANCHOR_CONFIDENCE)
        )
    return anchors


@dataclass
class _RunState:
    """Mutable bookkeeping for one run; frozen into an outcome at the end."""

    inspected: int = 0
    recorded: int = 0
    duplicates: int = 0
    components: int = 0
    denied: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    asset_ids: set[UUID] = field(default_factory=set)

    def outcome(self) -> CredentialedOutcome:
        return CredentialedOutcome(
            inspected=self.inspected,
            denied=len(self.denied),
            skipped_no_path=len(self.skipped),
            failed=len(self.failed),
            recorded=self.recorded,
            duplicates=self.duplicates,
            components=self.components,
            denied_targets=tuple(self.denied),
            skipped_targets=tuple(self.skipped),
            failed_targets=tuple(self.failed),
            asset_ids=frozenset(self.asset_ids),
        )
