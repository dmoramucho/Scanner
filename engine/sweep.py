"""The engine's ingestion path: scope gate → observation → resolved asset.

`ScopeAuthority.require_authorized` is called for every target, and it is called *first*.
A denied target never reaches the sink and never reaches entity resolution — no
observation, no asset, nothing recorded about it beyond the `audit_log` entry the
authority itself writes. That ordering is the whole control (AGENTS.md §2.5): the check is
not a filter applied to results, it is a gate in front of the work.

**Why a denial skips the target instead of aborting the run.** A passive capture is a
reading of the network's own tables, and a broadcast domain routinely contains addresses
outside our authorized ranges — a neighbour's device, an upstream router, a guest VLAN.
Aborting the sweep would make one foreign address suppress every legitimate observation in
the capture. So each denial aborts *its target*, is counted, and is audited.

**Why the asset link runs through `asset_identifier`.** `observation` is append-only, so a
row cannot be back-filled with an `asset_id` once resolution figures one out. The link is
made in the other direction: `upsert_from_anchors` records which observation asserted each
identifier. Immutability and provenance both survive, and neither is traded for the other.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from uuid import UUID

from domain.errors import ScopeViolation, ValidationError
from domain.models import AnchorObservation, IPAddress, ObservationInput
from domain.ports import AssetRepository, ObservationSink, ScopeAuthority

#: Target, observation, anchors. Structurally identical to
#: `adapters.collector.records.Candidate` and declared separately on purpose: the engine
#: depends on domain types, never on a collector module (AGENTS.md §2.1).
Candidate = tuple[IPAddress, ObservationInput, tuple[AnchorObservation, ...]]


@dataclass(frozen=True, slots=True)
class SweepOutcome:
    """What a sweep did. Denials are first-class output, not a silent drop."""

    recorded: int = 0
    duplicates: int = 0
    denied: int = 0
    denied_targets: tuple[str, ...] = field(default_factory=tuple)
    asset_ids: frozenset[UUID] = field(default_factory=frozenset)

    @property
    def observations(self) -> int:
        """Distinct observations now in the store from this sweep."""
        return self.recorded + self.duplicates

    @property
    def assets(self) -> int:
        """Distinct assets the sweep resolved to — the shape of the network as we see it."""
        return len(self.asset_ids)


class PassiveSweep:
    """Runs collector output through the scope gate, the observation spine, and ER."""

    def __init__(
        self, scope: ScopeAuthority, sink: ObservationSink, assets: AssetRepository
    ) -> None:
        self._scope = scope
        self._sink = sink
        self._assets = assets

    def run(self, tenant_id: UUID, candidates: Iterable[Candidate]) -> SweepOutcome:
        """Authorize each target, record what survives, and resolve it to an asset.

        Raises `ValidationError` if an observation claims a different tenant than the sweep
        — a cross-tenant write would be a far worse bug than a refused run, and the
        `tenant_id` discipline is what RLS will later formalise (AGENTS.md §5).
        """
        recorded = 0
        duplicates = 0
        denied_targets: list[str] = []
        asset_ids: set[UUID] = set()

        for target, observation, anchors in candidates:
            if observation.tenant_id != tenant_id:
                raise ValidationError(
                    f"observation tenant {observation.tenant_id} does not match the sweep "
                    f"tenant {tenant_id}"
                )

            try:
                self._scope.require_authorized(tenant_id, target)
            except ScopeViolation:
                # Denied: the target is not scanned, nothing about it is recorded, and no
                # asset is created for it. The authority has already written the audit
                # entry.
                denied_targets.append(str(target))
                continue

            result = self._sink.record(observation)
            if result.created:
                recorded += 1
            else:
                duplicates += 1

            # Resolution runs on repeats too: `upsert_from_anchors` is idempotent, and a
            # re-observation is still evidence that this asset is still there.
            if anchors:
                asset_ids.add(
                    self._assets.upsert_from_anchors(tenant_id, anchors, result.observation_id)
                )

        return SweepOutcome(
            recorded=recorded,
            duplicates=duplicates,
            denied=len(denied_targets),
            denied_targets=tuple(denied_targets),
            asset_ids=frozenset(asset_ids),
        )
