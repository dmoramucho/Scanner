"""The engine's pre-flight: scope is checked here, before anything is acted on.

`ScopeAuthority.require_authorized` is called for every target, and it is called *first*.
A denied target never reaches the sink — no observation, no row, nothing recorded about it
beyond the `audit_log` entry the authority itself writes. That ordering is the whole
control (AGENTS.md §2.5): the check is not a filter applied to results, it is a gate in
front of the work.

**Why a denial skips the target instead of aborting the run.** A passive capture is a
reading of the network's own tables, and a broadcast domain routinely contains addresses
outside our authorized ranges — a neighbour's device, an upstream router, a guest VLAN.
Aborting the sweep would make one foreign address suppress every legitimate observation in
the capture. So each denial aborts *its target*, is counted, and is audited. Nothing about
an out-of-scope target is persisted, which is the property the negative tests assert.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from uuid import UUID

from domain.errors import ScopeViolation, ValidationError
from domain.models import IPAddress, ObservationInput
from domain.ports import ObservationSink, ScopeAuthority


@dataclass(frozen=True, slots=True)
class SweepOutcome:
    """What a sweep did. Denials are first-class output, not a silent drop."""

    recorded: int = 0
    duplicates: int = 0
    denied: int = 0
    denied_targets: tuple[str, ...] = field(default_factory=tuple)

    @property
    def observations(self) -> int:
        """Distinct observations now in the store from this sweep."""
        return self.recorded + self.duplicates


class PassiveSweep:
    """Runs collector output through the scope gate and into the observation spine."""

    def __init__(self, scope: ScopeAuthority, sink: ObservationSink) -> None:
        self._scope = scope
        self._sink = sink

    def run(
        self, tenant_id: UUID, candidates: Iterable[tuple[IPAddress, ObservationInput]]
    ) -> SweepOutcome:
        """Authorize each target, then record the observations that survive.

        Raises `ValidationError` if an observation claims a different tenant than the sweep
        — a cross-tenant write would be a far worse bug than a refused run, and the
        `tenant_id` discipline is what RLS will later formalise (AGENTS.md §5).
        """
        recorded = 0
        duplicates = 0
        denied_targets: list[str] = []

        for target, observation in candidates:
            if observation.tenant_id != tenant_id:
                raise ValidationError(
                    f"observation tenant {observation.tenant_id} does not match the sweep "
                    f"tenant {tenant_id}"
                )

            try:
                self._scope.require_authorized(tenant_id, target)
            except ScopeViolation:
                # Denied: the target is not scanned, and nothing about it is recorded.
                # The authority has already written the audit entry.
                denied_targets.append(str(target))
                continue

            result = self._sink.record(observation)
            if result.created:
                recorded += 1
            else:
                duplicates += 1

        return SweepOutcome(
            recorded=recorded,
            duplicates=duplicates,
            denied=len(denied_targets),
            denied_targets=tuple(denied_targets),
        )
