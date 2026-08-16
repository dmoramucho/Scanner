"""Assembling the `AssetDossier` — the only thing the model will ever see about an asset.

Everything the LLM knows about a device, it knows from here. So this module's job is less
"gather data" than "decide what the model is entitled to", and the decision is already made:
the dossier contract §4 is an allowlist with a default-exclude rule, implemented in
`engine/redaction.py` and applied here.

Three properties hold by construction:

**Assembled, never stored as truth** (contract §8.1). A dossier is projected from
observations at reasoning time. The only one that is retained is the `TriageDossier`
snapshot behind a persisted insight, which is immutable — so what the model saw is always
reconstructable, and what it saw is never mistaken for what is true.

**Provenance on every observed value** (contract §8.2). An `Observed[…]` without provenance
is an assembly bug, because the LLM may only cite what carries provenance: a citation that
cannot be traced to an observation is not a citation.

**Secrets cannot pass** (AGENTS.md §2.10). The assembler is the one component allowed to
read secret-bearing observations, and it emits allowlisted fields only. It then sweeps its
own output and refuses to emit a dossier containing anything secret-shaped — see
`engine/redaction.py` for why that second layer exists.

`management_state` is carried deliberately: a vulnerability on a device nobody manages is a
different problem from the same vulnerability on a managed server, and M2 already knows
which is which (m3-design §3).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Final, Literal
from uuid import UUID, uuid4

from domain.errors import NotFoundError
from domain.models import (
    ApplicationContext,
    AssetClass,
    AssetContext,
    AssetDossier,
    Derivation,
    EmbeddedContext,
    ExposureBlock,
    GenericContext,
    ManagementBlock,
    ObservationSnapshot,
    Observed,
    OpenPort,
    Provenance,
    Reachability,
    SecurityFlag,
    ServerContext,
)
from domain.ports import DossierSource
from engine.redaction import assert_no_secrets, project, security_flags

#: Bumped when the projection changes shape. Recorded on every dossier and on every retained
#: snapshot, so an old insight can always be read against the rules that produced it.
ASSEMBLER_VERSION: Final = "1.0.0"

#: More than this and we are sending the model noise. Newest first, so the cut is the oldest.
MAX_OPEN_PORTS: Final = 100
MAX_SECURITY_FLAGS: Final = 40
MAX_RUNNING_SERVICES: Final = 40


@dataclass(frozen=True, slots=True)
class AssemblyReport:
    """What assembly dropped. Visible because an allowlist doing its job looks like loss."""

    observations_read: int = 0
    fields_dropped: int = 0


class DossierAssembler:
    """Projects an asset into the redacted dossier the insight path reasons over."""

    def __init__(
        self,
        source: DossierSource,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        new_id: Callable[[], UUID] = uuid4,
    ) -> None:
        self._source = source
        self._clock = clock
        self._new_id = new_id
        self._report = AssemblyReport()

    def assemble(self, tenant_id: UUID, asset_id: UUID) -> AssetDossier:
        """Build the dossier for one asset, or raise.

        Raises `NotFoundError` for an asset that does not exist in this tenant — never an
        empty dossier, which would look like an asset we know nothing about and would let
        the model reason about a device that is not there (AGENTS.md §67).
        """
        asset = self._source.asset(tenant_id, asset_id)
        if asset is None:
            raise NotFoundError(f"no asset {asset_id} in tenant {tenant_id}")

        assembled_at = self._clock()
        observations = list(self._source.observations(tenant_id, asset_id))
        dropped = 0

        exposure, exposure_dropped = self._exposure(observations)
        context, context_dropped = self._context(asset.asset_class, observations)
        dropped += exposure_dropped + context_dropped

        dossier = AssetDossier(
            dossier_id=self._new_id(),
            asset_id=asset_id,
            tenant_id=tenant_id,
            assembled_at=assembled_at,
            assembler_version=ASSEMBLER_VERSION,
            asset_class=asset.asset_class,
            identifiers=list(self._source.identifiers(tenant_id, asset_id)),
            software=list(self._source.software(tenant_id, asset_id)),
            exposure=exposure,
            management=ManagementBlock(
                state=Observed(
                    value=asset.management_state,
                    provenance=self._derived_provenance(assembled_at),
                ),
                known_to=list(self._source.managed_by(tenant_id, asset_id)),
            ),
            context=context,
            identification_confidence=asset.identification_confidence,
        )

        # The refusal, not a repair: if anything secret-shaped survived the projection, the
        # projection has a hole and this dossier does not get emitted (contract §4).
        assert_no_secrets(dossier.model_dump(mode="json"), where=f"dossier for asset {asset_id}")

        self._report = AssemblyReport(observations_read=len(observations), fields_dropped=dropped)
        return dossier

    def report(self) -> AssemblyReport:
        return self._report

    # --------------------------------------------------------------------- blocks

    def _exposure(self, observations: Sequence[ObservationSnapshot]) -> tuple[ExposureBlock, int]:
        """Reachability, the segment *label*, and open ports with normalized service names."""
        dropped = 0
        reachability: Observed[Reachability] | None = None
        segment: Observed[str] | None = None
        ports: list[OpenPort] = []

        for observation in observations:
            fields = project(observation.observation_type, observation.payload)
            dropped += fields.dropped

            if reachability is None:
                value = _reachability(fields.get("reachability"))
                if value is not None:
                    reachability = Observed(value=value, provenance=observation.provenance)
            if segment is None and fields.get("network_segment_label"):
                label = fields.get("network_segment_label")
                if label is not None:
                    segment = Observed(value=label, provenance=observation.provenance)

            port = _open_port(fields.get("port"), fields.get("protocol"), fields.get("service"))
            if port is not None and len(ports) < MAX_OPEN_PORTS:
                ports.append(
                    OpenPort(
                        port=port[0],
                        protocol=port[1],
                        service=port[2],
                        provenance=observation.provenance,
                    )
                )

        if reachability is None:
            # Unknown is a value, and the honest one. A dossier that omitted reachability
            # would invite the model to assume the comfortable answer.
            reachability = Observed(
                value=Reachability.UNKNOWN, provenance=self._derived_provenance(self._clock())
            )
        return ExposureBlock(
            reachability=reachability, network_segment_label=segment, open_ports=ports
        ), dropped

    def _context(
        self, asset_class: AssetClass, observations: Sequence[ObservationSnapshot]
    ) -> tuple[AssetContext, int]:
        """The per-class context axis (contract §5): what matters differs by what it is."""
        facts, flags, services, dropped = self._facts(observations)

        if asset_class is AssetClass.SERVER:
            return ServerContext(
                os_name=facts.get("os_name"),
                os_version=facts.get("os_version"),
                running_services=services[:MAX_RUNNING_SERVICES],
                security_flags=flags[:MAX_SECURITY_FLAGS],
            ), dropped
        if asset_class is AssetClass.EMBEDDED:
            return EmbeddedContext(
                vendor=facts.get("vendor"),
                model=facts.get("model"),
                device_family=facts.get("device_family"),
                firmware_version=facts.get("firmware_version"),
                # Embedded devices often have no package manager, which is *why* their
                # versions are banner- or vendor-API-derived. The model needs that context
                # to weigh a `probable` match correctly.
                limited_shell=facts.get("device_family") is not None,
                security_flags=flags[:MAX_SECURITY_FLAGS],
            ), dropped
        if asset_class is AssetClass.APPLICATION:
            return ApplicationContext(
                app_name=facts.get("app_name"),
                behind_reverse_proxy=_boolean(facts.get("behind_reverse_proxy")),
                behind_waf=_boolean(facts.get("behind_waf")),
            ), dropped
        return GenericContext(
            asset_class=(
                AssetClass.NETWORK_DEVICE
                if asset_class is AssetClass.NETWORK_DEVICE
                else AssetClass.UNKNOWN
            ),
            vendor=facts.get("vendor"),
            model=facts.get("model"),
            firmware_version=facts.get("firmware_version"),
        ), dropped

    def _facts(
        self, observations: Iterable[ObservationSnapshot]
    ) -> tuple[dict[str, Observed[str]], list[SecurityFlag], list[Observed[str]], int]:
        """Allowlisted scalars, derived flags and service names — each with its provenance.

        Newest wins: `observations` arrives newest first, so the first sighting of a fact is
        the current one and later ones are history the dossier does not need.
        """
        facts: dict[str, Observed[str]] = {}
        flags: list[SecurityFlag] = []
        services: list[Observed[str]] = []
        seen_flags: set[str] = set()
        seen_services: set[str] = set()
        dropped = 0

        for observation in observations:
            fields = project(observation.observation_type, observation.payload)
            dropped += fields.dropped
            for key, value in fields.fields.items():
                if key in {"port", "protocol", "service", "name"}:
                    continue
                facts.setdefault(key, Observed(value=value, provenance=observation.provenance))

            name = fields.get("name") or fields.get("service")
            if name and name not in seen_services:
                seen_services.add(name)
                services.append(Observed(value=name, provenance=observation.provenance))

            derived = security_flags(observation.observation_type, observation.payload)
            dropped += derived.dropped
            for key, value in derived.fields.items():
                if key in seen_flags:
                    continue
                seen_flags.add(key)
                flags.append(SecurityFlag(key=key, value=value, provenance=observation.provenance))

        return facts, flags, services, dropped

    def _derived_provenance(self, at: datetime) -> Provenance:
        """Provenance for a value this assembler derived rather than observed.

        Named honestly. `management_state` is the reconciliation engine's deterministic
        conclusion, not something a collector saw, and the dossier says so rather than
        borrowing an observation's provenance to look better attributed than it is
        (contract §8.2).
        """
        return Provenance(
            source="reconciliation",
            source_type="derived",
            collector="dossier-assembler",
            collector_version=ASSEMBLER_VERSION,
            collection_method="projection",
            observed_at=at,
            collected_at=at,
            confidence=1.0,
            derivation=Derivation.DETERMINISTIC,
        )


# ------------------------------------------------------------------- field coercion


def _reachability(value: str | None) -> Reachability | None:
    if value is None:
        return None
    try:
        return Reachability(value.strip().lower())
    except ValueError:
        return None


def _boolean(value: Observed[str] | None) -> Observed[bool] | None:
    if value is None:
        return None
    return Observed(
        value=value.value.strip().lower() in {"true", "yes", "1"}, provenance=value.provenance
    )


def _open_port(
    port: str | None, protocol: str | None, service: str | None
) -> tuple[int, Literal["tcp", "udp"], str | None] | None:
    """A port triple, or nothing. Bounds and enum-checked: this is untrusted payload data."""
    if port is None:
        return None
    try:
        number = int(float(port))
    except ValueError:
        return None
    if not 1 <= number <= 65535:
        return None
    transport = (protocol or "tcp").strip().lower()
    if transport not in {"tcp", "udp"}:
        return None
    return number, "tcp" if transport == "tcp" else "udp", service


__all__: Sequence[str] = [
    "ASSEMBLER_VERSION",
    "AssemblyReport",
    "DossierAssembler",
]
