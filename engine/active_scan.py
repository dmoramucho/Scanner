"""Active scanning, driven by judgment rather than by a flag string.

The nmap adapter knows how to scan. This module decides *whether*, *how hard*, and *when to
stop* — the two safety mechanisms m1-design §2 puts in the engine precisely so the adapter
cannot forget them:

**Detect-then-adapt.** Every candidate is classified from signals we already have — MAC
vendor, mDNS service types, ports seen passively, an asset class entity resolution already
assigned — and gets `GENTLE` or `STANDARD` accordingly. The default for an *unknown* device
is `GENTLE`. That is deliberate and it is the same shape as deny-by-default: on this
network fragile embedded stacks are the norm, not the exception (AGENTS.md §2.7), so the
burden of proof is on "this host is robust", never on "this host is delicate".

**Circuit breaker.** Each device is health-checked before and after it is touched. A device
that was answering and then goes quiet has been hurt: the breaker trips, the run backs off,
that device is not probed further, and the trip is recorded as evidence rather than counted
in silence. One unresponsive device never aborts the whole run — the same per-target shape
as the passive sweep's per-target denial. But a *streak* of trips does stop the run: if
everything we touch falls over, continuing is not diligence.

Ordering is the control, and it is fixed:

    authorize → pre-check → classify → scan → post-check → record → resolve

Scope comes first for **every** candidate, before any packet — including the health check,
which is itself a packet (AGENTS.md §2.5). A denied target is never health-checked, never
scanned, and leaves nothing but its audit entry.

What this module does *not* do: build scanner flags (that is the adapter, P5), inspect
anything with credentials (P7 — a device with a credentialed path is left alone here), or
change the observation spine or entity resolution. M1 adds a source of observations; it
does not touch what happens to them (m1-design §6).
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from domain.errors import DependencyError, ScopeViolation, ValidationError
from domain.models import (
    AnchorObservation,
    AssetClass,
    IPAddress,
    ObservationInput,
    ScanProfile,
    ScanResult,
)
from domain.ports import (
    ActiveScanner,
    AssetRepository,
    HealthProbe,
    ObservationSink,
    ScopeAuthority,
)

ENGINE_NAME = "scan-engine"
ENGINE_VERSION = "0.1.0"

#: A device that stopped answering after we scanned it is a fact worth keeping, not just a
#: counter in a run summary. It goes into the same append-only spine as everything else, so
#: "which devices has this scanner upset, and when?" is answerable later.
DEVICE_HEALTH_OBSERVATION = "device_health"


@dataclass(frozen=True, slots=True)
class ScanCandidate:
    """A device we are considering scanning, with the signals we already hold about it.

    Everything here comes from work already done — passive discovery, a previous scan,
    entity resolution — which is the point of detect-then-adapt: classify from what we
    know before spending a packet on finding out (m1-design §2).
    """

    target: IPAddress
    mac: str | None = None
    mac_vendor: str | None = None  # OUI lookup, or nmap's vendor field
    hostname: str | None = None
    mdns_services: tuple[str, ...] = ()  # e.g. ("_axis-video._tcp", "_ipp._tcp")
    open_ports: tuple[int, ...] = ()  # ports seen passively or in a previous scan
    asset_class: AssetClass | None = None  # if entity resolution already classified it
    credential_ref: str | None = None  # a credentialed path exists → do not probe hard


@dataclass(frozen=True, slots=True)
class ClassificationPolicy:
    """What counts as "fragile", spelled out rather than buried in an `if`.

    These are lists an operator can inspect and extend for their own estate — a new camera
    vendor is a data change, not a code change. The default is `GENTLE` for anything these
    signals do not positively identify as robust.
    """

    #: Substrings matched case-insensitively against the MAC vendor / OUI name. Cameras,
    #: VoIP handsets, printers, UPSes, badge readers — the estate AGENTS.md §2.7 is about.
    embedded_vendor_markers: frozenset[str] = frozenset(
        {
            "axis communications",
            "hikvision",
            "dahua",
            "hanwha",
            "mobotix",
            "vivotek",
            "bosch security",
            "polycom",
            "yealink",
            "grandstream",
            "snom",
            "avaya",
            "brother",
            "zebra",
            "epson",
            "kyocera",
            "lexmark",
            "ricoh",
            "canon",
            "american power conversion",
            "apc by schneider",
            "eaton",
            "tridium",
            "honeywell",
            "hid global",
            "ubiquiti",
            "espressif",  # ESP32 — the tell for a home-brew IoT thing on a corporate VLAN
            "raspberry pi",
            "texas instruments",
        }
    )

    #: mDNS service types that only embedded devices advertise.
    embedded_mdns_services: frozenset[str] = frozenset(
        {
            "_axis-video._tcp",
            "_rtsp._tcp",
            "_ipp._tcp",
            "_ipps._tcp",
            "_printer._tcp",
            "_pdl-datastream._tcp",
            "_scanner._tcp",
            "_sip._udp",
            "_h323._tcp",
            "_hap._tcp",
            "_homekit._tcp",
            "_dahua._tcp",
        }
    )

    #: Ports that all but name the device class: RTSP video, raw printing, SIP, MQTT,
    #: TR-069, and the vendor-specific camera ports.
    embedded_ports: frozenset[int] = frozenset({554, 8554, 9100, 515, 631, 5060, 1883, 7547, 37777})

    #: Ports whose combination says "general-purpose host with an OS behind it".
    robust_ports: frozenset[int] = frozenset({22, 445, 3389, 5432, 3306, 5985})

    #: Asset classes entity resolution may have already settled.
    embedded_classes: frozenset[AssetClass] = frozenset(
        {AssetClass.EMBEDDED, AssetClass.NETWORK_DEVICE}
    )
    robust_classes: frozenset[AssetClass] = frozenset({AssetClass.SERVER, AssetClass.APPLICATION})


@dataclass(frozen=True, slots=True)
class BreakerPolicy:
    """When to stop touching a device, and when to stop the run.

    Numbers an operator can tune per estate, and the reasoning behind the defaults:

    * `health_check_attempts = 2` — one missed reply is a lost packet on a busy VLAN, not
      distress. Two is enough to distinguish "quiet" from "gone" without a long wait.
    * `backoff_seconds = 5.0` — after a device falls over, give the segment a moment before
      touching the next one. Some embedded stacks share an upstream that also struggles.
    * `halt_after_consecutive_failures = 3` — one bad device must never abort the run
      (m1-design §2), but three in a row is not bad luck: it is us. Stopping and reporting
      beats scanning the rest of the estate the same way.
    """

    health_check_attempts: int = 2
    backoff_seconds: float = 5.0
    halt_after_consecutive_failures: int = 3

    def __post_init__(self) -> None:
        if self.health_check_attempts < 1:
            raise ValidationError("health_check_attempts must be at least 1")
        if self.backoff_seconds < 0:
            raise ValidationError("backoff_seconds cannot be negative")
        if self.halt_after_consecutive_failures < 1:
            raise ValidationError("halt_after_consecutive_failures must be at least 1")


@dataclass(frozen=True, slots=True)
class ActiveScanOutcome:
    """What a run did, with every way a device was *not* scanned made explicit.

    Silence is the enemy here: a device that was denied, unreachable, tripped, or skipped is
    reported as such, so a run that scanned nothing cannot be mistaken for a clean estate.
    """

    scanned: int = 0
    denied: int = 0
    tripped: int = 0
    unreachable: int = 0
    errored: int = 0
    skipped_credentialed: int = 0
    recorded: int = 0  # observations newly written
    duplicates: int = 0  # observations the sink had already
    denied_targets: tuple[str, ...] = ()
    tripped_targets: tuple[str, ...] = ()
    unreachable_targets: tuple[str, ...] = ()
    asset_ids: frozenset[UUID] = field(default_factory=frozenset)
    halted_reason: str | None = None

    @property
    def assets(self) -> int:
        return len(self.asset_ids)

    @property
    def touched(self) -> int:
        """Devices we actually sent a scan at — the number that matters for blast radius."""
        return self.scanned + self.tripped + self.errored


def classify(candidate: ScanCandidate, policy: ClassificationPolicy | None = None) -> ScanProfile:
    """Pick the profile for a device from what we already know about it.

    Strongest signal first: a class entity resolution settled, then the MAC vendor, then
    what the device advertises, then which ports it exposes. **Anything unresolved is
    `GENTLE`** — the fail-safe direction. A robust host scanned gently is slower; a camera
    scanned as though it were a server is an outage.
    """
    rules = policy or ClassificationPolicy()

    if candidate.asset_class in rules.embedded_classes:
        return ScanProfile.GENTLE
    if candidate.asset_class in rules.robust_classes:
        return ScanProfile.STANDARD

    vendor = (candidate.mac_vendor or "").casefold()
    if vendor and any(marker in vendor for marker in rules.embedded_vendor_markers):
        return ScanProfile.GENTLE

    services = {service.casefold() for service in candidate.mdns_services}
    if services & rules.embedded_mdns_services:
        return ScanProfile.GENTLE

    ports = set(candidate.open_ports)
    if ports & rules.embedded_ports:
        return ScanProfile.GENTLE
    if ports & rules.robust_ports:
        return ScanProfile.STANDARD

    # Nothing identified it. On this estate that means "assume fragile".
    return ScanProfile.GENTLE


class ActiveScanEngine:
    """Scope-gated, profile-selecting, breaker-protected active scanning."""

    def __init__(
        self,
        scope: ScopeAuthority,
        scanner: ActiveScanner,
        probe: HealthProbe,
        sink: ObservationSink,
        assets: AssetRepository,
        *,
        run_id: UUID,
        classification: ClassificationPolicy | None = None,
        breaker: BreakerPolicy | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._scope = scope
        self._scanner = scanner
        self._probe = probe
        self._sink = sink
        self._assets = assets
        self._run_id = run_id
        self._classification = classification or ClassificationPolicy()
        self._breaker = breaker or BreakerPolicy()
        self._sleep = sleep
        self._clock = clock

    def run(self, tenant_id: UUID, candidates: Iterable[ScanCandidate]) -> ActiveScanOutcome:
        """Scan each candidate under the rules above and return what happened to each."""
        state = _RunState()

        for candidate in candidates:
            if state.halted_reason is not None:
                break
            self._process(tenant_id, candidate, state)

        return state.outcome()

    # ------------------------------------------------------------------ per device

    def _process(self, tenant_id: UUID, candidate: ScanCandidate, state: _RunState) -> None:
        target = candidate.target
        address = str(target)

        # 1. Scope, before anything reaches the wire — including the health check.
        try:
            self._scope.require_authorized(tenant_id, target)
        except ScopeViolation:
            state.denied.append(address)
            return

        # 2. A device we can log into is not probed from outside: authenticated reading is
        #    gentler and truer (AGENTS.md §2.7). The inspector itself arrives in P7.
        if candidate.credential_ref is not None:
            state.skipped_credentialed += 1
            return

        # 3. Pre-flight health: never blame ourselves for a device that was already down,
        #    and never scan one that is not there.
        try:
            reachable = self._responsive(target)
        except DependencyError as exc:
            # We could not check. That is not permission to scan.
            state.errored += 1
            state.record_failure()
            self._check_halt(state, f"health probe failed for {address}: {exc}")
            return

        if not reachable:
            state.unreachable.append(address)
            state.record_failure()
            self._check_halt(state, f"{address} was unreachable before scanning")
            return

        profile = classify(candidate, self._classification)

        # 4. The scan itself.
        try:
            result = self._scanner.scan(tenant_id, target, profile)
        except DependencyError as exc:
            self._handle_scan_failure(tenant_id, candidate, profile, exc, state)
            return

        # 5. Post-flight health: it was answering before we touched it. Is it still?
        try:
            survived = self._responsive(target)
        except DependencyError:
            # A probe we cannot run leaves the device's state unknown, and unknown after a
            # scan is not the same as fine. Stop touching it and say why.
            survived = False

        # Evidence is recorded either way. What we learned before a device fell over is
        # still what we learned, and discarding it would hide the scan that caused the
        # damage (AGENTS.md §3).
        self._ingest(tenant_id, result, state)

        if survived:
            state.scanned += 1
            state.consecutive_failures = 0
            return

        self._trip(tenant_id, candidate, profile, "unresponsive_after_scan", state)

    def _handle_scan_failure(
        self,
        tenant_id: UUID,
        candidate: ScanCandidate,
        profile: ScanProfile,
        exc: DependencyError,
        state: _RunState,
    ) -> None:
        """A retryable failure — a timeout — is the shape of a device that stopped
        answering mid-scan, so the breaker treats it as distress. A permanent failure is
        our problem (a broken invocation, a missing binary), recorded as an error against
        this device; the streak guard stops the run if it keeps happening."""
        if exc.retryable:
            self._trip(tenant_id, candidate, profile, "scan_timed_out", state)
            return

        state.errored += 1
        state.record_failure()
        self._check_halt(state, f"scanning {candidate.target} failed: {exc}")

    def _trip(
        self,
        tenant_id: UUID,
        candidate: ScanCandidate,
        profile: ScanProfile,
        reason: str,
        state: _RunState,
    ) -> None:
        """Stop touching this device, write down what happened, and back off."""
        address = str(candidate.target)
        state.tripped.append(address)
        state.record_failure()

        self._record_distress(tenant_id, candidate, profile, reason, state)

        if self._breaker.backoff_seconds:
            self._sleep(self._breaker.backoff_seconds)

        self._check_halt(state, f"circuit breaker tripped on {address} ({reason})")

    def _responsive(self, target: IPAddress) -> bool:
        """Ask the probe, allowing for one lost packet on a busy segment.

        A probe that cannot run at all is not evidence of health: it propagates, because
        "we could not check" must never be read as "it is fine".
        """
        for _ in range(self._breaker.health_check_attempts):
            if self._probe.is_responsive(target):
                return True
        return False

    def _check_halt(self, state: _RunState, latest: str) -> None:
        if state.consecutive_failures >= self._breaker.halt_after_consecutive_failures:
            state.halted_reason = (
                f"halted after {state.consecutive_failures} consecutive device failures; "
                f"last: {latest}"
            )

    # ------------------------------------------------------------------- ingestion

    def _ingest(self, tenant_id: UUID, result: ScanResult, state: _RunState) -> None:
        """Hand the scan's observations to the existing spine, unchanged (m1-design §6)."""
        asserting_observation: UUID | None = None

        for observation in result.observations:
            if observation.tenant_id != tenant_id:
                raise ValidationError(
                    f"scan observation tenant {observation.tenant_id} does not match the run "
                    f"tenant {tenant_id}"
                )
            record = self._sink.record(observation)
            if record.created:
                state.recorded += 1
            else:
                state.duplicates += 1
            if asserting_observation is None:
                asserting_observation = record.observation_id

        if asserting_observation is not None:
            state.asset_ids.add(
                self._assets.upsert_from_anchors(
                    tenant_id, _anchors_for(result), asserting_observation
                )
            )

    def _record_distress(
        self,
        tenant_id: UUID,
        candidate: ScanCandidate,
        profile: ScanProfile,
        reason: str,
        state: _RunState,
    ) -> None:
        """Persist the trip as an observation.

        A counter in a run summary disappears when the process exits. The device that
        cannot survive a scan is exactly the thing an operator needs to know about next
        month, so it goes into the append-only spine with full provenance, like every other
        fact we assert.
        """
        now = self._clock()
        observation = ObservationInput(
            tenant_id=tenant_id,
            run_id=self._run_id,
            asset_id=None,
            observation_type=DEVICE_HEALTH_OBSERVATION,
            payload={
                "ip": str(candidate.target),
                "state": reason,
                "profile": profile.value,
                "mac": candidate.mac,
            },
            source="health_probe",
            source_type="active_scan",
            source_identifier=str(candidate.target),
            collector=ENGINE_NAME,
            collector_version=ENGINE_VERSION,
            collection_method="circuit_breaker",
            version_source=None,
            confidence=0.9,
            observed_at=now,
            collected_at=now,
            raw_record_ref=None,
        )
        try:
            record = self._sink.record(observation)
        except (DependencyError, ValidationError):
            # Failing to write the note must not mask the trip itself, which the outcome
            # already carries.
            return
        if record.created:
            state.recorded += 1
        else:
            state.duplicates += 1


def _anchors_for(result: ScanResult) -> Sequence[AnchorObservation]:
    """The scan's anchors, plus the address it was scanned at.

    The adapter reports what nmap saw; the engine can also assert the thing it knows for
    certain — that these observations concern the target it aimed at. Without that, a scan
    of a host with no visible MAC would have nothing for entity resolution to key on, and
    every run would mint a fresh candidate asset.
    """
    anchors = list(result.anchors)
    if not any(anchor.kind == "ip" and anchor.value == result.target for anchor in anchors):
        anchors.append(AnchorObservation(kind="ip", value=result.target, confidence=0.9))
    return anchors


@dataclass
class _RunState:
    """Mutable bookkeeping for one run; converted to a frozen outcome at the end."""

    scanned: int = 0
    errored: int = 0
    skipped_credentialed: int = 0
    recorded: int = 0
    duplicates: int = 0
    consecutive_failures: int = 0
    halted_reason: str | None = None
    denied: list[str] = field(default_factory=list)
    tripped: list[str] = field(default_factory=list)
    unreachable: list[str] = field(default_factory=list)
    asset_ids: set[UUID] = field(default_factory=set)

    def record_failure(self) -> None:
        self.consecutive_failures += 1

    def outcome(self) -> ActiveScanOutcome:
        return ActiveScanOutcome(
            scanned=self.scanned,
            denied=len(self.denied),
            tripped=len(self.tripped),
            unreachable=len(self.unreachable),
            errored=self.errored,
            skipped_credentialed=self.skipped_credentialed,
            recorded=self.recorded,
            duplicates=self.duplicates,
            denied_targets=tuple(self.denied),
            tripped_targets=tuple(self.tripped),
            unreachable_targets=tuple(self.unreachable),
            asset_ids=frozenset(self.asset_ids),
            halted_reason=self.halted_reason,
        )
