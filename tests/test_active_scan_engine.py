"""The judgment layer: scope first, gentle by default, and stop when a device suffers.

Everything here runs on fakes — no nmap, no network, no database (AGENTS.md §43). The
fakes are deliberately dumb recorders; the logic under test is entirely in the engine.

The assertions are ordered by how much damage their absence would do: the scope gate
first (scanning something we are not authorised to touch is the one that ends the
project), then the profile choice (the difference between a working camera and an outage),
then the breaker (whether we notice we broke something).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from ipaddress import ip_address
from uuid import UUID, uuid4

import pytest

from domain.errors import DependencyError, ScopeViolation, ValidationError
from domain.models import (
    AnchorObservation,
    AssetClass,
    AssetResolution,
    AssetView,
    IPAddress,
    MergeRequest,
    ObservationInput,
    ObservationRecord,
    ScanProfile,
    ScanResult,
    ScopeDecision,
    SoftwareComponent,
)
from engine.active_scan import (
    ActiveScanEngine,
    BreakerPolicy,
    ClassificationPolicy,
    ScanCandidate,
    classify,
)

TENANT = UUID("11111111-1111-1111-1111-111111111111")
RUN_ID = UUID("22222222-2222-2222-2222-222222222222")
NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)

CAMERA = ip_address("10.10.5.31")
SERVER = ip_address("10.10.5.7")
PRINTER = ip_address("10.10.5.20")
OUTSIDE = ip_address("192.168.99.14")


# --------------------------------------------------------------------------- fakes


class FakeScope:
    """Authorises a fixed set of addresses; records everything it was asked about."""

    def __init__(self, allowed: set[IPAddress]) -> None:
        self.allowed = allowed
        self.asked: list[str] = []

    def authorize(self, tenant_id: UUID, target: IPAddress) -> ScopeDecision:
        self.asked.append(str(target))
        return ScopeDecision(allowed=target in self.allowed, target=str(target), reason="fake")

    def require_authorized(self, tenant_id: UUID, target: IPAddress) -> None:
        if not self.authorize(tenant_id, target).allowed:
            raise ScopeViolation(f"deny-by-default: {target}")


class FakeScanner:
    """Records the profile it was asked for, and replays a scripted result or failure."""

    def __init__(
        self,
        results: dict[str, ScanResult] | None = None,
        failures: dict[str, Exception] | None = None,
    ) -> None:
        self.results = results or {}
        self.failures = failures or {}
        self.calls: list[tuple[str, ScanProfile]] = []

    def scan(self, tenant_id: UUID, target: IPAddress, profile: ScanProfile) -> ScanResult:
        address = str(target)
        self.calls.append((address, profile))
        failure = self.failures.get(address)
        if failure is not None:
            raise failure
        return self.results.get(address) or scan_result(address, profile)

    def profile_for(self, target: IPAddress) -> ScanProfile:
        return next(profile for address, profile in self.calls if address == str(target))

    @property
    def scanned(self) -> list[str]:
        return [address for address, _ in self.calls]


class FakeProbe:
    """A health probe with a scripted answer per address.

    `dies_after` models the device that survives the pre-check and not the scan — the
    exact case the circuit breaker exists for.
    """

    def __init__(
        self,
        responsive: set[IPAddress] | None = None,
        *,
        dies_after: set[IPAddress] | None = None,
        raises: set[IPAddress] | None = None,
    ) -> None:
        self.responsive = responsive if responsive is not None else set()
        self.dies_after = dies_after or set()
        self.raises = raises or set()
        self.checks: list[str] = []

    def is_responsive(self, target: IPAddress) -> bool:
        self.checks.append(str(target))
        if target in self.raises:
            raise DependencyError("probe unavailable", retryable=True)
        if target in self.dies_after:
            # Alive for the pre-check, silent for every check after it.
            return self.checks.count(str(target)) == 1
        return target in self.responsive

    def checks_for(self, target: IPAddress) -> int:
        return self.checks.count(str(target))


class FakeSink:
    def __init__(self) -> None:
        self.recorded: list[ObservationInput] = []
        self.seen: dict[tuple[str, str], UUID] = {}

    def record(self, obs: ObservationInput) -> ObservationRecord:
        self.recorded.append(obs)
        key = (obs.observation_type, str(obs.source_identifier))
        if key in self.seen:
            return ObservationRecord(observation_id=self.seen[key], created=False)
        observation_id = uuid4()
        self.seen[key] = observation_id
        return ObservationRecord(observation_id=observation_id, created=True)

    def record_batch(self, batch: Sequence[ObservationInput]) -> list[ObservationRecord]:
        return [self.record(obs) for obs in batch]

    def types_for(self, target: IPAddress) -> list[str]:
        return [
            obs.observation_type for obs in self.recorded if obs.source_identifier == str(target)
        ]


class FakeAssets:
    """The full `AssetRepository` shape, with everything the engine has no business calling
    wired to fail. M1 adds a source of observations; it does not merge assets or project
    software state (m1-design §6), and this fake makes that a test rather than a promise."""

    def __init__(self) -> None:
        self.upserts: list[tuple[tuple[str, ...], UUID]] = []
        self.by_anchor: dict[tuple[str, str], UUID] = {}

    def upsert_from_anchors(
        self, tenant_id: UUID, anchors: Sequence[AnchorObservation], observation_id: UUID
    ) -> UUID:
        self.upserts.append((tuple(anchor.value for anchor in anchors), observation_id))
        key = (anchors[0].kind, anchors[0].value)
        return self.by_anchor.setdefault(key, uuid4())

    def resolve(self, tenant_id: UUID, anchors: Sequence[AnchorObservation]) -> AssetResolution:
        raise AssertionError("the scan engine resolves through upsert_from_anchors only")

    def get(self, tenant_id: UUID, asset_id: UUID) -> AssetView | None:
        raise AssertionError("the scan engine does not read assets back")

    def set_current_software(self, asset_id: UUID, components: Sequence[SoftwareComponent]) -> None:
        raise AssertionError("projecting software state is not the scan engine's job")

    def record_merge(self, req: MergeRequest) -> UUID:
        raise AssertionError("the scan engine never merges assets")

    def reverse_merge(self, merge_id: UUID, *, rationale: str | None = None) -> UUID:
        raise AssertionError("the scan engine never reverses merges")


def scan_result(
    address: str,
    profile: ScanProfile = ScanProfile.GENTLE,
    *,
    mac: str | None = None,
    observations: int = 1,
) -> ScanResult:
    payloads = [
        ObservationInput(
            tenant_id=TENANT,
            run_id=RUN_ID,
            asset_id=None,
            observation_type=kind,
            payload={"ip": address},
            source="nmap",
            source_type="active_scan",
            source_identifier=address,
            collector="nmap-scanner",
            collector_version="0.1.0",
            collection_method=f"nmap_{profile.value}",
            version_source=None,
            confidence=0.9,
            observed_at=NOW,
            collected_at=NOW,
            raw_record_ref=None,
        )
        for kind in ("open_ports", "software")[:observations]
    ]
    anchors = [AnchorObservation(kind="mac", value=mac, confidence=0.9)] if mac else []
    return ScanResult(
        target=address,
        profile=profile,
        host_up=True,
        observations=payloads,
        anchors=anchors,
        started_at=NOW,
        finished_at=NOW,
    )


def build_engine(
    *,
    scope: FakeScope | None = None,
    scanner: FakeScanner | None = None,
    probe: FakeProbe | None = None,
    sink: FakeSink | None = None,
    assets: FakeAssets | None = None,
    breaker: BreakerPolicy | None = None,
    slept: list[float] | None = None,
) -> tuple[ActiveScanEngine, FakeScope, FakeScanner, FakeProbe, FakeSink, FakeAssets]:
    scope = scope or FakeScope({CAMERA, SERVER, PRINTER})
    scanner = scanner or FakeScanner()
    probe = probe or FakeProbe({CAMERA, SERVER, PRINTER})
    sink = sink or FakeSink()
    assets = assets or FakeAssets()
    engine = ActiveScanEngine(
        scope,
        scanner,
        probe,
        sink,
        assets,
        run_id=RUN_ID,
        breaker=breaker or BreakerPolicy(backoff_seconds=0.0),
        sleep=(slept.append if slept is not None else lambda _: None),
        clock=lambda: NOW,
    )
    return engine, scope, scanner, probe, sink, assets


# ------------------------------------------------------------- scope comes first


def test_an_out_of_scope_target_is_never_scanned() -> None:
    """The safety-critical assertion, in the P3 style: denied means no packet of any kind —
    not a scan, and not even a health check (AGENTS.md §2.5)."""
    engine, _, scanner, probe, sink, assets = build_engine(scope=FakeScope({CAMERA}))

    outcome = engine.run(TENANT, [ScanCandidate(OUTSIDE), ScanCandidate(CAMERA)])

    assert outcome.denied == 1
    assert outcome.denied_targets == (str(OUTSIDE),)
    assert str(OUTSIDE) not in scanner.scanned
    assert str(OUTSIDE) not in probe.checks
    assert not [obs for obs in sink.recorded if obs.source_identifier == str(OUTSIDE)]
    assert not [anchors for anchors, _ in assets.upserts if str(OUTSIDE) in anchors]
    assert outcome.scanned == 1  # the authorised device was still scanned


def test_a_denial_does_not_stop_the_run() -> None:
    engine, _, scanner, _, _, _ = build_engine(scope=FakeScope({SERVER}))

    outcome = engine.run(TENANT, [ScanCandidate(OUTSIDE), ScanCandidate(SERVER)])

    assert scanner.scanned == [str(SERVER)]
    assert outcome.denied == 1
    assert outcome.halted_reason is None


def test_every_candidate_passes_through_the_gate() -> None:
    """No path around the check: even the credentialed skip is asked first, so a run's
    audit trail accounts for every device it considered."""
    engine, scope, _, _, _, _ = build_engine()

    engine.run(
        TENANT,
        [ScanCandidate(CAMERA), ScanCandidate(SERVER, credential_ref="vault://ssh/server")],
    )

    assert scope.asked == [str(CAMERA), str(SERVER)]


# ------------------------------------------------------------- detect-then-adapt


def test_an_embedded_device_gets_the_gentle_profile() -> None:
    engine, _, scanner, _, _, _ = build_engine()

    engine.run(TENANT, [ScanCandidate(CAMERA, mac_vendor="Axis Communications AB")])

    assert scanner.profile_for(CAMERA) is ScanProfile.GENTLE


def test_a_robust_host_gets_the_standard_profile() -> None:
    engine, _, scanner, _, _, _ = build_engine()

    engine.run(TENANT, [ScanCandidate(SERVER, asset_class=AssetClass.SERVER)])

    assert scanner.profile_for(SERVER) is ScanProfile.STANDARD


@pytest.mark.parametrize(
    "candidate",
    [
        ScanCandidate(CAMERA, asset_class=AssetClass.EMBEDDED),
        ScanCandidate(CAMERA, mac_vendor="Hikvision Digital Technology"),
        ScanCandidate(CAMERA, mac_vendor="AXIS COMMUNICATIONS AB"),  # case-insensitive
        ScanCandidate(CAMERA, mdns_services=("_axis-video._tcp",)),
        ScanCandidate(PRINTER, mdns_services=("_ipp._tcp",)),
        ScanCandidate(CAMERA, open_ports=(80, 554)),  # RTSP: it is a camera
        ScanCandidate(PRINTER, open_ports=(9100,)),  # raw printing
        ScanCandidate(CAMERA),  # nothing known at all
    ],
    ids=[
        "resolved-embedded",
        "vendor-hikvision",
        "vendor-uppercase",
        "mdns-video",
        "mdns-printer",
        "port-rtsp",
        "port-jetdirect",
        "unknown",
    ],
)
def test_anything_not_positively_robust_is_treated_as_fragile(candidate: ScanCandidate) -> None:
    """The fail-safe direction, and the one that matters: a robust host scanned gently is
    slower, a camera scanned as a server is an outage (AGENTS.md §2.7)."""
    assert classify(candidate) is ScanProfile.GENTLE


@pytest.mark.parametrize(
    "candidate",
    [
        ScanCandidate(SERVER, asset_class=AssetClass.SERVER),
        ScanCandidate(SERVER, asset_class=AssetClass.APPLICATION),
        ScanCandidate(SERVER, open_ports=(22, 443)),
        ScanCandidate(SERVER, open_ports=(3389,)),
    ],
    ids=["resolved-server", "resolved-application", "ssh", "rdp"],
)
def test_a_positively_robust_host_gets_standard(candidate: ScanCandidate) -> None:
    assert classify(candidate) is ScanProfile.STANDARD


def test_an_embedded_signal_outweighs_a_robust_one() -> None:
    """A camera with SSH open is still a camera. Ambiguity resolves toward gentle."""
    both = ScanCandidate(CAMERA, mac_vendor="Axis Communications AB", open_ports=(22, 554))

    assert classify(both) is ScanProfile.GENTLE


def test_the_classification_policy_is_data_not_code() -> None:
    """A new vendor in the estate is a list entry, not a branch someone has to write."""
    policy = ClassificationPolicy(embedded_vendor_markers=frozenset({"acme robotics"}))

    assert classify(ScanCandidate(SERVER, mac_vendor="ACME Robotics Ltd"), policy) is (
        ScanProfile.GENTLE
    )
    assert classify(ScanCandidate(CAMERA, mac_vendor="Axis Communications AB"), policy) is (
        ScanProfile.GENTLE  # still gentle: unknown vendors default that way
    )


# --------------------------------------------------------- the credentialed seam


def test_a_device_with_a_credentialed_path_is_not_probed_at_all() -> None:
    """Logging in and reading is gentler and truer than probing from outside (AGENTS.md
    §2.7). The inspector arrives in P7; the seam is that this device is left alone."""
    engine, _, scanner, probe, sink, _ = build_engine()

    outcome = engine.run(TENANT, [ScanCandidate(SERVER, credential_ref="vault://ssh/app-01")])

    assert outcome.skipped_credentialed == 1
    assert scanner.calls == []
    assert probe.checks == []
    assert sink.recorded == []


# ------------------------------------------------------------- circuit breaker


def test_a_device_that_stops_responding_trips_the_breaker() -> None:
    """It answered before we touched it and not after. That is us."""
    probe = FakeProbe({SERVER}, dies_after={CAMERA})
    engine, _, scanner, _, sink, _ = build_engine(probe=probe)

    outcome = engine.run(TENANT, [ScanCandidate(CAMERA), ScanCandidate(SERVER)])

    assert outcome.tripped == 1
    assert outcome.tripped_targets == (str(CAMERA),)
    assert outcome.scanned == 1  # the healthy server still got scanned
    assert scanner.scanned == [str(CAMERA), str(SERVER)]
    assert "device_health" in sink.types_for(CAMERA)


def test_one_bad_device_does_not_abort_the_whole_run() -> None:
    """The per-target shape from the passive sweep: a casualty stops its own scan, not the
    run (m1-design §2)."""
    probe = FakeProbe({SERVER, PRINTER}, dies_after={CAMERA})
    engine, _, scanner, _, _, _ = build_engine(probe=probe)

    outcome = engine.run(
        TENANT, [ScanCandidate(CAMERA), ScanCandidate(SERVER), ScanCandidate(PRINTER)]
    )

    assert outcome.tripped == 1
    assert outcome.scanned == 2
    assert outcome.halted_reason is None
    assert scanner.scanned == [str(CAMERA), str(SERVER), str(PRINTER)]


def test_a_tripped_device_is_not_touched_again_in_the_run() -> None:
    """ "Abort the rest of the scan against that device" — a second candidate for the same
    address does not get another scan, because the pre-check now finds it silent."""
    probe = FakeProbe(set(), dies_after={CAMERA})
    engine, _, scanner, _, _, _ = build_engine(probe=probe)

    outcome = engine.run(TENANT, [ScanCandidate(CAMERA), ScanCandidate(CAMERA)])

    assert scanner.scanned == [str(CAMERA)]  # scanned once, never again
    assert outcome.unreachable == 1


def test_the_breaker_backs_off_after_a_trip() -> None:
    slept: list[float] = []
    probe = FakeProbe({SERVER}, dies_after={CAMERA})
    engine, *_ = build_engine(probe=probe, breaker=BreakerPolicy(backoff_seconds=5.0), slept=slept)

    engine.run(TENANT, [ScanCandidate(CAMERA), ScanCandidate(SERVER)])

    assert slept == [5.0]


def test_a_scan_timeout_counts_as_distress() -> None:
    """A timeout is what a device that stopped answering mid-scan looks like from here."""
    scanner = FakeScanner(failures={str(CAMERA): DependencyError("timed out", retryable=True)})
    engine, *_ = build_engine(scanner=scanner)

    outcome = engine.run(TENANT, [ScanCandidate(CAMERA)])

    assert outcome.tripped == 1
    assert outcome.tripped_targets == (str(CAMERA),)


def test_a_permanent_scanner_failure_is_an_error_not_a_trip() -> None:
    """nmap exiting non-zero is our problem, not evidence the device is hurt — recording it
    as damage would slander a device that is fine."""
    scanner = FakeScanner(failures={str(CAMERA): DependencyError("nmap exited 1", retryable=False)})
    engine, *_ = build_engine(scanner=scanner)

    outcome = engine.run(TENANT, [ScanCandidate(CAMERA)])

    assert outcome.errored == 1
    assert outcome.tripped == 0


def test_a_device_that_was_already_down_is_not_scanned_or_blamed() -> None:
    engine, _, scanner, _, _, _ = build_engine(probe=FakeProbe({SERVER}))

    outcome = engine.run(TENANT, [ScanCandidate(CAMERA), ScanCandidate(SERVER)])

    assert outcome.unreachable == 1
    assert outcome.unreachable_targets == (str(CAMERA),)
    assert outcome.tripped == 0  # we did not break it; it was already gone
    assert scanner.scanned == [str(SERVER)]


def test_a_single_missed_reply_is_not_distress() -> None:
    """One lost packet on a busy VLAN is not an outage: the probe is retried before the
    breaker believes it."""
    engine, _, scanner, probe, _, _ = build_engine(
        breaker=BreakerPolicy(health_check_attempts=2, backoff_seconds=0.0)
    )

    engine.run(TENANT, [ScanCandidate(CAMERA)])

    assert scanner.scanned == [str(CAMERA)]
    assert probe.checks_for(CAMERA) >= 2  # pre-check and post-check both ran


def test_a_probe_that_cannot_run_stops_us_scanning() -> None:
    """ "We could not check" must never be read as "it is fine"."""
    engine, _, scanner, _, _, _ = build_engine(probe=FakeProbe({CAMERA}, raises={CAMERA}))

    outcome = engine.run(TENANT, [ScanCandidate(CAMERA)])

    assert scanner.calls == []
    assert outcome.errored == 1
    assert outcome.scanned == 0


def test_a_streak_of_failures_halts_the_run() -> None:
    """One casualty is bad luck; three in a row is us. The run stops and says so instead of
    working through the rest of the estate the same way."""
    estate = [ip_address(f"10.10.5.{octet}") for octet in range(31, 41)]
    engine, _, scanner, _, _, _ = build_engine(
        scope=FakeScope(set(estate)),
        probe=FakeProbe(set()),  # nothing answers
        breaker=BreakerPolicy(halt_after_consecutive_failures=3, backoff_seconds=0.0),
    )

    outcome = engine.run(TENANT, [ScanCandidate(target) for target in estate])

    assert outcome.halted_reason is not None
    assert outcome.unreachable == 3  # stopped after the third, not the tenth
    assert scanner.calls == []


def test_a_healthy_device_resets_the_failure_streak() -> None:
    """The halt guard is about a *run* going wrong, not a tally of everything that ever
    failed. A device that scans cleanly clears it."""
    probe = FakeProbe({SERVER}, dies_after={CAMERA})
    engine, *_ = build_engine(
        probe=probe, breaker=BreakerPolicy(halt_after_consecutive_failures=2, backoff_seconds=0.0)
    )

    outcome = engine.run(
        TENANT,
        [ScanCandidate(CAMERA), ScanCandidate(SERVER), ScanCandidate(PRINTER)],
    )

    assert outcome.tripped == 1
    assert outcome.scanned == 1
    assert outcome.halted_reason is None  # SERVER's success reset the streak


@pytest.mark.parametrize(
    "policy_kwargs",
    [
        {"health_check_attempts": 0},
        {"backoff_seconds": -1.0},
        {"halt_after_consecutive_failures": 0},
    ],
)
def test_a_nonsensical_breaker_policy_is_refused(policy_kwargs: dict[str, float]) -> None:
    """A zero-attempt health check would disable the breaker silently."""
    with pytest.raises(ValidationError):
        BreakerPolicy(**policy_kwargs)  # type: ignore[arg-type]


# ------------------------------------------------------------------- ingestion


def test_surviving_observations_reach_the_sink_and_resolve_into_assets() -> None:
    scanner = FakeScanner(
        results={str(CAMERA): scan_result(str(CAMERA), mac="00:40:8c:9d:1e:2f", observations=2)}
    )
    engine, _, _, _, sink, assets = build_engine(scanner=scanner)

    outcome = engine.run(TENANT, [ScanCandidate(CAMERA)])

    assert outcome.recorded == 2
    assert [obs.source for obs in sink.recorded] == ["nmap", "nmap"]
    assert outcome.assets == 1
    anchors, _ = assets.upserts[0]
    assert "00:40:8c:9d:1e:2f" in anchors  # the MAC the scan saw
    assert str(CAMERA) in anchors  # plus the address we scanned


def test_a_rescan_is_idempotent_at_the_sink() -> None:
    engine, *_ = build_engine()

    first = engine.run(TENANT, [ScanCandidate(CAMERA)])
    second = engine.run(TENANT, [ScanCandidate(CAMERA)])

    assert first.recorded == 1
    assert second.recorded == 0
    assert second.duplicates == 1


def test_a_scan_with_no_mac_still_resolves_by_address() -> None:
    """Without the address anchor a MAC-less scan would mint a new candidate asset on every
    run — the graph inflation P4 exists to avoid."""
    engine, _, _, _, _, assets = build_engine()

    engine.run(TENANT, [ScanCandidate(SERVER)])
    engine.run(TENANT, [ScanCandidate(SERVER)])

    assert len({asset_id for _, asset_id in assets.by_anchor.items()}) == 1


def test_an_observation_for_another_tenant_is_refused() -> None:
    foreign = scan_result(str(CAMERA))
    foreign.observations[0] = foreign.observations[0].model_copy(update={"tenant_id": uuid4()})
    engine, *_ = build_engine(scanner=FakeScanner(results={str(CAMERA): foreign}))

    with pytest.raises(ValidationError, match="does not match the run tenant"):
        engine.run(TENANT, [ScanCandidate(CAMERA)])


def test_the_outcome_reports_how_many_devices_were_actually_touched() -> None:
    probe = FakeProbe({SERVER, PRINTER}, dies_after={CAMERA})
    engine, *_ = build_engine(probe=probe, scope=FakeScope({CAMERA, SERVER, PRINTER}))

    outcome = engine.run(
        TENANT,
        [
            ScanCandidate(CAMERA),
            ScanCandidate(SERVER),
            ScanCandidate(PRINTER, credential_ref="vault://ssh/printer"),
            ScanCandidate(OUTSIDE),
        ],
    )

    assert outcome.touched == 2  # camera (tripped) + server (scanned)
    assert outcome.skipped_credentialed == 1
    assert outcome.denied == 1


def test_denials_do_not_count_toward_the_halt_streak() -> None:
    """The halt guard watches for *us* hurting devices, not for an operator having scoped
    the run narrowly. A long list of out-of-scope addresses must not stop the run before it
    reaches the authorised ones."""
    engine, _, scanner, _, _, _ = build_engine(
        scope=FakeScope({SERVER}),
        breaker=BreakerPolicy(halt_after_consecutive_failures=2, backoff_seconds=0.0),
    )

    outcome = engine.run(
        TENANT,
        [
            ScanCandidate(ip_address("192.168.99.1")),
            ScanCandidate(ip_address("192.168.99.2")),
            ScanCandidate(ip_address("192.168.99.3")),
            ScanCandidate(SERVER),
        ],
    )

    assert outcome.denied == 3
    assert outcome.halted_reason is None
    assert scanner.scanned == [str(SERVER)]
