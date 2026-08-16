"""The credentialed ingestion path, on fakes: scope first, skip cleanly, fail loudly.

No device, no network, no database (AGENTS.md §43). The end-to-end proof against the real
store — including the `version_source` supersession that is the whole point of this slice —
lives in `tests/integration/test_credentialed_ingestion.py`.
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
    AssetResolution,
    AssetView,
    DeviceFingerprint,
    InspectionResult,
    IPAddress,
    MergeRequest,
    ObservationInput,
    ObservationRecord,
    ScopeDecision,
    SoftwareComponent,
    VersionSource,
)
from domain.ports import CredentialedInspector
from engine.credentialed_scan import CredentialedInspectionEngine

TENANT = UUID("11111111-1111-1111-1111-111111111111")
RUN_ID = UUID("22222222-2222-2222-2222-222222222222")
NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)

SERVER = "10.10.5.7"
PRINTER = "10.10.5.20"
OUTSIDE = "192.168.99.14"


# --------------------------------------------------------------------------- fakes


class FakeScope:
    def __init__(self, allowed: set[str]) -> None:
        self.allowed = allowed
        self.asked: list[str] = []

    def authorize(self, tenant_id: UUID, target: IPAddress) -> ScopeDecision:
        self.asked.append(str(target))
        return ScopeDecision(allowed=str(target) in self.allowed, target=str(target), reason="fake")

    def require_authorized(self, tenant_id: UUID, target: IPAddress) -> None:
        if not self.authorize(tenant_id, target).allowed:
            raise ScopeViolation(f"deny-by-default: {target}")


class FakeInspector:
    """Records every device it was pointed at, and replays a result or a failure."""

    def __init__(self, failure: Exception | None = None) -> None:
        self.failure = failure
        self.inspected: list[str] = []

    def inspect(self, tenant_id: UUID, target: IPAddress, credential_ref: str) -> InspectionResult:
        self.inspected.append(str(target))
        if self.failure is not None:
            raise self.failure
        return inspection_result(str(target))


class FakeRegistry:
    """Returns the inspector for devices that have a credential path, `None` otherwise."""

    def __init__(
        self, inspector: CredentialedInspector, *, matches: set[str] | None = None
    ) -> None:
        self.inspector = inspector
        self.matches = matches
        self.asked: list[str] = []

    def for_device(self, fingerprint: DeviceFingerprint) -> CredentialedInspector | None:
        self.asked.append(fingerprint.target)
        if not fingerprint.credential_ref:
            return None
        if self.matches is not None and fingerprint.target not in self.matches:
            return None
        return self.inspector


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


class FakeAssets:
    def __init__(self) -> None:
        self.by_anchor: dict[str, UUID] = {}
        self.projected: dict[UUID, list[SoftwareComponent]] = {}

    def upsert_from_anchors(
        self, tenant_id: UUID, anchors: Sequence[AnchorObservation], observation_id: UUID
    ) -> UUID:
        key = f"{anchors[0].kind}:{anchors[0].value}"
        return self.by_anchor.setdefault(key, uuid4())

    def set_current_software(self, asset_id: UUID, components: Sequence[SoftwareComponent]) -> None:
        self.projected[asset_id] = list(components)

    def resolve(self, tenant_id: UUID, anchors: Sequence[AnchorObservation]) -> AssetResolution:
        raise AssertionError("the credentialed engine resolves through upsert_from_anchors")

    def get(self, tenant_id: UUID, asset_id: UUID) -> AssetView | None:
        raise AssertionError("the credentialed engine does not read assets back")

    def record_merge(self, req: MergeRequest) -> UUID:
        raise AssertionError("the credentialed engine never merges assets")

    def reverse_merge(self, merge_id: UUID, *, rationale: str | None = None) -> UUID:
        raise AssertionError("the credentialed engine never reverses merges")


def inspection_result(address: str) -> InspectionResult:
    components = [
        SoftwareComponent(
            cpe=None,
            name=name,
            version=version,
            version_source=VersionSource.PACKAGE_MANAGER,
            confidence=0.95,
        )
        for name, version in (("ubuntu", "22.04"), ("openssl", "3.0.2-0ubuntu1.18"))
    ]
    observation = ObservationInput(
        tenant_id=TENANT,
        run_id=RUN_ID,
        asset_id=None,
        observation_type="software",
        payload={"ip": address, "components": [c.name for c in components]},
        source="ssh",
        source_type="credentialed",
        source_identifier=address,
        collector="ssh-inspector",
        collector_version="0.1.0",
        collection_method="ssh_read_only",
        version_source=VersionSource.PACKAGE_MANAGER,
        confidence=0.95,
        observed_at=NOW,
        collected_at=NOW,
        raw_record_ref=None,
    )
    return InspectionResult(
        target=address,
        inspector="ssh-inspector",
        observations=[observation],
        components=components,
        anchors=[AnchorObservation(kind="hostname", value="app-01", confidence=0.7)],
        started_at=NOW,
        finished_at=NOW,
    )


def fingerprint(
    address: str, *, credential_ref: str | None = "vault://ssh/app-01"
) -> DeviceFingerprint:
    return DeviceFingerprint(target=address, open_ports=(22,), credential_ref=credential_ref)


def build_engine(
    *,
    scope: FakeScope | None = None,
    inspector: FakeInspector | None = None,
    registry: FakeRegistry | None = None,
) -> tuple[CredentialedInspectionEngine, FakeScope, FakeInspector, FakeSink, FakeAssets]:
    scope = scope or FakeScope({SERVER, PRINTER})
    inspector = inspector or FakeInspector()
    registry = registry or FakeRegistry(inspector)
    sink = FakeSink()
    assets = FakeAssets()
    engine = CredentialedInspectionEngine(scope, registry, sink, assets)
    return engine, scope, inspector, sink, assets


# ------------------------------------------------------------- scope comes first


def test_an_out_of_scope_device_is_never_connected_to() -> None:
    """Safety-critical: authenticating to a device is emission, and emission goes through
    the gate (AGENTS.md §2.5). A denied device gets no connection and no credential use."""
    engine, _, inspector, sink, assets = build_engine(scope=FakeScope({SERVER}))

    outcome = engine.run(TENANT, [fingerprint(OUTSIDE), fingerprint(SERVER)])

    assert outcome.denied == 1
    assert outcome.denied_targets == (OUTSIDE,)
    assert inspector.inspected == [SERVER]  # the denied device was never touched
    assert not [obs for obs in sink.recorded if obs.source_identifier == OUTSIDE]
    assert assets.projected  # the authorised one still went through
    assert outcome.inspected == 1


def test_the_registry_is_not_even_consulted_for_a_denied_device() -> None:
    """Nothing about a device we may not touch is acted on — not the inspection, and not
    the selection that would precede it."""
    inspector = FakeInspector()
    registry = FakeRegistry(inspector)
    engine, *_ = build_engine(scope=FakeScope(set()), inspector=inspector, registry=registry)

    engine.run(TENANT, [fingerprint(SERVER)])

    assert registry.asked == []


def test_a_denial_does_not_stop_the_run() -> None:
    engine, _, inspector, _, _ = build_engine(scope=FakeScope({PRINTER}))

    outcome = engine.run(TENANT, [fingerprint(OUTSIDE), fingerprint(PRINTER)])

    assert outcome.denied == 1
    assert outcome.inspected == 1
    assert inspector.inspected == [PRINTER]


# ------------------------------------------------------------ no credentialed path


def test_a_device_with_no_registry_match_is_skipped_without_error() -> None:
    """A legitimate answer, not a failure: the device stays uncredentialed and keeps its
    banner-inferred versions (m1-design §1)."""
    inspector = FakeInspector()
    engine, *_ = build_engine(
        inspector=inspector, registry=FakeRegistry(inspector, matches={SERVER})
    )

    outcome = engine.run(TENANT, [fingerprint(PRINTER), fingerprint(SERVER)])

    assert outcome.skipped_no_path == 1
    assert outcome.skipped_targets == (PRINTER,)
    assert outcome.failed == 0  # emphatically not an error
    assert inspector.inspected == [SERVER]


def test_a_device_with_no_credential_reference_is_skipped() -> None:
    engine, _, inspector, _, _ = build_engine()

    outcome = engine.run(TENANT, [fingerprint(SERVER, credential_ref=None)])

    assert outcome.skipped_no_path == 1
    assert inspector.inspected == []


# --------------------------------------------------------------------- failures


@pytest.mark.parametrize(
    "failure",
    [
        DependencyError("ssh connection refused", retryable=True),
        DependencyError("ssh authentication rejected", retryable=False),
        ValidationError("no usable output from any read command"),
    ],
    ids=["refused", "auth-rejected", "unreadable"],
)
def test_a_failed_inspection_is_counted_and_does_not_block_the_run(
    failure: Exception,
) -> None:
    """One device we cannot read must not cost us the rest of the estate — the same
    per-target shape as the sweep's denial and the scanner's breaker trip."""
    failing = FakeInspector(failure=failure)
    healthy = FakeInspector()

    class SplitRegistry:
        def for_device(self, fp: DeviceFingerprint) -> CredentialedInspector | None:
            return failing if fp.target == SERVER else healthy

    engine = CredentialedInspectionEngine(
        FakeScope({SERVER, PRINTER}), SplitRegistry(), FakeSink(), FakeAssets()
    )

    outcome = engine.run(TENANT, [fingerprint(SERVER), fingerprint(PRINTER)])

    assert outcome.failed == 1
    assert outcome.failed_targets == (SERVER,)
    assert outcome.inspected == 1  # the printer was still read
    assert healthy.inspected == [PRINTER]


def test_a_failed_inspection_leaves_no_partial_state() -> None:
    """Nothing half-written: a device we could not read has no observation, no asset, and
    no projected software."""
    engine, _, _, sink, assets = build_engine(
        inspector=FakeInspector(failure=DependencyError("refused", retryable=True))
    )

    outcome = engine.run(TENANT, [fingerprint(SERVER)])

    assert outcome.failed == 1
    assert sink.recorded == []
    assert assets.by_anchor == {}
    assert assets.projected == {}


def test_a_fingerprint_with_an_unparseable_address_is_counted_not_fatal() -> None:
    engine, _, inspector, _, _ = build_engine(scope=FakeScope({SERVER}))

    outcome = engine.run(TENANT, [fingerprint("not-an-address"), fingerprint(SERVER)])

    assert outcome.failed == 1
    assert outcome.inspected == 1
    assert inspector.inspected == [SERVER]


def test_an_observation_for_another_tenant_is_refused() -> None:
    """A cross-tenant write is worse than a refused run (AGENTS.md §5)."""

    class ForeignInspector:
        def inspect(
            self, tenant_id: UUID, target: IPAddress, credential_ref: str
        ) -> InspectionResult:
            result = inspection_result(str(target))
            result.observations[0] = result.observations[0].model_copy(
                update={"tenant_id": uuid4()}
            )
            return result

    engine = CredentialedInspectionEngine(
        FakeScope({SERVER}), FakeRegistry(ForeignInspector()), FakeSink(), FakeAssets()
    )

    with pytest.raises(ValidationError, match="does not match the run tenant"):
        engine.run(TENANT, [fingerprint(SERVER)])


# ------------------------------------------------------------------- the payoff


def test_credentialed_components_are_projected_as_current_state() -> None:
    engine, _, _, _, assets = build_engine()

    outcome = engine.run(TENANT, [fingerprint(SERVER)])

    assert outcome.inspected == 1
    assert outcome.components == 2
    projected = next(iter(assets.projected.values()))
    assert [component.name for component in projected] == ["ubuntu", "openssl"]
    for component in projected:
        assert component.version_source is VersionSource.PACKAGE_MANAGER


def test_the_engine_reuses_the_existing_sink_and_resolution() -> None:
    """M1 adds a source of observations; it does not add a write path (m1-design §6)."""
    engine, _, _, sink, assets = build_engine()

    outcome = engine.run(TENANT, [fingerprint(SERVER)])

    assert outcome.recorded == 1
    assert sink.recorded[0].source_type == "credentialed"
    assert sink.recorded[0].version_source is VersionSource.PACKAGE_MANAGER
    assert outcome.assets == 1
    assert len(assets.by_anchor) == 1


def test_a_repeat_inspection_is_idempotent_at_the_sink() -> None:
    engine, _, _, _, _ = build_engine()

    first = engine.run(TENANT, [fingerprint(SERVER)])
    second = engine.run(TENANT, [fingerprint(SERVER)])

    assert first.recorded == 1
    assert second.recorded == 0
    assert second.duplicates == 1
    assert second.asset_ids == first.asset_ids


def test_the_address_travels_as_an_anchor_even_without_a_hostname() -> None:
    """Otherwise a device whose name we could not read would have nothing for entity
    resolution to key on, and every run would mint a fresh candidate asset."""

    class NamelessInspector:
        def inspect(
            self, tenant_id: UUID, target: IPAddress, credential_ref: str
        ) -> InspectionResult:
            result = inspection_result(str(target))
            return result.model_copy(update={"anchors": []})

    assets = FakeAssets()
    engine = CredentialedInspectionEngine(
        FakeScope({SERVER}), FakeRegistry(NamelessInspector()), FakeSink(), assets
    )

    engine.run(TENANT, [fingerprint(SERVER)])

    assert list(assets.by_anchor) == [f"ip:{SERVER}"]


def test_every_candidate_is_accounted_for_in_the_outcome() -> None:
    """A run that inspected nothing must be distinguishable from an estate with nothing to
    inspect: denied, skipped, and failed are all reported."""
    inspector = FakeInspector()
    engine = CredentialedInspectionEngine(
        FakeScope({SERVER, PRINTER}),
        FakeRegistry(inspector, matches={SERVER}),
        FakeSink(),
        FakeAssets(),
    )

    outcome = engine.run(
        TENANT,
        [
            fingerprint(SERVER),  # inspected
            fingerprint(PRINTER),  # no registry match
            fingerprint(OUTSIDE),  # denied
            fingerprint("nonsense"),  # unusable address
        ],
    )

    assert (outcome.inspected, outcome.skipped_no_path, outcome.denied, outcome.failed) == (
        1,
        1,
        1,
        1,
    )


def test_scope_is_asked_about_every_device_it_considers() -> None:
    engine, scope, _, _, _ = build_engine()

    engine.run(TENANT, [fingerprint(SERVER), fingerprint(PRINTER)])

    assert scope.asked == [SERVER, PRINTER]


def test_ip_address_objects_are_what_reach_the_scope_gate() -> None:
    """The gate types its target as an address, and the engine parses before asking — a
    string that is not an address never reaches it."""
    engine, scope, _, _, _ = build_engine()

    engine.run(TENANT, [fingerprint("nonsense"), fingerprint(SERVER)])

    assert scope.asked == [SERVER]
    assert str(ip_address(scope.asked[0])) == SERVER  # it really was an address
