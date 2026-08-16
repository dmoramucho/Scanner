"""Redaction: what the model is allowed to know about a device, and nothing else.

The first of P16's three safety-critical files. The dossier is the *only* thing the LLM sees
about an asset, and the observations it is projected from are the richest, most sensitive
data in the system — a credentialed inspection reads a device's own package database, and a
config-derived observation is one careless collector away from carrying the config itself.

So the property asserted here is not "we remember to strip secrets". It is that the
assembler **cannot emit one**: it copies an allowlist and drops the rest (dossier contract
§4), and then refuses to emit a dossier in which anything secret-shaped survived. A field
that is not on the list does not reach the model, whatever a collector put in a payload.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest

from domain.errors import NotFoundError, ValidationError
from domain.models import (
    AssetClass,
    AssetView,
    Identifier,
    ManagementState,
    ObservationSnapshot,
    Reachability,
    SoftwareComponent,
    VersionSource,
)
from engine.dossier import ASSEMBLER_VERSION, DossierAssembler
from engine.redaction import (
    INCLUDED_PAYLOAD_FIELDS,
    SECURITY_FLAG_KEYS,
    assert_no_secrets,
    looks_secret,
    project,
    security_flags,
)
from engine.segments import SubnetVlanMap
from tests.builders import observation

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
TENANT = UUID("11111111-1111-1111-1111-111111111111")
ASSET = UUID("22222222-2222-2222-2222-222222222222")

PRIVATE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END"


class FakeSource:
    """A `DossierSource` whose observations are as hostile as the test needs."""

    def __init__(
        self,
        *,
        asset: AssetView | None = None,
        observations: list[ObservationSnapshot] | None = None,
        software: list[SoftwareComponent] | None = None,
        known_to: list[str] | None = None,
    ) -> None:
        self._asset = (
            asset
            if asset is not None
            else AssetView(
                id=ASSET,
                tenant_id=TENANT,
                asset_class=AssetClass.SERVER,
                management_state=ManagementState.UNMANAGED,
                identification_confidence=0.9,
                status="active",
            )
        )
        self._observations = observations or []
        self._software = software or []
        self._known_to = known_to or []

    def asset(self, tenant_id: UUID, asset_id: UUID) -> AssetView | None:
        return self._asset if tenant_id == TENANT else None

    def identifiers(self, tenant_id: UUID, asset_id: UUID) -> list[Identifier]:
        return [Identifier(kind="mac", value="00:11:22:33:44:55", confidence=1.0)]

    def software(self, tenant_id: UUID, asset_id: UUID) -> list[SoftwareComponent]:
        return self._software

    def observations(
        self, tenant_id: UUID, asset_id: UUID, *, limit: int = 500
    ) -> list[ObservationSnapshot]:
        return self._observations

    def managed_by(self, tenant_id: UUID, asset_id: UUID) -> list[str]:
        return self._known_to


def assembler(source: FakeSource) -> DossierAssembler:
    return DossierAssembler(source, clock=lambda: NOW, new_id=uuid4)


def dossier_text(dossier: object) -> str:
    """Everything the model would see, as one string. What a test greps."""
    return str(dossier)


# ------------------------------------------------------- the safety-critical assertion


HOSTILE_OBSERVATIONS = [
    # A credentialed inspection that carried more than it should have.
    observation(
        "identity",
        {
            "vendor": "axis",
            "model": "p3245-lve",
            # None of the below are on the allowlist. All of them are realistic.
            "ssh_private_key": PRIVATE_KEY,
            "admin_password": "hunter2",
            "api_token": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "last_login_user": "maria.garcia@corp.example",
            "raw_config": "auth_password=hunter2\nsnmp_community=public",
        },
    ),
    # A config observation. Its allowlist is deliberately empty: the *file* never travels.
    observation(
        "config",
        {
            "telnet_enabled": True,
            "raw": "<config><admin password='hunter2'/></config>",
            "sshd_config": "PermitRootLogin yes\nPasswordAuthentication yes",
        },
    ),
    # An open-ports observation carrying a raw banner, which is not a normalized service.
    observation(
        "open_ports",
        {
            "port": 22,
            "protocol": "tcp",
            "service": "ssh",
            "banner": "SSH-2.0-OpenSSH_8.9p1 key=AAAAB3NzaC1yc2EAAAADAQABAAABgQ",
            "operator_email": "ops@corp.example",
        },
    ),
]


CAMERA = AssetView(
    id=ASSET,
    tenant_id=TENANT,
    asset_class=AssetClass.EMBEDDED,
    management_state=ManagementState.UNMANAGED,
    identification_confidence=0.9,
    status="active",
)


def test_a_dossier_never_carries_a_secret_a_collector_left_in_a_payload() -> None:
    """The assertion that carries this file.

    Every excluded field in the contract is represented above — a private key, a password, an
    API token, a person's email, a raw config, a raw banner — and none of them can appear in
    what the model is handed. Not because they were stripped by name, but because only the
    contracted fields were ever copied (dossier contract §4, AGENTS.md §2.10).
    """
    source = FakeSource(asset=CAMERA, observations=HOSTILE_OBSERVATIONS)

    dossier = assembler(source).assemble(TENANT, ASSET)

    rendered = dossier.model_dump_json()

    for excluded in (
        "PRIVATE KEY",
        "hunter2",
        "ghp_abcdefghijklmnopqrstuvwxyz",
        "maria.garcia@corp.example",
        "ops@corp.example",
        "PermitRootLogin",
        "snmp_community",
        "SSH-2.0-OpenSSH",
        "AAAAB3NzaC1yc2E",
    ):
        assert excluded not in rendered, f"{excluded!r} reached the model input"

    # And the legitimate signals did survive — redaction that empties the dossier would be
    # safe and useless.
    assert "axis" in rendered
    assert "p3245-lve" in rendered
    assert dossier.exposure.open_ports[0].port == 22
    assert dossier.exposure.open_ports[0].service == "ssh"


@pytest.mark.parametrize(
    ("observation_type", "key"),
    [
        ("identity", "ssh_private_key"),
        ("identity", "raw_config"),
        ("identity", "last_login_user"),
        ("open_ports", "banner"),
        ("config", "raw"),
        ("config", "sshd_config"),
        ("service", "command_line"),
        ("service", "environment"),
    ],
)
def test_a_field_not_on_the_allowlist_never_reaches_the_dossier(
    observation_type: str, key: str
) -> None:
    """The default-exclude rule, one field at a time. A collector adding a new payload key
    does not silently widen what the model sees — it has to be added to the allowlist, in
    the open, in one file."""
    fields = project(observation_type, {key: "any-value-at-all"})

    assert key not in fields.fields
    assert fields.dropped == 1


def test_an_unknown_observation_type_contributes_nothing() -> None:
    """Fail-closed at the type level too: a collector inventing `credential_dump` does not
    get an implicit pass because nobody wrote a rule for it."""
    fields = project("credential_dump", {"username": "root", "password": "hunter2"})

    assert fields.fields == {}
    assert fields.dropped == 2


def test_configuration_contributes_only_derived_flags_and_never_the_config() -> None:
    """The contract's "masked / summarised" bucket. `telnet_enabled: true` is a security
    signal the model genuinely needs; the file it was derived from is not."""
    payload = {
        "telnet_enabled": True,
        "tls_min_version": "1.0",
        "sshd_config": "PermitRootLogin yes",
        "admin_password": "hunter2",
    }

    assert project("config", payload).fields == {}  # the config path copies nothing at all
    flags = security_flags("config", payload)

    assert flags.fields == {"telnet_enabled": "true", "tls_min_version": "1.0"}
    assert flags.dropped == 2


def test_a_nested_payload_value_is_dropped_rather_than_flattened() -> None:
    """A nested structure is how a raw config or a log excerpt arrives. Flattening it would
    carry exactly what the contract excludes."""
    fields = project("identity", {"model": {"name": "p3245", "config": {"password": "hunter2"}}})

    assert fields.fields == {}


def test_an_allowlisted_key_holding_a_secret_shaped_value_is_still_dropped() -> None:
    """The key was vetted; the value was not. A collector that writes a private key into a
    field called `model` has still written a private key."""
    fields = project("identity", {"model": PRIVATE_KEY, "vendor": "axis"})

    assert fields.fields == {"vendor": "axis"}
    assert fields.dropped == 1


def test_an_oversized_value_is_dropped() -> None:
    """A dossier value is a short fact. Anything document-sized is the wrong field, or an
    attempt to smuggle a payload through a permitted one."""
    assert project("identity", {"model": "x" * 5000}).fields == {}


@pytest.mark.parametrize(
    "value",
    [
        PRIVATE_KEY,
        "-----BEGIN CERTIFICATE-----MIIC",
        "password=hunter2",
        "api_key: sk-abcdef",
        "Authorization: Bearer abc.def",
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_abcdefghijklmnopqrstuvwxyz0123",
        "xoxb-1234567890-abcdefghij",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcd",
        "https://admin:hunter2@camera.corp.example/",
        "maria.garcia@corp.example",
    ],
)
def test_the_secret_shapes_are_recognised(value: str) -> None:
    assert looks_secret(value)


@pytest.mark.parametrize(
    "value",
    ["axis", "p3245-lve", "ubuntu 22.04", "https://camera.corp.example/", "2.4.53", "dmz"],
)
def test_ordinary_dossier_values_are_not_mistaken_for_secrets(value: str) -> None:
    """The cost side. A sweep that fired on hostnames and versions would refuse to assemble
    any dossier at all, which is a different way of breaking the product."""
    assert not looks_secret(value)


def test_the_assembler_refuses_to_emit_a_dossier_that_still_holds_a_secret() -> None:
    """The second layer, tested directly.

    Reaching this check means the projection has a hole. The response is to refuse the whole
    dossier rather than strip the one value that happened to be spotted: if we do not know
    how it got through, we do not know what else did (contract §4 — a P0 defect).
    """
    with pytest.raises(ValidationError) as raised:
        assert_no_secrets(
            {"context": {"security_flags": [{"key": "note", "value": PRIVATE_KEY}]}},
            where="dossier for asset X",
        )

    message = str(raised.value)
    assert "private-key" in message
    assert "context.security_flags[0].value" in message
    # The offending value is *not* in the message: it is the secret.
    assert "b3BlbnNzaC1rZXktdjEA" not in message


def test_the_assembler_refuses_a_dossier_whose_unprojected_fields_carry_a_secret() -> None:
    """The second layer, exercised through the assembler — and the case that justifies it.

    Identifiers and software components are read from the store as typed models, so they do
    *not* pass through the payload projection. That is correct (they are contracted fields),
    and it is exactly why the sweep exists: the projection is not the only way into a
    dossier, so the refusal has to sit at the boundary rather than inside one path
    (contract §4).
    """

    class LeakySource(FakeSource):
        def identifiers(self, tenant_id: UUID, asset_id: UUID) -> list[Identifier]:
            return [Identifier(kind="cert_fingerprint", value=PRIVATE_KEY, confidence=1.0)]

    with pytest.raises(ValidationError) as raised:
        assembler(LeakySource()).assemble(TENANT, ASSET)

    assert "private-key" in str(raised.value)
    assert "P0" in str(raised.value)


def test_the_allowlist_and_the_flag_list_do_not_overlap_by_accident() -> None:
    """A key that is both a projected field and a derived flag would be copied twice under
    two different rules — and the second rule is the one with looser typing."""
    projected = {key for keys in INCLUDED_PAYLOAD_FIELDS.values() for key in keys}

    assert projected & SECURITY_FLAG_KEYS == set()


# --------------------------------------------------------------------- assembly


def test_the_dossier_carries_management_state_as_context() -> None:
    """M2's answer, handed to the model as a signal: a vulnerability on a device nobody
    manages is a different problem from the same one on a managed server (m3-design §3)."""
    dossier = assembler(FakeSource(known_to=[])).assemble(TENANT, ASSET)

    assert dossier.management.state.value is ManagementState.UNMANAGED
    assert dossier.management.known_to == []
    assert dossier.management.state.provenance.source == "reconciliation"


def test_every_observed_value_carries_provenance() -> None:
    """Contract §8.2: an `Observed[…]` without provenance is an assembly bug, because the
    model may only cite what can be traced back to an observation."""
    dossier = assembler(
        FakeSource(
            observations=[
                observation("network", {"reachability": "internet_facing"}),
                observation("open_ports", {"port": 443, "protocol": "tcp", "service": "https"}),
                observation("config", {"telnet_enabled": True}),
            ]
        )
    ).assemble(TENANT, ASSET)

    assert dossier.exposure.reachability.provenance.collector
    assert dossier.exposure.open_ports[0].provenance.collector
    assert isinstance(dossier.context.security_flags[0].provenance.confidence, float)  # type: ignore[union-attr]


def test_an_unknown_reachability_is_stated_rather_than_omitted() -> None:
    """A dossier missing reachability invites the model to assume the comfortable answer."""
    dossier = assembler(FakeSource()).assemble(TENANT, ASSET)

    assert dossier.exposure.reachability.value is Reachability.UNKNOWN


def test_the_newest_observation_of_a_fact_wins() -> None:
    dossier = assembler(
        FakeSource(
            observations=[
                observation("identity", {"os_name": "ubuntu", "os_version": "22.04"}),
                observation("identity", {"os_name": "ubuntu", "os_version": "20.04"}),
            ]
        )
    ).assemble(TENANT, ASSET)

    assert dossier.context.os_version is not None  # type: ignore[union-attr]
    assert dossier.context.os_version.value == "22.04"  # type: ignore[union-attr]


def test_software_components_reach_the_dossier_with_their_version_source() -> None:
    """The crux of vulnerability reasoning: whether a version is ground truth or a banner
    is what stops a backport from becoming a false positive (AGENTS.md §3)."""
    component = SoftwareComponent(
        cpe="cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*",
        name="apache http_server",
        version="2.4.53",
        version_source=VersionSource.BANNER,
        confidence=0.6,
    )

    dossier = assembler(FakeSource(software=[component])).assemble(TENANT, ASSET)

    assert dossier.software[0].version_source is VersionSource.BANNER


def test_an_unknown_asset_raises_rather_than_producing_an_empty_dossier() -> None:
    """An empty dossier reads as "a device we know nothing about", and the model would
    reason about it anyway (AGENTS.md §67)."""
    with pytest.raises(NotFoundError):
        assembler(FakeSource()).assemble(uuid4(), ASSET)


def test_the_dossier_records_the_assembler_that_produced_it() -> None:
    """So an insight from six months ago can be read against the rules that produced it."""
    dossier = assembler(FakeSource()).assemble(TENANT, ASSET)

    assert dossier.assembler_version == ASSEMBLER_VERSION
    assert dossier.assembled_at == NOW


def test_the_assembler_reports_what_it_dropped() -> None:
    """An allowlist doing its job looks like data loss, and an operator should be able to
    see it working rather than infer it."""
    engine = assembler(FakeSource(asset=CAMERA, observations=HOSTILE_OBSERVATIONS))

    engine.assemble(TENANT, ASSET)

    report = engine.report()
    assert report.observations_read == 3
    assert report.fields_dropped > 0


def test_the_dossier_is_immutable_once_assembled() -> None:
    """Contract §5: a dossier is a snapshot. What the model saw cannot be edited afterwards."""
    dossier = assembler(FakeSource()).assemble(TENANT, ASSET)

    with pytest.raises(ValueError, match="frozen"):
        dossier.asset_class = AssetClass.EMBEDDED  # type: ignore[misc]


def test_the_source_is_only_asked_about_the_tenant_it_was_given() -> None:
    """Redaction is not the only boundary in the dossier: an asset is never read across
    tenants (AGENTS.md §2.3)."""
    calls: list[tuple[UUID, UUID]] = []

    class RecordingSource(FakeSource):
        def asset(self, tenant_id: UUID, asset_id: UUID) -> AssetView | None:
            calls.append((tenant_id, asset_id))
            return super().asset(tenant_id, asset_id)

    assembler(RecordingSource()).assemble(TENANT, ASSET)

    assert calls == [(TENANT, ASSET)]


def test_the_dossier_source_protocol_is_satisfied_by_the_fake() -> None:
    """Keeps the fake honest: it stands in for the Postgres adapter in every test here."""
    from domain.ports import DossierSource

    source: DossierSource = FakeSource()

    assert source.asset(TENANT, ASSET) is not None


def test_payload_values_are_stringified_predictably() -> None:
    """Booleans and numbers arrive from JSON payloads; the dossier's fields are text."""
    fields = project("application", {"behind_waf": True, "app_name": "billing"})

    assert fields.fields == {"behind_waf": "true", "app_name": "billing"}


def test_assert_no_secrets_accepts_a_clean_dossier() -> None:
    payload: dict[str, Any] = {
        "asset_class": "server",
        "software": [{"cpe": "cpe:2.3:a:apache:http_server:2.4.53:*", "version": "2.4.53"}],
    }

    assert_no_secrets(payload, where="test")


# --------------------------------------------------------------- the inferred segment


VLAN_MAP = SubnetVlanMap.from_mapping({"10.0.60.0/24": "VLAN 60 (IoT)"})


class AddressedSource(FakeSource):
    """A source whose asset has an IP identifier, which is what the VLAN map reads."""

    def __init__(self, address: str = "10.0.60.14", **kwargs: object) -> None:
        super().__init__(**kwargs)  # type: ignore[arg-type]
        self._address = address

    def identifiers(self, tenant_id: UUID, asset_id: UUID) -> list[Identifier]:
        return [
            Identifier(kind="mac", value="00:11:22:33:44:55", confidence=1.0),
            Identifier(kind="ip", value=self._address, confidence=0.8),
        ]


def test_an_asset_in_a_mapped_range_gets_an_inferred_segment_label() -> None:
    """The UX shows a device's segment, and there is no switch to ask — so the label comes
    from the operator's subnet map and says, in its provenance, that it was inferred
    (ADR-0015)."""
    engine = DossierAssembler(AddressedSource(), segments=VLAN_MAP, clock=lambda: NOW, new_id=uuid4)

    dossier = engine.assemble(TENANT, ASSET)

    label = dossier.exposure.network_segment_label
    assert label is not None
    assert label.value == "VLAN 60 (IoT)"
    assert label.provenance.source_type == "inferred"
    assert label.provenance.confidence < 1.0


def test_an_asset_outside_every_mapped_range_has_no_segment_label() -> None:
    """Unknown, not guessed — the same honesty as the ambiguous category in shadow-IT
    reconciliation. Saying "isolated segment" about a device nobody mapped would be a
    fabrication an analyst would act on."""
    engine = DossierAssembler(
        AddressedSource(address="172.16.9.9"), segments=VLAN_MAP, clock=lambda: NOW, new_id=uuid4
    )

    dossier = engine.assemble(TENANT, ASSET)

    assert dossier.exposure.network_segment_label is None


def test_an_observed_segment_label_outranks_the_inferred_one() -> None:
    """If anything ever *measures* the segment, the measurement wins. The inference is the
    fallback, not the answer."""
    engine = DossierAssembler(
        AddressedSource(
            observations=[observation("network", {"network_segment_label": "VLAN 10 (Servers)"})]
        ),
        segments=VLAN_MAP,
        clock=lambda: NOW,
        new_id=uuid4,
    )

    dossier = engine.assemble(TENANT, ASSET)

    label = dossier.exposure.network_segment_label
    assert label is not None
    assert label.value == "VLAN 10 (Servers)"
    assert label.provenance.source_type != "inferred"


def test_an_assembler_with_no_map_labels_nothing() -> None:
    """The default deployment. No mapping configured means every segment is unknown, which
    is honest rather than broken."""
    engine = DossierAssembler(AddressedSource(), clock=lambda: NOW, new_id=uuid4)

    assert engine.assemble(TENANT, ASSET).exposure.network_segment_label is None
