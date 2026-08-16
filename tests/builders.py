"""Builders for the insight path's inputs, shared by the P16 test files.

Three files need a `TriageDossier`, and a forty-line literal repeated three times is a
forty-line literal that drifts. Kept minimal and explicit: every builder returns something
valid, and each test overrides only the field it is about.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from domain.models import (
    AdvisoryEvidence,
    AssetClass,
    AssetDossier,
    Derivation,
    EmbeddedContext,
    ExposureBlock,
    Identifier,
    ManagementBlock,
    ManagementState,
    ObservationSnapshot,
    Observed,
    OpenPort,
    Provenance,
    Reachability,
    SecurityFlag,
    ServerContext,
    SoftwareComponent,
    TriageDossier,
    VersionSource,
    VulnerabilityMatch,
)

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)

CVE = "CVE-2023-25690"
CPE = "cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*"

ADVISORY_TEXT = (
    "[[source: nvd:CVE-2023-25690]]\n"
    "Some mod_proxy configurations on Apache HTTP Server versions 2.4.0 through 2.4.55 "
    "allow a HTTP Request Smuggling attack. Configurations are affected when mod_proxy is "
    "enabled along with some form of RewriteRule or ProxyPassMatch."
)


def provenance(**overrides: object) -> Provenance:
    fields: dict[str, Any] = {
        "source": "nmap",
        "source_type": "active_scan",
        "collector": "nmap-scanner",
        "collector_version": "1.0.0",
        "collection_method": "gentle_scan",
        "observed_at": NOW,
        "collected_at": NOW,
        "confidence": 0.9,
        "derivation": Derivation.DETERMINISTIC,
    }
    fields.update(overrides)
    return Provenance(**fields)


def observation(
    observation_type: str, payload: dict[str, Any], **overrides: object
) -> ObservationSnapshot:
    return ObservationSnapshot(
        observation_id=uuid4(),
        observation_type=observation_type,
        payload=payload,
        provenance=provenance(**overrides),
        observed_at=NOW,
    )


def asset_dossier(
    *,
    tenant_id: UUID | None = None,
    asset_id: UUID | None = None,
    asset_class: AssetClass = AssetClass.SERVER,
    management_state: ManagementState = ManagementState.UNMANAGED,
    software: Sequence[SoftwareComponent] | None = None,
    open_ports: Sequence[OpenPort] | None = None,
    security_flags: Sequence[SecurityFlag] | None = None,
    known_to: Sequence[str] = (),
) -> AssetDossier:
    context = (
        ServerContext(
            os_name=Observed(value="ubuntu", provenance=provenance()),
            os_version=Observed(value="22.04", provenance=provenance()),
            security_flags=list(security_flags or []),
        )
        if asset_class is AssetClass.SERVER
        else EmbeddedContext(
            vendor=Observed(value="axis", provenance=provenance()),
            model=Observed(value="p3245", provenance=provenance()),
            security_flags=list(security_flags or []),
        )
    )
    return AssetDossier(
        dossier_id=uuid4(),
        asset_id=asset_id or uuid4(),
        tenant_id=tenant_id or uuid4(),
        assembled_at=NOW,
        assembler_version="1.0.0",
        asset_class=asset_class,
        identifiers=[Identifier(kind="mac", value="00:11:22:33:44:55", confidence=1.0)],
        software=list(
            software
            or [
                SoftwareComponent(
                    cpe=CPE,
                    name="apache http_server",
                    version="2.4.53",
                    version_source=VersionSource.PACKAGE_MANAGER,
                    confidence=0.95,
                )
            ]
        ),
        exposure=ExposureBlock(
            reachability=Observed(value=Reachability.INTERNET_FACING, provenance=provenance()),
            network_segment_label=Observed(value="dmz", provenance=provenance()),
            open_ports=list(
                open_ports
                or [OpenPort(port=443, protocol="tcp", service="https", provenance=provenance())]
            ),
        ),
        management=ManagementBlock(
            state=Observed(value=management_state, provenance=provenance()),
            known_to=list(known_to),
        ),
        context=context,
        identification_confidence=0.9,
    )


def advisory(**overrides: object) -> AdvisoryEvidence:
    fields: dict[str, Any] = {
        "advisory_id": CVE,
        "advisory_source": "nvd:CVE-2023-25690; 2 cited reference(s)",
        "advisory_text": ADVISORY_TEXT,
        "fix_diff_ref": "https://github.com/apache/httpd/commit/4f0e51c0b9e5",
        "fix_touched_summary": 'commit subject: "Fix request smuggling"; touched 2 file(s)',
    }
    fields.update(overrides)
    return AdvisoryEvidence(**fields)


def match(**overrides: object) -> VulnerabilityMatch:
    fields: dict[str, Any] = {
        "cve_id": CVE,
        "matched_cpe": CPE,
        "version_source": VersionSource.PACKAGE_MANAGER,
        "confidence_state": "confirmed",
        "kev": False,
        "epss": 0.42,
        "provenance": provenance(source="correlation", source_type="derived"),
    }
    fields.update(overrides)
    return VulnerabilityMatch(**fields)


def triage_dossier(
    *,
    kev: bool = False,
    asset: AssetDossier | None = None,
    evidence: AdvisoryEvidence | None = None,
    triage_id: UUID | None = None,
) -> TriageDossier:
    return TriageDossier(
        triage_id=triage_id or uuid4(),
        match=match(kev=kev),
        advisory=evidence or advisory(),
        asset=asset or asset_dossier(),
    )
