"""Smoke coverage that the dossier contract is actually constructible as written:
the generic `Observed[T]`, the discriminated `AssetContext` union, and dossier
immutability (asset-dossier-contract.md §5–§6)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError as PydanticValidationError

from domain.models import (
    AssetClass,
    AssetDossier,
    Derivation,
    EmbeddedContext,
    ExposureBlock,
    Identifier,
    ManagementBlock,
    ManagementState,
    Observed,
    Provenance,
    Reachability,
    ServerContext,
)

NOW = datetime(2026, 8, 15, 12, 0, tzinfo=UTC)

PROVENANCE = Provenance(
    source="vapix",
    source_type="credentialed",
    collector="scanner-collector",
    collector_version="0.1.0",
    collection_method="vendor_api",
    observed_at=NOW,
    collected_at=NOW,
    confidence=0.95,
)


def _dossier() -> AssetDossier:
    return AssetDossier(
        dossier_id=uuid4(),
        asset_id=uuid4(),
        tenant_id=uuid4(),
        assembled_at=NOW,
        assembler_version="0.1.0",
        asset_class=AssetClass.EMBEDDED,
        identifiers=[Identifier(kind="serial", value="ACCC8E1F2A3B", confidence=1.0)],
        exposure=ExposureBlock(
            reachability=Observed[Reachability](
                value=Reachability.INTERNAL_ONLY, provenance=PROVENANCE
            )
        ),
        management=ManagementBlock(
            state=Observed[ManagementState](value=ManagementState.UNMANAGED, provenance=PROVENANCE)
        ),
        context=EmbeddedContext(
            vendor=Observed[str](value="Axis", provenance=PROVENANCE),
            firmware_version=Observed[str](value="10.12.184", provenance=PROVENANCE),
        ),
        identification_confidence=0.8,
    )


def test_dossier_is_constructible_with_provenance_carrying_values() -> None:
    dossier = _dossier()
    assert dossier.schema_version == 1
    assert dossier.exposure.reachability.provenance.derivation is Derivation.DETERMINISTIC
    assert dossier.management.known_to == []  # empty ⇒ the shadow-IT signal


def test_dossier_is_frozen() -> None:
    """A dossier is a snapshot: the thing the model saw must stay reconstructible."""
    dossier = _dossier()
    with pytest.raises(PydanticValidationError):
        dossier.identification_confidence = 1.0  # type: ignore[misc]


def test_context_union_is_discriminated_by_asset_class() -> None:
    payload = _dossier().model_dump(mode="json")
    payload["context"]["asset_class"] = AssetClass.SERVER.value
    payload["context"] = {"asset_class": "server", "os_name": None}

    rebuilt = AssetDossier.model_validate(payload)
    assert isinstance(rebuilt.context, ServerContext)


def test_confidence_is_bounded() -> None:
    with pytest.raises(PydanticValidationError):
        Identifier(kind="mac", value="00:11:22:33:44:55", confidence=1.4)
