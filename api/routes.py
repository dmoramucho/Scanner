"""The read endpoints: three surfaces, no logic.

Each handler does the same four things and nothing else — take a validated query, get the
tenant from the server-side context, call a port, map the result to an explicit response
model. Every decision they appear to make was already made in the engine: the priority band
and its reason in P17, the confidence state in P14, the redaction in the dossier assembler.
An endpoint that sorted, scored or filtered on its own would be business logic in an adapter
(AGENTS.md §2.1, m4-design §1).

`tenant` is a dependency, never a parameter. There is no route below that accepts a tenant
identifier from the caller, which is what makes "no endpoint can read across the tenant
boundary" a property of the routing table rather than a habit.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from api.schemas import (
    AssetDetailOut,
    AssetListOut,
    AssetQuery,
    FindingOut,
    InsightQueueItemOut,
    SummaryOut,
    WorklistOut,
    WorklistQuery,
    asset_detail_out,
)
from api.security import Dossiers, Reads, TenantId
from domain.errors import NotFoundError
from domain.models import AssetFilters

router = APIRouter(prefix="/api")


@router.get("/worklist", response_model=WorklistOut, summary="The prioritised worklist")
def worklist(
    tenant: TenantId,
    reads: Reads,
    query: Annotated[WorklistQuery, Query()],
) -> WorklistOut:
    """Triage Home in one request (ux-design §3.1).

    The order is the store's — KEV first, then band, then exploitation probability — because
    that ordering is the product's opinion and it lives in `engine/priority.py`. This
    endpoint does not re-rank; if it did, the reason shown beside a finding could disagree
    with the position it was shown in.
    """
    return WorklistOut(
        summary=SummaryOut.of(reads.worklist_summary(tenant)),
        findings=[FindingOut.of(finding) for finding in reads.worklist(tenant, limit=query.limit)],
        needs_verification=[
            FindingOut.of(finding)
            for finding in reads.needs_verification(tenant, limit=query.limit)
        ],
        review_queue=[
            InsightQueueItemOut.of(item) for item in reads.review_queue(tenant, limit=query.limit)
        ],
    )


@router.get("/assets", response_model=AssetListOut, summary="The inventory")
def assets(
    tenant: TenantId,
    reads: Reads,
    query: Annotated[AssetQuery, Query()],
) -> AssetListOut:
    """Asset Explorer (ux-design §3.2), filtered by a closed set and paginated.

    `AssetQuery` forbids unknown parameters, so a filter the API does not implement is a
    422 rather than a silently unfiltered list — a caller who believes they narrowed a
    result set and did not is the worse outcome.
    """
    return AssetListOut.of(
        reads.assets(
            tenant,
            filters=AssetFilters(
                asset_class=query.asset_class,
                management_state=query.management_state,
                has_kev=query.has_kev,
                query=query.q,
            ),
            limit=query.limit,
            offset=query.offset,
        )
    )


@router.get("/assets/{asset_id}", response_model=AssetDetailOut, summary="One asset, in full")
def asset_detail(
    tenant: TenantId,
    reads: Reads,
    dossiers: Dossiers,
    asset_id: UUID,
) -> AssetDetailOut:
    """Asset Analysis (ux-design §3.3), served from the **redacted dossier**.

    This is the endpoint where the redaction contract meets HTTP. The asset's own facts come
    from `DossierAssembler`, which projects the contract's allowlist and then refuses to emit
    anything secret-shaped (contract §4, ADR-0014) — so there is no path here that reads an
    observation payload and shapes it into a response.

    `NotFoundError` propagates: the assembler raises it for an asset that is not in this
    tenant, which is the same answer as one that does not exist. A caller cannot use a 404
    against a 403 to learn that an asset exists somewhere else.
    """
    dossier = dossiers.assemble(tenant, asset_id)
    findings = reads.asset_findings(tenant, asset_id)
    timeline = reads.asset_timeline(tenant, asset_id)
    label = next((finding.asset_label for finding in findings if finding.asset_label), None)
    if label is None:
        label = next(
            (item.value for item in dossier.identifiers if item.kind == "hostname"),
            next((item.value for item in dossier.identifiers), None),
        )
    return asset_detail_out(dossier, label=label, findings=findings, timeline=timeline)


@router.get("/assets/{asset_id}/findings", summary="One asset's findings")
def asset_findings(tenant: TenantId, reads: Reads, asset_id: UUID) -> list[FindingOut]:
    """The findings alone, for a panel that refreshes without the whole dossier."""
    findings = reads.asset_findings(tenant, asset_id)
    if not findings and not reads.asset_timeline(tenant, asset_id, limit=1):
        # An asset with neither findings nor observations in this tenant is not an asset we
        # know. Answering `[]` would confirm the id exists somewhere.
        raise NotFoundError(f"no asset {asset_id}")
    return [FindingOut.of(finding) for finding in findings]


def routers() -> Sequence[APIRouter]:
    return (router,)


__all__: Sequence[str] = ["router", "routers"]
