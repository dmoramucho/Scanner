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

**One route writes.** The analyst's review decision is the only mutation this API offers, it
takes a write-capable connection no other route has, and it re-enforces every rule the UI
will merely *reflect*. A disabled button is a convenience; the refusal below is the control
(m4-design §1).
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
    ReviewOut,
    ReviewRequest,
    SummaryOut,
    WorklistOut,
    WorklistQuery,
    asset_detail_out,
)
from api.security import Dossiers, Reads, Reviewer, ReviewStore, TenantId
from domain.errors import NotFoundError
from domain.models import AssetFilters, InsightReview

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


@router.post(
    "/insights/{insight_id}/review",
    response_model=ReviewOut,
    summary="Record the analyst's decision on an insight",
)
def review_insight(
    tenant: TenantId,
    reviewer: Reviewer,
    store: ReviewStore,
    insight_id: UUID,
    decision: ReviewRequest,
) -> ReviewOut:
    """Accept, reject or adjust one insight — the only write in the API.

    **The KEV floor is enforced here, not in the UI.** A decision that would bury a finding
    CISA lists as actively exploited is refused with a 422, and the refusal does not depend
    on any frontend state: a request crafted by hand, by a script, or by a UI with the button
    re-enabled in a debugger meets exactly the same check (AGENTS.md §2.8, m4-design §1).
    Two more layers sit behind it — the store repeats the check, and the DB CHECK
    `insight_analyst_kev_not_hidden` refuses the row — so the guarantee survives a refactor
    of any single one of them.

    The state change and its immutable `insight_review_event` are written in one transaction
    (P17): there is no path that records a decision without recording who made it, and none
    that records who without the decision.

    Retrying an identical decision is a no-op that returns the current state — a
    double-clicked button must not become a second entry in an append-only history. A
    *different* decision that would move the lifecycle backwards is a 409, because it
    conflicts with a decision a human already made (ADR-0017).
    """
    insight = store.review_insight(
        tenant,
        InsightReview(
            insight_id=insight_id,
            outcome=decision.outcome,
            # Never from the request: with no authentication, a caller-supplied name would
            # let anyone sign a colleague to a decision (ADR-0017).
            reviewer=reviewer,
            recommendation=decision.recommendation,
            rationale=decision.rationale,
        ),
    )
    return ReviewOut.of(insight, store.review_history(tenant, insight_id))


def routers() -> Sequence[APIRouter]:
    return (router,)


__all__: Sequence[str] = ["router", "routers"]
