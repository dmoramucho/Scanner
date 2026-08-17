"""The read side the interface is served from: joins, counts, and nothing else.

Every query in this module is tenant-scoped in its `where` clause, and there is no method
that can be called without a tenant. That is deliberate belt-and-braces with the API's own
scoping: the inbound adapter cannot construct a query, and this adapter cannot answer an
unscoped one, so a cross-tenant read needs two independent mistakes rather than one
(m4-design §1).

**Values are never interpolated.** The only dynamic SQL here is which of a fixed set of
`and …` fragments is appended, each carrying a bound parameter. A filter value reaches
Postgres as a parameter or not at all (AGENTS.md §2.9, §68).

**Nothing here returns an observation payload.** The timeline is provenance — who saw this
asset, how, and when. The asset's own facts come from the redacted dossier via
`DossierAssembler`, which applies the contract's allowlist. Serving payloads from here would
route around that in the one place it matters most (dossier contract §4).
"""

# ruff: noqa: S608 — the SQL below is composed exclusively of module-level literals
# (`_LABEL_JOIN`, `_FINDING_COLUMNS`, `_FINDING_ORDER`) and `psycopg.sql` fragments written
# in this file. No caller-supplied value is ever interpolated: filter values are bound
# parameters without exception, which `tests/test_api_security.py` asserts directly.
from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Final, Literal
from uuid import UUID

import psycopg
from psycopg import sql

from domain.errors import ValidationError
from domain.models import (
    AssetClass,
    AssetFilters,
    AssetPage,
    AssetSummary,
    ConfidenceState,
    InsightSummary,
    ManagementState,
    Priority,
    Recommendation,
    ReviewOutcome,
    TimelineEntry,
    VersionSource,
    WorklistFinding,
    WorklistSummary,
)

Connection = psycopg.Connection[tuple[Any, ...]]
InsightState = Literal["proposed", "human_reviewed", "accepted"]

#: Hard ceilings the API's own validation sits above. A caller that got past the boundary
#: still cannot ask for a million rows.
MAX_PAGE: Final = 200
MAX_TIMELINE: Final = 500

#: The identifier an asset is named by in a list, most identifying first. `ip` is last on
#: purpose: it rotates, and a UI that labels assets by address relabels them weekly.
_LABEL_PRIORITY: Final = (
    "case kind when 'hostname' then 1 when 'serial' then 2 "
    "when 'cert_fingerprint' then 3 when 'mac' then 4 else 5 end"
)

_LABEL_JOIN: Final = f"""
    left join lateral (
        select value from asset_identifier ai
        where ai.tenant_id = a.tenant_id and ai.asset_id = a.id
        order by {_LABEL_PRIORITY}, ai.confidence desc, ai.value
        limit 1
    ) label on true
"""

#: The worklist order *is* the product's opinion, and it is the same one `engine/priority.py`
#: encodes: exploited first, then band, then exploitation probability (ux-design §3.1).
_FINDING_ORDER: Final = "order by m.kev desc, m.priority, m.epss desc nulls last, m.cve_id"

_FINDING_COLUMNS: Final = """
    m.id, m.asset_id, label.value, a.asset_class, a.management_state, m.cve_id, m.matched_cpe,
    m.priority, m.priority_rule, m.priority_reason, m.confidence_state, m.version_source,
    m.kev, m.epss, m.cvss_score, m.cvss_version, m.matched_at,
    exists (
        select 1 from triage_snapshot t join insight i on i.triage_id = t.id
        where t.tenant_id = m.tenant_id and t.asset_id = m.asset_id and t.cve_id = m.cve_id
    ) as has_insight
"""

_WORKLIST_SQL: Final = f"""
    select {_FINDING_COLUMNS}
    from vulnerability_match m
    join asset a on a.id = m.asset_id and a.tenant_id = m.tenant_id
    {_LABEL_JOIN}
    where m.tenant_id = %(tenant_id)s and m.is_current and a.status = 'active'
    {_FINDING_ORDER}
    limit %(limit)s
"""

_NEEDS_VERIFICATION_SQL: Final = f"""
    select {_FINDING_COLUMNS}
    from vulnerability_match m
    join asset a on a.id = m.asset_id and a.tenant_id = m.tenant_id
    {_LABEL_JOIN}
    where m.tenant_id = %(tenant_id)s and m.is_current and a.status = 'active'
      and m.confidence_state = 'probable'
    {_FINDING_ORDER}
    limit %(limit)s
"""

_ASSET_FINDINGS_SQL: Final = f"""
    select {_FINDING_COLUMNS}
    from vulnerability_match m
    join asset a on a.id = m.asset_id and a.tenant_id = m.tenant_id
    {_LABEL_JOIN}
    where m.tenant_id = %(tenant_id)s and m.asset_id = %(asset_id)s and m.is_current
    {_FINDING_ORDER}
    limit %(limit)s
"""

_REVIEW_QUEUE_SQL: Final = f"""
    select i.id, i.triage_id, t.asset_id, label.value, t.cve_id, i.recommendation,
           i.confidence, i.state, i.review_outcome, i.kev_locked_visible, i.model_version,
           i.created_at
    from insight i
    join triage_snapshot t on t.id = i.triage_id
    join asset a on a.id = t.asset_id and a.tenant_id = t.tenant_id
    {_LABEL_JOIN}
    where i.tenant_id = %(tenant_id)s and i.state = 'proposed'
    order by i.kev_locked_visible desc, i.created_at
    limit %(limit)s
"""

_SUMMARY_SQL: Final = """
    select
        (select count(*) from vulnerability_match
            where tenant_id = %(tenant_id)s and is_current and kev) as kev_findings,
        (select count(*) from vulnerability_match
            where tenant_id = %(tenant_id)s and is_current and priority = 'p1') as p1_findings,
        (select count(*) from vulnerability_match
            where tenant_id = %(tenant_id)s and is_current
              and confidence_state = 'probable') as needs_verification,
        (select count(*) from insight
            where tenant_id = %(tenant_id)s and state = 'proposed') as proposed_insights,
        (select count(*) from asset
            where tenant_id = %(tenant_id)s and status = 'active'
              and management_state = 'unmanaged') as shadow_it_assets,
        (select count(*) from asset
            where tenant_id = %(tenant_id)s and status = 'active'
              and management_state = 'unknown') as unknown_management_assets,
        (select count(*) from vulnerability_match
            where tenant_id = %(tenant_id)s and is_current) as total_findings
"""

_ASSET_COUNTS: Final = """
    left join lateral (
        select
            count(*) filter (where m.confidence_state = 'confirmed') as confirmed,
            count(*) filter (where m.confidence_state = 'probable') as probable,
            count(*) filter (where m.kev) as kev,
            min(m.priority) as top_priority
        from vulnerability_match m
        where m.tenant_id = a.tenant_id and m.asset_id = a.id and m.is_current
    ) counts on true
"""

_TIMELINE_SQL: Final = """
    select id, observation_type, source, source_type, collector, collection_method,
           confidence, observed_at, collected_at
    from observation
    where tenant_id = %(tenant_id)s and asset_id = %(asset_id)s
    order by observed_at desc, id
    limit %(limit)s
"""


class PostgresReadModel:
    """`ReadModel` over the existing tables. Reads only; writes nothing, ever."""

    def __init__(self, conn: Connection) -> None:
        self._conn = conn

    # ------------------------------------------------------------------ the worklist

    def worklist(self, tenant_id: UUID, *, limit: int = 50) -> Sequence[WorklistFinding]:
        rows = self._conn.execute(
            _WORKLIST_SQL, {"tenant_id": tenant_id, "limit": _bounded(limit, MAX_PAGE)}
        ).fetchall()
        return [_finding(row) for row in rows]

    def needs_verification(self, tenant_id: UUID, *, limit: int = 50) -> Sequence[WorklistFinding]:
        rows = self._conn.execute(
            _NEEDS_VERIFICATION_SQL, {"tenant_id": tenant_id, "limit": _bounded(limit, MAX_PAGE)}
        ).fetchall()
        return [_finding(row) for row in rows]

    def review_queue(self, tenant_id: UUID, *, limit: int = 50) -> Sequence[InsightSummary]:
        rows = self._conn.execute(
            _REVIEW_QUEUE_SQL, {"tenant_id": tenant_id, "limit": _bounded(limit, MAX_PAGE)}
        ).fetchall()
        return [
            InsightSummary(
                insight_id=row[0],
                triage_id=row[1],
                asset_id=row[2],
                asset_label=_text_or_none(row[3]),
                cve_id=str(row[4]),
                recommendation=_recommendation(str(row[5])),
                confidence=float(row[6]),
                state=_state(str(row[7])),
                review_outcome=None if row[8] is None else ReviewOutcome(str(row[8])),
                kev_locked_visible=bool(row[9]),
                model_version=str(row[10]),
                created_at=row[11],
            )
            for row in rows
        ]

    def worklist_summary(self, tenant_id: UUID) -> WorklistSummary:
        row = self._conn.execute(_SUMMARY_SQL, {"tenant_id": tenant_id}).fetchone()
        if row is None:  # pragma: no cover — scalar subqueries always return a row
            return WorklistSummary()
        return WorklistSummary(
            kev_findings=int(row[0]),
            p1_findings=int(row[1]),
            needs_verification=int(row[2]),
            proposed_insights=int(row[3]),
            # `unmanaged` only. An `unknown` management state is an unresolved match, and
            # counting it as shadow IT is the overclaim ADR-0009 exists to prevent.
            shadow_it_assets=int(row[4]),
            unknown_management_assets=int(row[5]),
            total_findings=int(row[6]),
        )

    # ------------------------------------------------------------------ the inventory

    def assets(
        self, tenant_id: UUID, *, filters: AssetFilters, limit: int = 50, offset: int = 0
    ) -> AssetPage:
        """A page of the inventory.

        The `where` clause is assembled from a fixed set of fragments — the *shape* varies
        with which filters were supplied, never the values, which are bound parameters
        throughout.
        """
        clauses, params = _filter_clauses(filters)
        params["tenant_id"] = tenant_id
        params["limit"] = _bounded(limit, MAX_PAGE)
        params["offset"] = max(0, offset)

        where = sql.SQL(" ").join(
            [sql.SQL("where a.tenant_id = %(tenant_id)s and a.status = 'active'"), *clauses]
        )
        listing = sql.SQL("""
            select a.id, label.value, a.asset_class, a.management_state,
                   a.identification_confidence, coalesce(counts.confirmed, 0),
                   coalesce(counts.probable, 0), coalesce(counts.kev, 0),
                   counts.top_priority, a.last_seen_at
            from asset a {label_join} {counts_join} {where}
            order by counts.kev desc nulls last, counts.top_priority nulls last,
                     label.value nulls last, a.id
            limit %(limit)s offset %(offset)s
        """).format(
            label_join=sql.SQL(_LABEL_JOIN),
            counts_join=sql.SQL(_ASSET_COUNTS),
            where=where,
        )
        counting = sql.SQL("select count(*) from asset a {label_join} {where}").format(
            label_join=sql.SQL(_LABEL_JOIN), where=where
        )

        rows = self._conn.execute(listing, params).fetchall()
        total = self._conn.execute(counting, params).fetchone()

        return AssetPage(
            items=[
                AssetSummary(
                    asset_id=row[0],
                    label=_text_or_none(row[1]),
                    asset_class=AssetClass(str(row[2])),
                    management_state=ManagementState(str(row[3])),
                    identification_confidence=float(row[4]),
                    confirmed_findings=int(row[5]),
                    probable_findings=int(row[6]),
                    kev_findings=int(row[7]),
                    highest_priority=None if row[8] is None else Priority(str(row[8])),
                    last_seen_at=row[9],
                )
                for row in rows
            ],
            total=int(total[0]) if total is not None else 0,
            limit=int(params["limit"]),
            offset=int(params["offset"]),
        )

    # --------------------------------------------------------------------- one asset

    def asset_findings(self, tenant_id: UUID, asset_id: UUID) -> Sequence[WorklistFinding]:
        rows = self._conn.execute(
            _ASSET_FINDINGS_SQL,
            {"tenant_id": tenant_id, "asset_id": asset_id, "limit": MAX_PAGE},
        ).fetchall()
        return [_finding(row) for row in rows]

    def asset_timeline(
        self, tenant_id: UUID, asset_id: UUID, *, limit: int = 100
    ) -> Sequence[TimelineEntry]:
        rows = self._conn.execute(
            _TIMELINE_SQL,
            {
                "tenant_id": tenant_id,
                "asset_id": asset_id,
                "limit": _bounded(limit, MAX_TIMELINE),
            },
        ).fetchall()
        return [
            TimelineEntry(
                observation_id=row[0],
                observation_type=str(row[1]),
                source=str(row[2]),
                source_type=str(row[3]),
                collector=str(row[4]),
                collection_method=str(row[5]),
                confidence=float(row[6]),
                observed_at=row[7],
                collected_at=row[8],
            )
            for row in rows
        ]


# --------------------------------------------------------------------- filters


def _filter_clauses(filters: AssetFilters) -> tuple[list[sql.Composable], dict[str, Any]]:
    """Turn validated filters into `and …` fragments plus their bound parameters.

    Every fragment is a literal written here; every value is a parameter. There is no path
    by which caller text becomes SQL.
    """
    clauses: list[sql.Composable] = []
    params: dict[str, Any] = {}

    if filters.asset_class is not None:
        clauses.append(sql.SQL("and a.asset_class = %(asset_class)s"))
        params["asset_class"] = filters.asset_class.value
    if filters.management_state is not None:
        clauses.append(sql.SQL("and a.management_state = %(management_state)s"))
        params["management_state"] = filters.management_state.value
    if filters.has_kev is not None:
        clauses.append(
            sql.SQL("""
                and {maybe} exists (
                    select 1 from vulnerability_match m
                    where m.tenant_id = a.tenant_id and m.asset_id = a.id
                      and m.is_current and m.kev
                )
            """).format(maybe=sql.SQL("" if filters.has_kev else "not"))
        )
    if filters.query:
        clauses.append(
            sql.SQL("""
                and exists (
                    select 1 from asset_identifier ai
                    where ai.tenant_id = a.tenant_id and ai.asset_id = a.id
                      and ai.value ilike %(query)s
                )
            """)
        )
        # Escaped so `%` and `_` in a search box are literal characters rather than
        # wildcards — a correctness fix, not a safety one: the value is bound either way.
        escaped = filters.query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        params["query"] = f"%{escaped}%"

    return clauses, params


# --------------------------------------------------------------------- coercion


def _finding(row: tuple[Any, ...]) -> WorklistFinding:
    return WorklistFinding(
        match_id=row[0],
        asset_id=row[1],
        asset_label=_text_or_none(row[2]),
        asset_class=AssetClass(str(row[3])),
        management_state=ManagementState(str(row[4])),
        cve_id=str(row[5]),
        matched_cpe=str(row[6]),
        priority=Priority(str(row[7])),
        priority_rule=str(row[8]),
        priority_reason=str(row[9]),
        confidence_state=ConfidenceState(str(row[10])),
        version_source=VersionSource(str(row[11])),
        kev=bool(row[12]),
        epss=None if row[13] is None else float(row[13]),
        cvss_score=None if row[14] is None else float(row[14]),
        cvss_version=_text_or_none(row[15]),
        matched_at=row[16],
        has_insight=bool(row[17]),
    )


#: Stored values narrowed to their contract types. The columns already carry CHECKs; reading
#: them back through a lookup means a row that somehow escaped one surfaces as a clear error
#: rather than as a wrong `Literal` in a response.
_RECOMMENDATIONS: Final[dict[str, Recommendation]] = {
    "raise_priority": "raise_priority",
    "lower_priority": "lower_priority",
    "maintain": "maintain",
}
_STATES: Final[dict[str, InsightState]] = {
    "proposed": "proposed",
    "human_reviewed": "human_reviewed",
    "accepted": "accepted",
}


def _recommendation(value: str) -> Recommendation:
    found = _RECOMMENDATIONS.get(value)
    if found is None:
        raise ValidationError(f"unknown recommendation in the store: {value!r}")
    return found


def _state(value: str) -> InsightState:
    found = _STATES.get(value)
    if found is None:
        raise ValidationError(f"unknown insight state in the store: {value!r}")
    return found


def _bounded(value: int, ceiling: int) -> int:
    return max(1, min(value, ceiling))


def _text_or_none(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
