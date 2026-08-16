"""Postgres-backed `DossierSource` and `TriageStore` — reading the estate, writing the record.

Two adapters, one module, because they are two halves of one path: what the assembler is
allowed to read, and what the insight path is obliged to write.

`PostgresDossierSource` reads *raw* observation payloads on purpose. It would be tempting to
filter in SQL, and that would put the redaction contract in two places — one of which is a
string. The allowlist lives in `engine/redaction.py`, once, where it can be reviewed
(dossier contract §4).

`PostgresTriageStore` writes the snapshot first and the insight second, and the schema makes
both durable in the way the contract requires: `triage_snapshot` carries the append-only
trigger, and `insight` carries the three CHECKs that outrank any code path — grounded,
KEV-visible, `llm_generated`. Everything below has already been enforced in Python; the
constraints exist because a future refactor cannot be trusted to keep enforcing it.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import Any, Final, Literal
from uuid import UUID

import psycopg

from domain.errors import ConflictError, NotFoundError, ValidationError
from domain.models import (
    AssetClass,
    AssetView,
    CitedSource,
    Derivation,
    Identifier,
    InsightProposal,
    InsightRecord,
    InsightReviewState,
    ManagementState,
    MatchForTriage,
    ObservationSnapshot,
    Provenance,
    Recommendation,
    SoftwareComponent,
    TriageDossier,
    VersionSource,
    VulnerabilityMatch,
)

Connection = psycopg.Connection[tuple[Any, ...]]

#: `proposed → human_reviewed → accepted`, forward only. A review that could be undone by
#: another review is not a decision anybody owns (AGENTS.md §2.8).
_REVIEW_ORDER: Final = ("proposed", "human_reviewed", "accepted")

_ASSET_SQL: Final = """
    select id, tenant_id, asset_class, management_state, identification_confidence, status
    from asset where tenant_id = %(tenant_id)s and id = %(asset_id)s
"""

_IDENTIFIERS_SQL: Final = """
    select kind, value, confidence from asset_identifier
    where tenant_id = %(tenant_id)s and asset_id = %(asset_id)s
    order by confidence desc, kind
"""

_SOFTWARE_SQL: Final = """
    select cpe, name, version, version_source, confidence from software_component
    where tenant_id = %(tenant_id)s and asset_id = %(asset_id)s and is_current
    order by name
"""

_OBSERVATIONS_SQL: Final = """
    select id, observation_type, payload, source, source_type, collector, collector_version,
           collection_method, confidence, raw_record_ref, observed_at, collected_at
    from observation
    where tenant_id = %(tenant_id)s and asset_id = %(asset_id)s
    order by observed_at desc
    limit %(limit)s
"""

_MANAGED_BY_SQL: Final = """
    select distinct source from managed_record
    where tenant_id = %(tenant_id)s and asset_id = %(asset_id)s
    order by source
"""

#: Matches with no insight yet. KEV first, then the most confident: if a run is cut short,
#: it is cut short after the findings that matter most.
_PENDING_SQL: Final = """
    select m.id, m.tenant_id, m.asset_id, m.cve_id, m.matched_cpe, m.version_source,
           m.confidence_state, m.kev, m.epss, m.derivation, m.matched_at
    from vulnerability_match m
    left join triage_snapshot t on t.match_id = m.id
    where m.tenant_id = %(tenant_id)s and t.id is null
    order by m.kev desc, m.epss desc nulls last, m.matched_at
    limit %(limit)s
"""

_SNAPSHOT_SQL: Final = """
    insert into triage_snapshot (
        id, tenant_id, asset_id, match_id, cve_id, snapshot, content_hash, assembler_version
    ) values (
        %(id)s, %(tenant_id)s, %(asset_id)s, %(match_id)s, %(cve_id)s,
        %(snapshot)s::jsonb, %(content_hash)s, %(assembler_version)s
    )
    returning id
"""

_SNAPSHOT_READ_SQL: Final = "select snapshot from triage_snapshot where id = %(id)s"

_INSIGHT_SQL: Final = """
    insert into insight (
        id, tenant_id, triage_id, recommendation, rationale, cited_sources, confidence,
        derivation, model_version, state, kev_locked_visible
    ) values (
        %(id)s, %(tenant_id)s, %(triage_id)s, %(recommendation)s, %(rationale)s,
        %(cited_sources)s::jsonb, %(confidence)s, 'llm_generated', %(model_version)s,
        %(state)s, %(kev_locked_visible)s
    )
    returning id
"""

_INSIGHT_READ_SQL: Final = """
    select id, triage_id, recommendation, rationale, cited_sources, confidence,
           model_version, state, kev_locked_visible
    from insight where id = %(id)s
"""

_REVIEW_SQL: Final = """
    update insight set state = %(state)s, reviewed_by = %(reviewer)s,
                       reviewed_at = now(), updated_at = now()
    where id = %(id)s
    returning id
"""


class PostgresDossierSource:
    """`DossierSource` over the asset spine. Reads raw; the engine redacts."""

    def __init__(self, conn: Connection) -> None:
        self._conn = conn

    def asset(self, tenant_id: UUID, asset_id: UUID) -> AssetView | None:
        row = self._conn.execute(
            _ASSET_SQL, {"tenant_id": tenant_id, "asset_id": asset_id}
        ).fetchone()
        if row is None:
            return None
        return AssetView(
            id=row[0],
            tenant_id=row[1],
            asset_class=AssetClass(str(row[2])),
            management_state=ManagementState(str(row[3])),
            identification_confidence=float(row[4]),
            status="merged" if str(row[5]) == "merged" else "active",
        )

    def identifiers(self, tenant_id: UUID, asset_id: UUID) -> Sequence[Identifier]:
        rows = self._conn.execute(
            _IDENTIFIERS_SQL, {"tenant_id": tenant_id, "asset_id": asset_id}
        ).fetchall()
        return [
            Identifier(
                kind=_lookup(_ANCHOR_KINDS, str(row[0]), what="anchor kind"),
                value=str(row[1]),
                confidence=float(row[2]),
            )
            for row in rows
        ]

    def software(self, tenant_id: UUID, asset_id: UUID) -> Sequence[SoftwareComponent]:
        rows = self._conn.execute(
            _SOFTWARE_SQL, {"tenant_id": tenant_id, "asset_id": asset_id}
        ).fetchall()
        return [
            SoftwareComponent(
                cpe=_text_or_none(row[0]),
                name=str(row[1]),
                version=_text_or_none(row[2]),
                version_source=VersionSource(str(row[3])),
                confidence=float(row[4]),
            )
            for row in rows
        ]

    def observations(
        self, tenant_id: UUID, asset_id: UUID, *, limit: int = 500
    ) -> Sequence[ObservationSnapshot]:
        rows = self._conn.execute(
            _OBSERVATIONS_SQL,
            {"tenant_id": tenant_id, "asset_id": asset_id, "limit": max(1, min(limit, 2000))},
        ).fetchall()
        return [
            ObservationSnapshot(
                observation_id=row[0],
                observation_type=str(row[1]),
                payload=row[2] if isinstance(row[2], dict) else {},
                provenance=Provenance(
                    source=str(row[3]),
                    source_type=str(row[4]),
                    collector=str(row[5]),
                    collector_version=str(row[6]),
                    collection_method=str(row[7]),
                    observed_at=row[10],
                    collected_at=row[11],
                    confidence=float(row[8]),
                    derivation=Derivation.DETERMINISTIC,
                    raw_record_ref=_text_or_none(row[9]),
                ),
                observed_at=row[10],
            )
            for row in rows
        ]

    def managed_by(self, tenant_id: UUID, asset_id: UUID) -> Sequence[str]:
        rows = self._conn.execute(
            _MANAGED_BY_SQL, {"tenant_id": tenant_id, "asset_id": asset_id}
        ).fetchall()
        return [str(row[0]) for row in rows]


class PostgresTriageStore:
    """`TriageStore` over `triage_snapshot` and `insight`."""

    def __init__(self, conn: Connection) -> None:
        self._conn = conn

    def pending_matches(self, tenant_id: UUID, *, limit: int = 100) -> Sequence[MatchForTriage]:
        rows = self._conn.execute(
            _PENDING_SQL, {"tenant_id": tenant_id, "limit": max(1, min(limit, 1000))}
        ).fetchall()
        return [
            MatchForTriage(
                match_id=row[0],
                tenant_id=row[1],
                asset_id=row[2],
                match=VulnerabilityMatch(
                    cve_id=str(row[3]),
                    matched_cpe=str(row[4]),
                    version_source=VersionSource(str(row[5])),
                    confidence_state=_lookup(
                        _CONFIDENCE_STATES, str(row[6]), what="confidence state"
                    ),
                    kev=bool(row[7]),
                    epss=None if row[8] is None else float(row[8]),
                    # The match's provenance is the correlator: a deterministic conclusion
                    # from the feed, not something a collector saw (AGENTS.md §3).
                    provenance=Provenance(
                        source="correlation",
                        source_type="derived",
                        collector="vulnerability-correlator",
                        collector_version="1.0.0",
                        collection_method="cpe_match",
                        observed_at=row[10],
                        collected_at=row[10],
                        confidence=1.0,
                        derivation=Derivation.DETERMINISTIC,
                        raw_record_ref=f"vulnerability_match:{row[0]}",
                    ),
                ),
            )
            for row in rows
        ]

    def record_snapshot(self, triage: TriageDossier) -> UUID:
        """Write exactly what the model will be given, before it is given.

        The content hash is over the canonical JSON, so "is this what the model saw?" is a
        comparison rather than an argument. The row is immutable — the append-only trigger
        refuses an UPDATE, which is what makes the answer worth having.
        """
        document = triage.model_dump(mode="json")
        canonical = json.dumps(document, sort_keys=True, separators=(",", ":"))
        row = self._conn.execute(
            _SNAPSHOT_SQL,
            {
                "id": triage.triage_id,
                "tenant_id": triage.asset.tenant_id,
                "asset_id": triage.asset.asset_id,
                # Null on purpose: `TriageDossier` carries the *contract's* match, which
                # has no row id. The CVE id and asset id on this row answer every question
                # anybody actually asks of it, and inventing a join key would be worse.
                "match_id": None,
                "cve_id": triage.match.cve_id,
                "snapshot": canonical,
                "content_hash": hashlib.sha256(canonical.encode("utf-8")).digest(),
                "assembler_version": triage.asset.assembler_version,
            },
        ).fetchone()
        if row is None:  # pragma: no cover — insert…returning always returns or raises
            raise ConflictError("triage snapshot was not written")
        written: UUID = row[0]
        return written

    def record_insight(self, insight: InsightProposal) -> InsightRecord:
        """Persist a validated proposal.

        Both safety CHECKs are re-stated here as Python guards, not because the generator is
        distrusted but because this adapter is a public entry point: a future caller with a
        hand-built `InsightProposal` meets the same rules.
        """
        if not insight.cited_sources:
            raise ValidationError("refusing to persist an ungrounded insight (contract §7)")
        if insight.kev_locked_visible and insight.recommendation == "lower_priority":
            raise ValidationError(
                "refusing to persist an insight that hides a KEV-listed finding (contract §7)"
            )

        snapshot = self._conn.execute(
            "select tenant_id from triage_snapshot where id = %(id)s", {"id": insight.triage_id}
        ).fetchone()
        if snapshot is None:
            # The snapshot is written first, always. No snapshot means nobody can reconstruct
            # what this insight was reasoning about (contract §8.1).
            raise NotFoundError(
                f"no retained snapshot {insight.triage_id}; an insight without its evidence "
                "is not auditable"
            )

        row = self._conn.execute(
            _INSIGHT_SQL,
            {
                "id": insight.insight_id,
                "tenant_id": snapshot[0],
                "triage_id": insight.triage_id,
                "recommendation": insight.recommendation,
                "rationale": insight.rationale,
                "cited_sources": json.dumps(
                    [source.model_dump(mode="json") for source in insight.cited_sources]
                ),
                "confidence": insight.confidence,
                "model_version": insight.model_version,
                "state": insight.state,
                "kev_locked_visible": insight.kev_locked_visible,
            },
        ).fetchone()
        if row is None:  # pragma: no cover
            raise ConflictError("insight was not written")
        return InsightRecord(insight_id=row[0], triage_id=insight.triage_id, created=True)

    def review_insight(
        self, insight_id: UUID, *, state: InsightReviewState, reviewer: str
    ) -> InsightProposal:
        """Move a proposal forward through human review, recording who and when."""
        name = reviewer.strip()
        if not name:
            raise ValidationError("a review must record who performed it")

        current = self.insight(insight_id)
        if current is None:
            raise NotFoundError(f"no insight {insight_id}")
        if _REVIEW_ORDER.index(state) <= _REVIEW_ORDER.index(current.state):
            # Forward only. Re-reviewing backwards would quietly erase a human decision.
            raise ValidationError(
                f"cannot move an insight from {current.state} to {state}; review is forward-only"
            )

        self._conn.execute(_REVIEW_SQL, {"id": insight_id, "state": state, "reviewer": name})
        reviewed = self.insight(insight_id)
        if reviewed is None:  # pragma: no cover — it existed a statement ago
            raise NotFoundError(f"no insight {insight_id}")
        return reviewed

    def insight(self, insight_id: UUID) -> InsightProposal | None:
        row = self._conn.execute(_INSIGHT_READ_SQL, {"id": insight_id}).fetchone()
        if row is None:
            return None
        return InsightProposal(
            insight_id=row[0],
            triage_id=row[1],
            recommendation=_lookup(_RECOMMENDATIONS, str(row[2]), what="recommendation"),
            rationale=str(row[3]),
            cited_sources=[CitedSource.model_validate(entry) for entry in row[4]],
            confidence=float(row[5]),
            model_version=str(row[6]),
            state=_lookup(_REVIEW_STATES, str(row[7]), what="insight state"),
            kev_locked_visible=bool(row[8]),
        )

    def snapshot(self, triage_id: UUID) -> TriageDossier | None:
        row = self._conn.execute(_SNAPSHOT_READ_SQL, {"id": triage_id}).fetchone()
        if row is None:
            return None
        return TriageDossier.model_validate(row[0])


# --------------------------------------------------------------------- coercion

AnchorKind = Literal["mac", "serial", "cert_fingerprint", "hostname", "ip"]
ConfidenceStateText = Literal["confirmed", "probable", "verified_exploitable"]
ReviewState = Literal["proposed", "human_reviewed", "accepted"]

#: Lookups rather than casts: a value reaches a contract type only by being in one of these.
_ANCHOR_KINDS: Final[dict[str, AnchorKind]] = {
    "mac": "mac",
    "serial": "serial",
    "cert_fingerprint": "cert_fingerprint",
    "hostname": "hostname",
    "ip": "ip",
}
_CONFIDENCE_STATES: Final[dict[str, ConfidenceStateText]] = {
    "confirmed": "confirmed",
    "probable": "probable",
    "verified_exploitable": "verified_exploitable",
}
_RECOMMENDATIONS: Final[dict[str, Recommendation]] = {
    "raise_priority": "raise_priority",
    "lower_priority": "lower_priority",
    "maintain": "maintain",
}
_REVIEW_STATES: Final[dict[str, ReviewState]] = {
    "proposed": "proposed",
    "human_reviewed": "human_reviewed",
    "accepted": "accepted",
}


def _lookup[T](table: dict[str, T], value: str, *, what: str) -> T:
    """A stored value, narrowed to its contract type — or a named failure.

    The database CHECKs already restrict every one of these columns. Reading them back
    through a lookup means a row that somehow escaped a constraint surfaces as a clear error
    here rather than as a wrong `Literal` two layers up.
    """
    found = table.get(value)
    if found is None:
        raise ValidationError(f"unknown {what} in the store: {value!r}")
    return found


def _text_or_none(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
