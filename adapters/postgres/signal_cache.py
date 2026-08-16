"""Postgres-backed `KevCache` and `EpssCache` — the two prioritisation snapshots.

Both follow the same shape, from migration `0004_kev_epss_cache`: a table of entries, and a
row in `feed_snapshot` recording that the whole catalog was loaded and when.

**Replacement, not accumulation.** A refresh swaps the entire snapshot inside one
transaction. CISA withdraws KEV entries and FIRST re-scores CVEs, so a cache we only ever
added to would keep asserting an exploitation that has been retracted, or a probability that
has been revised. These tables are projections of an external source's current state — the
same reasoning as the current-software projection in ADR-0006 — and the history that matters
lives in the source, not here.

The snapshot row is what makes "not listed" a real answer rather than an absence: without
it, an empty cache would answer "this CVE is not exploited" for every CVE in existence
(AGENTS.md §4.9).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Final

import psycopg

from domain.errors import ValidationError
from domain.models import EpssScore, FeedSnapshot, KevEntry

Connection = psycopg.Connection[tuple[Any, ...]]

_SNAPSHOT_SQL: Final = """
    select source, record_count, raw_record_ref, fetched_at
    from feed_snapshot where source = %(source)s
"""

_STORE_SNAPSHOT_SQL: Final = """
    insert into feed_snapshot (source, record_count, raw_record_ref, fetched_at)
    values (%(source)s, %(record_count)s, %(raw_record_ref)s, %(fetched_at)s)
    on conflict (source) do update set
        record_count = excluded.record_count,
        raw_record_ref = excluded.raw_record_ref,
        fetched_at = excluded.fetched_at,
        ingested_at = now()
"""

_KEV_ENTRY_SQL: Final = """
    select cve_id, source, vendor, product, name, date_added, due_date,
           known_ransomware, raw_record_ref, fetched_at
    from kev_cache where source = %(source)s and cve_id = %(cve_id)s
"""

_KEV_INSERT_SQL: Final = """
    insert into kev_cache (
        source, cve_id, vendor, product, name, date_added, due_date,
        known_ransomware, raw_record_ref, fetched_at
    ) values (
        %(source)s, %(cve_id)s, %(vendor)s, %(product)s, %(name)s, %(date_added)s,
        %(due_date)s, %(known_ransomware)s, %(raw_record_ref)s, %(fetched_at)s
    )
"""

_EPSS_SCORE_SQL: Final = """
    select cve_id, source, score, percentile, model_version, scored_at,
           raw_record_ref, fetched_at
    from epss_cache where source = %(source)s and cve_id = %(cve_id)s
"""

_EPSS_INSERT_SQL: Final = """
    insert into epss_cache (
        source, cve_id, score, percentile, model_version, scored_at,
        raw_record_ref, fetched_at
    ) values (
        %(source)s, %(cve_id)s, %(score)s, %(percentile)s, %(model_version)s,
        %(scored_at)s, %(raw_record_ref)s, %(fetched_at)s
    )
"""


def _snapshot_from(row: tuple[Any, ...] | None) -> FeedSnapshot | None:
    if row is None:
        return None
    return FeedSnapshot(
        source=str(row[0]),
        record_count=int(row[1]),
        raw_record_ref=str(row[2]) if row[2] else None,
        fetched_at=row[3],
    )


class PostgresKevCache:
    """`KevCache` over `kev_cache` and `feed_snapshot`."""

    def __init__(self, conn: Connection) -> None:
        self._conn = conn

    def snapshot(self, source: str) -> FeedSnapshot | None:
        return _snapshot_from(self._conn.execute(_SNAPSHOT_SQL, {"source": source}).fetchone())

    def entry(self, source: str, cve_id: str) -> KevEntry | None:
        row = self._conn.execute(_KEV_ENTRY_SQL, {"source": source, "cve_id": cve_id}).fetchone()
        if row is None:
            return None
        return KevEntry(
            cve_id=str(row[0]),
            source=str(row[1]),
            vendor=_text(row[2]),
            product=_text(row[3]),
            name=_text(row[4]),
            date_added=row[5],
            due_date=row[6],
            known_ransomware=row[7],
            raw_record_ref=_text(row[8]),
            fetched_at=row[9],
        )

    def replace(self, source: str, entries: Sequence[KevEntry], snapshot: FeedSnapshot) -> int:
        """Swap the whole catalog, atomically.

        The delete and the inserts commit together, so there is no window in which the
        catalog is empty and every CVE would answer "not exploited".
        """
        if snapshot.fetched_at.tzinfo is None:
            raise ValidationError("FeedSnapshot.fetched_at must be timezone-aware (UTC)")

        with self._conn.transaction():
            self._conn.execute("delete from kev_cache where source = %s", (source,))
            for entry in entries:
                self._conn.execute(
                    _KEV_INSERT_SQL,
                    {
                        "source": source,
                        "cve_id": entry.cve_id,
                        "vendor": entry.vendor,
                        "product": entry.product,
                        "name": entry.name,
                        "date_added": entry.date_added,
                        "due_date": entry.due_date,
                        "known_ransomware": entry.known_ransomware,
                        "raw_record_ref": entry.raw_record_ref,
                        "fetched_at": entry.fetched_at,
                    },
                )
            self._conn.execute(_STORE_SNAPSHOT_SQL, _snapshot_params(snapshot, len(entries)))
        return len(entries)


class PostgresEpssCache:
    """`EpssCache` over `epss_cache` and `feed_snapshot`."""

    def __init__(self, conn: Connection) -> None:
        self._conn = conn

    def snapshot(self, source: str) -> FeedSnapshot | None:
        return _snapshot_from(self._conn.execute(_SNAPSHOT_SQL, {"source": source}).fetchone())

    def score(self, source: str, cve_id: str) -> EpssScore | None:
        row = self._conn.execute(_EPSS_SCORE_SQL, {"source": source, "cve_id": cve_id}).fetchone()
        if row is None:
            return None
        return EpssScore(
            cve_id=str(row[0]),
            source=str(row[1]),
            score=float(row[2]),
            percentile=float(row[3]) if row[3] is not None else None,
            model_version=_text(row[4]),
            scored_at=row[5],
            raw_record_ref=_text(row[6]),
            fetched_at=row[7],
        )

    def replace(self, source: str, scores: Sequence[EpssScore], snapshot: FeedSnapshot) -> int:
        """Swap the whole snapshot, atomically. Same reasoning as the KEV cache."""
        if snapshot.fetched_at.tzinfo is None:
            raise ValidationError("FeedSnapshot.fetched_at must be timezone-aware (UTC)")

        with self._conn.transaction():
            self._conn.execute("delete from epss_cache where source = %s", (source,))
            for entry in scores:
                self._conn.execute(
                    _EPSS_INSERT_SQL,
                    {
                        "source": source,
                        "cve_id": entry.cve_id,
                        "score": entry.score,
                        "percentile": entry.percentile,
                        "model_version": entry.model_version,
                        "scored_at": entry.scored_at,
                        "raw_record_ref": entry.raw_record_ref,
                        "fetched_at": entry.fetched_at,
                    },
                )
            self._conn.execute(_STORE_SNAPSHOT_SQL, _snapshot_params(snapshot, len(scores)))
        return len(scores)


def _snapshot_params(snapshot: FeedSnapshot, count: int) -> dict[str, Any]:
    return {
        "source": snapshot.source,
        "record_count": count,
        "raw_record_ref": snapshot.raw_record_ref,
        "fetched_at": snapshot.fetched_at,
    }


def _text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
