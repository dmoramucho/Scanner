"""Postgres-backed `CveCache` — what the feed told us, kept so we need not ask again.

Two tables, from migration `0003_cve_cache`: the normalized records, and a log of which
CPEs we have asked about. The second is what makes "NVD says there are none" a cacheable
answer rather than an absence indistinguishable from never having looked (m3-design §2).

Not tenant-scoped: a CVE is a fact about software in the world. The tenant-scoped
conclusions about our own devices are `vulnerability_match`, which is P14's.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import Any, Final

import psycopg

from domain.errors import ValidationError
from domain.models import CveQueryCacheEntry, CveRecord

Connection = psycopg.Connection[tuple[Any, ...]]

_STORE_RECORD_SQL: Final = """
    insert into cve_cache (
        source, cve_id, record, content_hash, raw_record_ref,
        published_at, last_modified_at, fetched_at
    ) values (
        %(source)s, %(cve_id)s, %(record)s::jsonb, %(content_hash)s, %(raw_record_ref)s,
        %(published_at)s, %(last_modified_at)s, %(fetched_at)s
    )
    on conflict (source, cve_id) do update set
        record = excluded.record,
        content_hash = excluded.content_hash,
        raw_record_ref = excluded.raw_record_ref,
        published_at = excluded.published_at,
        last_modified_at = excluded.last_modified_at,
        fetched_at = excluded.fetched_at,
        ingested_at = now()
    returning (xmax = 0) as created
"""

_RECORDS_SQL: Final = """
    select record from cve_cache
    where source = %(source)s and cve_id = any(%(cve_ids)s)
"""

_QUERY_ENTRY_SQL: Final = """
    select cpe, source, cve_ids, fetched_at, raw_record_ref
    from cve_query_cache
    where source = %(source)s and cpe = %(cpe)s
"""

_STORE_QUERY_SQL: Final = """
    insert into cve_query_cache (source, cpe, cve_ids, raw_record_ref, fetched_at)
    values (%(source)s, %(cpe)s, %(cve_ids)s, %(raw_record_ref)s, %(fetched_at)s)
    on conflict (source, cpe) do update set
        cve_ids = excluded.cve_ids,
        raw_record_ref = excluded.raw_record_ref,
        fetched_at = excluded.fetched_at,
        ingested_at = now()
"""


class PostgresCveCache:
    """`CveCache` over `cve_cache` and `cve_query_cache`."""

    def __init__(self, conn: Connection) -> None:
        self._conn = conn

    def query_entry(self, source: str, cpe: str) -> CveQueryCacheEntry | None:
        row = self._conn.execute(_QUERY_ENTRY_SQL, {"source": source, "cpe": cpe}).fetchone()
        if row is None:
            return None
        return CveQueryCacheEntry(
            cpe=str(row[0]),
            source=str(row[1]),
            cve_ids=[str(value) for value in row[2]],
            fetched_at=row[3],
            raw_record_ref=_text_or_none(row[4]),
        )

    def records(self, source: str, cve_ids: Sequence[str]) -> Sequence[CveRecord]:
        if not cve_ids:
            return []
        rows = self._conn.execute(
            _RECORDS_SQL, {"source": source, "cve_ids": list(cve_ids)}
        ).fetchall()
        return [CveRecord.model_validate(row[0]) for row in rows]

    def store(self, records: Sequence[CveRecord]) -> int:
        """Upsert each record; returns how many were new.

        A CVE's contents genuinely change — a score is revised, a CPE range is corrected —
        so a re-fetch refreshes rather than being discarded. `xmax = 0` distinguishes the
        two outcomes in one round trip, as it does for `managed_record`.
        """
        created = 0
        for record in records:
            row = self._conn.execute(_STORE_RECORD_SQL, self._params(record)).fetchone()
            if row is not None and bool(row[0]):
                created += 1
        return created

    def store_query(self, entry: CveQueryCacheEntry) -> None:
        self._conn.execute(
            _STORE_QUERY_SQL,
            {
                "source": entry.source,
                "cpe": entry.cpe,
                "cve_ids": list(entry.cve_ids),
                "raw_record_ref": entry.raw_record_ref,
                "fetched_at": entry.fetched_at,
            },
        )

    def _params(self, record: CveRecord) -> dict[str, Any]:
        if record.fetched_at.tzinfo is None:
            raise ValidationError("CveRecord.fetched_at must be timezone-aware (UTC)")
        serialized = record.model_dump(mode="json")
        canonical = json.dumps(serialized, sort_keys=True, separators=(",", ":"))
        return {
            "source": record.source,
            "cve_id": record.cve_id,
            "record": canonical,
            # Tamper-evidence, and a cheap way to see whether a re-fetch actually changed
            # anything (AGENTS.md §3).
            "content_hash": hashlib.sha256(canonical.encode("utf-8")).digest(),
            "raw_record_ref": record.raw_record_ref,
            "published_at": record.published_at,
            "last_modified_at": record.last_modified_at,
            "fetched_at": record.fetched_at,
        }


def _text_or_none(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
