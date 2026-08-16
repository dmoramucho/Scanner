"""Postgres-backed `AdvisoryDocumentCache` — the reference material we already hold.

One table from migration `0006_advisory_cache`, keyed by URL. Two properties are worth
stating because they are easy to erode:

**A dead reference is an answer.** A row with `status = 'unavailable'` records that we asked
and there was nothing there, so the next run does not ask again. That is the same device as
`cve_query_cache`, and it only works because the retriever refuses to write that status for
a *failed* fetch — a timeout is not evidence that a URL is dead (ADR-0013).

**Only sanitized text is stored.** The retriever defangs everything before it gets here, so
there is no path from this table to unsanitised bytes. The DB CHECK
`advisory_document_grounded` backs the other half: a document that claims to be retrieved
must have content, so "we have an advisory" can never mean an empty string.

Not tenant-scoped: a published advisory is a fact about software in the world.
"""

from __future__ import annotations

import hashlib
from typing import Any, Final

import psycopg

from domain.errors import ValidationError
from domain.models import AdvisoryDocument, AdvisoryDocumentStatus

Connection = psycopg.Connection[tuple[Any, ...]]

_DOCUMENT_SQL: Final = """
    select url, status, content, content_hash, media_type, cve_id, fetched_at, raw_record_ref
    from advisory_document
    where url = %(url)s
"""

_STORE_SQL: Final = """
    insert into advisory_document (
        url, status, content, content_hash, media_type, cve_id, raw_record_ref, fetched_at
    ) values (
        %(url)s, %(status)s, %(content)s, %(content_hash)s, %(media_type)s,
        %(cve_id)s, %(raw_record_ref)s, %(fetched_at)s
    )
    on conflict (url) do update set
        status = excluded.status,
        content = excluded.content,
        content_hash = excluded.content_hash,
        media_type = excluded.media_type,
        cve_id = excluded.cve_id,
        raw_record_ref = excluded.raw_record_ref,
        fetched_at = excluded.fetched_at,
        ingested_at = now()
"""


class PostgresAdvisoryDocumentCache:
    """`AdvisoryDocumentCache` over `advisory_document`."""

    def __init__(self, conn: Connection) -> None:
        self._conn = conn

    def document(self, url: str) -> AdvisoryDocument | None:
        row = self._conn.execute(_DOCUMENT_SQL, {"url": url}).fetchone()
        if row is None:
            return None
        return AdvisoryDocument(
            url=str(row[0]),
            status=AdvisoryDocumentStatus(str(row[1])),
            content=str(row[2] or ""),
            content_hash=_text_or_none(row[3]),
            media_type=_text_or_none(row[4]),
            cve_id=_text_or_none(row[5]),
            fetched_at=row[6],
            raw_record_ref=_text_or_none(row[7]),
        )

    def store(self, document: AdvisoryDocument) -> None:
        """Upsert one document. A re-fetch replaces the previous one: the question this
        table answers is "what does this URL say now", and a changed patch is not history
        we need — the immutable lineage of what a model saw is the `TriageDossier` (P16)."""
        if document.fetched_at.tzinfo is None:
            raise ValidationError("AdvisoryDocument.fetched_at must be timezone-aware (UTC)")
        if document.status is AdvisoryDocumentStatus.OK and not document.content.strip():
            # The DB CHECK refuses this too. Refused here as well so the failure names the
            # reason rather than surfacing as an integrity error three layers down.
            raise ValidationError(
                f"refusing to cache an empty document as retrieved: {document.url[:120]}"
            )

        self._conn.execute(
            _STORE_SQL,
            {
                "url": document.url,
                "status": document.status.value,
                "content": document.content,
                "content_hash": document.content_hash
                or hashlib.sha256(document.content.encode("utf-8")).hexdigest(),
                "media_type": document.media_type,
                "cve_id": document.cve_id,
                "raw_record_ref": document.raw_record_ref,
                "fetched_at": document.fetched_at,
            },
        )


def _text_or_none(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
