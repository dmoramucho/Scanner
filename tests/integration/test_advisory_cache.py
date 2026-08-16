"""The advisory document cache against the real store.

Retrieval logic is covered hermetically in `tests/test_advisory_retriever.py`. This file
asserts what only the database can show: that a retrieved document round-trips intact, that
a re-fetch replaces rather than duplicates, and — the one that matters — that the schema
itself refuses to hold an empty document claiming to have been retrieved. That CHECK is the
last line under "no hollow grounding": Python can be refactored, a constraint cannot be
sidestepped by a caller (AGENTS.md §67, ADR-0013).

Like `cve_cache`, this table is deliberately not tenant-scoped, so isolation comes from the
rolling-back `conn` fixture rather than from a tenant id.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import psycopg
import pytest

from adapters.postgres.advisory_cache import PostgresAdvisoryDocumentCache
from domain.errors import ValidationError
from domain.models import AdvisoryDocument, AdvisoryDocumentStatus

pytestmark = pytest.mark.integration

Connection = psycopg.Connection[tuple[Any, ...]]

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
PATCH_URL = "https://github.com/apache/httpd/commit/4f0e51c0b9e5e1d4bc0e9f0f9b3f0d5f2ab3c1de.patch"
PATCH_TEXT = "Subject: [PATCH] Fix smuggling\n\ndiff --git a/src/proxy.c b/src/proxy.c\n"


def document(**overrides: object) -> AdvisoryDocument:
    fields: dict[str, Any] = {
        "url": PATCH_URL,
        "status": AdvisoryDocumentStatus.OK,
        "content": PATCH_TEXT,
        "media_type": "text/plain",
        "cve_id": "CVE-2023-25690",
        "fetched_at": NOW,
        "raw_record_ref": PATCH_URL,
    }
    fields.update(overrides)
    return AdvisoryDocument(**fields)


def test_a_document_round_trips(conn: Connection) -> None:
    cache = PostgresAdvisoryDocumentCache(conn)

    cache.store(document())
    stored = cache.document(PATCH_URL)

    assert stored is not None
    assert stored.content == PATCH_TEXT
    assert stored.cve_id == "CVE-2023-25690"
    assert stored.media_type == "text/plain"
    assert stored.usable


def test_a_url_never_fetched_is_distinguishable_from_one_with_nothing_at_it(
    conn: Connection,
) -> None:
    """The distinction the negative cache exists for. `None` means nobody has asked;
    `unavailable` means we asked and there was nothing — a different answer, and the reason
    a dead reference is not re-fetched every night."""
    cache = PostgresAdvisoryDocumentCache(conn)

    assert cache.document(PATCH_URL) is None

    cache.store(document(status=AdvisoryDocumentStatus.UNAVAILABLE, content=""))
    asked = cache.document(PATCH_URL)

    assert asked is not None
    assert asked.status is AdvisoryDocumentStatus.UNAVAILABLE
    assert not asked.usable


def test_the_database_refuses_an_empty_document_that_claims_to_be_retrieved(
    conn: Connection,
) -> None:
    """No hollow grounding, enforced by the schema.

    A row saying `status = 'ok'` with no content would let an insight "ground" on an empty
    string. The adapter refuses it and so does the CHECK — this asserts the second, because
    the first is the one that can be refactored away.
    """
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """
            insert into advisory_document (url, status, content, fetched_at)
            values (%s, 'ok', '   ', %s)
            """,
            (PATCH_URL, NOW),
        )


def test_the_adapter_refuses_an_empty_retrieved_document_by_name(conn: Connection) -> None:
    """The same rule one layer up, so the failure names the reason rather than surfacing as
    an integrity error three layers down."""
    cache = PostgresAdvisoryDocumentCache(conn)

    with pytest.raises(ValidationError) as raised:
        cache.store(document(content=""))

    assert "empty document" in str(raised.value)


def test_an_unknown_status_is_refused(conn: Connection) -> None:
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """
            insert into advisory_document (url, status, content, fetched_at)
            values (%s, 'probably', 'text', %s)
            """,
            (PATCH_URL, NOW),
        )


def test_a_refetch_replaces_rather_than_duplicating(conn: Connection) -> None:
    """The question this table answers is "what does this URL say now". A second copy of the
    same URL would make that question ambiguous."""
    cache = PostgresAdvisoryDocumentCache(conn)

    cache.store(document())
    cache.store(document(content=PATCH_TEXT + "one more hunk\n", fetched_at=NOW + timedelta(1)))

    rows = conn.execute(
        "select count(*) from advisory_document where url = %s", (PATCH_URL,)
    ).fetchone()
    stored = cache.document(PATCH_URL)

    assert rows is not None
    assert rows[0] == 1
    assert stored is not None
    assert "one more hunk" in stored.content
    assert stored.fetched_at == NOW + timedelta(1)


def test_a_naive_timestamp_is_refused(conn: Connection) -> None:
    """Everything stored is UTC and says so (AGENTS.md §5)."""
    cache = PostgresAdvisoryDocumentCache(conn)

    with pytest.raises(ValidationError):
        cache.store(document(fetched_at=datetime(2026, 8, 16, 12, 0)))  # noqa: DTZ001


def test_a_content_hash_is_stored_even_when_the_caller_omits_one(conn: Connection) -> None:
    """Tamper-evidence, and a cheap way to see whether a re-fetch changed anything
    (AGENTS.md §3)."""
    cache = PostgresAdvisoryDocumentCache(conn)

    cache.store(document(content_hash=None))
    stored = cache.document(PATCH_URL)

    assert stored is not None
    assert stored.content_hash
