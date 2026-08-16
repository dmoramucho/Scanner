"""0006_advisory_cache — fetched advisory/fix documents, cached by URL.

Expand-only. One table, holding the reference material the `AdvisoryRetriever` pulls in so
the insight generator can reason over text somebody actually published rather than over a
model's recollection (m3-design §3, AGENTS.md §4.8).

Two constraints carry the safety properties, and both are here rather than only in Python
because the schema is the last line that cannot be refactored away by accident:

* `advisory_document_grounded` — a row claiming `status = 'ok'` must have content. An empty
  document that reads as successfully retrieved is exactly the hollow grounding P15 exists
  to prevent: it would let the generator "ground" on nothing (AGENTS.md §67).
* `status in ('ok','unavailable')` — a reference we asked about and found nothing at is a
  storable answer, so it is not re-fetched every run. It is a *fact about the reference*,
  never a failure; failures raise and are never written.

`content` holds **sanitized** text, not the raw response (ADR-0013). Sanitisation happens
before the write, so nothing that reads this table can reach unsanitised bytes.

Not tenant-scoped, like `cve_cache` and the signal caches: a published advisory is a fact
about software in the world. The tenant-scoped conclusions stay in `vulnerability_match`.

Revision ID: 0006_advisory_cache
Revises: 0005_vulnerability_match
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0006_advisory_cache"
down_revision: str | None = "0005_vulnerability_match"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("""
        create table advisory_document (
            id             uuid primary key default gen_random_uuid(),
            url            text not null,
            status         text not null check (status in ('ok','unavailable')),
            media_type     text,
            content        text not null default '',
            content_hash   text,
            cve_id         text,
            raw_record_ref text,
            fetched_at     timestamptz not null,
            ingested_at    timestamptz not null default now(),
            constraint advisory_document_unique unique (url),
            -- A retrieved document with no text is not grounding material. Refused here so
            -- that "we have an advisory" can never mean "we have an empty string".
            constraint advisory_document_grounded
                check (status <> 'ok' or length(btrim(content)) > 0)
        )
    """)
    # The lookup the retriever actually makes when tracing a CVE's material back.
    op.execute("create index advisory_document_cve_idx on advisory_document (cve_id)")


def downgrade() -> None:
    op.execute("drop table if exists advisory_document")
