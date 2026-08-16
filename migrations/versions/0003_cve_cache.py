"""0003_cve_cache — the local cache of an external vulnerability feed.

Expand-only. Two tables, and the second one is the interesting one.

`cve_cache` holds the normalized record for each CVE, plus a pointer back to the raw
response it was derived from — the raw/normalized split applied to an external feed
(AGENTS.md §3, m3-design §2). NVD is slow and rate-limited; without this, a correlation run
over a few hundred components would take hours and risk a ban.

`cve_query_cache` records *what we asked and when*. It exists because "we asked NVD about
this CPE and the answer was none" has to be storable. Without it, a CPE with no CVEs is
indistinguishable from a CPE nobody ever looked up — and that ambiguity is a false-negative
path, because an empty result would read as "this component is clean" when it might mean
"we never checked" (AGENTS.md §67).

**Neither table is tenant-scoped, deliberately.** A CVE is a fact about software in the
world, identical for every tenant; scoping it would multiply the fetching by the number of
tenants for nothing. AGENTS.md §2.3 puts `tenant_id` on every *tenant-scoped* table — this
is not one. The tenant-scoped conclusions about our own devices live in
`vulnerability_match`, which is not created here (that is P14).

Revision ID: 0003_cve_cache
Revises: 0002_software_component
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0003_cve_cache"
down_revision: str | None = "0002_software_component"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("""
        create table cve_cache (
            id               uuid primary key default gen_random_uuid(),
            source           text not null default 'nvd' check (source in ('nvd')),
            cve_id           text not null,
            record           jsonb not null,
            content_hash     bytea not null,
            raw_record_ref   text,
            published_at     timestamptz,
            last_modified_at timestamptz,
            fetched_at       timestamptz not null,
            ingested_at      timestamptz not null default now(),
            constraint cve_cache_unique unique (source, cve_id)
        )
    """)
    op.execute("create index cve_cache_fetched_idx on cve_cache (fetched_at)")
    op.execute("create index cve_cache_modified_idx on cve_cache (last_modified_at)")

    op.execute("""
        create table cve_query_cache (
            id             uuid primary key default gen_random_uuid(),
            source         text not null default 'nvd' check (source in ('nvd')),
            cpe            text not null,
            cve_ids        text[] not null default '{}',
            raw_record_ref text,
            fetched_at     timestamptz not null,
            ingested_at    timestamptz not null default now(),
            constraint cve_query_cache_unique unique (source, cpe)
        )
    """)
    # The staleness lookup: "did we ask about this CPE, and was it recently enough?"
    op.execute("create index cve_query_cache_fetched_idx on cve_query_cache (source, fetched_at)")


def downgrade() -> None:
    op.execute("drop table if exists cve_query_cache")
    op.execute("drop table if exists cve_cache")
