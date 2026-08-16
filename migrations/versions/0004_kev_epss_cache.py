"""0004_kev_epss_cache — the two prioritisation signals, cached locally.

Expand-only, and the same shape as `0003_cve_cache` for the same reasons (m3-design §2).

`kev_cache` holds CISA's catalog of CVEs known to be exploited in the wild; `epss_cache`
holds FIRST's per-CVE exploitation probability. `feed_snapshot` records *that a whole
catalog was loaded, and when* — one row per source.

**That third table is the important one.** Without it, "this CVE is not in KEV" is
indistinguishable from "the catalog was never loaded", and a failed refresh would make every
CVE look un-exploited. That is the worst false negative this system could produce: an
actively-exploited vulnerability, silently de-prioritised (AGENTS.md §4.9, §67). The same
idea as `cve_query_cache` in the previous revision, applied to a bulk source.

Neither cache is tenant-scoped: KEV and EPSS are facts about software in the world,
identical for every tenant. The tenant-scoped conclusions land in `vulnerability_match`,
which is P14's.

Revision ID: 0004_kev_epss_cache
Revises: 0003_cve_cache
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0004_kev_epss_cache"
down_revision: str | None = "0003_cve_cache"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # One row per source: "the whole catalog was loaded at this time". A lookup against a
    # source with no snapshot row must fetch, never answer "not listed".
    op.execute("""
        create table feed_snapshot (
            id             uuid primary key default gen_random_uuid(),
            source         text not null check (source in ('cisa_kev','epss')),
            record_count   integer not null default 0 check (record_count >= 0),
            raw_record_ref text,
            fetched_at     timestamptz not null,
            ingested_at    timestamptz not null default now(),
            constraint feed_snapshot_unique unique (source)
        )
    """)

    op.execute("""
        create table kev_cache (
            id                uuid primary key default gen_random_uuid(),
            source            text not null default 'cisa_kev'
                check (source in ('cisa_kev')),
            cve_id            text not null,
            vendor            text,
            product           text,
            name              text,
            date_added        timestamptz,
            due_date          timestamptz,
            known_ransomware  boolean,
            raw_record_ref    text,
            fetched_at        timestamptz not null,
            ingested_at       timestamptz not null default now(),
            constraint kev_cache_unique unique (source, cve_id)
        )
    """)
    op.execute("create index kev_cache_added_idx on kev_cache (date_added desc)")

    op.execute("""
        create table epss_cache (
            id             uuid primary key default gen_random_uuid(),
            source         text not null default 'epss' check (source in ('epss')),
            cve_id         text not null,
            score          double precision not null check (score between 0 and 1),
            percentile     double precision check (percentile between 0 and 1),
            model_version  text,
            scored_at      timestamptz,
            raw_record_ref text,
            fetched_at     timestamptz not null,
            ingested_at    timestamptz not null default now(),
            constraint epss_cache_unique unique (source, cve_id)
        )
    """)
    # The ranking query: "which of these CVEs are most likely to be exploited?"
    op.execute("create index epss_cache_score_idx on epss_cache (score desc)")


def downgrade() -> None:
    op.execute("drop table if exists epss_cache")
    op.execute("drop table if exists kev_cache")
    op.execute("drop table if exists feed_snapshot")
