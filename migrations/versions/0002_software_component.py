"""0002_software_component — the current-state software projection.

Expand-only, and deliberately narrow: this adds `software_component` and nothing else.

**Why now, when P2 deferred it.** `AssetRepository.set_current_software` (ports.md §6) is
part of the entity-resolution slice, and it projects into exactly this table. The rest of
the M2/M3 schema — `vulnerability_match`, `triage_snapshot`, `insight` — stays deferred,
because nothing yet needs it. A control (or a table) arrives when the thing that uses it
does, not before (AGENTS.md §5).

The DDL is verbatim from `docs/data/data-model.md` §5, including the partial unique index
that makes "the current set of components for this asset" a database guarantee rather than
an application convention. History is not stored here: it stays in `observation`, which is
append-only. A component that stops being current is flipped to `is_current = false`, never
deleted (AGENTS.md §3).

Revision ID: 0002_software_component
Revises: 0001_expand
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0002_software_component"
down_revision: str | None = "0001_expand"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("""
        create table software_component (
            id             uuid primary key default gen_random_uuid(),
            tenant_id      uuid not null,
            asset_id       uuid not null references asset(id),
            cpe            text,
            name           text not null,
            version        text,
            version_source text not null
                check (version_source in ('package_manager','vendor_api','banner')),
            confidence     double precision not null check (confidence between 0 and 1),
            observation_id uuid references observation(id),
            is_current     boolean not null default true,
            first_seen_at  timestamptz not null,
            last_seen_at   timestamptz not null,
            created_at     timestamptz not null default now()
        )
    """)
    # One current row per (asset, component, version). `coalesce(cpe, name)` is the
    # identity of a component: a CPE when we could map one, its name when we could not.
    op.execute("""
        create unique index software_component_current_unique on software_component
            (tenant_id, asset_id, coalesce(cpe, name), coalesce(version, '')) where is_current
    """)
    op.execute("""
        create index software_component_asset_idx on software_component (asset_id)
            where is_current
    """)
    op.execute("""
        create index software_component_cpe_idx on software_component (cpe)
            where is_current and cpe is not null
    """)


def downgrade() -> None:
    op.execute("drop table if exists software_component")
