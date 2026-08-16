"""0001_expand — the M0 store schema.

The *expand* phase of `expand → migrate → validate → contract` (AGENTS.md §5): this
revision only adds structure. The DDL is the schema of record from
`docs/data/data-model.md` §5, written by hand as raw SQL — there are no SQLAlchemy models
and `--autogenerate` is not a supported workflow here (ADR-0001).

In scope (M0): `scope_authorization`, `audit_log`, `asset`, `observation`,
`asset_identifier`, `asset_merge_event`, `managed_record`.

Deliberately not in this revision:
  * `software_component`, `vulnerability_match`, `triage_snapshot`, `insight` — M2/M3.
  * Row-level security. `tenant_id` and the query discipline are NOW; RLS enforcement is
    LATER, when a second tenant or external exposure exists (AGENTS.md §5,
    data-model.md §6). The columns are here so that switch is a policy, not a rewrite.

What the database guarantees on its own, without trusting the application:
  * `observation`, `audit_log`, `asset_merge_event` are append-only — UPDATE and DELETE
    are refused by the `forbid_mutation()` trigger.
  * Strong anchors (serial, cert_fingerprint, mac) are unique per tenant; IP and hostname
    are deliberately not, because they rotate and are locators, not identity.
  * A merged asset points at a survivor and is never deleted; an LLM-proposed merge
    without a rationale is rejected.

Revision ID: 0001_expand
Revises:
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0001_expand"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # gen_random_uuid(); a recognised primitive rather than home-rolled ID generation.
    op.execute("create extension if not exists pgcrypto")

    # Append-only enforcement. Immutability is a database guarantee, not a convention
    # (data-model.md §4) — the application cannot opt out of it, and neither can psql.
    op.execute("""
        create or replace function forbid_mutation() returns trigger
            language plpgsql as $$
        begin
            raise exception 'append-only table %: % is not permitted', tg_table_name, tg_op;
        end $$
    """)

    # --- governance & tenancy ------------------------------------------------------
    # Backs the scope allowlist ENFORCED IN THE ENGINE before a packet is emitted
    # (AGENTS.md §2.5). Deny-by-default lives in the engine; this table is its evidence.
    op.execute("""
        create table scope_authorization (
            id               uuid primary key default gen_random_uuid(),
            tenant_id        uuid not null,
            cidr             cidr not null,
            written_auth_ref text not null,
            active           boolean not null default true,
            authorized_at    timestamptz not null,
            expires_at       timestamptz,
            created_at       timestamptz not null default now(),
            constraint scope_auth_window check (expires_at is null or expires_at > authorized_at)
        )
    """)
    op.execute("create index scope_auth_tenant_idx on scope_authorization (tenant_id) where active")
    # Hot path: "is this target inside any authorized range?"  cidr >>= $target
    # inet/cidr has a built-in SP-GiST opclass supporting containment operators.
    op.execute("""
        create index scope_auth_contains_idx on scope_authorization
            using spgist (cidr) where active
    """)

    # Audit log — separate from operational logs. Append-only.
    op.execute("""
        create table audit_log (
            id             uuid primary key default gen_random_uuid(),
            tenant_id      uuid,
            actor          text not null,
            actor_type     text not null check (actor_type in ('user','service','agent','system')),
            action         text not null,
            resource_type  text not null,
            resource_id    text,
            result         text not null check (result in ('success','denied','error')),
            request_id     text,
            correlation_id text,
            source_ip      inet,
            metadata       jsonb not null default '{}'::jsonb,
            occurred_at    timestamptz not null default now()
        )
    """)
    op.execute("create index audit_tenant_time_idx on audit_log (tenant_id, occurred_at desc)")
    op.execute("create index audit_resource_idx on audit_log (resource_type, resource_id)")
    op.execute("""
        create trigger audit_log_append_only before update or delete on audit_log
            for each row execute function forbid_mutation()
    """)

    # --- normalized / current-state: the resolved asset ----------------------------
    op.execute("""
        create table asset (
            id                        uuid primary key default gen_random_uuid(),
            tenant_id                 uuid not null,
            asset_class               text not null default 'unknown'
                check (asset_class in
                    ('server','embedded','application','network_device','unknown')),
            management_state          text not null default 'unknown'
                check (management_state in ('managed','unmanaged','unknown')),
            identification_confidence double precision not null default 0
                check (identification_confidence between 0 and 1),
            status                    text not null default 'active'
                check (status in ('active','merged')),
            merged_into               uuid references asset(id),
            first_seen_at             timestamptz not null,
            last_seen_at              timestamptz not null,
            created_at                timestamptz not null default now(),
            updated_at                timestamptz not null default now(),
            constraint asset_merge_consistent check (
                (status = 'merged' and merged_into is not null) or
                (status = 'active' and merged_into is null)
            )
        )
    """)
    op.execute("create index asset_tenant_idx on asset (tenant_id) where status = 'active'")

    # --- provenance spine: observation (append-only) -------------------------------
    op.execute("""
        create table observation (
            id                uuid primary key default gen_random_uuid(),
            tenant_id         uuid not null,
            asset_id          uuid references asset(id),
            observation_type  text not null,
            payload           jsonb not null,
            source            text not null,
            source_type       text not null,
            source_identifier text,
            collector         text not null,
            collector_version text not null,
            collection_method text not null,
            version_source    text
                check (version_source in ('package_manager','vendor_api','banner')),
            confidence        double precision not null check (confidence between 0 and 1),
            content_hash      bytea not null,
            raw_record_ref    text,
            observed_at       timestamptz not null,
            collected_at      timestamptz not null,
            ingested_at       timestamptz not null default now(),
            run_id            uuid not null
        )
    """)
    # Idempotent ingestion: retries WITHIN a run land once; a new run re-observing the same
    # thing is a NEW row (re-observation is evidence, not noise).
    op.execute("""
        create unique index observation_dedup on observation
            (tenant_id, run_id, coalesce(source_identifier, ''), observation_type, content_hash)
    """)
    op.execute("""
        create index observation_asset_time_idx on observation (asset_id, observed_at desc)
    """)
    op.execute("create index observation_run_idx on observation (run_id)")
    op.execute("""
        create trigger observation_append_only before update or delete on observation
            for each row execute function forbid_mutation()
    """)

    # --- identity anchors ----------------------------------------------------------
    op.execute("""
        create table asset_identifier (
            id             uuid primary key default gen_random_uuid(),
            tenant_id      uuid not null,
            asset_id       uuid not null references asset(id),
            kind           text not null
                check (kind in ('mac','serial','cert_fingerprint','hostname','ip')),
            value          text not null,
            confidence     double precision not null check (confidence between 0 and 1),
            observation_id uuid references observation(id),
            first_seen_at  timestamptz not null,
            last_seen_at   timestamptz not null,
            created_at     timestamptz not null default now()
        )
    """)
    # Strong anchors are unique per tenant (they drive entity resolution). IP/hostname
    # rotate and are deliberately NOT constrained unique — locators, not durable identity.
    op.execute("""
        create unique index asset_identifier_strong_unique on asset_identifier
            (tenant_id, kind, value) where kind in ('serial','cert_fingerprint','mac')
    """)
    op.execute("""
        create index asset_identifier_lookup_idx on asset_identifier (tenant_id, kind, value)
    """)
    op.execute("create index asset_identifier_asset_idx on asset_identifier (asset_id)")

    # --- reversible merges (append-only) -------------------------------------------
    # A reversal is a new event row, never an update — that is how "merges are reversible"
    # and "evidence is immutable" hold at the same time (AGENTS.md §3).
    op.execute("""
        create table asset_merge_event (
            id            uuid primary key default gen_random_uuid(),
            tenant_id     uuid not null,
            kind          text not null check (kind in ('merge','reversal')),
            survivor_id   uuid not null references asset(id),
            merged_id     uuid not null references asset(id),
            reverses_id   uuid references asset_merge_event(id),
            derivation    text not null check (derivation in ('deterministic','llm_proposed')),
            rationale     text,
            confidence    double precision check (confidence between 0 and 1),
            model_version text,
            created_at    timestamptz not null default now(),
            constraint merge_not_self check (survivor_id <> merged_id),
            constraint merge_llm_has_rationale
                check (derivation <> 'llm_proposed' or rationale is not null),
            constraint reversal_targets_a_merge
                check (kind <> 'reversal' or reverses_id is not null)
        )
    """)
    op.execute("create index merge_event_survivor_idx on asset_merge_event (survivor_id)")
    op.execute("""
        create trigger merge_event_append_only before update or delete on asset_merge_event
            for each row execute function forbid_mutation()
    """)

    # --- external knowledge: managed records (backs the shadow-IT diff) -------------
    # Shadow IT = active assets with no managed_record from an IAM source. Derivable;
    # no extra table.
    op.execute("""
        create table managed_record (
            id          uuid primary key default gen_random_uuid(),
            tenant_id   uuid not null,
            source      text not null check (source in ('ad','mdm','edr','vcenter','cmdb')),
            external_id text not null,
            asset_id    uuid references asset(id),
            payload     jsonb not null default '{}'::jsonb,
            observed_at timestamptz not null,
            ingested_at timestamptz not null default now(),
            constraint managed_record_unique unique (tenant_id, source, external_id)
        )
    """)
    op.execute("create index managed_record_asset_idx on managed_record (asset_id)")


def downgrade() -> None:
    """Reverse dependency order — a real rollback path, not a database reset.

    Indexes and triggers fall with their tables; `forbid_mutation()` is dropped after the
    tables that reference it. `pgcrypto` is intentionally left installed: it is a
    database-wide extension this revision did not necessarily introduce, and dropping it
    could break anything else in the database that uses `gen_random_uuid()`.
    """
    op.execute("drop table if exists managed_record")
    op.execute("drop table if exists asset_merge_event")
    op.execute("drop table if exists asset_identifier")
    op.execute("drop table if exists observation")
    op.execute("drop table if exists asset")
    op.execute("drop table if exists audit_log")
    op.execute("drop table if exists scope_authorization")
    op.execute("drop function if exists forbid_mutation()")
