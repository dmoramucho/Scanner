# Store Schema

`docs/data/data-model.md` · migration `0001` (expand phase) · Postgres 14+

The relational store the dossier (`asset-dossier-contract.md`) projects from, and that every collection adapter writes into. This is the schema of record. The DDL below is the *expand* phase of migration `0001` — it adds structure without breaking anything, per `expand → migrate → validate → contract` (AGENTS.md §5).

Every field in the dossier contract has a home here, or is derivable from one (contract §9).

---

## 1. Principles encoded at the database layer

The database protects integrity — it does not trust the application to (AGENTS.md §3, master-doc §15). Concretely:

- **Provenance is first-class**, but modelled DRY (§2 below).
- **Observation ≠ entity.** One real asset, many observations; history is queryable (§3).
- **Evidence and lineage are immutable**, with tamper-evidence (§4).
- **Merges are reversible**; merged assets are never hard-deleted (§4).
- **Two product invariants are enforced as CHECK constraints**, not left to app code: an insight cannot be ungrounded, and a KEV finding cannot be hidden by the AI (§ `insight`).
- **`tenant_id` on every tenant-scoped table** — the column and the query discipline are NOW; RLS enforcement is deferred to LATER and provided, marked, in §6 (AGENTS.md §5).

**Conventions:** UUID primary keys; `timestamptz` everywhere, stored UTC; `text + CHECK` instead of native `ENUM` (far friendlier to `expand→contract` migrations); one collection = one `run_id`.

---

## 2. Design decision — provenance lives on `observation`

Repeating the ~12 provenance columns on every table is noise and drifts out of sync. Instead: **`observation` is the provenance record of record.** It carries the full provenance envelope. Current-state tables (`asset_identifier`, `software_component`) reference the `observation` that asserts them. Derived-fact tables (`vulnerability_match`, `insight`) carry their own generation metadata (`run_id` / `model_version` / `derivation` / timestamps), because their "source" is a computation, not a collection.

This keeps provenance complete and auditable without redundancy, and it means the LLM can only cite what traces back to an `observation` (contract §8.2).

## 3. Design decision — `observation` is the history spine

`observation` is **append-only**. Every reading from every source at every point in time is an immutable row. That *is* the historical record: "what did this asset look like on date X?" is `... where asset_id = $1 and observed_at <= $X`. Current-state tables hold only the current projection (`is_current`), derived from observations. This gives us history and current-state without temporal-table machinery or event sourcing (AGENTS.md §5 / §4.11).

## 4. Design decision — immutability & tamper-evidence

Append-only tables (`observation`, `audit_log`, `asset_merge_event`, `triage_snapshot`) are enforced with a trigger that forbids `UPDATE`/`DELETE` — immutability is a database guarantee, not a convention (master-doc §11). Integrity-critical rows carry a `content_hash` (sha256) so later alteration is detectable (master-doc §12; recognised primitive, no home-rolled crypto). Reversible merges stay append-only by modelling a reversal as a *new event row*, never an update.

---

## 5. DDL — migration 0001 (expand)

```sql
create extension if not exists pgcrypto;   -- gen_random_uuid()

-- Append-only enforcement (attached to the immutable tables below).
create or replace function forbid_mutation() returns trigger
    language plpgsql as $$
begin
    raise exception 'append-only table %: % is not permitted', tg_table_name, tg_op;
end $$;
```

### Governance & tenancy

```sql
-- Backs the scope allowlist ENFORCED IN THE ENGINE before a packet is emitted (AGENTS.md §2.5).
create table scope_authorization (
    id               uuid primary key default gen_random_uuid(),
    tenant_id        uuid not null,
    cidr             cidr not null,
    written_auth_ref text not null,                    -- reference to the signed authorization
    active           boolean not null default true,
    authorized_at    timestamptz not null,
    expires_at       timestamptz,
    created_at       timestamptz not null default now(),
    constraint scope_auth_window check (expires_at is null or expires_at > authorized_at)
);
create index scope_auth_tenant_idx on scope_authorization (tenant_id) where active;
-- Hot path: "is this target inside any authorized range?"  cidr >>= $target
-- inet/cidr has a built-in SP-GiST opclass supporting containment operators.
create index scope_auth_contains_idx on scope_authorization using spgist (cidr) where active;

-- Audit log — separate from operational logs (master-doc §14). Append-only.
create table audit_log (
    id             uuid primary key default gen_random_uuid(),
    tenant_id      uuid,                               -- null for tenant-agnostic system actions
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
);
create index audit_tenant_time_idx on audit_log (tenant_id, occurred_at desc);
create index audit_resource_idx on audit_log (resource_type, resource_id);
create trigger audit_log_append_only before update or delete on audit_log
    for each row execute function forbid_mutation();
```

### Normalized / current-state: the resolved asset

```sql
create table asset (
    id                        uuid primary key default gen_random_uuid(),
    tenant_id                 uuid not null,
    asset_class               text not null default 'unknown'
        check (asset_class in ('server','embedded','application','network_device','unknown')),
    management_state          text not null default 'unknown'
        check (management_state in ('managed','unmanaged','unknown')),
    identification_confidence double precision not null default 0
        check (identification_confidence between 0 and 1),
    -- reversible-merge support: a merged asset is never deleted; it points to its survivor.
    status                    text not null default 'active' check (status in ('active','merged')),
    merged_into               uuid references asset(id),
    first_seen_at             timestamptz not null,
    last_seen_at              timestamptz not null,
    created_at                timestamptz not null default now(),
    updated_at                timestamptz not null default now(),
    constraint asset_merge_consistent check (
        (status = 'merged' and merged_into is not null) or
        (status = 'active' and merged_into is null)
    )
);
create index asset_tenant_idx on asset (tenant_id) where status = 'active';
```

### Provenance spine: observation (append-only)

```sql
create table observation (
    id                uuid primary key default gen_random_uuid(),
    tenant_id         uuid not null,
    asset_id          uuid references asset(id),       -- null: may arrive before entity resolution
    observation_type  text not null,                   -- 'open_ports'|'software'|'firmware'|'identity'|'security_flag'|...
    payload           jsonb not null,                  -- the NORMALIZED observation (never secret-bearing)
    -- full provenance envelope (this table is the record of record — §2)
    source            text not null,                   -- 'nmap'|'ad_ldap'|'vapix'|'snmp'|...
    source_type       text not null,                   -- 'active_scan'|'authoritative'|'credentialed'|'passive'
    source_identifier text,
    collector         text not null,
    collector_version text not null,
    collection_method text not null,
    version_source    text check (version_source in ('package_manager','vendor_api','banner')),
    confidence        double precision not null check (confidence between 0 and 1),
    -- tamper-evidence + raw linkage
    content_hash      bytea not null,                  -- sha256(payload)
    raw_record_ref    text,                            -- pointer to raw object in MinIO; never inline secrets
    -- distinguished timestamps (master-doc §61)
    observed_at       timestamptz not null,
    collected_at      timestamptz not null,
    ingested_at       timestamptz not null default now(),
    run_id            uuid not null
);
-- Idempotent ingestion: retries WITHIN a run land once; a new run re-observing the same
-- thing is a NEW row (freshness/history preserved — re-observation is evidence, master-doc §18).
create unique index observation_dedup on observation
    (tenant_id, run_id, coalesce(source_identifier, ''), observation_type, content_hash);
create index observation_asset_time_idx on observation (asset_id, observed_at desc);  -- history queries
create index observation_run_idx on observation (run_id);
create trigger observation_append_only before update or delete on observation
    for each row execute function forbid_mutation();
```

### Identity anchors

```sql
create table asset_identifier (
    id             uuid primary key default gen_random_uuid(),
    tenant_id      uuid not null,
    asset_id       uuid not null references asset(id),
    kind           text not null check (kind in ('mac','serial','cert_fingerprint','hostname','ip')),
    value          text not null,
    confidence     double precision not null check (confidence between 0 and 1),
    observation_id uuid references observation(id),    -- which observation asserted it (provenance link)
    first_seen_at  timestamptz not null,
    last_seen_at   timestamptz not null,
    created_at     timestamptz not null default now()
);
-- Strong anchors are unique per tenant (they drive ER). IP/hostname rotate and are
-- deliberately NOT constrained unique — they are locators, not durable identity.
create unique index asset_identifier_strong_unique on asset_identifier (tenant_id, kind, value)
    where kind in ('serial','cert_fingerprint','mac');
create index asset_identifier_lookup_idx on asset_identifier (tenant_id, kind, value);
create index asset_identifier_asset_idx on asset_identifier (asset_id);
```

### Reversible merges (append-only)

```sql
create table asset_merge_event (
    id            uuid primary key default gen_random_uuid(),
    tenant_id     uuid not null,
    kind          text not null check (kind in ('merge','reversal')),
    survivor_id   uuid not null references asset(id),
    merged_id     uuid not null references asset(id),
    reverses_id   uuid references asset_merge_event(id),  -- set when kind = 'reversal'
    derivation    text not null check (derivation in ('deterministic','llm_proposed')),
    rationale     text,                                    -- required when llm_proposed
    confidence    double precision check (confidence between 0 and 1),
    model_version text,
    created_at    timestamptz not null default now(),
    constraint merge_not_self check (survivor_id <> merged_id),
    constraint merge_llm_has_rationale check (derivation <> 'llm_proposed' or rationale is not null),
    constraint reversal_targets_a_merge check (kind <> 'reversal' or reverses_id is not null)
);
create index merge_event_survivor_idx on asset_merge_event (survivor_id);
create trigger merge_event_append_only before update or delete on asset_merge_event
    for each row execute function forbid_mutation();
```

### External knowledge: managed records (backs the shadow-IT diff)

```sql
create table managed_record (
    id          uuid primary key default gen_random_uuid(),
    tenant_id   uuid not null,
    source      text not null check (source in ('ad','mdm','edr','vcenter','cmdb')),
    external_id text not null,
    asset_id    uuid references asset(id),             -- null = known to IAM but not yet matched
    payload     jsonb not null default '{}'::jsonb,
    observed_at timestamptz not null,
    ingested_at timestamptz not null default now(),
    constraint managed_record_unique unique (tenant_id, source, external_id)
);
create index managed_record_asset_idx on managed_record (asset_id);
-- Shadow IT = active assets with no managed_record from an IAM source. Derivable, no extra table.
```

### Current-state: software components (derived from observations)

```sql
create table software_component (
    id             uuid primary key default gen_random_uuid(),
    tenant_id      uuid not null,
    asset_id       uuid not null references asset(id),
    cpe            text,
    name           text not null,
    version        text,
    version_source text not null check (version_source in ('package_manager','vendor_api','banner')),
    confidence     double precision not null check (confidence between 0 and 1),
    observation_id uuid references observation(id),    -- the observation currently asserting it
    is_current     boolean not null default true,
    first_seen_at  timestamptz not null,
    last_seen_at   timestamptz not null,
    created_at     timestamptz not null default now()
);
create unique index software_component_current_unique on software_component
    (tenant_id, asset_id, coalesce(cpe, name), coalesce(version, '')) where is_current;
create index software_component_asset_idx on software_component (asset_id) where is_current;
create index software_component_cpe_idx on software_component (cpe)
    where is_current and cpe is not null;
```

### Derived: vulnerability matches

```sql
create table vulnerability_match (
    id               uuid primary key default gen_random_uuid(),
    tenant_id        uuid not null,
    asset_id         uuid not null references asset(id),
    component_id     uuid references software_component(id),
    cve_id           text not null,
    matched_cpe      text not null,
    version_source   text not null check (version_source in ('package_manager','vendor_api','banner')),
    confidence_state text not null
        check (confidence_state in ('confirmed','probable','verified_exploitable')),
    kev              boolean not null default false,
    epss             double precision check (epss between 0 and 1),
    -- The match is ALWAYS deterministic — the LLM never decides it (AGENTS.md §2.8).
    derivation       text not null default 'deterministic' check (derivation = 'deterministic'),
    run_id           uuid,
    matched_at       timestamptz not null default now(),
    is_current       boolean not null default true,
    constraint vuln_match_unique unique (tenant_id, asset_id, cve_id, matched_cpe)
);
create index vuln_match_asset_idx on vulnerability_match (asset_id) where is_current;
create index vuln_match_kev_idx on vulnerability_match (tenant_id) where is_current and kev;
```

### Lineage: retained triage snapshot (append-only)

```sql
-- The exact TriageDossier the model saw, retained immutably so any insight is reconstructable
-- (contract §2, master-doc §10). content_hash gives tamper-evidence.
create table triage_snapshot (
    id           uuid primary key default gen_random_uuid(),
    tenant_id    uuid not null,
    match_id     uuid not null references vulnerability_match(id),
    payload      jsonb not null,                        -- the full TriageDossier, verbatim
    content_hash bytea not null,                        -- sha256(payload)
    created_at   timestamptz not null default now()
);
create index triage_snapshot_match_idx on triage_snapshot (match_id);
create trigger triage_snapshot_append_only before update or delete on triage_snapshot
    for each row execute function forbid_mutation();
```

### Derived: insight (LLM output; product invariants enforced by the DB)

```sql
create table insight (
    id                 uuid primary key default gen_random_uuid(),
    tenant_id          uuid not null,
    triage_snapshot_id uuid not null references triage_snapshot(id),
    recommendation     text not null
        check (recommendation in ('raise_priority','lower_priority','maintain')),
    rationale          text not null,
    cited_sources      jsonb not null,
    confidence         double precision not null check (confidence between 0 and 1),
    derivation         text not null default 'llm_generated' check (derivation = 'llm_generated'),
    model_version      text not null,
    state              text not null default 'proposed'
        check (state in ('proposed','human_reviewed','accepted')),
    kev_locked_visible boolean not null default false,
    created_at         timestamptz not null default now(),
    reviewed_at        timestamptz,
    reviewed_by        text,
    -- Invariant 1: an ungrounded insight cannot exist (contract §7, AGENTS.md §4.8).
    constraint insight_must_be_grounded check (jsonb_array_length(cited_sources) >= 1),
    -- Invariant 2: the AI may not hide a KEV finding (contract §8.5, AGENTS.md §2.8).
    constraint insight_kev_not_hidden check (
        not kev_locked_visible or recommendation <> 'lower_priority'
    )
);
create index insight_snapshot_idx on insight (triage_snapshot_id);
```

> `insight` is mutable only along the review path (`state`, `reviewed_at`, `reviewed_by`) — it is not append-only, but the two CHECK invariants hold on every write.

---

## 6. Tenant isolation (RLS) — deferred, provided

Per AGENTS.md §5, the `tenant_id` column and query discipline are NOW; **full RLS enforcement is deferred** until a second tenant or external exposure exists. When that trigger arrives, enable it per tenant-scoped table and ship the cross-tenant negative tests alongside (master-doc §21, §75). The pattern:

```sql
-- LATER — do not enable in M0.
-- alter table asset enable row level security;
-- create policy asset_tenant_isolation on asset
--     using (tenant_id = current_setting('app.tenant_id')::uuid);
-- (repeat for every tenant-scoped table; add a test asserting tenant A cannot read tenant B.)
```

---

## 7. Migration & next step

This DDL is `0001_expand`. It only adds; nothing to migrate or contract yet. Validation for this migration: the append-only triggers reject `UPDATE`/`DELETE` on the four immutable tables, the two `insight` invariants reject ungrounded / KEV-hidden rows, and the scope containment index answers `cidr >>= $target`.

Next artifacts, in dependency order:
1. **Port contracts** — `ObservationSink` (idempotent write into `observation`), `AssetRepository` (resolve + current-state projection), `ScopeAuthority` (the engine's pre-flight check against `scope_authorization`), `SecretsPort`, `AdvisoryRetriever` (RAG grounding), `InsightGenerator`. These are the seams the adapters plug into.
2. **P-series build prompts for M0** — starting with the collector + `ScopeAuthority` enforcement + passive sweep, then the ingestion path into `observation`, then entity resolution into `asset`. Continues your existing P-numbering.
