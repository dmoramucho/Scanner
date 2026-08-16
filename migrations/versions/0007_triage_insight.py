"""0007_triage_insight — the retained snapshot, and the insight it backs.

Expand-only. The last two tables in the design, and the two that hold the AI to its
contract. These have been named in the dossier contract since M0 and deliberately not
created until the feature that needs them arrived (AGENTS.md §5).

`triage_snapshot` is **exactly what the model was given**, stored before it is given: the
redacted asset dossier, the retrieved advisory evidence, and the deterministic match, as one
immutable JSON document. It carries the append-only trigger for the same reason
`observation` does — an insight whose evidence can be edited afterwards is not auditable,
and the audit is the entire claim this system makes about its AI (dossier contract §2, §8).

`insight` is the model's *proposal*. Three constraints turn the design's rules into things
the database will not let us get wrong, whatever a future refactor does to the Python:

* `insight_must_be_grounded` — `cited_sources` cannot be empty. An ungrounded insight is a
  claim with nothing behind it, which is the shape a hallucination arrives in
  (AGENTS.md §4.8, contract §7).
* `insight_kev_not_hidden` — an insight on a KEV-locked finding cannot recommend
  `lower_priority`. CISA says this vulnerability is being exploited *right now*; no model
  gets to argue it down the page (contract §7, AGENTS.md §2.8).
* `insight_derivation` — `llm_generated`, always. The same statement `vulnerability_match`
  makes in the other direction: that table cannot hold an LLM's opinion, and this one cannot
  pretend to be deterministic.

Plus `insight_review_recorded`: a state past `proposed` must name the human who moved it
there. The recommendation is advisory until a person accepts it, and "a person accepted it"
has to mean a specific person (AGENTS.md §2.8).

Tenant-scoped, like `vulnerability_match`: an insight is a statement about one tenant's
estate.

Revision ID: 0007_triage_insight
Revises: 0006_advisory_cache
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0007_triage_insight"
down_revision: str | None = "0006_advisory_cache"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("""
        create table triage_snapshot (
            id             uuid primary key default gen_random_uuid(),
            tenant_id      uuid not null,
            asset_id       uuid not null references asset(id),
            match_id       uuid references vulnerability_match(id),
            cve_id         text not null,
            -- The whole TriageDossier: redacted dossier + advisory evidence + match.
            snapshot       jsonb not null,
            -- Tamper-evidence over the exact bytes the model was handed.
            content_hash   bytea not null,
            model_version  text,
            assembler_version text not null,
            created_at     timestamptz not null default now(),
            constraint triage_snapshot_has_content check (snapshot <> '{}'::jsonb)
        )
    """)
    op.execute("create index triage_snapshot_asset_idx on triage_snapshot (tenant_id, asset_id)")
    op.execute("create index triage_snapshot_cve_idx on triage_snapshot (tenant_id, cve_id)")
    # Immutable, like `observation` and `audit_log`: what the model saw cannot be rewritten
    # after the fact, or the insight it backs proves nothing.
    op.execute("""
        create trigger triage_snapshot_append_only before update or delete on triage_snapshot
            for each row execute function forbid_mutation()
    """)

    op.execute("""
        create table insight (
            id                 uuid primary key default gen_random_uuid(),
            tenant_id          uuid not null,
            triage_id          uuid not null references triage_snapshot(id),
            recommendation     text not null
                check (recommendation in ('raise_priority','lower_priority','maintain')),
            rationale          text not null check (length(btrim(rationale)) > 0),
            cited_sources      jsonb not null default '[]'::jsonb,
            confidence         double precision not null check (confidence between 0 and 1),
            derivation         text not null default 'llm_generated',
            model_version      text not null,
            state              text not null default 'proposed'
                check (state in ('proposed','human_reviewed','accepted')),
            kev_locked_visible boolean not null default false,
            reviewed_by        text,
            reviewed_at        timestamptz,
            created_at         timestamptz not null default now(),
            updated_at         timestamptz not null default now(),

            -- An insight cites something real, or it is not an insight.
            constraint insight_must_be_grounded
                check (jsonb_typeof(cited_sources) = 'array'
                       and jsonb_array_length(cited_sources) > 0),
            -- A KEV finding cannot be argued down the page by a model.
            constraint insight_kev_not_hidden
                check (not kev_locked_visible or recommendation <> 'lower_priority'),
            -- This table holds the model's opinion, and says so.
            constraint insight_derivation check (derivation = 'llm_generated'),
            -- Past `proposed`, a specific human owns the decision.
            constraint insight_review_recorded
                check (state = 'proposed' or (reviewed_by is not null and reviewed_at is not null)),
            -- One insight per snapshot: re-running triage writes a new snapshot.
            constraint insight_per_snapshot unique (triage_id)
        )
    """)
    op.execute("create index insight_tenant_state_idx on insight (tenant_id, state)")
    # The operator's view: what is exploited and still waiting on a human.
    op.execute("""
        create index insight_kev_idx on insight (tenant_id, created_at desc)
            where kev_locked_visible
    """)


def downgrade() -> None:
    op.execute("drop table if exists insight")
    op.execute("drop trigger if exists triage_snapshot_append_only on triage_snapshot")
    op.execute("drop table if exists triage_snapshot")
