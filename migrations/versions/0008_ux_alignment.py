"""0008_ux_alignment — CVSS, an explainable priority, and the review history.

Expand-only, and small on purpose: the UX design (docs/design/ux-design.md) asked for four
things the data model could not answer, and these are three of them. The fourth — VLAN —
needs no schema at all, because `network_segment_label` already exists in the dossier and is
now populated from an operator-configured subnet mapping (ADR-0015).

**CVSS on the match.** NVD publishes it, P12 already parses it, and it was being thrown away
at the correlation step. Nullable throughout: a CVE with no published score keeps `null`
rather than a substituted zero, because a guessed severity becomes a guessed priority.

**Priority, with the rule that produced it.** `priority` is the band; `priority_rule` is the
id of the rule that decided it; `priority_reason` is the sentence an analyst reads. Storing
all three is the point — an interface must be able to show *why* something is P1 without
re-implementing the rules, and a priority that cannot explain itself is the competitor's
failure this product exists to displace (ux-design §2). The CHECK
`vuln_match_priority_explained` makes the explanation structurally inseparable from the
value: no row can carry a band without the rule that produced it.

**The review history.** `insight` already holds current review state, which is what a list
view needs. `insight_review_event` is the append-only history behind it — who decided what,
when, and what changed — the same shape and the same discipline as `asset_merge_event`
(data-model §4). The current-state columns stay as the fast-read projection and are written
in the *same transaction* as the event, so the two can never disagree.

Two new projection columns come with it. `review_outcome` records accept/reject/adjust,
which the contract's `state` (`proposed → human_reviewed → accepted`) cannot express — a
rejection leaves an insight reviewed-and-not-accepted, and the UX needs to show that without
a join. `analyst_recommendation` holds the human's own call when they adjust one, leaving
the model's `recommendation` untouched as evidence of what it actually said. It carries the
same KEV constraint the model's does: the UX is explicit that neither the AI nor the analyst
gets to bury an actively-exploited finding.

Revision ID: 0008_ux_alignment
Revises: 0007_triage_insight
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0008_ux_alignment"
down_revision: str | None = "0007_triage_insight"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # --- gap 1: CVSS, as the feed published it ------------------------------------
    op.execute("""
        alter table vulnerability_match
            add column cvss_score   double precision check (cvss_score between 0 and 10),
            add column cvss_vector  text,
            add column cvss_version text
    """)

    # --- gap 2: an explainable priority --------------------------------------------
    op.execute("""
        alter table vulnerability_match
            add column priority        text not null default 'p4'
                check (priority in ('p1','p2','p3','p4')),
            add column priority_rule   text not null default 'insufficient-signal',
            -- A default that is itself an explanation. Rows written before this revision
            -- get an honest one rather than an empty string the CHECK below would refuse.
            add column priority_reason text not null
                default 'Recorded before priority derivation existed; not yet re-derived.'
    """)
    # A band with no rule behind it is exactly the unexplainable number this product is
    # built against. The database refuses to hold one.
    op.execute("""
        alter table vulnerability_match
            add constraint vuln_match_priority_explained
                check (length(btrim(priority_rule)) > 0 and length(btrim(priority_reason)) > 0)
    """)
    # The worklist query: "what do I look at first", per tenant.
    op.execute("""
        create index vuln_match_priority_idx on vulnerability_match
            (tenant_id, priority, epss desc nulls last) where is_current
    """)

    # --- gap 3: the review history --------------------------------------------------
    op.execute("""
        alter table insight
            add column review_outcome text
                check (review_outcome in ('accepted','rejected','adjusted')),
            add column analyst_recommendation text
                check (analyst_recommendation in
                       ('raise_priority','lower_priority','maintain'))
    """)
    # The same rule the model is held to, applied to the human. The UX is explicit that
    # neither may bury a KEV finding.
    op.execute("""
        alter table insight
            add constraint insight_analyst_kev_not_hidden
                check (not kev_locked_visible
                       or analyst_recommendation is distinct from 'lower_priority')
    """)

    op.execute("""
        create table insight_review_event (
            id             uuid primary key default gen_random_uuid(),
            tenant_id      uuid not null,
            insight_id     uuid not null references insight(id),
            kind           text not null
                check (kind in ('accept','reject','adjust','state_change')),
            from_state     text not null
                check (from_state in ('proposed','human_reviewed','accepted')),
            to_state       text not null
                check (to_state in ('proposed','human_reviewed','accepted')),
            -- The human's own recommendation, when they adjusted one.
            recommendation text
                check (recommendation in ('raise_priority','lower_priority','maintain')),
            reviewer       text not null check (length(btrim(reviewer)) > 0),
            rationale      text,
            -- `clock_timestamp()`, not `now()`: `now()` is the *transaction* start time,
            -- so two decisions recorded in one transaction would share a timestamp and the
            -- history would read back in an arbitrary order.
            occurred_at    timestamptz not null default clock_timestamp(),
            -- An adjustment that adjusts nothing is a state change wearing the wrong label.
            constraint insight_review_adjust_has_change
                check (kind <> 'adjust' or recommendation is not null)
        )
    """)
    op.execute("""
        create index insight_review_event_insight_idx on insight_review_event
            (insight_id, occurred_at)
    """)
    # Append-only, like `asset_merge_event` and `observation`: a review history that can be
    # edited afterwards is not a history (data-model §4).
    op.execute("""
        create trigger insight_review_event_append_only
            before update or delete on insight_review_event
            for each row execute function forbid_mutation()
    """)


def downgrade() -> None:
    op.execute("drop trigger if exists insight_review_event_append_only on insight_review_event")
    op.execute("drop table if exists insight_review_event")
    op.execute("alter table insight drop constraint if exists insight_analyst_kev_not_hidden")
    op.execute("""
        alter table insight
            drop column if exists analyst_recommendation,
            drop column if exists review_outcome
    """)
    op.execute("drop index if exists vuln_match_priority_idx")
    op.execute("""
        alter table vulnerability_match
            drop constraint if exists vuln_match_priority_explained
    """)
    op.execute("""
        alter table vulnerability_match
            drop column if exists priority_reason,
            drop column if exists priority_rule,
            drop column if exists priority,
            drop column if exists cvss_version,
            drop column if exists cvss_vector,
            drop column if exists cvss_score
    """)
