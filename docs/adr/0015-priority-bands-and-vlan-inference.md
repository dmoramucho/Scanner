# ADR-0015 — Priority bands, the review history, and VLAN inference

- **Status:** accepted
- **Date:** 2026-08-16
- **Stage:** P17 (aligning the data model with the final UX). No new capability — four fields
  the interface needs, each carrying where it came from.
- **Context refs:** AGENTS.md §2.2 (derivation on every fact), §2.8 (LLM proposes,
  deterministic disposes), §3 (provenance; deterministic anchors win), §4.9 (a false negative
  we introduce is a hole we created), §4.11 (don't overengineer), §5 (NOW-tier), §6 (validate
  config at startup), §67 (a failure is not an empty result); `docs/design/ux-design.md` §2,
  §3.1, §4; `docs/data/data-model.md` §2–§4; the dossier contract §4, §5, §7;
  [ADR-0009](0009-reconciliation-and-shadow-it.md), [ADR-0014](0014-contained-insight-generation.md).

## Context

The UX design surfaced four things the data model could not answer. Three are columns; one is
a mapping. The rule over all of them is the same one this product is built on: **every field is
explainable and says where it came from**. The competitor's failure being displaced here is a
0–100 risk score nobody can account for, so a priority that cannot explain itself would
reproduce the exact problem the product exists to solve.

## Decision

**1. CVSS is persisted on the match, from the feed, or not at all.**

P12 already parsed `cvss_score` / `cvss_vector` / `cvss_version` out of NVD and P14 was
discarding them. They are now carried through correlation onto `vulnerability_match`, nullable
throughout. A CVE NVD has not scored keeps `null` — never a substituted zero, because a guessed
severity silently becomes a guessed priority.

**2. Priority is an ordered list of named rules, first match wins.**

Not a weighted formula. `engine/priority.py` holds the whole policy as a readable table, and
`derive_priority` returns three things that are all persisted: the band, the **rule id** that
produced it, and a **sentence naming the actual evidence and the actual threshold**. The CHECK
`vuln_match_priority_explained` refuses a row carrying a band without them, and
`VulnerabilityMatchInput` makes them required fields with no defaults — so a priority that
cannot explain itself is unrepresentable in the type system *and* in the schema.

The rules, in evaluation order:

| # | rule | condition | band |
|---|---|---|---|
| 1 | `verified-exploitable` | exploitability demonstrated on this asset | **P1** |
| 2 | `kev-actively-exploited` | in CISA KEV — any confidence | **P1** |
| 3 | `actionable-high-epss` | confirmed ∧ EPSS ≥ 0.10 | **P1** |
| 4 | `actionable-critical-cvss` | confirmed ∧ CVSS ≥ 9.0 | **P2** |
| 5 | `actionable-elevated-epss` | confirmed ∧ EPSS ≥ 0.01 | **P2** |
| 6 | `actionable-high-cvss` | confirmed ∧ CVSS ≥ 7.0 | **P2** |
| 7 | `probable-high-epss` | EPSS ≥ 0.10, version unverified | **P2** |
| 8 | `actionable-moderate` | confirmed, nothing severe or likely | **P3** |
| 9 | `probable-severe-unverified` | CVSS ≥ 7.0 ∨ EPSS ≥ 0.01, unverified | **P3** |
| 10 | `probable-unverified` | banner-inferred, low signal | **P4** |
| — | `insufficient-signal` | nothing published either way | **P4** |

Three properties of that ordering are the product decisions worth arguing about:

* **Exploitation outranks severity.** A CVSS 9.8 nobody exploits is a worse use of an afternoon
  than a CVSS 6.5 being used today. So EPSS and KEV sit above CVSS.
* **Confirmed outranks probable at every severity.** A banner-inferred version may already be
  patched by a distribution backport; sending an analyst to patch that is how a scanner loses
  their trust. `probable` is a *verification* queue (ux-design §3.1's "needs verification"), and
  it never reaches P1 on its own.
* **Absence is not a low score.** FIRST not having scored a CVE says nothing about it; treating
  a missing EPSS as 0.0 would push everything newly published to the bottom of the worklist.

**Every threshold is somebody else's published number.** EPSS ≥ 0.10 is the commonly cited
operational cut for "likely to be exploited" and ≥ 0.01 already puts a CVE in the top few
percent of everything FIRST scores; CVSS 9.0 and 7.0 are the v3 standard's own critical/high
boundaries. Nothing here is a number chosen because it felt right — which is what makes a band
defensible to a CISO who wants to argue with one.

**KEV has a floor, enforced as a clamp.** `KEV_FLOOR = P2`, applied after rule selection rather
than trusted to rule ordering. The KEV rule already returns P1, so it should never fire; it
exists because "should never fire" is what a rule inserted in the wrong place two years from now
will quietly disprove. A test evaluates every rule against every combination of KEV inputs and
asserts none can go below the floor.

**3. Review history is an append-only event log beside the current-state projection.**

`insight` keeps `state` / `reviewed_by` / `reviewed_at` as the fast read a list view needs;
`insight_review_event` is the immutable record of what happened, with the `forbid_mutation`
trigger, exactly like `asset_merge_event`. Both writes commit in one transaction, as the merge
path does — a projection that can disagree with its own history is worse than no projection.

Two consequences of keeping the dossier contract intact:

* **"Rejected" is not a new state.** The contract fixes `state` at
  `proposed → human_reviewed → accepted`, and a rejection is an insight reviewed and *not*
  accepted. Rather than widen a contract type, a `review_outcome` column
  (`accepted`/`rejected`/`adjusted`) records the decision beside the state, so the UI shows it
  without a join. If M4 needs a persistent `rejected` badge in the lifecycle itself, that is a
  contract change with a review attached.
* **"Adjusted" means the analyst recorded their own recommendation**, stored in
  `analyst_recommendation`. The model's `recommendation` is never overwritten: it is evidence of
  what the model actually said. An adjustment with no recommendation is refused by the adapter
  and by `insight_review_adjust_has_change`.

The analyst's recommendation carries the **same KEV constraint the model's does**
(`insight_analyst_kev_not_hidden`). The UX is explicit: neither the AI nor the analyst gets to
bury an actively-exploited finding.

`occurred_at` defaults to `clock_timestamp()`, not `now()`. `now()` is the transaction start
time, so two decisions recorded in one transaction would share a timestamp and the history would
read back in an arbitrary order.

**4. VLAN is inferred from an operator-configured subnet map, and says so.**

`SCANNER_VLAN_MAP` (inline JSON) or `SCANNER_VLAN_MAP_FILE` (a path), `{cidr: label}`, validated
at startup and fatal if malformed — a mapping nobody validated would mislabel devices silently
for months. Longest prefix wins, as in any routing table.

Every label carries `source_type = "inferred"` and a confidence below 1.0. There is no SNMP
access to the switches, so the mapping describes how the network was *designed*: a device with a
static address from another range, or a VLAN renumbered last quarter, makes it wrong without
anything looking wrong. That gap is the reason for the marker, and it travels into the dossier,
the retained snapshot, and whatever the interface renders.

**An address outside every mapped range is unknown.** No nearest match, no default VLAN. The
same honesty as the ambiguous category in shadow-IT reconciliation (ADR-0009): telling an analyst
a camera sits on an isolated segment when nobody established that is a fabrication they would act
on.

## Alternatives considered

| Option | Why not |
|---|---|
| **A weighted risk score (0–100)** | The failure mode being displaced. It cannot answer "why is this P1?", and every attempt to explain one post-hoc is a reconstruction, not a reason. |
| **More bands (P1–P5, or per-CVSS-decimal)** | Four is what an analyst can hold and work top-down. Bands exist to group work, and a band with three items a week is a band nobody learns. |
| **Let the accepted insight rewrite the band** | Tempting, and deferred: it would put an LLM-influenced value in a column marked `deterministic`. The insight's recommendation stays advisory beside the band; wiring it into priority is an M4 decision with the KEV floor as its guard rail. |
| **Treat a missing EPSS as 0.0 to simplify the rules** | Quietly de-prioritises everything newly published — a false negative of exactly the kind §67 exists to prevent. |
| **Derive the band at read time in the UI** | Then every client re-implements the policy and they drift. It is derived once, stored with its reason, and read. |
| **Recompute priority only for new matches** | A CVE added to KEV overnight must raise its band the next morning. The upsert re-derives on every run, which is safe because the derivation is pure. |
| **A `rejected` insight state** | A contract change to `docs/data/asset-dossier-contract.md` §7 for something a projection column expresses. Available if M4 wants it. |
| **Mutating `recommendation` on adjust** | Destroys the evidence of what the model proposed, which is the thing the audit trail exists to preserve. |
| **Hardcoding common RFC1918 ranges to plausible VLAN names** | Inventing facts about a customer's network. Empty is the honest default. |
| **Guessing the nearest range for unmapped addresses** | The one thing this project consistently refuses: a plausible answer where there is no answer. |
| **SNMP switch collection for ground-truth VLAN** | Not available in this deployment, and explicitly out of scope. No stub was built — a stub would imply a path that does not exist. |

## Trade-off accepted

**First-match-wins ordering makes some combinations coarse.** A confirmed CVSS 9.9 with EPSS
0.09 lands in P2 while a confirmed CVSS 4.0 with EPSS 0.11 lands in P1, and somebody will
disagree with that pair. It is the honest consequence of ranking exploitation above severity,
and the priority *says so in its own reason*, which is the difference between a debatable rule
and an inscrutable one.

**A rule change re-bands the estate on the next run.** Because priority is re-derived on every
correlation, editing this table moves findings for every tenant at once. That is correct — a
stale band derived from last quarter's rules would be worse — but it means the rules table is a
product surface, and changing it is a release note, not a refactor.

**`analyst_recommendation` has no consumer yet.** The UI that sets it is M4. It is here because
the review event that records it is append-only, and retrofitting a column into a history is
worse than carrying one that is briefly unused (§4.11's limit, knowingly approached).

**The VLAN confidence is a constant.** 0.6 reflects the *kind* of evidence — a design document,
not a measurement — rather than anything about a particular device. A per-asset number would be
false precision.

## Consequences

- One migration (`0008_ux_alignment`), expand-only, round-tripped on the compose Postgres.
- `engine/priority.py` and `engine/segments.py` are pure: no clock, no I/O, no model. The
  priority is a pure function of five values, so recomputation is stable and a nightly re-run
  does not churn a worklist an analyst is working through.
- `TriageStore.review_insight` now takes an `InsightReview` and writes the projection and the
  event together; `review_history` reads the log back in order.
- The correlation outcome reports `p1_matches` — the number an operator actually reacts to.
- Everything M4 needs from the data model is now present: a band with its reason, CVSS beside
  it, a review history with who and when, and a segment label that is honest about being
  inferred.
