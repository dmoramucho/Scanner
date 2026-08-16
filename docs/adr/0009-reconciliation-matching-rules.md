# ADR-0009 — Matching rules and the ambiguity threshold for the shadow-IT diff

- **Status:** accepted
- **Date:** 2026-08-16
- **Stage:** P11 (reconciliation + bidirectional diff). Closes M2.
- **Context refs:** AGENTS.md §2.8 (deterministic anchors win), §3 (ER anchor priority; IP is
  never identity; threshold by consequence), §4.9 (a false negative we introduce is a hole we
  created), §4.11 (don't overengineer), §5 (deterministic now, LLM seam);
  `docs/architecture/m2-design.md` §3, §4, §5; [ADR-0006](0006-credentialed-supersession.md).

## Context

The diff's headline is *"N devices nobody manages"*. Its entire value is that the number is
**defensible** — that an operator can walk a CISO through any entry on the list. m2-design §3
states the governing risk plainly: weak matching makes the diff lie. A server that *is* in the
CMDB but whose hostname was typed differently, reported as shadow IT, discredits the whole system
on first demo.

Three decisions determine whether that happens: which anchors may settle a match, what happens
when they cannot, and what "unmanaged" is allowed to mean.

## Decision

**1. Anchor priority is the entity resolution's own: `serial › mac › hostname`.**

A serial or MAC agreeing links confidently (`STRONG`, confidence 0.95). A hostname links only
when **exactly one** asset answers to it, and links weakly (0.6) — a name is a label a person
typed, and people rename machines. IP is not used at all: it is a locator, never an identity
(AGENTS.md §3). This is the same "is this the same real thing?" problem the ER already solves,
now crossing management records against discovered assets, so it uses the same ordering.

**2. Hostnames are normalised by case and domain suffix, but never by punctuation.**

`SRV-APP-03`, `srv-app-03.corp.local.` and `srv-app-03` all compare equal: case is
meaningless and a DNS domain is a *location*, not a name.

`srvapp03` does **not** link to `srv-app-03`. Removing punctuation is where false matches come
from — `a-b1` and `ab-1` squash identically and are not obviously the same machine. A
squash-only similarity is reported as **ambiguous**: probably the same device, and "probably" is
not a conclusion this layer is allowed to reach.

**3. Ambiguity is a category, and it is absorbing.**

Four things make a case ambiguous: two or more assets answer to the same name; strong anchors
disagree (the record's serial names one asset, its MAC another); a hostname matches only after
squashing; or an asset has no serial, MAC or hostname at all and therefore cannot be looked up in
a CMDB.

**Any asset touched by an ambiguous case can never be counted as shadow IT**, and resolves to
`management_state = unknown`. That is the single rule the module is built around, asserted as an
invariant over a deliberately messy estate rather than as one example.

**4. "Unmanaged" means we looked and found nothing — not that we could not look.**

An asset must have at least one comparable anchor before it can be called shadow IT. Confidence
is graded: 0.9 when a serial or MAC found nothing (we had something durable to check), 0.5 when
only a name did (the CMDB may simply spell it differently), and the reason string says which.

## Alternatives considered

| Option | Why not |
|---|---|
| **Link on squashed hostnames** | Would shrink the ambiguous pile and inflate the false-match rate — in the direction that produces confidently wrong links, which are harder to detect than open questions. |
| **Fuzzy matching (Levenshtein, trigram similarity)** | A threshold nobody can defend. "0.82 similar" is not a sentence you can say to a CISO, and tuning it is tuning how often the product lies. |
| **Match on IP** | Addresses rotate; a DHCP lease from Tuesday would link a CMDB row to whatever holds the address today. AGENTS.md §3 forbids it, and this is exactly why. |
| **Force a decision on ambiguous cases** (pick the first, or the highest-confidence) | Manufactures certainty. The whole product claim is that the number is trustworthy. |
| **Count ambiguous as unmanaged** | Inflates the headline with our own matching failures — the specific failure m2-design §3 says burns trust. |
| **Count ambiguous as managed** | The other direction, and worse: a genuine shadow-IT device hidden because its name was confusing is a false negative we introduced (AGENTS.md §4.9). `unknown` is the honest third answer, and the schema already has it. |
| **Bring in the LLM proposer now for the ambiguous queue** | M3, and only if measurement justifies it (§4.11). The findings already carry their candidate assets and `ReconciliationLink.derivation` can already say `llm_proposed`; the seam is built, and empty. |
| **Extend `AssetRepository` with the reads the diff needs** | ADR-0006 drew that boundary from the other side: the ER answers "which asset is this observation about?". `ReconciliationStore` is a separate port so the ER contract does not acquire a reporting surface. |

## Trade-off accepted

**A conservative matcher produces a bigger ambiguous pile**, and on an estate with inconsistent
naming it may be large. That is the cost, and it is paid in a review queue rather than in wrong
answers — the two lists are separately reported, so the headline stays defensible while the queue
stays visible.

**The `unmanaged` number understates by design.** An asset we could not look up is not counted,
even though some of those genuinely are shadow IT. Understating a security finding is not
costless (AGENTS.md §4.9 warns precisely about self-inflicted false negatives) — but the
alternative is a number that includes cases we never tested, and a number that overclaims once
is never trusted again. The ambiguous list is published alongside so nothing is hidden, only
categorised.

**`srvapp03`-style naming will read as ambiguous.** For an estate that names things that way
consistently, the rate will be high — which is the signal working as intended, and the input to
the M3 decision rather than a reason to loosen the rule quietly.

## Consequences

- `ShadowItDiff.ambiguous_rate` is counted **per asset**, not per finding: one confusing CMDB row
  can produce several findings, and that must not look like more unresolved devices than exist.
  It is the number the runbook asks operators to measure, with documented thresholds (<5% fine,
  5–20% look for a fixable pattern, >20% is the case for M3).
- `management_state` and the headline count are derived from the same conclusion, so there is no
  path that marks an asset unmanaged without listing it as shadow IT, or the reverse.
- Merged assets are excluded from the diff entirely: a merged asset is history pointing at its
  survivor, and counting it would double-count one machine.
- Both projections are recomputed from scratch each run and written as assignments, so a link
  that was right last month and is wrong now is cleared rather than defended.
- The next lever, if the rate demands it, is **more deterministic normalisation** (a documented
  domain-suffix or prefix rule for this estate) before it is an LLM. The runbook says so
  explicitly.
