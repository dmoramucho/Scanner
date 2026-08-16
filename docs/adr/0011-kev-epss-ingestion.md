# ADR-0011 — KEV and EPSS: snapshot sources, replacement semantics, and the load marker

- **Status:** accepted
- **Date:** 2026-08-16
- **Stage:** P13 (KEV + EPSS ingestion). M3 Half A, fetch and cache only.
- **Context refs:** AGENTS.md §2.9 (external input is untrusted), §3 (raw/normalized,
  provenance), §4.9 (a false negative we introduce is a hole we created), §4.11 (don't
  overengineer), §67 (a failure is not an empty result);
  `docs/architecture/m3-design.md` §2; the dossier contract §7 (KEV is sticky);
  [ADR-0010](0010-nvd-feed-fetch-and-cache.md); [ADR-0006](0006-credentialed-supersession.md).

## Context

KEV and EPSS are the two prioritisation signals. They are simpler than NVD — one static JSON
catalog, one daily CSV — but KEV carries the highest stakes in the whole system.

A KEV listing is the override that keeps a finding visible regardless of how confident the
version match was (dossier contract §7). Which means **a KEV lookup that quietly returns `False`
on a failed fetch would silently de-prioritise an actively-exploited vulnerability** — the worst
false negative this codebase could produce. Everything below follows from refusing that.

## Decision

**1. A failed lookup raises. `False` and `None` are answers, never fallbacks.**

`is_known_exploited` returns `False` only when CISA published a catalog we hold and this CVE is
not in it. `score_for` returns `None` only when FIRST published a snapshot we hold and this CVE
is not scored in it. Anything else — transport failure, 5xx after retries, a non-JSON body, a
shape we do not recognise — raises `DependencyError` or `ValidationError` with the right
`retryable` flag. This is ADR-0010's rule, applied where it costs the most.

**2. Both are bulk snapshots, fetched whole and cached with a TTL.**

KEV is a couple of thousand entries that change a few times a week (6-hour TTL); EPSS is a daily
publication (24-hour TTL). One request answers every question we will ask, which is far kinder
to both publishers than per-CVE lookups — and neither source offers a rate limit we are near.

**3. A refresh *replaces* the snapshot, atomically.**

CISA withdraws KEV entries and FIRST re-scores CVEs daily. A cache we only ever added to would
keep asserting an exploitation that has been retracted, or a probability that has been revised.
The delete and the inserts commit together, so there is no window in which the catalog is empty
and every CVE would answer "not exploited".

The replacement happens **only after a successful parse**. A half-read catalog never replaces a
good one, and a failed fetch leaves the previous snapshot in place — stale, and honest about it.

**4. A `feed_snapshot` row records that a catalog was loaded, and when.**

This is the same structural device as `cve_query_cache` in ADR-0010: without it, "this CVE is not
in KEV" is indistinguishable from "the catalog was never loaded", and an empty cache would answer
"not exploited" for every CVE in existence.

**5. An EPSS snapshot with no usable rows is refused rather than stored.**

An empty snapshot is not a world in which nothing is exploitable; it is a download that went
wrong. Storing it would erase every score we have and silently flatten the ranking.

**6. A score that is not a probability is refused.** Unparseable, out of range, negative, or NaN.
NaN is called out explicitly because it compares false against everything: a NaN score would sort
unpredictably and misrank a finding without anything looking broken.

## Alternatives considered

| Option | Why not |
|---|---|
| **Return `False` from a failed KEV lookup and log a warning** | The failure mode this ADR exists to prevent. Nobody reads the warning; the ranking silently loses its most important signal. |
| **Per-CVE EPSS API lookups** (`api.first.org/data/v1/epss?cve=…`) | Hundreds of requests per correlation run instead of one, and it reintroduces the per-CVE "did we ask?" bookkeeping the snapshot makes unnecessary. Worth revisiting only if the daily snapshot becomes too large to hold, which it is not. |
| **Merge KEV and EPSS into one signal table** | They have different shapes, cadences and failure modes; one table would need nullable halves and a source discriminator to say which half is meaningful. Two tables and one shared snapshot marker is smaller. |
| **Append-only KEV history** | Tempting for auditability, but the question this cache answers is "is it exploited *now*". CISA's own catalog is the history, and the observation spine already carries the immutable evidence for anything we conclude from it (ADR-0006 drew the same line for current software). |
| **A stale-but-usable fallback when a refresh fails** | Already the behaviour: the previous snapshot stays and keeps answering. What is refused is *manufacturing* an answer when there is no snapshot at all. |
| **Trusting the CSV's `percentile` column for ranking** | It is carried, but `score` is the probability and the thing to rank on. Percentile is a presentation aid, and treating it as a probability would be a category error. |
| **Storing the raw catalog/CSV blob** | Megabytes per refresh for data that is re-fetchable from a stable URL. `raw_record_ref` points at the source, as in ADR-0010 — the same honest limitation until the raw object store lands. |

## Trade-off accepted

**A KEV outage stops correlation rather than degrading it.** If the catalog has never been
loaded and CISA is unreachable, every lookup raises and the caller cannot proceed. That is loud
and inconvenient, and it is the correct direction: proceeding would mean publishing findings with
the exploitation signal silently absent. Once a snapshot exists, an outage is invisible — the
cached catalog keeps answering until it is refreshed.

**A 6-hour KEV TTL means a newly-catalogued CVE can be up to six hours stale.** CISA adds entries
irregularly and rarely more than a few times a week, so this is a small window against a static
file. It is a constructor parameter, and P14 should call `refresh()` at the start of a
correlation run rather than relying on the TTL alone.

**The EPSS snapshot is a few hundred thousand rows, replaced wholesale each day.** That is a
larger write than anything else in this system. Accepted because the table is three columns wide
and the alternative is per-CVE fetching; if it ever becomes a problem the fix is a diff-based
update, not a smaller cache.

**Storing scores for CVEs we will never look at.** The snapshot covers everything FIRST scores,
not just our components' CVEs. Filtering would require knowing our CVEs before fetching, which
inverts the dependency for no measurable gain (§4.11).

## Consequences

- Neither cache is tenant-scoped, for the same reason as `cve_cache`: KEV and EPSS are facts
  about software in the world. The tenant-scoped conclusions land in `vulnerability_match` (P14).
- Nothing in `adapters/feed/` imports a model client, asserted by the boundary test — Half A
  stays deterministic by construction (m3-design §1).
- The HTTP seam is now shared (`adapters/feed/http.py`), extracted from the NVD adapter, with a
  bounded gzip helper for EPSS's `.csv.gz` artifact — a small download that expands to gigabytes
  is a real way to take a process down.
- P14 consumes all three feeds: NVD for the match, KEV for the override, EPSS for the gradient.
  A KEV failure there must abort the run rather than produce matches with `kev=false`, which is
  this ADR's rule one level up.
