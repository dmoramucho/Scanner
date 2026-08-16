# ADR-0010 — NVD feed: HTTP client, rate/backoff strategy, and the cache

- **Status:** accepted
- **Date:** 2026-08-16
- **Stage:** P12 (`VulnerabilityFeed` port + NVD adapter). M3 Half A, fetch and cache only.
- **Context refs:** AGENTS.md §2.3 (`tenant_id` on tenant-scoped tables), §2.9 (external input
  is untrusted), §3 (raw/normalized split, provenance), §4.8 (never learn CVEs from a model),
  §4.9 (a false negative we introduce is a hole we created), §4.11 (don't overengineer), §6
  (dependency justification), §67 (a failure is not an empty result);
  `docs/architecture/m3-design.md` §1, §2; [ADR-0003](0003-nmap-orchestration.md).

## Context

NVD is the authoritative CVE source and it is, in m3-design's own words, "notoriously slow,
rate-limited, and inconsistent". Three decisions follow from taking that seriously: what speaks
HTTP, how we stay inside the rate limit, and what we keep locally so we need not ask twice.

One property outranks all three. **A feed failure must never look like "no CVEs".** If a timeout
returned an empty list, the correlator would later record a component as having nothing against
it, and an operator would read that as clean. That is a false negative the system invented —
precisely what AGENTS.md §4.9 warns is a security hole of our own making.

## Decision

**1. HTTP via `httpx`, behind a one-method seam.**

`HttpClient` is a `Protocol` with a single `get`; `HttpxClient` implements it and everything else
— rate limiting, retries, backoff, parsing — sits above it and is tested without a network.

httpx rather than stdlib for three specific properties: it ships its own CA bundle (certificate
verification does not depend on the host Python's TLS store, which is a real source of on-prem
failure on macOS and minimal containers), it decompresses gzip transparently (NVD responses for a
broad CPE are large), and it requires an explicit timeout rather than defaulting to none.

**2. Rate limiting is enforced before each request, not discovered by rejection.**

A minimum interval (`window ÷ requests`) is waited out before every call, from config, defaulting
to NVD's documented *unauthenticated* limit of 5 requests per 30 seconds. An API key raises it to
50 deliberately; a missing key costs throughput, never a ban. On 429/500/502/503/504 the request
is retried with exponential backoff, honouring `Retry-After` when NVD sends one, up to
`max_retries` — after which it raises `DependencyError(retryable=True)`.

**3. Cache-first, with two tables, because "none" is an answer.**

`cve_cache` holds normalized records; `cve_query_cache` records *which CPEs we asked about and
when*. The second table exists solely so that "NVD says this CPE has no CVEs" is storable and
distinguishable from "nobody ever asked". Without it, an empty result set is ambiguous, and the
ambiguity resolves in the dangerous direction.

Neither table is tenant-scoped. A CVE is a fact about software in the world, identical for every
tenant; the tenant-scoped conclusions about our devices are `vulnerability_match` (P14).

TTL defaults to 24 hours: long enough to be kind to the feed, short enough that a new CVE lands
the next working day.

**4. Every response is parsed defensively into `CveRecord`.**

NVD's JSON never reaches the domain. Payloads are typed `object`, not `Any`, so every field
access must pass an `isinstance` check. One malformed record is skipped with a reason and a
count; the rest of the batch survives. A body that is not JSON, a shape we do not recognise, or a
response past 32 MB raises rather than yielding nothing.

## Alternatives considered

| Option | Why not |
|---|---|
| **stdlib `urllib.request`** | No dependency, and genuinely close. Rejected on two counts: gzip would have to be requested and decompressed by hand for responses that are megabytes, and certificate verification depends on the host's TLS store — a class of on-prem failure httpx's bundled CA avoids. |
| **`requests`** | Comparable dependency weight, no type hints of its own (needs `types-requests`), and no advantage over httpx here. |
| **A retry/backoff library (`tenacity`, `backoff`)** | The policy is fifteen lines and has one non-obvious rule — honour `Retry-After` — that a generic decorator would hide rather than express. |
| **Discovering the rate limit by handling 429s** | How a client gets banned. The interval is cheap; a ban is not. |
| **One cache table, inferring "asked" from the presence of records** | The false-negative path this ADR exists to close: a CPE with no CVEs would be indistinguishable from a CPE never looked up. |
| **Caching the raw NVD JSON as the cache** | Every reader would then re-parse NVD's schema, which is exactly the coupling `CveRecord` exists to prevent. The raw response is referenced instead (`raw_record_ref`), so the normalized record stays traceable (AGENTS.md §3). |
| **Tenant-scoping the CVE cache** | Multiplies fetching by the number of tenants for identical public data, against a feed whose rate limit is the binding constraint. |
| **Fetching KEV/EPSS here too** | P13. Each is a different endpoint with a different shape and its own failure modes; bundling them would make this adapter three adapters wearing one coat. |

## Trade-off accepted

**Six new transitive packages** (`httpx`, `httpcore`, `h11`, `anyio`, `sniffio`, `certifi`,
`idna`) for one GET. That is real added surface on an on-prem deployment, accepted for the TLS and
gzip properties above, and contained by the seam — replacing httpx means replacing one class.

**A 24-hour TTL means a CVE published this morning is invisible until tomorrow** for a CPE we
already asked about. Acceptable while nothing consumes the cache yet, and it is a config value
rather than a constant. When correlation lands (P14), the right follow-up is an incremental
refresh using NVD's `lastModStartDate` parameter rather than a shorter blanket TTL — that is a
smaller ask of the feed, not a bigger one.

**Only the first page is fetched** (`resultsPerPage=2000`). A single CPE with more than 2000 CVEs
does not exist today; if one ever does, this silently truncates. That is a real gap, and the
honest mitigation is that P14 should assert on `totalResults` versus what it received rather than
this adapter pretending to paginate before there is anything to paginate (§4.11).

**`raw_record_ref` is a feed-canonical identifier (`nvd:CVE-…`), not an object-store key.** The
raw-response store is not wired yet, so the reference points at what can be re-fetched rather than
at a stored artifact. That satisfies traceability today and should become a real object reference
when the raw store lands.

## Consequences

- Nothing in `adapters/feed/` imports a model client, and `tests/test_adapter_boundaries.py`
  fails if that changes — the safety assertion m3-design §4 asks for. CVE facts enter this system
  through a feed that said so, never through something that generated them (AGENTS.md §4.8).
- The port speaks `CveRecord`; the core never learns it is NVD. A second feed (a mirror, an
  offline snapshot for air-gapped deployments) is another adapter behind the same port.
- Rate, timeout, retries and TTL are `NvdSettings` in `config`, so an operator behind a slow link
  or with an API key tunes them without touching code.
- P13 adds KEV and EPSS as their own adapters; P14 consumes this port to build
  `vulnerability_match`. Neither needs this module to change.
