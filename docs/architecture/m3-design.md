# M3 — Vulnerability Correlation & AI Insight

`docs/architecture/m3-design.md`

M0–M2 built a reconciled inventory that answers "what is on the network, and what does nobody manage?" M3 answers the next two questions: **"what is vulnerable?"** (deterministic) and **"what does it actually mean for us?"** (AI insight). This is the innovation mandate — and the most delicate milestone, because the risk here is not breaking a device or leaking a secret. **The risk is epistemic: the system asserting something false with confidence, or the LLM inventing.** A scanner that reports a CVE that isn't there, or buries one that is, is worse than one that reports nothing.

Everything the earlier milestones built — provenance in the data, the confidence stratification, and above all the **LLM-proposes / deterministic-disposes** pattern — was built *for this moment*. M3 is where it does real work.

---

## 1. The non-negotiable split

M3 has two halves that must never be entangled:

- **Half A — Deterministic correlation (no LLM).** CPE → CVE via NVD, enriched with KEV (actively exploited?) and EPSS (exploitation probability). The match "this version has this CVE" is deterministic, verifiable, and **must never come from a model** (AGENTS.md §4.8 — models hallucinate CVE IDs and their knowledge is stale). Produces `vulnerability_match` (already in the schema).
- **Half B — AI insight (contained).** *On top of* deterministic matches, the LLM reasons about contextual relevance ("critical only if internet-facing; this isn't — but it's in KEV, don't dismiss it"). Produces `insight` (already in the schema), grounded, cited, propose/dispose.

**Why the split is a safety barrier, not just organization:** if the two are built together, the code where the LLM might "decide" whether a vuln exists gets mixed with the code where it should only reason about relevance. That entanglement is exactly where the LLM hallucinates a version and injects a false negative into a security system. **Half A must be solid and tested before Half B touches it.** The separation in build-time guarantees the separation in the architecture.

The `AdvisoryRetriever` and `InsightGenerator` ports from M0 (`ports.md` §7, §8) are the seams Half B fills. The `TriageDossier`, `AdvisoryEvidence`, and `InsightProposal` contracts from the dossier doc are already written for this. M3 implements them; it does not redesign them.

---

## 2. Half A — deterministic correlation

### Source: NVD API (online, rate-limited)
NVD is authoritative but **notoriously slow, rate-limited, and inconsistent**. Treat it accordingly:
- A `VulnerabilityFeed` port; an NVD-API adapter behind it. The core never knows it's NVD.
- **Respect the rate limit** (NVD's documented request cap; back off on 429). Cache/persist fetched CVE data so we don't re-hit NVD for the same CPE — a local `cve_cache` (raw NVD responses, provenance-stamped) that the correlator reads. This is the raw/normalized split (AGENTS.md §3) applied to an external feed.
- NVD responses are **untrusted input** (§68): parse defensively, tolerate missing/malformed fields, never crash a correlation run on one bad record.

### KEV and EPSS from the start
- **KEV** (CISA Known Exploited Vulnerabilities): a small, authoritative list of what is *actually* being exploited. This is the single most important prioritization signal — it is the override that keeps a finding visible regardless of confidence (dossier contract §7). Fetch and cache it.
- **EPSS** (Exploit Prediction Scoring System): a 0–1 probability per CVE. The gradient that ranks the rest once KEV is accounted for. Fetch and cache.

### The correlation
- For each `software_component` with a CPE, find matching CVEs; produce `vulnerability_match` with `cve_id`, `matched_cpe`, `version_source` (carried from the component — `package_manager` vs `banner`), `confidence_state`, `kev` flag, `epss` score.
- **`confidence_state` is derived, not guessed** (dossier contract, confidence stratification): `confirmed` when the component's `version_source` is `package_manager`; `probable` when it's `banner` (the backport false-positive problem — a banner-inferred version might already be patched). `verified_exploitable` is reserved for a later `check`-module step, out of M3 scope.
- **The match `derivation` is always `deterministic`** — the DB CHECK already enforces this. No LLM anywhere in Half A.
- Idempotent: re-correlating the same component/CVE lands once (`vulnerability_match` unique key exists).

### Half A is done when
The store answers "what is vulnerable, how confident are we in the version, is it actively exploited (KEV), and how likely is exploitation (EPSS)" — entirely deterministically, with provenance, and the KEV/confidence stratification correct. **No LLM has run.** This is the cimiento; it must be verified before Half B.

---

## 3. Half B — AI insight (contained)

Only after Half A is approved. Fills the `AdvisoryRetriever` + `InsightGenerator` ports. Every rule here is a containment rule (all already specified in `ports.md` §8 and the dossier contract — M3 enforces them):

- **Grounding, never memory (AGENTS.md §4.8).** The `AdvisoryRetriever` supplies the *real* advisory text + fix diff via RAG. The `InsightGenerator` reasons only over the `TriageDossier` it's handed (redacted asset dossier + the retrieved `AdvisoryEvidence` + the deterministic match). It has **no other path to CVE knowledge.**
- **The dossier is redacted before it reaches the model** (dossier contract §4, allowlist/fail-closed). Secrets, raw config, PII never reach the LLM. Uses a **local/self-hosted model** for anything sensitive (AGENTS.md §2.10).
- **Insight is advisory and non-suppressing.** It recommends `raise`/`lower`/`maintain` priority; it never closes a finding on its own. An ungrounded insight (empty `cited_sources`) is **rejected before persistence** — the DB CHECK already enforces this. A human confirms consequential cases (`state` starts `proposed`).
- **KEV is sticky.** If the match is KEV, `kev_locked_visible` is set and the insight cannot recommend hiding it — enforced in the generator *and* by the DB CHECK. Belt and suspenders.
- **Conservative bias.** A false negative the AI introduced is a security hole the system created. When in doubt, keep visible.
- **The retained `TriageDossier` snapshot** backs every insight (dossier contract §2, immutable lineage) — you can always reconstruct what the model saw.
- **The context axis differs by asset class** (dossier contract §5): for a server, config/exposure; for a camera/firmware, deployment/network; for an app, architecture. The insight reasons over whatever the dossier populated — and `management_state` from M2 is now a context signal ("this vuln is on a device nobody manages").

### Half B is done when
A deterministic match can be turned into a grounded, cited, advisory `InsightProposal` that a human can review — and it is structurally impossible for the LLM to fabricate a vuln, suppress a KEV finding, or emit an ungrounded claim.

---

## 4. Testing

- **Half A on fixtures**: recorded NVD/KEV/EPSS responses (a clean CPE with CVEs, a CPE with none, a malformed NVD record, a KEV-listed CVE, a rate-limit 429). CI never hits the real NVD. Assert: correct CPE→CVE matching, `confidence_state` derived correctly (package_manager→confirmed, banner→probable), KEV flag set, EPSS carried, idempotency, rate-limit backoff, and that a bad NVD record doesn't crash the run. Safety assertion: **no code path in Half A produces a match from anything but the deterministic feed** (no model import in the correlator).
- **Half B on fakes**: a fake `InsightGenerator`/model for the pipeline, real contract enforcement for the rules. Assert: ungrounded insight rejected; KEV insight can't recommend hide; the model only ever sees the redacted dossier (no secret reaches it); the retained snapshot matches what was generated; a human-review state transition works.
- **Real-source validation** (manual, documented): point Half A at the real NVD API with real components and sanity-check the matches; if a local model is used for Half B, validate it on a few real advisories. Measure NVD's real latency/rate behavior.

---

## 5. Tiering — what M3 is, and is not (AGENTS.md §5)

### In M3
- Half A: `VulnerabilityFeed` port + NVD adapter (rate-limited, cached), KEV + EPSS ingestion, deterministic correlation into `vulnerability_match`, confidence-stratified.
- Half B: `AdvisoryRetriever` + `InsightGenerator` implementations, grounded/contained AI insight into `insight`, propose/dispose, human-review path.
- Fixtures/fakes tests; documented real-source validation.

### Deferred (LATER — not M3)
- `check`-module verification (`verified_exploitable` state, Metasploit `auxiliary`/`check`) — a later step; never exploitation.
- LLM-proposed *entity* matching for the M2 ambiguous queue — a distinct use of the same propose/dispose seam; can follow.
- A local-model *serving* stack beyond what the adapter needs — infra, out of scope.
- Any UI — presentation is separate (this is where the mockup eventually plugs in).
- Auto-remediation, ticketing integrations — out of scope.

---

## 6. Where this plugs into what exists

`vulnerability_match`, `insight`, `triage_snapshot` already exist in the schema. The `AdvisoryRetriever`, `InsightGenerator` ports and the `TriageDossier`/`InsightProposal` contracts already exist. `software_component` (with `version_source`) and `management_state` already feed it. **M3 adds two feeds and two adapters — it fills seams that have been waiting since M0.** The moat completes: from "what's on the network" → "what does nobody manage" → "what's vulnerable and what does it actually mean."

Build order (P-series continues from P11) — **Half A first, verified, then Half B**:
1. **P12** — `VulnerabilityFeed` port + NVD-API adapter (rate-limited, cached `cve_cache`, untrusted-response-safe), fixtures. Just fetch+cache; no correlation yet.
2. **P13** — KEV + EPSS ingestion (fetch + cache both), fixtures.
3. **P14** — deterministic correlation into `vulnerability_match` (CPE→CVE, `confidence_state` derived, KEV/EPSS enrichment, idempotent), fixtures. **Half A complete — verify before P15.**
4. **P15** — `AdvisoryRetriever` (RAG grounding: real advisory text + fix diff), fixtures.
5. **P16** — `InsightGenerator` + the contained insight pipeline (redacted dossier → grounded/cited/advisory insight, KEV-sticky, propose/dispose, human-review), fakes + contract enforcement. **Half B complete — M3 complete.**
