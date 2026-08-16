# ADR-0013 — Advisory retrieval: what we ground on, what we fetch, and how hostile text is defanged

- **Status:** accepted
- **Date:** 2026-08-16
- **Stage:** P15 (`AdvisoryRetriever`). M3 Half B, grounding only — no insight, no model.
- **Context refs:** AGENTS.md §2.9 (external input is untrusted), §2.10 (secrets never reach a
  model), §3 (raw/normalized, provenance), §4.8 (ground, never recall), §4.9 (a false negative
  we introduce is a hole we created), §4.11 (don't overengineer), §5 (NOW-tier), §67 (a failure
  is not an empty result); `docs/architecture/m3-design.md` §3; `docs/architecture/ports.md` §7;
  the dossier contract §6; [ADR-0010](0010-nvd-feed-fetch-and-cache.md);
  [ADR-0011](0011-kev-epss-ingestion.md).

## Context

P16 hands a `TriageDossier` to a language model. The model's own CVE knowledge is stale,
partial, and confidently wrong in the way that is hardest to notice — hallucinated CVE ids are
its signature failure. So AGENTS.md §4.8 says the model may know nothing about a CVE that it was
not given, and this retriever is the channel it is given things through. Everything below
follows from that one sentence, plus one new fact: **advisory text is attacker-influenced input
that ends up inside a prompt**, which makes a CVE description an injection vector aimed at our
own triage.

## Decision

**1. `advisory_text` is quoted, never composed.**

The text is NVD's description, plus the header of a fix patch where one exists, each under a
`[[source: …]]` header naming where it came from. There is no summariser in this package and no
model import — `tests/test_adapter_boundaries.py` fails if one appears. A citation in P16 can
therefore be checked against a document a human can open.

**2. The one derived field is derived mechanically, or left empty.**

`fix_touched_summary` is the commit subject (quoted) plus the paths the diff touches (extracted).
When the fix reference is not a diff, or there is no fix reference, it is `None`. A sentence
about what a fix "probably" changed is exactly the plausible fiction this architecture exists to
exclude, and it would be indistinguishable from the real thing downstream.

**3. Only patches are fetched, only over https, only from an allowlist of code hosts.**

Anyone can attach a reference URL to a CVE, and this process runs *inside* the network it is
meant to protect. Dereferencing arbitrary references would be a server-side request forgery
primitive pointed at the estate — `https://169.254.169.254/…`, an intranet host, a colleague's
box. So an outbound fetch requires all three of: `https`, a host in `PATCH_HOSTS` (or a
`.googlesource.com` suffix), and a patch-shaped path. Everything else is *cited* and never
dereferenced. GitHub and GitLab commit URLs are fetched in their documented `.patch` form,
because a diff is machine-readable and an HTML page is not.

**4. All fetched text is sanitised before it is cached.**

`adapters/advisory/sanitize.py`, in this order, and the order is the decision:

1. **NFKC normalise, then strip invisibles.** Normalising first means a fullwidth
   `Ｉｇｎｏｒｅ` is matched like the plain word instead of sailing past. Stripping zero-width,
   bidi and format characters second means an instruction hidden between the letters of an
   innocuous word is no longer hidden — from the matcher, or from the human reading the evidence.
2. **Neutralise control tokens**: chat-template markers (`<|im_start|>`, `[INST]`, a
   `Human:`/`Assistant:` turn boundary), fence runs, and any tag whose name collides with the
   envelope P16 quotes this text inside. These are the *mechanically* dangerous class: they do
   not argue with the prompt, they impersonate its structure.
3. **Neutralise instruction-shaped spans**: six named patterns (override, role-reassignment,
   injected-instructions, verdict-steering, suppression, output-steering).
4. **Bound it**: a hard input cap before any pattern runs, then an output cap with a visible
   truncation marker.

Every replacement is a **visible marker**, never a silent deletion: `[[neutralized:
instruction-like:override]]` says something was here and we removed it, where a quiet excision
would leave text that reads like an ordinary advisory with a hole in it. The `[[…]]` family is
reserved — any `[[` or `]]` arriving in untrusted text is broken apart (`[ [`) before our markers
are inserted, so an advisory cannot forge a source attribution and put words in NVD's mouth. The
brackets are separated rather than deleted, because this is evidence.

**5. Sanitisation happens on the way *in*, not on the way out.**

The cache stores sanitized text. There is therefore no ordering, no configuration, and no future
caller that can route raw advisory bytes into a prompt: the raw form exists only inside the
adapter, for the duration of one function.

**6. Absence, failure, and evidence are three different answers.**

| Situation | Result |
|---|---|
| Real text sourced | `AdvisoryEvidence` with non-empty `advisory_text` and its provenance |
| Feed has no such CVE / no quotable text | `NotFoundError` — P16 must refuse, not recall |
| A source could not be reached | `DependencyError(retryable=…)` — ask again |
| A *fix patch* could not be fetched | Degrades: `fix_diff_ref` kept, `fix_touched_summary` empty |

The fourth row is the only graceful degradation, and it is safe because it degrades a
supplementary field while still naming the commit: the evidence says "there is a fix here and we
have no summary of it", never "there is no fix". What never happens is an `AdvisoryEvidence`
whose `advisory_text` is empty, which would look like grounding and be nothing (§67). The
database enforces the same rule for the cache: `advisory_document_grounded` refuses a document
claiming `status = 'ok'` with no content.

**7. A dead reference is a storable answer; a failed fetch is not.**

A 404/410 is cached as `unavailable`, so a dead link is asked about once rather than nightly. A
timeout is cached nowhere. This is ADR-0010's `cve_query_cache` rule applied to documents, and it
only works because the two are kept apart.

## Alternatives considered

| Option | Why not |
|---|---|
| **Let the model summarise the advisory** | It is the thing being grounded. A summary produced by the model cannot ground the model, and the citation would look identical to a real one. |
| **Fetch and text-extract every referenced advisory page (vendor HTML, GHSA)** | The largest surface in the step for the least certain gain: hostile HTML → text is its own attack surface, and NVD's description is already real quotable text. GHSA (structured JSON, one host, ecosystem-aware) is the right next source and is deliberately LATER (§4.11, §5). |
| **Reject an advisory outright when injection is detected** | Hands an attacker a way to make their own CVE un-triageable by writing "ignore previous instructions" into the description. Defanging keeps the finding visible, which is the conservative direction (§4.9). |
| **Detect injection and pass the text through flagged** | Theatre: the words still reach the model. The span is replaced, and the flag is *additional*. |
| **Escape all markup (`<` → `&lt;`) instead of neutralising named tags** | Corrupts real advisory text — `<script>` and `<iframe>` are content in an XSS advisory, not decoration. |
| **An LLM-based injection classifier at the boundary** | A model in the grounding channel, which is the one thing this step exists to prevent; and it would itself be the thing being injected. |
| **Fetch references through a proxy allowlist instead of an in-process one** | Better, and compatible: the host allowlist is the same policy either way. A proxy is infrastructure this deployment does not have yet. |
| **Store the raw response bytes alongside the sanitized text** | Would put unsanitised attacker-controlled text one careless query away from a prompt. `raw_record_ref` points at the URL instead, as in ADR-0010. |
| **Per-CPE source selection using `matched_cpe`** | Retrieval is per-CVE today; the parameter is validated and carried, and is where GHSA-by-ecosystem hooks in later. |

## Trade-off accepted

**Pattern-matching cannot reliably detect prompt injection.** A determined attacker rephrases,
and the six patterns here will miss them. This is defence in depth and nothing more — the real
containment is structural and belongs to P16: the model only *proposes*, an insight with no
citations is refused, a KEV match cannot be hidden, and the database CHECKs enforce all three.
Anyone reading the sanitiser as the safety story has read it wrong, which is why the module
docstring says so first.

**Neutralisation can fire on legitimate advisory prose.** "Do not report" appears in real vendor
text. The cost is a marker in place of a phrase in an advisory a human can still open via
`advisory_source`; the benefit is that the common injections do not reach the model. The
patterns are deliberately narrow — verb lists rather than keywords — and
`test_ordinary_advisory_prose_is_not_mistaken_for_an_injection` pins six near-miss sentences
("The fix ignores malformed headers", "Do not expose the management interface") so a future
widening has to break a test to happen.

**The allowlist means a fix on an unlisted host yields no `fix_touched_summary`.** Self-hosted
GitLab, a vendor's own cgit, an FTP tarball. The reference is still cited and a human can open
it. Widening the list is a one-line change with a security review attached, which is the right
shape for that decision.

**NFKC normalisation changes some legitimate text** — ligatures, fullwidth CJK punctuation. On
English advisory prose the effect is negligible; the alternative is leaving a trivial bypass open.

**`fix_touched_summary` is file paths and a subject line, not reachability.** Knowing that a fix
touched `mod_proxy_ajp.c` is not knowing whether this asset reaches that code. It is the input to
that judgement, and P16 must present it as such rather than as a conclusion.

## Consequences

- `adapters/advisory/` imports no model package, asserted by the boundary test — the grounding
  channel cannot itself invent (m3-design §1, §3).
- A new port, `AdvisoryDocumentCache`, and one table, `advisory_document` (migration
  `0006_advisory_cache`). Not tenant-scoped, like `cve_cache` and the signal caches: a published
  advisory is a fact about software in the world.
- The retriever depends on `VulnerabilityFeed`, not on `CveCache` directly, so P12's cache-first
  behaviour and its failure discipline are inherited rather than re-implemented.
- `client=None` (or `fetch_fix_documents=False`) is a supported configuration: a retriever that
  grounds entirely on what is already cached and never makes an outbound request. That is the
  configuration for an air-gapped install, and it degrades exactly one field.
- `AdvisoryRetrievalReport` counts what had to be defused. Nothing branches on it — it exists so
  that a *pattern* of hostile advisories reaches an operator instead of being silently handled.
- P16 must still fence this text as data in its prompt, require citations, and validate the
  model's output. This ADR removes the mechanical vectors; it does not remove that obligation.
