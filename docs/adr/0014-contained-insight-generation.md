# ADR-0014 — Contained insight generation: a local model, a hard boundary, and no way to hide a finding

- **Status:** accepted
- **Date:** 2026-08-16
- **Stage:** P16 (`InsightGenerator` + `TriageDossier` assembly). M3 Half B; completes M3.
- **Context refs:** AGENTS.md §2.2 (derivation on every fact), §2.8 (LLM proposes, deterministic
  disposes), §2.9 (external input is untrusted — including model output), §2.10 (secrets never
  reach a model; sensitive work stays local), §3 (provenance, immutable evidence), §4.8 (ground,
  never recall), §4.9 (a false negative we introduce is a hole we created), §4.11 (don't
  overengineer), §43 (CI hermetic), §67 (a failure is not an empty result);
  `docs/architecture/m3-design.md` §3; `docs/architecture/ports.md` §8; the dossier contract §4,
  §6, §7, §8; [ADR-0012](0012-cpe-version-matching.md), [ADR-0013](0013-advisory-retrieval-and-sanitization.md).

## Context

This is the step the whole architecture was arranged around. A language model finally reasons,
and what it writes is read by a CISO who will act on it. Three things could go wrong, and each
would be worse than having no insight at all:

1. **It leaks.** The dossier is corporate asset data assembled from observations that include
   credentialed reads of real devices.
2. **It fabricates.** A confident sentence about a CVE the model half-remembers is
   indistinguishable, to a reader, from one grounded in an advisory.
3. **It buries.** A recommendation to de-prioritise an actively-exploited vulnerability would be
   this system creating the exact failure it exists to prevent.

Every rule below is one of the three. None of them are new: they were specified in M0's contracts
and this step is where they stop being prose.

## Decision

**1. The model sees one object, and that object is an allowlist projection.**

`TriageDossier` = redacted `AssetDossier` + `AdvisoryEvidence` + the deterministic
`VulnerabilityMatch`. `engine/redaction.py` holds the contract's §4 allowlist in full, in one
readable list, and `engine/dossier.py` applies it. Two layers, because one is not enough for a
rule this consequential:

* **Projection.** Only contracted keys, only bounded scalars, and a value that is *shaped* like a
  credential is dropped even when its key was allowed. An unknown observation type contributes
  nothing — fail-closed at the type level as well as the field level. `config` observations have a
  deliberately **empty** projection allowlist: the file never travels, and only the derived
  security flags (`telnet_enabled`, `tls_min_version`, …) are read from it.
* **Refusal.** The assembled dossier is swept for secret shapes, and a hit raises rather than
  strips. Identifiers and software components arrive as typed models and never pass through the
  projection, so the projection is not the only way in — which is precisely why the refusal sits
  at the boundary rather than inside one path.

**2. `advisory_text` is the model's only route to CVE knowledge.**

The generator holds a `ModelClient` and nothing else: no feed, no cache, no retriever
(asserted structurally by `tests/test_adapter_boundaries.py`). Because a model's signature failure
is a confident reference to a CVE nobody mentioned, a rationale naming any CVE other than the
match's is **rejected outright** — an exact check, not a heuristic, because we know exactly which
CVE this insight is about.

**3. "Grounded" means the citations resolve, not that a citations array exists.**

A model told that answers need citations will produce citations. So each one is checked: an
`advisory` citation must name the advisory we supplied; a `dossier_field` citation must name a
path that exists in the dossier; and a `quote` must actually appear in the text it claims to
quote (whitespace-insensitive, because models re-wrap lines). Unresolvable citations are dropped;
if none survive, the insight is ungrounded and raises `GroundingError`. A fabricated citation is a
hallucination wearing a footnote.

**4. KEV is sticky, and the rule is asymmetric.**

`kev_locked_visible` is set from the deterministic match, never read from the model's output. A
`lower_priority` recommendation on a KEV match raises `ValidationError`. And because
`lower_priority` is the *only* direction that can make a finding less visible, it additionally
requires a citation of the advisory text: raising or maintaining may rest on the dossier alone,
but arguing a finding down has to rest on what the advisory actually says.

**5. The snapshot is written before the model is called.**

Everything else in the system can be re-derived; what a model was handed at 03:00 last Tuesday
cannot. `triage_snapshot` is written first, carries the append-only trigger, and stores a content
hash of the canonical JSON — so "is this what the model saw?" is a comparison rather than an
argument. The insight refuses to persist without its snapshot. A refused or failed generation
still leaves the evidence behind, which is exactly the case somebody will want to audit.

**6. Three database CHECKs outrank all of the above.**

`insight_must_be_grounded`, `insight_kev_not_hidden`, `insight_derivation = 'llm_generated'`, plus
`insight_review_recorded` (a state past `proposed` names a specific human). The Python guards give
clear errors; the constraints survive a refactor, a new caller, or hand-written SQL at 02:00.

**7. The model is local, enforced at construction.**

`LocalChatModelClient` refuses any endpoint that is not loopback, a private/link-local address, or
an explicitly internal hostname. Point it at a hosted API and it does not start. The wire format
is OpenAI-compatible `/v1/chat/completions`, which Ollama, llama.cpp's server, vLLM and LM Studio
all speak — a choice of *protocol* over *vendor*, so **no model client dependency was added**:
httpx was already here for the feeds. Temperature defaults to 0, because a triage system that says
something different every night is not auditable.

**8. Failure is always conservative.**

Unreachable model, unparseable reply, ungrounded answer, refused answer, no advisory to ground on:
every one produces *no insight*, and the deterministic finding stays exactly as visible as the
correlator left it. The AI can only ever *add* a recommendation, so its absence costs nothing —
which is what makes it safe to fail loudly.

## Alternatives considered

| Option | Why not |
|---|---|
| **A hosted frontier model** | Better reasoning, and it would send a list of this company's unmanaged, exploitable devices to a third party. "Redacted" is not "publishable" (AGENTS.md §2.10). The port makes the model swappable if a customer's policy ever allows it. |
| **Let the model see raw observations "just for context"** | The single change that would undo the whole contract. Every path to the model goes through the projection. |
| **Trust the citations the model returns** | It is the cheapest possible fabrication: a plausible ref costs the model nothing. Resolving them is what makes "grounded" a property rather than a format. |
| **Reject an insight the moment any citation fails to resolve** | Too brittle: one sloppy path in an otherwise well-grounded answer would discard a good insight. Unresolvable citations are dropped, and the insight fails only if *nothing* is left. |
| **Let the model set `kev_locked_visible`** | Asking the thing being contained whether the containment applies. |
| **Allow `lower_priority` on a KEV match with a strong rationale** | There is no rationale strong enough to outweigh CISA observing exploitation in the wild. If a KEV finding genuinely does not apply, that is a *match* problem — fix the correlator, not the visibility. |
| **A structured-output/function-calling API instead of JSON-in-text** | Not portable across local runtimes, and it would move parsing into the model's control. The lenient parser (fences, prose around the object) costs ~20 lines and works everywhere. |
| **Auto-accept high-confidence insights** | `state` starts `proposed` and a human moves it. Confidence is the model's opinion of itself, which is not evidence (AGENTS.md §2.8). |
| **Retry a refused generation with a corrective prompt** | Coaching a model past a safety check until it produces an acceptable answer defeats the check. A refusal is a result. |
| **Store only the prompt string instead of the `TriageDossier`** | The dossier regenerates the prompt exactly (asserted), and it stays queryable. Storing the string would retain the same bytes in a shape nothing can read. |

## Trade-off accepted

**A local 70B model reasons less well than a frontier one.** This is the real cost of §2.10, paid
knowingly. It is mitigated by the shape of the task: the model is not asked to find
vulnerabilities or judge versions — those are deterministic and already done — but to weigh
exposure and reachability against advisory text it has been handed. And every containment rule is
enforced in code, so a weaker model produces *worse* insights, never unsafe ones.

**The secret sweep can refuse a legitimate dossier.** A `cert_fingerprint` is not a certificate,
but a collector that wrote a PEM body into one would take that asset out of the insight path
entirely. That is the intended direction — refusing to reason about one asset is recoverable;
leaking its key is not — and the failure is loud, per-asset, and names the field.

**The foreign-CVE check forbids legitimate comparisons.** "Similar to CVE-2021-44228 in impact"
is a genuinely useful sentence and it is rejected. Accepted because the same sentence is what a
hallucination looks like, and there is no way to tell them apart from the outside.

**`lower_priority` is hard to earn.** It needs the advisory cited, and it is impossible on KEV
matches. Some noisy findings will therefore stay noisy. That asymmetry is deliberate: the cost of
a finding that should have been quieter is a wasted hour, and the cost of one that should have
stayed visible is a breach (AGENTS.md §4.9).

**Redaction limits what the insight can say.** The model cannot reason about configuration detail
it never sees, so some genuinely relevant context is unavailable to it. The derived security flags
are the negotiated middle, and widening them is a contract change with a review attached — not a
field somebody adds to a payload.

## Consequences

- Nothing in `engine/` imports a model package: assembly, redaction and orchestration stay
  deterministic, and the model is reached only through `ModelClient` from `engine/triage.py`.
- Two new tables (`0007_triage_insight`), the last two in the design. `triage_snapshot` is
  append-only; `insight` carries the four constraints above.
- No new Python dependency. `uv sync` is unchanged; CI never talks to a model, because
  `ScriptedModel` and `FakeTransport` stand in at the port (AGENTS.md §43).
- The human-review path (`proposed → human_reviewed → accepted`) is forward-only and records who
  and when. Nothing in the system closes a finding automatically.
- M3 is complete. The platform now answers, end to end: what is on the network → what does nobody
  manage → what is vulnerable → what does it actually mean — with the AI contained, grounded, and
  structurally unable to fabricate a vulnerability, leak a secret, or bury an exploited finding.
- Still deliberately absent (AGENTS.md §5): `check`-module verification and
  `verified_exploitable`, LLM-proposed entity matching for M2's ambiguous queue, any UI, and any
  form of auto-remediation.
