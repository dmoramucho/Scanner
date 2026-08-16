# UX Design — Final Product

`docs/design/ux-design.md`

The blueprint for the product UX, before any mockups — the interface equivalent of the milestone design docs. It fixes *who uses it, for what, and how the interface embodies the moat*, so the mockups (and eventually the UI code, M4) are built on a plan rather than improvised.

This is the **final product UX**, not a demo. A demo shows the "aha"; this supports the daily work of a security analyst who lives in the tool. The product lives or dies on how it handles **volume and prioritization** — which is exactly the moat (noise reduction, confidence stratification). The UX must *be* that, not just show it.

---

## 1. Who, and the core job

**Primary user: a security analyst doing daily triage.** Not an occasional visitor — someone who opens this tool every morning and works in it. Design for their eight-hour day, not a five-minute impression.

**Core job:** analyze assets with all their associated information — vulnerabilities and AI insights — *across all assets*. This decomposes into **two distinct work modes**, and the UX lives in the flow between them:

- **Fleet-wide (sweep):** across all assets, find what's most urgent. The analyst looks at the *set*, not one asset, and lets prioritization pull them to what matters. The work is *finding signal in volume*.
- **Asset-deep (investigate):** once prioritization surfaces an asset or vuln, see *everything* about it — identifiers, exposure, history, vulnerabilities, and the AI insights to review and accept/reject.

**The daily loop:** sweep → spot the urgent → drill in → review the insight → decide → back to sweep. The UX must make this loop *fluid* — not force jumps between disconnected screens. This flow is the single most important thing the design gets right.

**The interaction is read + review/accept AI insights** — the human-in-the-loop of the propose/dispose pattern. The analyst seeing what the AI proposed, why, and deciding is a **first-class interaction — probably the most important one in the product.** It's literally where the insight `state` transitions `proposed → human_reviewed → accepted`.

**Platform: desktop-first web app.** The core work — sweeping hundreds of assets, comparing, drilling in — needs screen width and information density. Tablet/responsive can follow; mobile-first would compromise the density this user needs.

---

## 2. The principle: the UX embodies the moat

Everything the backend earned — provenance, confidence stratification, the LLM-proposes/deterministic-disposes discipline — has to become *legible* here, without overwhelming. This is the hardest and most important part of the design.

Three distinctions run through every screen and must be visually consistent everywhere:

- **Confidence** — `confirmed` (package-manager ground truth) vs `probable` (banner-inferred, may be a backport false-positive) vs `verified_exploitable`. Leads with confirmed; probable is a *work queue* ("verify by logging in"), never mixed in as equal-weight noise.
- **Management state** — `managed` vs `unmanaged` (shadow IT) vs `unknown` (ambiguous match — never overclaimed as shadow IT).
- **Fact vs AI** — deterministic data vs AI-generated insight. AI content is *always* visually distinct, always shows its citations (grounding), always shows a confidence and a review state. The analyst must always be able to tell "this is what the system knows" from "this is what the AI suggests, and here's why."

A consistent, legible visual language for these three (a badge/color system, used identically everywhere) is the backbone of the whole UI. If these read clearly, the analyst can trust what they see and know when to doubt — which is the entire value proposition made visible.

**The anti-pattern to avoid:** an alert firehose. Hierarchy and clarity over raw density. The competitor's failure (Rapid7's noise) is the thing this UX must not reproduce.

---

## 3. Information architecture

Five surfaces, connected so the daily loop flows. Ordered by how central they are to the analyst's day.

### 3.1 Triage Home (the default landing — the "what do I look at first")
Where the analyst starts every day. NOT a vanity dashboard — a *prioritized worklist* across all assets. It answers "what's most urgent right now" by surfacing:
- KEV-flagged findings first (actively exploited — the sticky override), regardless of confidence.
- Then high-EPSS confirmed findings.
- The AI-insight review queue (insights in `proposed` state awaiting human review) — the human-in-the-loop work, front and center.
- The shadow-IT count as a persistent, glanceable figure (the CISO number, but here it's a filter into work).
- A "needs verification" queue (probable findings the analyst could confirm by logging in).

This is the entry to *fleet-wide* mode. Every item is a doorway into *asset-deep* mode.

### 3.2 Asset Explorer (fleet-wide browse/filter)
The full inventory as a dense, filterable table — the sweep surface. Columns: name/hostname, class (server/camera/VoIP/…), management state, identification confidence, open-vuln count (broken down by confidence), KEV flag. Powerful filtering (by class, management state, confidence, has-KEV, "unmanaged only"). This is where the analyst slices the fleet. Sortable by risk. Every row → the Asset Analysis view.

### 3.3 Asset Analysis (asset-deep — the core screen, where the analyst spends the most time)
The heart of the product — everything about one asset in one place, because the core job is "analyze an asset with all its associated info." Sections:
- **Identity & context header**: name, class, management state, identification confidence. The management state is prominent (managed / shadow IT / unknown).
- **Exposure**: reachability (internet-facing / internal / isolated), VLAN/segment, open ports with services.
- **Software/firmware**: each component with its version and — critically — its `version_source` badge (**confirmed via credentials** vs **inferred from banner**). This is where the confidence distinction first bites.
- **Observation timeline**: the asset seen by different sources over time (passive, active, credentialed, CMDB) — the provenance/history made visible. "What did this look like on date X."
- **Vulnerabilities**: the asset's findings, confidence-stratified, KEV/EPSS shown, each expandable into its AI insight.

### 3.4 Insight Review (the human-in-the-loop — a first-class flow, not a modal afterthought)
Where the analyst reviews an AI insight and decides. This is *the* interaction. For a given vulnerability match, it shows — with the AI content *visually separated* from the deterministic facts:
- The deterministic facts: CVE, confidence-state badge, KEV badge, EPSS.
- The **AI Insight panel** (clearly AI-marked): the recommendation (raise/lower/maintain priority), the plain-language rationale, and the **citations** — which advisory text and which asset facts the insight grounded on (the analyst can *check the AI's work*). Plus the AI's confidence and current review state.
- The **decision controls**: accept / reject / adjust — transitioning `proposed → human_reviewed → accepted`, recorded with who/when. KEV findings show as locked-visible (the AI can't and the analyst shouldn't bury them).

The design goal: reviewing an insight should feel like *checking a colleague's reasoning*, not rubber-stamping a black box. The citations are what make that possible — they're not decoration, they're the trust mechanism.

### 3.5 Posture Overview (the CISO/leadership glance — secondary, but present)
A summary surface for the leadership audience: shadow-IT count, KEV-exposed count, coverage, trend. Not the analyst's daily driver, but the product needs it — and it's what turns the analyst's work into the executive story. Kept deliberately separate from the analyst's triage surfaces so neither compromises the other.

---

## 4. The flow (how the surfaces connect — this is the design)

```
Triage Home ──(urgent item)──▶ Asset Analysis ──(a vuln)──▶ Insight Review ──(decide)──▶ back to Triage Home
     │                              ▲                                                          
     └──(browse/slice)──▶ Asset Explorer ──(a row)──┘                                         
```

The loop must be *fast*: from "what's urgent" to "the asset" to "the insight" to "decided" and back, without losing context. Breadcrumbs, back-to-worklist that preserves filters, keyboard navigation for a power user who does this hundreds of times. The analyst should never feel they're "navigating an app" — they're working a queue.

---

## 5. What makes this the *final* UX, not a demo

- **Volume-first, not example-first.** Every surface is designed for hundreds/thousands of items — pagination, filtering, sorting, saved views — not the tidy five-row demo. The noise-reduction moat only matters at scale, so the UI must feel good at scale.
- **The human-in-the-loop is built in, not bolted on.** The review queue is on the landing page; the decision controls are a first-class flow; the state transition is recorded. This is the product's core interaction, treated as such.
- **Trust is designed, not assumed.** Citations visible, provenance surfaceable, confidence never hidden, AI always distinguishable from fact. The analyst is given the means to *doubt correctly*.
- **The three distinctions are consistent everywhere.** One badge/color language for confidence, management state, and fact-vs-AI — learned once, applied everywhere.

---

## 6. What's deferred (so the first mockups stay focused)

- Multi-user / assignment / collaboration (who's working what) — real for a team, but layer it after the single-analyst flow is right.
- Actions beyond insight review (ticketing, export, remediation workflows) — the current scope is read + review/accept; other actions come later.
- Notifications/alerting, saved reports, scheduling — product surface area that follows the core loop.
- Theming/branding polish — the mockups establish structure and the visual *language*; final polish is later.
- Role-based views (CISO vs analyst vs IT) as separate experiences — Posture Overview is the leadership seed; full role separation is a later decision.

---

## 7. Next steps

1. **Mockups in Claude Design**, built from this blueprint — starting with the two most important surfaces: **Triage Home** (the daily entry / worklist) and **Asset Analysis** (where the analyst spends the most time), plus the **Insight Review** flow (the first-class human-in-the-loop interaction). These three prove the daily loop.
2. Establish the **visual language** for the three distinctions (confidence, management state, fact-vs-AI) in the mockups — this is the backbone everything else reuses.
3. Iterate on the mockups against real-ish volume (a realistic fleet, not five rows) to confirm the noise-reduction moat actually feels calmer than the alternative.
4. Once the mockups settle, the UI becomes a build milestone (M4) — and, critically, validates the data model: if a screen needs a field the schema doesn't have, we catch it here, before more backend.
