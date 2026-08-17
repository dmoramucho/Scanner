# ADR-0018 — The frontend stack, and the component system as the visual backbone

- **Status:** accepted
- **Date:** 2026-08-16
- **Stage:** P20 (React scaffold + the shared component system). Against mocked data; the real
  API wiring is P21.
- **Context refs:** AGENTS.md §4.11 (don't overengineer), §5 (NOW-tier), §43 (tests are
  hermetic); `docs/design/ux-design.md` §2 (the three distinctions), §3 (the surfaces), §5;
  `docs/design/m4-design.md` §3 (the component system as backbone), §5;
  [ADR-0009](0009-reconciliation-and-shadow-it.md), [ADR-0014](0014-contained-insight-generation.md),
  [ADR-0015](0015-priority-bands-and-vlan-inference.md), [ADR-0016](0016-api-boundary-and-auth-seam.md).

## Context

Everything the backend earned — provenance, the confidence stratification, propose/dispose —
has to become *legible* now, and ux-design §2 is unusually specific about how: three
distinctions, rendered identically on every screen. Confidence (confirmed vs probable vs
verified-exploitable), management state (managed vs shadow IT vs unknown), and fact vs AI.

This step builds that layer and nothing else. The risk here is not security — that closed in
P18/P19, in the API — it is **drift**: a second screen inventing a second way to render
"probable", and the two disagreeing in front of a customer. So the decisions below are mostly
about making drift structurally hard rather than about pixels.

One thing to record honestly: **the SIGHTLINE mockup is referenced by m4-design but is not in
this repository.** The visual language below is derived from `ux-design.md` §2–§3 and
m4-design §3 — the rules the mockup was itself built from — not from the mockup's own CSS. If
the mockup's palette and spacing exist elsewhere, reconciling the two is a token-file edit
(that is the point of §3 below) and should happen before P21 wires real screens.

## Decision

**1. Vite + React 19 + TypeScript, Vitest + React Testing Library.**

Vite for the dev server and build: no bundler configuration to maintain, and it is what the
React ecosystem defaults to. Vitest because it reuses the same Vite config — one module
resolver for the app and its tests, so a component cannot pass under a resolver it does not
ship with. RTL because it asserts on what a user sees rather than on component internals,
which is the right bias for a layer whose whole job is what a user sees.

TypeScript in `strict` mode plus `noUncheckedIndexedAccess` and `exactOptionalPropertyTypes`.
The stricter pair are not decoration: the first makes `findings[0]` honestly `T | undefined`,
which is exactly the mistake an empty-worklist screen makes.

**No router, no state library, no CSS framework.** There is one surface and no server calls
yet; a dependency chosen before the problem exists is one you maintain through the version in
which it turns out to be wrong (AGENTS.md §4.11). P21 adds routing when there is something to
route between.

**2. The API's unions are the component system's vocabulary.**

`src/types/api.ts` mirrors the response models from P18/P19 by hand. Every distinction is
rendered through a `Record<Union, Treatment>` keyed by that union, so:

* a state added to the backend is a **compile error** here, not a blank badge in production;
* there is no `switch`, no string comparison, and nowhere for a fourth rendering of
  "probable" to appear.

Each union also has a `const` tuple (`CONFIDENCE_STATES`, …) so the gallery and the tests
*iterate* the same list the types are built from, rather than a hand-maintained second copy.

Hand-written rather than generated from OpenAPI: at six unions, a generator is a build step to
maintain in exchange for removing an edit that should have a human's eyes on it anyway. Worth
revisiting when the contract is ten times this size.

**3. One dictionary, one token file.**

`src/components/treatments.ts` maps every contract value to its label, its token prefix, and
the sentence that explains it. `src/theme/tokens.css` decides what a token prefix looks like.
Components contain neither: they are four-line functions that look a value up and render a
`Badge`.

That split is what makes the language reviewable — "is this consistent?" is answered by
reading one screen of code — and it is enforced: `tokens.test.ts` fails the build if any
component source contains a hex, `rgb()` or `hsl()`, or references a token the theme does not
define.

**4. The palette is quiet, and exactly one signal shouts.**

The anti-pattern named in ux-design §2 is the alert firehose: if everything is red, nothing is
urgent. So the base is near-monochrome, colour carries meaning rather than decoration, and
**KEV is the only badge with a solid fill** — asserted by a test that renders KEV beside the
loudest of everything else and counts one loud badge.

Two treatments encode rules the backend also enforces:

* **Probable is amber, not red.** It is a work queue ("verify by logging in"), and dressing it
  as an alarm puts a maybe-backport beside a real finding.
* **Unknown management state is grey and says "Unknown".** ADR-0009 refuses to count an
  ambiguous match as shadow IT; a red badge would make the same overclaim visually. The label
  is never "Possibly shadow IT".

**5. AI content cannot be rendered as if it were a fact.**

`AiPanel` carries a tinted surface, a coloured rule, the word AI-GENERATED, the model's
confidence, the review state, and the citations. `citations` is a **required prop typed as a
non-empty tuple** (`readonly [Citation, ...Citation[]]`), so a call that renders AI content
with no grounding does not compile. The UI does not *enforce* grounding — the generator, the
store and a database CHECK do (ADR-0014) — but it also refuses to be the place where an
ungrounded claim gets displayed as though it were fine.

`FactPanel` exists as its counterweight, because the distinction is only convincing when the
two sit adjacent: in isolation, any treatment looks deliberate.

**6. The gallery is a test, not documentation.**

`Gallery.tsx` renders every state of every component, driven by the union tuples, and
`Gallery.test.tsx` asserts each one appears. A component added without a gallery entry is a
component nobody will compare against the others — which is how a language drifts.

## Alternatives considered

| Option | Why not |
|---|---|
| **Next.js** | Server rendering, routing and data fetching for an app that is a single-tenant, loopback-only internal tool. A Vite SPA behind the existing FastAPI is smaller in every dimension that matters here. |
| **Storybook** | The right tool at a certain size, and a large dependency plus a second build for what one route and one test file do today. Revisit when designers are working in it. |
| **Tailwind / a component library (MUI, shadcn)** | Both would supply the *shape* and take away the *system*. The value of this layer is that the three distinctions are defined once, in terms the domain uses; a utility framework spreads colour choices back across every call site, which is the drift this ADR exists to prevent. |
| **CSS-in-JS (styled-components, vanilla-extract)** | Solves theming at the cost of a runtime or a build step. CSS custom properties are the platform's own answer, and they make the "no literal colours" test a plain text scan. |
| **Generating types from the OpenAPI schema** | Right at scale; today it trades a reviewed edit for a maintained pipeline. The P18 schema is served in dev, so this stays easy to adopt later. |
| **A single `<Badge variant="...">` with an internal variant list** | The obvious shape, and it puts every distinction in one component's `switch` — where "management state" and "priority" become the same kind of thing. The inversion here (Badge knows shape; treatments know meaning) keeps them separate. |
| **Asserting colours in tests** | Would pin the design rather than the *distinction*, and fail on every legitimate redesign. The tests assert that two states differ, and that the difference comes from a token. |
| **Snapshot tests** | They fail on every change and are approved without reading. The assertions here name the property they protect. |

## Trade-off accepted

**The visual language is derived from the blueprint, not from the mockup.** The mockup is not
in the repo, so the palette is my reading of "quiet, dense, one signal shouts". If SIGHTLINE's
own colours differ, this is a `tokens.css` edit — which is precisely why the tokens exist —
but it is an edit somebody has to notice. Flagged rather than assumed.

**Hand-mirrored API types will drift if nobody looks.** They are a copy, and copies rot. The
mitigation is small: the unions are short, the API's own tests cover the shapes, and P21 is
where a mismatch shows up immediately because the fixtures get replaced by real responses.

**No dark theme.** m4-design §5 defers theming polish. The token layer is structured so a dark
scheme is a second `:root` block and nothing else.

**Emoji as marks (🔒, 🔑).** Cheap, legible, and they render differently across platforms. Fine
for a lock and a key at 11px; an icon set is the answer when there are twenty of them.

**60 tests for a component layer may read as a lot.** They are cheap and they run in under a
second, and every one of them names a rule from the design docs rather than a rendering
detail — which is what makes them worth keeping when the design changes.

## Consequences

- New `frontend/` directory, self-contained: `npm install && npm run dev` serves the gallery on
  `127.0.0.1:5173`, with `/api` proxied to the backend so the two share an origin from the
  start and nobody reaches for CORS as a workaround.
- `npm run check` runs lint, format, type-check and tests together — the frontend's equivalent
  of the backend's four commands.
- Zero runtime dependencies beyond React and React DOM. `npm audit` is clean (vitest was
  pinned forward to pull patched vite/esbuild).
- The backend is untouched: `ruff`, `mypy` and `pytest` are unaffected by this step.
- P21 replaces `src/mock/fixtures.ts` with real `fetch` calls against P18's endpoints. Nothing
  else in this layer should need to change — which is the test of whether it was built right.
