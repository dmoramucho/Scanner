# M4 — The Functional Web Application

`docs/design/m4-design.md`

M0–M3 built the platform; P17 aligned the data model to the UX. M4 turns the mockup (SIGHTLINE) into a *working* application: a FastAPI layer exposing the backend, and a React frontend the analyst actually uses. The `ux-design.md` blueprint and the SIGHTLINE mockup are the plan; M4 builds it, connected to real data.

This is the largest milestone after M3, so it's built in steps — API first (verified), then frontend surface by surface — the same discipline that carried the backend.

---

## 1. The non-negotiable: the API is a security boundary

Until now the backend ran unexposed — code the operator executed. An HTTP API opens the platform to network requests, so **everything built with care (scope gate, secrets, LLM containment, tenant isolation) now has a new attack surface: the API itself.** M4 extends the same security discipline to the web layer; it is not "a pretty face on the backend."

Principles that hold in every endpoint:

- **The frontend never decides security.** The UI *reflects* rules (a KEV finding can't be lowered below P2; an unreviewed insight doesn't change priority) — but those rules live in the backend (DB CHECKs, `InsightGenerator`, the ports). The API **re-enforces** them. A disabled button in the UI is a convenience; if someone bypasses the frontend and calls the API directly, the API must reject just the same. Double lock, as everywhere else.
- **`tenant_id` on every request.** The API is single-tenant now (the org itself), but every query stays tenant-scoped — the discipline the schema has carried since M0. The API never lets a request read across the tenant boundary. (When RLS is later enabled, the API is where the tenant context is set.)
- **Secrets never cross the API.** The `Secret` primitive, the vault, the redaction — none of that is exposed. The API serves inventory, findings, and insights; it never serves a credential, a raw config, or an un-redacted dossier. The dossier redaction (dossier contract §4) applies to anything the API returns, not just to LLM prompts.
- **The API is an inbound adapter (AGENTS.md §2.1).** It lives in `adapters/` (or a dedicated `api/` package), depends on the domain ports, and contains no business logic — it translates HTTP to port calls and back. Correlation, ER, insight generation stay in the engine/domain; the API just exposes them.
- **Write endpoints respect the same invariants as the backend.** The only write the analyst performs is the insight review decision (accept/reject/adjust). That endpoint enforces the KEV floor and records the append-only review event (P17) — it cannot do what the backend forbids.
- **All input is untrusted (AGENTS.md §68).** Request bodies, query params, path params — validated at the boundary (Pydantic models, as the domain already uses). No injection, no unvalidated filters into queries.

---

## 2. The two pieces

### FastAPI backend-for-frontend
A thin API tailored to what the UI needs — not a generic CRUD-over-everything API. It exposes read endpoints for the surfaces (worklist, inventory, asset detail, insight detail) and the one write (review decision). It calls the existing engine/repositories through ports; it adds no logic. Auth/session is a boundary concern (see tiering — a real auth story is needed before this is exposed beyond localhost).

### React frontend
The web app, built from the SIGHTLINE mockup and the `ux-design.md` blueprint. Desktop-first, dense, calm-at-scale. Its backbone is the **shared component system for the three distinctions** (§3). It consumes the API; it holds no security logic of its own.

---

## 3. The visual language is a shared component system (the frontend backbone)

The mockup already proved this: a single `Badge` component classifying confidence / management-state / fact-vs-AI, used identically everywhere. In the real frontend this becomes the reusable core:

- **Confidence**: `Confirmed` / `Probable` / `Verified-exploitable` — one component, consistent color/treatment.
- **Management state**: `Managed` / `Shadow IT` / `Unknown` — never overclaiming ambiguous as shadow IT.
- **Fact vs AI**: deterministic data vs AI insight — AI always visually distinct, always with citations, confidence, and review state.
- Plus the recurring signals: `KEV` (urgent, locked-visible), priority band (with its reason, from P17), version-source (`credentials` vs `banner`), VLAN (marked `inferred`, per P17 — the UI shows it but never as ground truth).

Build this component layer first; every screen reuses it. If these read clearly and consistently, the analyst can trust what they see — the entire value proposition, made visible.

---

## 4. The surfaces (from the blueprint, connected to real data)

In priority order — the daily loop:

1. **Triage Home** — the prioritized worklist (KEV first, review queue, confirmed-by-EPSS, shadow-IT figure, needs-verification queue). The analyst's entry.
2. **Asset Explorer** — the dense, filterable inventory (the sweep surface).
3. **Asset Analysis** — everything about one asset (identity, exposure, software with version-source, observation timeline, vulnerabilities). Where the analyst spends the most time.
4. **Insight Review** — the human-in-the-loop: deterministic facts | AI insight with citations | decision controls. The write path. The most important interaction.
5. **Posture Overview** — the leadership glance (secondary).

The loop must be fast and stateful: filters preserved on back-navigation, breadcrumbs, keyboard navigation for a power user.

---

## 5. Tiering — what M4 is, and is not (AGENTS.md §5)

### In M4
- FastAPI BFF: read endpoints for the surfaces + the review-decision write, tenant-scoped, redacted, re-enforcing backend invariants, input-validated.
- React app: the shared component system for the three distinctions + the core surfaces (Triage Home, Asset Analysis, Insight Review first; Explorer and Posture next), consuming the API.
- Tests: API contract/enforcement tests (esp. the security ones — KEV floor, tenant scope, no-secret-exposure, redaction) + frontend component/interaction tests. API tests hermetic against a test DB; frontend against mocked API.

### Deferred (LATER — not M4, AGENTS.md §5)
- **A real authentication/authorization story** — required before the app is exposed beyond localhost. M4 builds the app; production auth (SSO, sessions, RBAC) is its own hardening step. Do NOT hand-roll auth; note it as the gate to exposure.
- Multi-user/collaboration/assignment — after the single-analyst flow.
- Real-time updates/websockets — polling suffices first.
- Actions beyond insight review (ticketing, export workflows) — read + review is the scope.
- Theming/branding polish beyond the mockup's visual language.
- Deployment/serving infra beyond local — the app runs local-first (docker-compose) like the rest.

---

## 6. Where this plugs into what exists

The API is a new inbound adapter over the existing engine/repositories/ports — the domain doesn't change. The frontend consumes it. Nothing about scanning, correlation, ER, or insight generation changes; M4 exposes and presents what's already built. Crucially, M4 also **validates the P17 alignment end-to-end**: if a screen needs a field even P17 didn't add, we catch it wiring the real UI.

Build order (P-series continues from P17) — **API first, verified, then frontend**:
1. **P18** — FastAPI BFF scaffold + read endpoints for the worklist and asset detail, tenant-scoped, redacted, input-validated; API contract + security tests (no secret exposure, tenant scope, redaction). No write yet.
2. **P19** — the insight-review write endpoint: accept/reject/adjust, re-enforcing the KEV floor and writing the append-only review event; security tests that the API rejects a KEV-lowering even if asked directly (frontend-bypass).
3. **P20** — React scaffold + the shared component system for the three distinctions (the visual backbone), against mocked data.
4. **P21** — Triage Home + Asset Analysis wired to the real API.
5. **P22** — Insight Review flow (the human-in-the-loop) wired end-to-end; then Asset Explorer + Posture Overview.
