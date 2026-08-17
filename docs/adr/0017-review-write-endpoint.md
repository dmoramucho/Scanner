# ADR-0017 — The one write: connection scoping, the KEV floor over HTTP, and idempotency

- **Status:** accepted
- **Date:** 2026-08-16
- **Stage:** P19 (insight-review write endpoint). Completes the API: reads (P18) plus the one
  write. No frontend yet (P20).
- **Context refs:** AGENTS.md §2.1 (adapters carry no business logic), §2.2 (derivation),
  §2.3 (tenant isolation), §2.8 (LLM proposes / deterministic disposes; KEV non-suppression),
  §2.10, §68 (untrusted input), §4.11, §5 (auth is LATER);
  `docs/design/m4-design.md` §1, §5; `docs/design/ux-design.md` §3.4;
  `docs/data/data-model.md` §4 (append-only); [ADR-0015](0015-priority-bands-and-vlan-inference.md),
  [ADR-0016](0016-api-boundary-and-auth-seam.md).

## Context

The analyst's review decision — accept, reject, adjust — is the product's central interaction
(ux-design §3.4) and the only mutation the app offers. Exposing it over HTTP puts a specific
claim to the test: m4-design §1 says **the frontend never decides security**. A UI will grey
out the control that would bury a KEV-listed finding. That greying-out is a courtesy to the
analyst; it is worth nothing against a script, a `curl`, or the same UI with the button
re-enabled in a debugger.

So the question this step answers is not "how do we save a decision" but "what does the API
refuse, and does it still refuse when nobody is looking".

## Decision

**1. The KEV floor is enforced in the endpoint, and twice more behind it.**

A decision carrying `recommendation = "lower_priority"` on an insight with
`kev_locked_visible` is refused with a 422, whatever outcome it is wrapped in — accept,
reject or adjust. Three independent layers, none of which is load-bearing alone:

| layer | mechanism |
|---|---|
| API / store | `_refuse_kev_suppression` raises `ValidationError` → 422, before any write |
| store, again | the same check runs for an *accept* of a stored `lower_priority` insight |
| database | `insight_analyst_kev_not_hidden` refuses the row (P17) |

The second row is the interesting one: it should be unreachable, because the DB CHECK
`insight_kev_not_hidden` prevents such an insight existing. It is checked anyway, because
"unreachable" is a claim about today's code and the other is a claim about a finding staying
visible (AGENTS.md §4.9).

**2. The write capability belongs to one route, not to the app.**

P18 serves reads on connections with `read_only = True`. P19 adds `write_connection` — a
separate dependency, used only by `review_store`, which only the review route takes. Adding a
handler does not silently grant it the ability to mutate the estate; asking for the write
connection is a visible change to a signature. A test asserts, structurally, that
`review_store` depends on `write_connection` and nothing else — because a test that overrides
both connections cannot tell them apart.

**3. Who decided is server-side, exactly like which tenant.**

There is no `reviewer` field in the request body. With authentication deferred, a
caller-supplied name would let anyone sign a colleague to a decision *in an append-only
history that cannot be corrected*. `reviewer_context()` returns `SCANNER_API_REVIEWER`,
defaulting to `local-operator` — a placeholder that says what it is. It is the other half of
the auth seam opened in ADR-0016: both start returning the authenticated principal in the same
change. `extra="forbid"` on the request model means sending `reviewer` is a 422 rather than a
field quietly ignored.

**4. There is no `state` field either.** The lifecycle is derived from the outcome —
`accepted → accepted`, `rejected`/`adjusted` → `human_reviewed` — so a caller cannot ask for a
transition and an outcome that disagree.

**5. Idempotency: an identical decision is a no-op; a different one is a conflict.**

* **Identical** (same outcome, same recommendation, insight already in the resulting state) →
  200 with the current state, **nothing written**. A double-clicked button, or a client that
  never saw the first response, must not become a second entry in an immutable history.
* **Backwards** (`accepted` → `human_reviewed`) → **409**, from `ConflictError`. It is a
  well-formed request that conflicts with a decision a human already made; 422 would call the
  request malformed, which it is not. P17's store raised `ValidationError` here — changed to
  `ConflictError` so the distinction survives to the status line.
* **Forward or lateral-but-different** (adjusting to a different recommendation) → recorded.
  Changing your mind is a decision and belongs in the history.

**6. The state change and its event stay in one transaction.**

Unchanged from P17, and now asserted by breaking it: a test injects a failure on the event
insert and confirms the projection did not move. Never a state change without its event —
a projection that outlived its history would be a decision nobody can trace.

**7. Tenant scoping reaches into the store.**

`review_insight`, `insight` and `review_history` now take `tenant_id` as their first
parameter, matching `ReadModel`'s discipline (ADR-0016). Reviewing another tenant's insight is
`NotFoundError` → 404, indistinguishable from one that does not exist, so an id cannot be
probed for existence.

## Alternatives considered

| Option | Why not |
|---|---|
| **Rely on the UI to prevent KEV-lowering** | The thing this ADR exists to refuse. m4-design §1: a disabled button is a convenience; if someone bypasses the frontend the API must reject just the same. |
| **Enforce the KEV floor only at the database** | The CHECK would hold, and the caller would get a 500 from an integrity error carrying a constraint name. A refusal should be a designed answer, not a driver exception. |
| **One write-capable connection for the whole app** | Simpler by one dependency, and it makes "this API can write" a property of the process rather than of a route. The read-only default is what makes a bug in a read handler harmless. |
| **`reviewer` in the request body** | The obvious shape, and on an unauthenticated API it is a forgery primitive against an append-only audit trail. |
| **`PUT /insights/{id}` with the full object** | Invites a caller to send `state`, `kev_locked_visible`, or the model's `recommendation`. The endpoint accepts a *decision*, not a row. |
| **Idempotency keys (`Idempotency-Key` header)** | The general solution to a problem that has a specific one here: the decision itself is the key, because an identical decision on an unchanged state is definitionally a repeat. Revisit if the API ever accepts genuinely non-idempotent writes. |
| **Recording a repeat as a second event** | Defensible — a second reviewer concurring is real information — but it makes retries indistinguishable from concurrence, and a retry storm writes an unbounded history. Chosen against, and noted below as the cost. |
| **409 for an identical re-submission** | Punishes the client for a network failure it did not cause. The state already matches what was asked for; that is success. |
| **Allowing a backwards transition with a rationale** | An "unaccept" is a real workflow need and a real decision — it deserves its own verb and its own event kind, not a silent reinterpretation of `reject`. Deferred until somebody asks for it. |

## Trade-off accepted

**A second reviewer concurring is not recorded.** If two analysts both accept the same
insight, the history shows one accept. The alternative — recording every repeat — makes a
retried request indistinguishable from a genuine second opinion, and a client in a retry loop
writes an unbounded number of immutable rows. When multi-user arrives (LATER), the reviewer
identity becomes real and this policy should be revisited with it.

**`local-operator` is not a person.** Every review in the audit trail says the same thing until
authentication lands, which makes the *who* column honest but uninformative. That is the right
way round: an uninformative truth beats a name somebody could have forged.

**The KEV rule is checked in three places.** Duplication, deliberately, and it will drift if
someone changes one and not the others. The mitigation is that all three are tested — including
the database layer on its own — so drift shows up as a failure rather than as a gap.

**Backwards transitions are simply refused, not queued for approval.** An analyst who accepted
the wrong insight has no path back through this API. Given the review is advisory and the
finding stays visible either way, that is a small harm compared with a lifecycle that can be
walked in both directions.

## Consequences

- One new route: `POST /api/insights/{insight_id}/review`. The API is now complete for M4 —
  reads plus the single write, both re-enforcing the backend's invariants.
- Two new dependencies in `api/security.py`: `write_connection` and `reviewer_context`, plus
  `review_store`. Reads are untouched and still read-only, asserted.
- One new configuration key, `SCANNER_API_REVIEWER` (default `local-operator`).
- `TriageStore`'s three insight methods are now tenant-scoped; `ConflictError` replaces
  `ValidationError` for backwards transitions.
- No migration: P17 already created `insight_review_event` and the projection columns. This
  step exposes them, it does not extend them.
- P20 builds the React frontend against this API. It reflects these rules; it does not hold
  them.
