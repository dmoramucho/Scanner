# ADR-0016 — The API as a security boundary, and where authentication will plug in

- **Status:** accepted
- **Date:** 2026-08-16
- **Stage:** P18 (FastAPI backend-for-frontend, read endpoints). First network exposure of the
  platform. No writes (P19), no frontend (P20).
- **Context refs:** AGENTS.md §2.1 (adapters carry no business logic), §2.3 (tenant isolation),
  §2.9/§68 (all external input untrusted), §2.10 (secrets never exposed), §4.11 (don't
  overengineer), §5 (NOW-tier; auth is LATER), §43 (hermetic tests), §67;
  `docs/design/m4-design.md` §1, §2, §5; `docs/design/ux-design.md` §3;
  the dossier contract §4; [ADR-0009](0009-reconciliation-and-shadow-it.md),
  [ADR-0014](0014-contained-insight-generation.md), [ADR-0015](0015-priority-bands-and-vlan-inference.md).

## Context

Everything before this ran unexposed: an operator executed code. An HTTP listener gives every
protection built in M0–M3 a front door — the scope gate, the `Secret` primitive, tenant
scoping, the redaction allowlist, the LLM containment. m4-design §1 states the rule plainly:
**the API re-enforces the backend's rules; it never trusts a caller.** A disabled button in a
future UI is a convenience. This layer is the control.

The complication is that authentication is deliberately deferred (m4-design §5, AGENTS.md §5).
Building an unauthenticated HTTP API over a corporate asset inventory is only defensible if
"unauthenticated" is *enforced to mean local-only* rather than written in a README.

## Decision

**1. The tenant comes from the server, never from the request.**

`tenant_context()` returns `config.tenant_id`, loaded and UUID-validated at startup. No route
accepts a tenant path, query or body parameter, and no header is read — an `X-Tenant-Id` on an
unauthenticated API is a "read anything" switch, and the way to not have that bug is to not
have the parameter. `AssetQuery` uses `extra="forbid"`, so `?tenant_id=…` is a 422 rather than
something quietly ignored. A test asserts both the query and the header forms change nothing.

**This is the auth seam.** When sessions exist, the tenant starts coming from the authenticated
principal *in this one function*, and every endpoint keeps working unchanged because none of
them ever knew where it came from.

**2. Non-loopback callers are refused, in code.**

`require_local_client` is an app-level dependency (so it covers routes added later, without
anyone remembering), and it 403s anything that is not loopback unless
`SCANNER_API_ALLOW_REMOTE=1`. Bind the server to `0.0.0.0` by mistake and remote clients still
get nothing. That is the difference between a documented constraint and an enforced one.

**3. Requests run on a read-only database connection.**

P18 has no write endpoints; rather than trust that to inspection, `conn.read_only = True` on
every request connection means Postgres refuses a mutation on this path. P19's write endpoint
will take its own connection, deliberately and visibly.

**4. Asset facts are served from the redacted dossier — there is no second path.**

The asset endpoint calls `DossierAssembler`, which applies the contract's §4 allowlist and then
refuses to emit anything secret-shaped (ADR-0014). The read model deliberately has **no method
that returns an observation payload**: the timeline is provenance (who saw this, how, when).
So "the API cannot serve a secret" is a property of what the read side *can express*, not of
remembering to strip fields. A boundary test walks the routing module's syntax tree and fails
if it ever touches a payload.

**5. Responses are explicit models.**

Every endpoint declares a response schema. A field added to a domain model later cannot appear
on the wire until somebody adds it to `api/schemas.py` on purpose — the difference between
"these fields are public" and "these fields have not been made private yet".

**6. Errors say what kind, never what happened.**

Domain errors map to statuses (`NotFoundError` → 404, `ValidationError` → 422, retryable
`DependencyError` → 503, permanent → 502). Three rules on the way out:

* A **404 is a constant sentence**. "In another tenant" and "does not exist" must be the same
  answer, or the API is a membership oracle over every id in the estate.
* Every outbound detail is **swept**: UUIDs scrubbed to `<id>` (an internal identifier is not
  the caller's business), and anything credential- or PII-shaped — checked with the same
  matcher `engine/redaction.py` uses — replaced wholesale.
* An **unhandled exception is a generic 500**. A psycopg error quotes the failing statement,
  and the statement is the schema. The real thing goes to the log under the `request_id` the
  caller was given, so an operator can find it and the caller cannot read it.

**7. The API contains no business logic.**

Handlers validate, call a port, and map the result. The worklist arrives already ordered by the
store — the API does not re-rank, because the ordering is `engine/priority.py`'s opinion and a
second implementation would drift from the reason shown beside each finding. Boundary tests
assert the API imports no engine module, no model client, and that the domain and engine do not
import the API.

**8. The read side is its own port.**

`ReadModel` + `PostgresReadModel`. The surfaces need joins and counts no single write-side
repository owns, and putting those in HTTP handlers would be business logic in an adapter.
`tenant_id` is the first parameter of every method, so a cross-tenant read needs two
independent mistakes: one in the API, one in the store.

**9. FastAPI, for one reason above convenience.**

Its validation *is* Pydantic, which is already the domain's validation layer — so "all input is
untrusted" is enforced by the same models and the same rules on both sides of the boundary
rather than by two schemes that disagree at the edges. No other dependency was added: uvicorn
is the local server, starlette and the test client come with FastAPI, and httpx was already
here for the feeds.

## Alternatives considered

| Option | Why not |
|---|---|
| **A tenant header or path prefix (`/api/tenants/{id}/…`)** | The standard shape, and a "read anything" switch on an API with no authentication. Single-tenant today means there is nothing to gain and a boundary to lose. |
| **Hand-rolled auth now (a token, a session cookie)** | AGENTS.md §5 and m4-design §5 both say not to. Auth built casually is worse than auth deferred visibly: the second is a known gap, the first is a believed-solved one. The loopback gate is the honest interim. |
| **Generic CRUD/REST over the tables** | Every surface would need several round-trips and the client would assemble them — which is where security decisions leak into a frontend. A BFF returns Triage Home in one request. |
| **GraphQL** | Hands callers a query planner over the estate; the field-level authorisation story it needs does not exist yet. |
| **Serving asset facts straight from the read model** | Faster, and it would put a second path to observation data beside the redacted one. The dossier assembler is the only reader of payloads by design. |
| **Returning FastAPI's default validation errors** | They echo the offending input back, which is a reflection channel. The handler names the field and stops. |
| **A connection pool (`psycopg_pool`)** | Correct for load, and load is not a NOW-tier problem (§4.11). A connection per request keeps the read-only guarantee trivial to see. Revisit when there is a user count. |
| **Serving OpenAPI/docs everywhere** | An unauthenticated schema browser is a map of the attack surface. Dev only. |
| **Mocking the database in the API tests** | The properties under test are *tenant scoping* and *redaction*, and both are enforced partly in SQL. A mocked store would assert the mock (AGENTS.md §43 wants hermetic, which a local test DB is). |

## Trade-off accepted

**The loopback gate is not authentication and must not be mistaken for it.** It stops the API
answering the network; it does nothing about anyone with a shell on the host, and it is a
single boolean away from off. It buys the time to build auth properly. Exposing this beyond
localhost before that exists is the one thing this ADR asks nobody to do.

**Single-tenant scoping is enforced but not proven at scale.** Every query filters by tenant
and the tests plant a second tenant's data specifically to catch a leak — but the real
enforcement for a multi-tenant deployment is Postgres RLS, which is LATER. This API is where
the tenant context will be set when it lands, which is why the discipline is here now.

**A connection per request is slow.** Measurably so under concurrency. Accepted for a
single-analyst local app; the seam (`read_connection`) is one function to change.

**Error details are terse to the point of being unhelpful.** "the requested resource was not
found" tells a developer very little. The `request_id` is the compensation: it is in the
response, the header and the log line. That trade favours the operator over the caller, which
is the right way round for an API over a security tool.

**No caching, no ETags, no pagination cursors.** Offset pagination drifts under concurrent
writes and the worklist has no cache headers at all. Fine at this size; both are ordinary
work when there is a reason.

## Consequences

- New top-level `api/` package: `app` (wiring), `security` (tenant, gate, connections),
  `routes` (three surfaces), `schemas` (explicit responses), `errors` (mapping), `main`
  (the uvicorn entrypoint). `api/main.py` loads config; `api/app.create_app(config)` does not,
  so tests build an app without an environment.
- Two new configuration keys: `SCANNER_TENANT_ID` (required to serve the API, validated at
  startup) and `SCANNER_API_ALLOW_REMOTE` (off).
- Run it as `uvicorn api.main:app --host 127.0.0.1 --port 8000`. Verified end to end against
  the compose Postgres.
- P19 adds exactly one write endpoint — the insight review decision — and it will re-enforce
  the KEV floor and write the append-only review event, on its own writable connection.
