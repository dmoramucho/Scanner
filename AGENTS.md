# AGENTS.md — Corporate Asset Scanner

Operating rules for any AI agent (Claude Code, Cursor, Codex) working in this repo.
Read this **and** `docs/ARCHITECTURE.md` before writing or modifying code.

These rules are ordered by authority. When they conflict, the higher rule wins:
1. **Non-negotiable invariants** (§2) — never violated, at any stage.
2. **Data architecture rules** (§3) — the product's core value; never traded for speed.
3. **AI agent rules** (§4) — how you are allowed to work.
4. **Stage tiering** (§5) — what to build *now* vs *later*. This governs everything else.
5. Stack, conventions, DoD (§6–§8).

---

## 1. What this is

A single-tenant, **on-prem** scanner for corporate networks: it discovers, fingerprints, reconciles, and correlates assets (servers, IoT, IP cameras, VoIP, UPS), prioritises vulnerabilities by real-world exploitability, and produces **AI-assisted contextual insight** on top of deterministic facts.

**First and only current client: our own organization.** Immediate goal: replace Rapid7 on-prem.

Shares conventions, and the collection→normalization→entity-resolution→correlation spine, with the broader OSINT platform. Whether this lives as a module of that repo or as a sibling repo is an **open decision** — write everything deployment- and packaging-agnostic so either works (see ADR-0001, to be written).

**Where value lives:** not in scanning (commoditised — we orchestrate nmap/masscan/Nuclei, we don't rebuild them). Value is in entity resolution, the unmanaged-device (shadow-IT) diff, confidence-based noise reduction, and contextual AI insight — exactly what Rapid7 does poorly.

**Success metric:** the diff against Rapid7. Fewer missed devices, less noise on the ones both see.

---

## 2. Non-negotiable invariants

These hold in every commit, at every stage. No feature, deadline, or agent convenience overrides them.

1. **Ports & adapters.** No infrastructure SDK (cloud, queue, DB driver, LLM client) in `domain/`. Sources and capabilities are adapters behind ports; the core never knows where a fact came from.

2. **Provenance on every asserted fact.** Every observation and every derived fact carries: `source`, `source_type`, `collector`, `collector_version`, `collection_method`, `observed_at`, `collected_at`, `confidence`, `derivation` (`deterministic | llm_proposed | llm_generated`), and a reference to the raw record. Provenance lives *in the data*, never as a runtime recompute. This is the moat — see §3.

3. **`tenant_id` on every tenant-scoped table and query, from the first migration.** Cheap now, near-impossible to retrofit. (The *enforcement machinery* — RLS, cross-tenant tests — is tiered to LATER; the *column and the discipline* are NOW. See §5.)

4. **Read-only against target/client infrastructure.** No adapter writes device or network config — ever. Credentialed access (SSH/SNMP/VAPIX) reads; it does not configure. Any future actuation (quarantine, VLAN change) is a **separate `ActuationPort`** with human-in-the-loop and dry-run, never folded into a scanning adapter.

5. **Scope is enforced in the engine, before a packet is emitted.** A target outside a tenant's registered, authorised ranges is rejected by the scheduler/engine — not by the UI, not by convention. Without this, the platform is attack infrastructure. Deny-by-default.

6. **Correlation, not exploitation.** No Metasploit `exploit`/`payload` modules, no code execution on assets. Only `auxiliary/scanner` and `check` modules, opt-in per scope, read-only. Exploitation is a different product with a different legal and insurance posture; it does not enter through a side door.

7. **Do not break embedded devices.** Fragile embedded stacks (cameras, VoIP, printers, UPS, badge readers) are the norm here, not the exception. Active scanning of anything fingerprinted as embedded uses gentle profiles (no `-A`, no `--version-all`, SYN not connect, `-T2` ceiling, rate-limited, one probe at a time per device), preceded by passive discovery, gated by a before/after health check and a circuit breaker that aborts on the first sign of distress. Devices we can authenticate to skip aggressive probing entirely — logging in and reading is gentler and truer than probing from outside.

8. **The LLM proposes; the deterministic layer disposes.** An LLM never mutates the asset graph silently, never decides a vulnerability match, never suppresses a finding on its own. It emits proposals with rationale, cited sources, and confidence. Deterministic anchors always win a conflict (a differing serial beats "the LLM says they're the same"). LLM-driven merges are soft and reversible. See §3 and §4.

9. **All external input is untrusted — including device responses AND LLM output.** Validate at every boundary before persisting, rendering, using as a filename/URL, or interpolating into a query. No `eval`/`exec`/shell interpolation/dynamic SQL on external data. LLM output is external input: it is grounded, validated, and never executed.

10. **Secrets never touch code, Git, logs, or an LLM prompt.** Credentials live in a vault behind a `SecretsPort`. Redact aggressively before anything goes to a model (see §3, asset dossier). Sensitive analysis uses a **local/self-hosted model**; nothing sensitive leaves the perimeter.

---

## 3. Data architecture rules (the moat)

The data will outlive many versions of this software. Never sacrifice integrity, provenance, lineage, auditability, or historisation to simplify an implementation.

- **Separate raw / normalized / derived.** Raw = exactly as observed. Normalized = canonical schema + CPE. Derived = correlations, scores, AI insight. Never mix categories without an explicit reason.
- **A duplicate observation is not the same real-world entity.** The same device seen by AD, passive capture, and nmap is *one asset* with *many observations* — not three rows. But a repeated observation from another source is **additional evidence** and keeps its own provenance; never silently discard it.
- **Entity resolution anchors, in priority order:** `serial › cert_fingerprint › MAC › hostname`. IP is a weak, rotating signal, never an identity.
- **`version_source` is first-class.** `package_manager` (credentialed, ground truth) vs `banner` (inferred). This flag is what prevents false positives from OS backports (a header saying `Apache/2.4.52` that is actually patched). CVE matching must read it.
- **Confidence is stratified, not boolean.** Vulnerability states: `confirmed` (credentialed version) / `probable` (banner-inferred) / `verified_exploitable` (passed a `check` module). The UI leads with confirmed; probable is a work queue ("confirm by logging in"), not noise. **KEV always overrides** — an actively-exploited match stays visible even when only inferred.
- **Evidence and history are immutable.** Do not overwrite historical or evidence records. When an attribute changes, the old state remains queryable and the new state becomes current — "what did this asset look like on date X?" must be answerable. Prefer append-only / versioned records / SCD-2; do **not** reach for event sourcing just to get immutability.
- **Merges are reversible.** Store merge events; never hard-delete a merged entity. An incorrect merge — especially one an LLM proposed — must be undoable without surgery.
- **Threshold by consequence.** Enriching a label is cheap and reversible → low bar. Merging two assets alters the graph → high bar or human review.

---

## 4. AI agent rules (mandatory)

**How you work:**

1. **Inspect before modifying.** Read the existing code, its dependencies, its tests, the affected models and migrations, and any public contract — before you change anything.
2. **Do not invent APIs.** No made-up methods, SDK functions, config keys, or framework capabilities. If unsure, check the docs or ask; do not guess.
3. **No fake implementations as a final answer.** No placeholder security, hardcoded data standing in for logic, or mock behaviour presented as done.
4. **No silent TODOs.** If something is incomplete, say so explicitly in the response — don't bury a `FIXME` that hides missing functionality.
5. **Never bypass security or weaken tests to make something pass.** Don't disable auth, TLS, cert validation, or input validation; don't delete a failing test or cut assertions. Fix the real problem.
6. **Small, coherent, reversible changes.** One concern per change. Don't refactor unrelated code while implementing a feature. Don't mix a feature, a dependency bump, and a schema change in one commit.
7. **Explain architectural decisions.** When several reasonable solutions exist: present the alternatives, state the trade-offs, recommend one, and record it as an ADR under `docs/adr/`.

**How you use AI capabilities inside the product** (in addition to §2.8):

8. **Ground, never recall.** The LLM reasons over the *real* advisory text / fix diff you pass it via RAG. It must not reason about CVEs from memory — CVE IDs are exactly what models hallucinate, and their training is stale. Every LLM claim cites its source (which advisory, which dossier field).
9. **Insight is advisory, and conservative.** The LLM may propose "probably not reachable, lower priority"; it never closes or hides a finding alone. Bias toward keeping things visible: a false negative the AI introduced is a security hole you created. KEV override is absolute.
10. **The dossier is the interface, and it is redacted.** The LLM reasons over an assembled, secret-free **asset dossier** (base contract + per-asset-type extensions), not a raw dump. What isn't in the dossier never reaches the model. This is both the token/cost boundary and the minimisation boundary.

**What you don't do:**

11. **Do not overengineer.** No microservices, message queues, event sourcing, CQRS, Kubernetes, distributed caches, graph DBs, or additional datastores without a demonstrated need. See §5 — this is where most agent failure happens on this project.

---

## 5. Stage tiering — NOW vs LATER (this governs everything)

This project has a strong engineering baseline (see `docs/`), and a baseline applied without staging becomes the overengineering §4.11 forbids. **A control is implemented when its risk is actually present — not before.** We are single-tenant, on-prem, internal. Many enterprise-grade controls are *correct later* and *premature now*.

### NOW — required for M0 (single-tenant, internal, on our own network)
- `tenant_id` column + tenant-scoped queries (discipline, not full RLS enforcement yet).
- Ports & adapters boundaries (§2.1) — get these right from line one; they're the expensive-to-retrofit part.
- Provenance and the raw/normalized/derived split (§3) — the moat; non-negotiable from the start.
- Secrets via `SecretsPort` + vault; redaction before any LLM call.
- Input validation at boundaries; external data (incl. LLM output) treated as untrusted.
- Scope allowlist enforced in the engine (§2.5) — this is a safety control, not a scaling one; it ships in M0.
- Read-only enforcement against targets (§2.4).
- Versioned migrations (`expand → migrate → validate → contract`; never reset the DB to fix a migration).
- Tests where they earn their keep **now**: parsers, normalizers, entity-resolution logic, the scope enforcer, and **negative tests** for scope rejection and read-only violation.
- Timestamps in UTC; distinguish `observed_at` / `collected_at` / `ingested_at` / `processed_at` (never collapse into `created_at`).

### LATER — deliberately deferred (revisit when the triggering risk appears)
- **Full RLS + cross-tenant isolation tests** → when a second tenant or external exposure exists.
- **SLSA, release signing, reproducible builds, artifact provenance** → when we distribute artifacts beyond this org.
- **DAST, staging-based security gates** → when there's a staging environment and an external attack surface.
- **DR formalisation (RPO/RTO), read replicas, partitioning, materialized views** → when data volume or availability targets demand it, proven by measurement not intuition.
- **SLOs / OpenTelemetry tracing across services** → when there's more than one service to trace between. (Structured logs with correlation IDs are worth doing now; distributed tracing is not.)
- **Neo4j / graph store** → only when correlation complexity outgrows Postgres, consistent with the platform's graph layer. Postgres is the M0–M2 store.
- **Transactional outbox, feature-flag infrastructure** → when a concrete consistency or rollout problem exists.

If you believe a LATER item should move to NOW, make the case in an ADR with the specific risk that justifies it. Don't just add it.

---

## 6. Stack & conventions

Match the OSINT platform's conventions:
- **Python**, managed with **uv**; **ruff** (lint+format), **mypy** (strict typing where the language allows), **pytest**.
- **Postgres** as the store (with the `tenant_id` discipline above). No second datastore without §4.11 justification.
- **Local-first**: docker-compose + LocalStack + MinIO — this is the production target for on-prem, not just a dev convenience. No cloud SDK in `domain/`, `adapters/` boundaries respected.
- **Collector**: may be a separate lightweight process orchestrating nmap/masscan/Zeek/Nuclei as subprocesses. Its language is an ADR-level decision; do not assume without recording it.
- Config separated from code; validate config at startup and **fail fast** on missing critical config — never fall back to an insecure default silently.
- Lockfiles committed; dependencies pinned; every new dependency justified (maintainer, activity, known CVEs, license, transitive weight) — a dev dependency is attack surface too.

---

## 7. Repository layout & persistent docs

Extend the existing skeleton (`docs/`, `prompts/`, `.cursor/rules/`, `data/`) with:

```
docs/
  architecture/architecture.md     # the condensed reference (see docs/ARCHITECTURE.md)
  adr/                             # one ADR per material decision (module-vs-repo, collector lang, ...)
  security/threat-model.md         # STRIDE per component; a living document
  security/security-requirements.md
  data/data-model.md               # the schema of record (built in the data phase)
  data/data-dictionary.md          # field · type · meaning · source · sensitivity · mutability · retention
  data/data-lineage.md
  runbooks/
```

`.cursor/rules/*.mdc` mirror the **durable subset** of this file (§2–§4) so they're always in the agent's context. This file is the source of truth; rules files are a projection of it.

---

## 8. Definition of Done (tiered)

A change is done when, **for its stage**:
- Acceptance criteria met; ruff + mypy clean; reviewed (AI-produced code is **not** auto-approved because tests pass — §4).
- Tests appropriate to the surface: unit for logic, negative tests for anything touching scope, read-only, or (later) tenant boundaries.
- If it touches the DB: a versioned migration with constraints, indexes, and a rollback/recovery consideration.
- Provenance preserved; historical/evidence data not overwritten; no secrets in code or logs.
- Structured logging with correlation IDs where the operation crosses a boundary.
- Docs updated (schema, data dictionary, ADR) where the change warrants it.

LATER-tier evidence (SLSA attestation, DAST pass, DR test) is **not** part of DoD until §5 moves the corresponding item to NOW.

---

## 9. Two fundamental rules

- **On the data:** never sacrifice integrity, provenance, lineage, auditability, historisation, or security to simplify temporarily. The data outlives the code.
- **On speed vs correctness:** when forced to choose between fast and correct, choose correct — but do not add complexity that isn't justified. The target is always *the simplest solution that correctly preserves architecture, security, data integrity, maintainability, and the stage-appropriate controls above.*
