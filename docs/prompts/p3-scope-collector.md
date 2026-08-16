Task: P3 — Scope enforcement + outbound collector + passive sweep

Goal: the safety-critical scope gate, the write path into `observation`, and a passive collector that produces observations — end to end, on fixtures.

First, read `docs/architecture/ports.md` §3 and §5, and `AGENTS.md` §2.4, §2.5, §2.10.

In scope:
- `adapters/postgres/scope_authority.py` implementing `ScopeAuthority` over `scope_authorization` (deny-by-default; every decision writes an `audit_log` entry).
- `engine/` pre-flight: the engine calls `require_authorized` before any emission; an out-of-scope target aborts and is NEVER scanned.
- `adapters/postgres/observation_sink.py` implementing `ObservationSink`: it computes `content_hash` itself, and is idempotent via `ON CONFLICT` on the run dedup key (never check-then-insert — AGENTS.md §62).
- `adapters/collector/` — the passive collector as a separable component run in-process for M0 (the mTLS/outbound boundary is LATER; structure it so it can be extracted later). Parsers for ARP table / DHCP leases / mDNS output → `ObservationInput` → `ObservationSink`. Build against fixtures (sample ARP/DHCP/mDNS captures); live packet capture is a thin wrapper, deferred.
- Read-only is satisfied by construction here (passive only; no device writes).

Out of scope (deferred — do NOT build): active scanning (nmap/masscan) and credentialed adapters — those are M1. Live packet capture wiring.

Definition of Done:
- Tests, including the negative tests that matter most (AGENTS.md §42, §75):
  - an out-of-scope target is denied, produces no observation, and produces an `audit_log` entry;
  - deny-by-default: a target with no active authorization is denied;
  - the same fixture ingested twice yields exactly one observation (`created=False` on the repeat).
- Passive sweep on a fixture produces provenance-complete observations.
- Keep it to one coherent commit.

Note to the operator: this is the safety-critical step. Before committing, I (the reviewer) want to see the full diff of `scope_authority.py` and the negative tests — paste them back.
