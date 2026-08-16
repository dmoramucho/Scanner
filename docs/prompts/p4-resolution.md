Task: P4 — Entity resolution

Goal: observations resolve into assets by stable anchors, with reversible merges — the start of the moat.

First, read `docs/architecture/ports.md` §6 and `AGENTS.md` §3 (ER rules, deterministic-wins, reversible merges).

In scope:
- `adapters/postgres/asset_repository.py` implementing `AssetRepository`:
  - `resolve` — match on strong anchors first (`serial › cert_fingerprint › mac`); deterministic only, never an inferred identity as a hard match.
  - `upsert_from_anchors` — idempotent get-or-create, linking the asserting observation.
  - `set_current_software` — current-state projection (history stays in `observation`).
  - `record_merge` / `reverse_merge` — transactional: the append-only event and the `asset.status`/`merged_into` change commit together; LLM-proposed merges without a rationale are rejected.
- Wire the ingestion path: observation → resolve/upsert asset → attach identifiers.

Out of scope (deferred — do NOT build): LLM-proposed merges (the generator is M3; the schema/`derivation` support exists now but nothing produces `llm_proposed` yet). Correlation, insight.

Definition of Done:
- Tests:
  - two observations sharing a `serial` resolve to one asset; differing serials to two;
  - `upsert_from_anchors` is idempotent under repeat;
  - a merge then its reversal leaves the merged asset `active` again, and both events are recorded (append-only);
  - a `record_merge` with `derivation='llm_proposed'` and no rationale is rejected (belt-and-suspenders with the DB CHECK).
- Keep it to one coherent commit. M0 done: collector → scope-gated → observation → resolved assets, all tested.
