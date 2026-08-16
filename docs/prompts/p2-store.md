Task: P2 — Store & database-enforced invariants

Goal: the M0 store schema applied as a migration, with its guarantees proven by tests.

First, read `docs/data/data-model.md` and `AGENTS.md` §3 and §5.

In scope:
- A migration tool (the one chosen in P1's ADR). Migration `0001_expand` applying the M0 subset of `data-model.md`: the tables `scope_authorization`, `audit_log`, `asset`, `observation`, `asset_identifier`, `asset_merge_event`, `managed_record` — plus the `forbid_mutation` trigger function and its triggers, and the SP-GiST containment index on `scope_authorization.cidr`.
- `tenant_id` columns exactly as specified. Do NOT enable RLS (that is LATER per AGENTS.md §5 and §6).

Out of scope (deferred — do NOT build): the tables `software_component`, `vulnerability_match`, `triage_snapshot`, `insight` (those belong to M2/M3, not M0). RLS policies.

Definition of Done:
- The migration applies cleanly on the compose Postgres, and a down/rollback path exists (never reset the DB to fix a migration — AGENTS.md §5).
- Integration tests (against the real compose Postgres, not mocks):
  - `UPDATE` and `DELETE` on each append-only table (`observation`, `audit_log`, `asset_merge_event`) are rejected by the trigger.
  - The containment query `cidr >>= $target` returns the right authorization and uses the index.
  - The strong-anchor unique index rejects a duplicate `serial`; a duplicate `ip` is allowed.
- Keep it to one coherent commit.
