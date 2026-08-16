# M2 — CMDB Ingestion & Bidirectional Shadow-IT Diff

`docs/architecture/m2-design.md`

M0/M1 built discovery from three sources into one reconciled inventory. M2 brings in the organization's **authoritative source** — the CMDB — and computes the **diff** that turns the inventory into the sentence a CISO reacts to: *"you list 300 assets; the scanner found 347; here are the 47 nobody registered."*

This is the commercial moat. It is also **lighter than M1** — there is no new scanning engine. M2 is: (1) an adapter that reads the CMDB and lands rows in the `managed_record` table that **already exists in the schema**, and (2) the diff, which is reconciliation over pieces already built (`AssetRepository`, the store, the ER anchors).

The CMDB source for M2 is a **CSV/Excel export**. ServiceNow/API adapters are future adapters behind the same port.

---

## 1. The honest framing: the CMDB is authoritative but stale-prone

Unlike AD (updated when a machine joins the domain) or EDR (updated when the agent reports), a CMDB is often **maintained by hand** and is routinely out of date: decommissioned devices still listed, new devices never registered. This is not a defect to hide — it is a **feature of the product**, because the diff runs *both ways*:

- **In the scanner, not in the CMDB** → likely shadow IT (nobody registered it). The headline finding.
- **In the CMDB, not in the scanner** → likely stale (a record for something gone, off, or misrecorded). Shows the CMDB owner their inventory has rot.

Because the source is stale-prone, the diff produces **graded signal, not verdicts**: "this asset does not appear in your authoritative source — review it," never "this is definitely rogue." This is exactly what the existing confidence stratification is for. A false "shadow IT!" that the CISO disproves in the first demo burns trust in the whole system — so the diff must be honest about its own uncertainty.

---

## 2. New port and adapter

### `ManagedSource`
Reads an authoritative inventory and yields normalized `ManagedRecordInput`s for the `managed_record` table. A `Protocol` in the domain; the CMDB-CSV specifics live in the adapter.

```
ManagedSource.records(tenant_id) -> Iterable[ManagedRecordInput]
```

### `CsvCmdbSource` (the M2 adapter)
Reads a CSV/Excel export and normalizes each row into a `ManagedRecordInput` with `source='cmdb'`, `external_id` (the CMDB's own record id), and whatever identity fields the row carries (hostname, serial, MAC, IP, owner).

**The column mapping is explicit and configurable — never hardcoded.** A real CMDB export names columns anything (`hostname` vs `Nombre` vs `Device Name`; `serial` vs `S/N`). The adapter takes a **mapping config** (which spreadsheet column feeds which identity field) so it works against the operator's real export without code changes. This is the difference between "works on the fixture" and "works on your actual Excel."

- Rows are **untrusted input** (AGENTS.md §68): validate/sanitize before they become records. A CSV can carry malformed rows, injection-shaped cells, huge fields, blank identity — handle each explicitly (skip-with-reason, never crash, never silently drop without counting).
- No secret-bearing data goes into `managed_record`; the CMDB export shouldn't contain credentials, but sanitize regardless.
- Idempotent ingestion: re-importing the same export lands once (the `managed_record` unique key `(tenant_id, source, external_id)` already enforces this).

---

## 3. The reconciliation: matching CMDB records to assets

The diff is only as good as this matching. A record matches an asset by the **same anchor priority the ER already uses**: `serial › mac › hostname` (normalized). This reuses the entity-resolution logic conceptually — it is the same "are these the same real thing?" problem, now crossing *management records* against *discovered assets*.

- **Strong-anchor match** (serial/MAC) → confident link; the `managed_record.asset_id` is set.
- **Hostname-only match** → weaker; normalize aggressively (case, domain suffix, separators) before comparing, and mark the link's confidence lower.
- **No match** → the record stays unlinked (a CMDB entry with no discovered asset = a stale candidate).

**Deterministic now, LLM seam prepared (AGENTS.md §5).** Matching is deterministic in M2. The genuinely ambiguous cases — a hostname written three different ways, no serial, unreliable DNS — are left as explicitly *unresolved*, not force-matched. The code is structured so an LLM proposer (M3) can later resolve those ambiguous cases through the existing propose/dispose pattern; the `derivation` field already exists for it. We do NOT bring the LLM into M2 — first **measure** how many ambiguous cases the real CMDB actually produces (§4.11, prove the need).

> Why this matters: weak matching makes the diff **lie**. If a server IS in the CMDB but didn't match (hostname typed differently), the diff falsely flags it as shadow IT. So unmatched-by-ambiguity is reported as its own category ("could not confidently match"), distinct from confidently-shadow-IT — the diff never overclaims.

---

## 4. The bidirectional diff

Computed over the current state, produced as graded findings:

| Category | Meaning | Confidence framing |
|---|---|---|
| **Unmanaged (shadow IT)** | Active asset, no CMDB record by any anchor | strong when the asset has strong anchors; softer when only a locator matched |
| **Stale** | CMDB record, no discovered asset | a candidate — the device may be off, not just gone |
| **Matched** | Asset ↔ CMDB record linked | the healthy baseline |
| **Ambiguous** | Could not confidently match either way | explicitly *not* a shadow-IT claim — a review queue |

The diff derives `management_state` on the asset (`managed` / `unmanaged` / `unknown`) — the field already in the schema — from the confident links. Ambiguous cases resolve to `unknown`, not `unmanaged`, so the headline shadow-IT number is defensible: it counts only assets we are confident nobody manages.

---

## 5. Testing (fixtures for CI + real CMDB to validate)

- **CI on fixtures**: sample CSV exports — a clean one, and a messy one (renamed columns, blank rows, a duplicate, a malformed cell, a decommissioned entry with no matching asset, an asset with no CMDB row). Assert the column mapping works, bad rows are skipped-with-reason, ingestion is idempotent, and the four diff categories come out correct. CI never needs the real CMDB.
- **Real CMDB validation** (manual, documented like the M1 runbook): point the adapter at the operator's actual export with the real column mapping, and check the diff against reality — is the shadow-IT list actually unregistered devices, or matching failures? This is where the real CMDB's naming idiosyncrasies get shaken out, and where you **measure** whether deterministic matching suffices or M3's LLM proposer is needed.
- Safety-style assertions: the shadow-IT count never includes an ambiguous/unmatched-by-weakness case (no overclaiming); re-import is idempotent; a hostile CSV cell never executes or corrupts a record.

---

## 6. Tiering — what M2 is, and is not (AGENTS.md §5)

### In M2
- `ManagedSource` port + `CsvCmdbSource` adapter with configurable column mapping.
- Ingestion into the existing `managed_record` (idempotent, untrusted-input-safe).
- Deterministic reconciliation (record ↔ asset) reusing anchor priority.
- The bidirectional, confidence-graded diff; `management_state` derived.
- Fixtures-based tests; a documented real-CMDB validation procedure.

### Deferred (LATER — not M2)
- AD/LDAP, MDM, EDR adapters — future `ManagedSource` adapters behind the same port.
- ServiceNow/API CMDB — a future adapter (M2 is CSV/Excel).
- LLM-proposed matching for ambiguous cases — M3, through propose/dispose; seam only in M2.
- CPE→CVE correlation and AI insight — M3.
- Any UI for the diff — the diff is data in M2; presentation is separate.

---

## 7. Where this plugs into what exists

`managed_record` already exists; the ER anchors already exist; `management_state` already exists on `asset`. M2 adds a *source of authoritative records* and the *diff logic* — it does not change the spine, the ER, or the scanning. The moat becomes visible: the reconciled inventory can now answer "what does nobody manage?" — the single most valuable question the product answers.

Build order (P-series continues from P9):
1. **P10** — `ManagedSource` port + `CsvCmdbSource` adapter (configurable column mapping, untrusted-CSV-safe, idempotent into `managed_record`), fixtures-based tests. No diff yet.
2. **P11** — deterministic reconciliation (record ↔ asset by anchor priority, LLM seam left) + the bidirectional confidence-graded diff + `management_state` derivation; the documented real-CMDB validation procedure.
