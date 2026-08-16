# Runbook — validating the shadow-IT diff against the real CMDB

`docs/runbooks/validate-cmdb-diff.md` · owner: whoever runs the import · **not a CI test**

---

## Why this exists

The tests prove the diff is *internally* correct: a shared serial links, an unresolved case
never inflates the shadow-IT number, the four categories partition the estate. What they cannot
prove is whether the matching rules survive contact with **your** CMDB — whose hostnames were
typed by fourteen people over nine years, whose serial column is half empty, and whose
"decommissioned" devices are still listed.

That is what this procedure shakes out. Two questions, and the second matters more:

1. **Is the shadow-IT list real?** Are those devices genuinely unregistered, or did our matching
   fail on a naming quirk?
2. **How big is the ambiguous pile?** That number decides whether deterministic matching suffices
   for this estate or whether M3's LLM proposer is warranted (m2-design §5). Measure it before
   deciding — that is the entire point of running this rather than assuming.

Unlike the gentle-scan runbook, **nothing here touches a device**. The risk is not an outage; it
is showing someone a confidently wrong list and losing their trust in the product. Budget an
afternoon and a person who knows the estate.

---

## 0. Before you start

- [ ] **A CMDB export you are allowed to have.** It is an inventory of the organization's
      hardware — treat it as internal-confidential and keep it off shared drives.
- [ ] **A person who knows the estate** to sit with you for the spot checks. You cannot judge
      whether `SRV-APP-03` is a real server or a decommissioned one; they can.
- [ ] **The stack up and migrated** (`docker compose up -d`, `alembic upgrade head`), with
      discovery already run — the diff compares against what has been *found*, so a half-scanned
      network produces a meaningless "stale" list.
- [ ] Know your `tenant_id`.

> **A word about expectations.** The first run is usually ugly: a big ambiguous pile, stale rows
> for devices that were switched off, shadow IT that turns out to be the lab. That is the
> product working — it is showing you the state of your inventory. The output to be suspicious
> of is a suspiciously clean one.

---

## 1. Export the CMDB

Ask for **everything, not a filtered view**. A pre-filtered export ("only active servers") will
make every filtered-out device look like shadow IT.

- [ ] Export as `.csv` or `.xlsx` — both are read the same way.
- [ ] Include, at minimum: the CMDB's own **record id**, and whichever of **serial**, **MAC**,
      **hostname** it holds. Owner and site are useful for the spot checks.
- [ ] **Export values, not formulas.** If the sheet computes a column (`=B2&"-"&C2`), the
      importer stores the formula text rather than its result — visible in the import's
      `defanged_cells` count. Paste-as-values first (ADR-0008).
- [ ] Note **when** it was exported. That timestamp becomes `observed_at`, and it is what makes
      "the CMDB said this as of Tuesday" answerable later.

---

## 2. Write the column mapping

Open the file, read the header row, and map it. The names are the operator's, not ours — this
step is the difference between "works on the fixture" and "works on your actual Excel"
(m2-design §2).

```python
from adapters.managed.cmdb_csv import ColumnMapping

MAPPING = ColumnMapping(
    external_id="Asset ID",  # the CMDB's own record id — required
    hostname="Device Name",
    serial="S/N",
    mac="MAC Address",
    ip="IP",
    owner="Assigned To",
    extras={"site": "Location", "lifecycle": "Status"},
)
```

- A mapped column that is not in the file fails immediately, by name. That is deliberate:
  reading it as empty would produce an import that succeeds and loses the field you cared about.
- At least one of serial / MAC / hostname must be mapped, or nothing can ever be matched.
- **Check the serial column is actually serials.** A column called `Asset Tag` containing
  inventory stickers rather than hardware serials will match nothing, and everything will look
  like shadow IT. Eyeball twenty rows against a device.

---

## 3. Import, then diff

```python
# validate_cmdb_diff.py — run with: set -a; . ./.env; set +a; uv run python validate_cmdb_diff.py
from datetime import datetime, UTC
from uuid import UUID

import psycopg

from adapters.managed.cmdb_csv import ColumnMapping, CsvCmdbSource
from adapters.postgres.managed_record_sink import PostgresManagedRecordSink
from adapters.postgres.reconciliation_store import PostgresReconciliationStore
from config import load_config
from engine.managed_import import ManagedImport
from engine.shadow_it import ShadowItReconciler

TENANT = UUID("<TENANT_UUID>")
EXPORTED_AT = datetime(2026, 8, 14, 9, 0, tzinfo=UTC)  # when the export was taken

with psycopg.connect(load_config().database_url.reveal(), autocommit=True) as conn:
    imported = ManagedImport(
        CsvCmdbSource("<PATH-TO-EXPORT>", MAPPING, observed_at=EXPORTED_AT),
        PostgresManagedRecordSink(conn),
    ).run(TENANT)
    print("import:", imported.rows_read, "rows →", imported.records, "records")
    print("skipped:", imported.skip_reasons)
    print("defanged cells:", imported.defanged_cells)

    diff = ShadowItReconciler(PostgresReconciliationStore(conn)).run(TENANT)
    print("diff:", diff.counts)
    print("shadow IT:", diff.shadow_it_count)
    print("ambiguous rate:", round(diff.ambiguous_rate, 3))
```

**Read the import numbers before the diff numbers.** They come first for a reason:

- `rows_read` should match the row count of the file. If it does not, the mapping or the header
  is wrong.
- `skip_reasons` is a conversation with the CMDB owner, not an error log. `no_identity: 340` means
  a third of their inventory has no serial, MAC or hostname — which is why the diff will be
  vague about those devices.
- `defanged_cells > 0` means the export contains formulas (see §1).

---

## 4. Spot-check a sample of each category

This is the part that cannot be automated. Take **ten of each**, at random, and ask the person
who knows the estate.

```sql
-- Shadow IT: what we say nobody manages.
select a.id, a.management_state,
       array_agg(distinct i.kind || '=' || i.value) as anchors
from asset a join asset_identifier i on i.asset_id = a.id
where a.tenant_id = '<TENANT_UUID>' and a.management_state = 'unmanaged' and a.status = 'active'
group by a.id limit 10;

-- Stale: CMDB rows nothing on the network matches.
select external_id, payload ->> 'hostname' as hostname, payload ->> 'serial' as serial,
       payload ->> 'owner' as owner
from managed_record
where tenant_id = '<TENANT_UUID>' and asset_id is null limit 10;

-- Matched: the healthy baseline.
select m.external_id, m.payload ->> 'hostname' as cmdb_name, a.id as asset_id
from managed_record m join asset a on a.id = m.asset_id
where m.tenant_id = '<TENANT_UUID>' limit 10;

-- Ambiguous: assets the diff refused to judge.
select id from asset
where tenant_id = '<TENANT_UUID>' and management_state = 'unknown' and status = 'active' limit 10;
```

For each sample, record the verdict:

| Category | Ask | A good answer | A bad answer, and what it means |
|---|---|---|---|
| **Shadow IT** | "Is this device registered anywhere?" | "No — that is the lab Pi / a contractor's laptop / nobody knows" — a true finding | "Yes, it is right here in the CMDB" — a **matching failure**. The most important bug this exercise can find |
| **Stale** | "Does this device still exist?" | "It was decommissioned last year" — the CMDB has rot, which is a finding for its owner | "It is switched on right now" — discovery has not reached it (wrong VLAN? scope not registered?) |
| **Matched** | "Is this the same machine?" | Yes | A wrong link — check whether the serial column is really serials |
| **Ambiguous** | "Which of these is it?" | They can tell instantly from context | They cannot either — genuinely ambiguous, and the LLM proposer would not help |

**Every shadow-IT false positive is a bug worth chasing.** Find out *why* it did not match: a
hostname typed differently, a serial with a prefix, a MAC recorded for the wrong NIC. That is the
data that decides what M3 needs to be.

---

## 5. Measure the ambiguous rate — the number that decides M3

```
ambiguous rate = assets the diff could not resolve ÷ assets it reached a conclusion about
```

Printed by the script (`diff.ambiguous_rate`), and counted **per asset**, not per finding.

| Rate | Reading | What to do |
|---|---|---|
| **< 5%** | Deterministic matching is doing its job on this estate | Nothing. An LLM proposer would be solving a problem you do not have (AGENTS.md §4.11) |
| **5–20%** | A real review queue, but a bounded one | Look at *why*. If it is one repeated pattern (a domain suffix, a naming convention), a normalisation rule fixes it deterministically and costs nothing |
| **> 20%** | The CMDB and the network disagree about naming at scale | **This is the evidence M3's proposer is warranted.** Record the rate, the sample, and the dominant pattern — that is the case for it, in an ADR |

Write the number down with the date and the export it came from. Re-measure after any
normalisation change: the point of the rate is to watch it move.

> **Do not reach for the LLM because the pile looks big.** Read twenty ambiguous cases first.
> The common outcome is that most of them share one fixable pattern, and a deterministic rule
> removes them for good — with no model, no cost, and no non-determinism in the number a CISO is
> looking at.

---

## 6. Before showing anyone the number

The headline is *"N devices nobody manages"*. Before that sentence is said out loud:

- [ ] **Every shadow-IT sample checked out** as genuinely unregistered. If any was a matching
      failure, the number is wrong — fix the matching and re-run before presenting.
- [ ] **The ambiguous pile is disclosed alongside it.** "47 unmanaged, and 12 we could not
      confidently match either way" is a defensible sentence. "47 unmanaged" alone is not, if
      those 12 exist.
- [ ] **Coverage is stated.** The diff compares against what discovery *found*. If a VLAN was
      never scanned, its devices are missing from both sides, and the number understates.
- [ ] **The export date is stated.** A CMDB from March compared against a scan from today will
      show as stale everything decommissioned since.

---

## 7. Re-running

The diff is recomputed from scratch every run and both projections are assignments, so re-running
after a corrected export or more discovery is safe and idempotent. A link that was right last
month and is wrong now is cleared, not defended.

```bash
# After a fresh export or another discovery run:
uv run python validate_cmdb_diff.py
```

Keep a small log: date, export date, `counts`, `shadow_it_count`, `ambiguous_rate`. The trend is
the interesting part — a rate that falls as normalisation improves, and a shadow-IT count that
falls as the CMDB owner registers what you found. That log is the product working.

---

## Known gaps

- **No CLI.** §3 is a script, like the gentle-scan runbook. Both want the same missing thing.
- **The diff is data, not a report.** M2 produces categories and counts in the database; there is
  no UI and no export (m2-design §6). The SQL in §4 is how you read it.
- **One source.** `ManagedSource` is a port with one adapter (CSV/Excel). AD, MDM and EDR would
  each answer "is this ours?" differently and better for their own slice of the estate; they are
  future adapters behind the same port.
- **Hostname matching is deliberately conservative.** `srvapp03` and `srv-app-03` are reported as
  ambiguous rather than linked, because squashing punctuation is where false matches come from
  (ADR-0009). If your estate names things that way consistently, that shows up as a high
  ambiguous rate — which is the signal, working as intended.
