# ADR-0008 — CMDB import: column mapping, formula defanging, and the Excel reader

- **Status:** accepted
- **Date:** 2026-08-16
- **Stage:** P10 (`ManagedSource` port + `CsvCmdbSource` adapter).
- **Context refs:** AGENTS.md §2.2 (provenance), §2.9 (external input is untrusted), §3 (data
  integrity, never silently dropped), §4.4 (no silent gaps), §4.11 (don't overengineer), §6
  (dependency justification), §62 (unique constraint, not check-then-insert);
  `docs/architecture/m2-design.md` §1, §2; [ADR-0003](0003-nmap-orchestration.md).

## Context

The CMDB export is the other half of the shadow-IT diff, and it arrives as a file a person
edited in a spreadsheet. Three decisions in reading it are material enough to record: how
columns are named, what to do about the fact that spreadsheet cells are programs, and which
library reads `.xlsx`.

The consequence of getting any of them wrong is specific and bad. A row lost on import does not
merely go missing — in P11 it makes a *managed* device look like shadow IT, which is the false
accusation m2-design §1 says burns trust in the whole product on first demo.

## Decision

**1. The column mapping is explicit configuration, and a missing mapped column is a hard error.**

`ColumnMapping` names which spreadsheet column feeds `external_id`, `hostname`, `serial`, `mac`,
`ip`, `owner`, plus free-text `extras`. `external_id` is mandatory (idempotency has to key on
something) and at least one identity column is mandatory (records with none can never be
matched). A mapped column absent from the file raises before a single row is read.

Reading a missing column as empty was the alternative, and it is the trap: the import succeeds,
the operator sees "3,412 records", and every one of them is missing exactly the field they
mapped.

**2. Every cell is defanged at ingestion, and identity fields must additionally validate.**

A cell beginning `=`, `+`, `-`, `@`, tab, or carriage return is prefixed with `'` — the marker
every spreadsheet already reads as "this is text" — and the defanging is counted in the report.
The content is preserved, not deleted.

Identity fields go further: a hostname must match a hostname pattern, a MAC must normalise to
canonical form, an IP must be a valid dotted quad. A defanged value fails all of these, so a
formula in an identity column becomes `None` — refused as an anchor rather than stored in
defanged form, because P11 *matches* on these and a poisoned anchor is worse than a missing one.

**3. `.xlsx` is read with openpyxl, `read_only=True, data_only=False`.**

`data_only=False` is the deliberate half. Asking for cached values instead returns `None` for
any formula the file was saved without a cached result for — a field that silently becomes
empty, which is the failure mode this adapter exists not to have. Taking the literal cell
content means an `.xlsx` behaves exactly like the same export saved as `.csv`: formulas arrive
as text, get defanged, and are counted.

## Alternatives considered

| Option | Why not |
|---|---|
| **Infer columns by fuzzy header matching** (`"S/N"` ≈ serial) | Guesses about which column is the serial, silently, on the data the whole diff is computed from. A wrong guess is invisible and produces a confidently wrong shadow-IT list. |
| **Hardcode the column names** | Works on the fixture, fails on the operator's actual export — which m2-design §2 calls out as the difference that matters. |
| **Read a mapped-but-missing column as empty** | An import that succeeds while losing the field the operator cared about most. |
| **Strip the leading formula character** | Loses data, and silently: `-1234` becomes `1234`. A prefix preserves the value and is visible. |
| **Reject any row containing a formula-shaped cell** | Throws away real inventory because a free-text "Notes" column starts with a dash. Defang the cell, keep the row, refuse it only if what remains has no identity. |
| **Defang on export instead of on import** | The export code does not exist yet, and would have to remember. Defanging at the boundary means every future consumer of `managed_record` is safe by default. |
| **`data_only=True` for Excel** | Returns the cached value when the file has one — nicer for formula-computed cells — but `None` when it does not, which is a silent field loss. Rejected for that; the visible defanged value is the better failure. |
| **pandas / `read_excel`** | A very large dependency (and NumPy) to read a few thousand rows, with type coercion that would turn a serial like `1.20E+05` into a float. |
| **A CSV-only adapter** | Operators export what their CMDB gives them, and that is frequently `.xlsx`. Refusing it moves the conversion — and the risk of a hand-edited intermediate file — onto the operator. |

## Trade-off accepted

**A legitimate value starting with `-`, `+` or `@` is stored with an apostrophe.** A negative
number in a free-text column, or a serial beginning with a dash, will look slightly altered. The
report counts every defanged cell so this is visible rather than mysterious, and identity fields
are unaffected in practice because such a value fails its pattern and is refused anyway.

**A formula-computed cell is stored as its formula, not its result.** With `data_only=False`, an
export whose hostname column is `=B2&"-"&C2` yields a defanged formula rather than `APP-01`.
That row will usually be refused as identity-less — counted, not silent — and the operator's
remedy is to export values rather than formulas. The alternative silently produced empty fields,
which is worse.

**`external_id` collisions within one file take the first row.** The file disagrees with itself
and there is no principled way to know which row is current; the second is refused with a reason
so the CMDB owner can fix their export.

## Consequences

- One new dependency: **openpyxl** (pure Python, one small transitive dependency, `et-xmlfile`).
  It parses workbook XML through `defusedxml` when that is installed — which it is, since P5 —
  so the XXE and entity-expansion classes are handled by the same library the nmap adapter uses.
  Verified, not assumed: `openpyxl.DEFUSEDXML` is `True` in this environment.
- `SourceReadReport` accounts for every row (`rows_read == records_yielded + skipped`), and the
  `ManagedSource` port carries `read_report()` for that reason — a source that could quietly
  discard half an export while looking successful would make "never silently drop" unenforceable
  at the engine level. That second method is an addition to the one-line signature in
  m2-design §2.
- Ingestion into `managed_record` is `INSERT … ON CONFLICT DO UPDATE`, so a re-import refreshes
  rather than duplicating, and `created=False` distinguishes the two. `xmax = 0` is how the
  statement reports which happened in one round trip.
- P11 matches on the normalised anchors this produces. Their normalisation deliberately mirrors
  the collector's and the scanner's (lower-case colon-form MACs, lower-case hostnames) so the
  two sides actually compare equal.
