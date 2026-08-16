# ADR-0012 — CPE version comparison and the inconclusive verdict

- **Status:** accepted
- **Date:** 2026-08-16
- **Stage:** P14 (deterministic correlation). Completes M3 Half A.
- **Context refs:** AGENTS.md §2.8 (deterministic anchors win; the LLM never decides a match),
  §3 (`version_source` is first-class; confidence is stratified), §4.8 (never learn CVEs from a
  model), §4.9 (a false negative we introduce is a hole we created), §4.11 (don't overengineer),
  §6 (dependency justification); `docs/architecture/m3-design.md` §1, §2; the dossier contract's
  confidence stratification; [ADR-0010](0010-nvd-feed-fetch-and-cache.md),
  [ADR-0011](0011-kev-epss-ingestion.md).

## Context

Correlation turns "this component exists" into "this component is vulnerable". Two ways to get
it wrong, and they fail in opposite directions:

- **Match a CVE to a version it does not affect.** A false positive. It discredits the tool with
  the first person who checks one, and in M3 it is worse than that: Half B's insight will reason
  earnestly about a vulnerability that does not exist.
- **Miss a CVE that does affect a version.** A false negative — a security hole we created
  (AGENTS.md §4.9).

Both are decided by version comparison, on strings like `2.4.52`, `8.9p1`,
`3.0.2-0ubuntu1.18` and `1.0.0rc2`, against NVD ranges expressed as four optional bounds.

## Decision

**1. Version comparison is hand-written, tokenised, and natural-ordered.**

Versions split into numeric and alphabetic runs and compare run by run: numeric runs compare as
numbers (so `2.4.10` follows `2.4.9`, which a lexical compare gets backwards), and a numeric run
outranks an alphabetic one at the same position — except for a documented list of pre-release
markers (`alpha`, `beta`, `rc`, `pre`, `dev`, `snapshot`), where the word sorts first because
that is what those words mean.

**2. Comparison has four outcomes, not three. `UNKNOWN` is one of them.**

A version with no numeric component at all — `unknown`, `latest`, `n/a` — cannot be placed on a
line. The comparison says so rather than guessing, and the range check surfaces that as
`INCONCLUSIVE`.

**3. An inconclusive range check keeps the match and downgrades its confidence.**

The match is recorded — dropping it would hide a possible vulnerability — but as `probable`
whatever the version source, because `confirmed` has to mean we checked. This is one rule beyond
the source-only mapping the dossier contract specifies, and it is the only place the two differ.

**4. `confidence_state` is otherwise derived from `version_source` alone.** `package_manager`
and `vendor_api` → `confirmed`; `banner` → `probable`. `verified_exploitable` is never produced:
it belongs to a later `check` step that actually demonstrates exploitability.

**5. The feed proposes; the correlator disposes.** Every criterion NVD returns is re-checked
locally against the component's version. NVD's `cpeName` query matches on product broadly, and
trusting its version arithmetic would mean trusting a remote service with the correctness of
every finding.

**6. Which version is compared:** the CPE's own version field when it carries one, because NVD's
ranges are expressed in CPE-space versions; the component's reported version when the CPE is
wildcarded.

## Alternatives considered

| Option | Why not |
|---|---|
| **`packaging.version` (PEP 440)** | A Python packaging scheme applied to Apache, OpenSSH and camera firmware. It rejects `8.9p1` outright and reads `2.4.52-1ubuntu4.9` as something its authors never intended. |
| **`semver`** | Assumes semantic versioning, which most of the software in a corporate estate does not follow. |
| **A CPE library (`cpe`, `cvelib`)** | Another dependency for parsing we can do in thirty lines, and none of them owns the part that actually matters — the range comparison. |
| **Lexical string comparison** | The wrong answer twice over: `"2.4.6" > "2.4.57"` and `"2.4.10" < "2.4.9"`. Both are in the boundary test precisely because this is the tempting shortcut. |
| **Trusting NVD's `cpeName` matching** | It answers by product; our version may be far outside the affected range. It would also make our correctness a property of someone else's service. |
| **Dropping matches with an unparseable version** | The safest-looking option and a false negative: a component whose version we cannot read is not a component we know to be safe. |
| **Keeping them as `confirmed`** | The opposite error: claiming we verified a range we could not evaluate. |
| **Letting KEV upgrade `probable` to `confirmed`** | Conflates two different things. KEV says the *world* is exploiting this CVE; `confidence_state` says how well we know *our* version. A KEV listing does not make a banner reading trustworthy — it makes the finding urgent, which the `kev` flag already conveys. |

## Trade-off accepted

**The pre-release marker list is a heuristic.** `1.0.0rc2 < 1.0.0` is right; a version whose
suffix is an unlisted word (`1.0.0-milestone3`) sorts *after* the bare version, which may be
wrong for that project's conventions. The list is explicit and extendable, and the failure mode
is a match that is slightly too eager rather than one that is silently missing.

**Comparison is not aware of epochs or distribution semantics.** Debian's `1:2.4.52` epoch
notation and RPM's release ordering are not modelled. `3.0.2-0ubuntu1.18` compares as
`3 0 2 0 ubuntu 1 18`, which orders correctly against other Ubuntu builds of the same upstream
version but is not a general dpkg comparison. Correct for the CPE-space versions NVD publishes
ranges in; noted here because a future credentialed inspector feeding raw dpkg versions would
need more.

**Inconclusive matches inflate `probable`.** An estate with many unparseable versions gets a
larger `probable` pile — visible in `CorrelationOutcome.inconclusive_versions`, which exists so
the size of that pile is a number rather than a surprise.

## Consequences

- `engine/cpe.py` is a separate module with its own test file because it is the correctness floor
  of every finding, and it is worth being able to read and test on its own.
- `CveRecord.cpe_criteria` (a list of strings, from P12) became `cpe_matches` — criteria *with*
  their version bounds. Without the bounds, every version of a product looks affected; the
  original shape could not have supported this ADR's first rule.
- Nothing in `engine/correlation.py` or `engine/cpe.py` imports a model, asserted by
  `tests/test_adapter_boundaries.py`. **Half A is complete and deterministic**, which is the
  precondition m3-design §1 sets before Half B may be built.
- The next lever, if real-world matching proves too eager or too shy, is *measurement against a
  real estate* — the same discipline P11 applied to the ambiguous rate — before any change to the
  comparison rules.
