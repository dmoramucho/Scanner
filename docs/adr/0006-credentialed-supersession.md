# ADR-0006 — Credentialed reads replace the current software set

- **Status:** accepted
- **Date:** 2026-08-16
- **Stage:** P8 (wiring credentialed inspection into the ingestion path).
- **Context refs:** AGENTS.md §3 (`version_source` is first-class; evidence and history are
  immutable; confidence is stratified), §5 (NOW-tier), §4.11 (don't overengineer);
  `docs/architecture/m1-design.md` §6; `docs/architecture/ports.md` §6;
  [ADR-0004](0004-scan-safety-policy.md).

## Context

Two sources now describe what software is on an asset, and they disagree in kind rather than in
detail:

- An **active scan** reads a banner and *infers*: `Apache/2.4.52` in a header,
  `version_source='banner'`, and possibly a lie — a distribution that backported the fix serves
  the old version string forever.
- A **credentialed read** asks the package database: `apache2 2.4.52-1ubuntu4.9`,
  `version_source='package_manager'`, which is the device's own account of itself.

`AssetRepository.set_current_software(asset_id, components)` projects "the current set" for an
asset and retires anything not in it. So the moment P8 calls it with credentialed components, a
question that had been theoretical becomes concrete: what happens to a banner-inferred component
that the package database does not mention?

The awkward case is real. A Tomcat unpacked from a tarball, a vendor daemon installed outside
`dpkg`, an application server dropped into `/opt` — a banner sees them; `dpkg -l` does not.

## Decision

**A credentialed read replaces the current set for that asset, wholesale.**

`set_current_software` is called with exactly the components the inspection produced. Anything
previously current and absent from that list is retired (`is_current = false`), not deleted.

Two supporting facts make this less lossy than it first appears, and both are why it is
acceptable:

1. **Nothing is destroyed.** The retired row stays queryable, and the banner observation that
   produced it remains in the append-only `observation` spine with full provenance. "What did we
   believe on date X, and why?" is still answerable (AGENTS.md §3).
2. **The alternative is not available at this port surface.** Merging by precedence requires
   reading the current components back, and `AssetRepository` has no such method. Adding one is a
   change to the ER contract, which P8 was explicitly not to make.

## Alternatives considered

| Option | Why not |
|---|---|
| **Merge by precedence** (keep banner components the package database does not cover, credentialed wins on collision) | Almost certainly where this ends up — it is the honest model of two partial views. But it needs a "read current components" method on `AssetRepository`, and inventing it here would change the ER port in the slice that was meant to reuse it. Deferred deliberately, not overlooked. |
| **Never retire, only add** | The current set stops meaning anything: an uninstalled package would stay "current" forever, and the vulnerability matcher would report findings against software that is no longer there. Worse than losing a banner row. |
| **Keep both rows and let downstream sort it out** | Pushes an unresolved contradiction into the CVE matcher, which would then need precedence rules of its own — the wrong place, since it is a data-quality question, not a matching one. |
| **Do not call `set_current_software` at all** | Leaves the entire point of credentialed inspection unrealised: the ground truth would sit in the observation spine and never reach current state. |
| **Give the projection a `source` argument** (replace only components from the same source) | A cleaner version of merge-by-precedence, and the same objection: it changes the port. Worth revisiting together with the read method. |

## Trade-off accepted

**A component only a banner can see is dropped from current state the first time we log into
that asset.** On a device where the credentialed path is partial — a package manager that does
not cover everything installed — the current set will *understate* what is running.

This direction is the safer of the two mistakes but is not harmless. Understating current
software means a missed finding; overstating it means a false positive. AGENTS.md §4.9 warns
specifically that a false negative we introduce is a security hole we created, so this is a real
cost, mitigated only by the fact that the evidence is retained and the correction is a
projection change rather than a data recovery.

**When the banner projection lands** — nothing writes banner components to
`software_component` today; the test that proves supersession has to seed one by hand — this
decision needs revisiting *before* both sources are writing current state routinely. That is the
trigger, and it is close: it arrives with M2/M3 CVE matching.

## Consequences

- The credentialed engine calls the existing `set_current_software`; no port, no migration, and
  no schema change (m1-design §6).
- `tests/integration/test_credentialed_ingestion.py::test_credentialed_truth_supersedes_banner_inference`
  pins the behaviour, including that the banner row is retired rather than deleted.
- A follow-up is owed: a components read on `AssetRepository`, then merge-by-precedence, with
  `version_source` deciding collisions. It should land with, or before, CVE matching.
- A failed inspection writes nothing at all — no partial state, and no `device_health`-style
  record. That differs from the circuit breaker (ADR-0004), on purpose: a breaker trip is
  evidence *about the device*, while a refused credential is evidence about our configuration,
  and it belongs in the run outcome rather than in the asset's history.
