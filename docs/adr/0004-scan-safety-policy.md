# ADR-0004 — Scan safety policy: classification defaults and circuit-breaker behaviour

- **Status:** accepted
- **Date:** 2026-08-16
- **Stage:** P6 (active-scan engine).
- **Context refs:** AGENTS.md §2.5 (scope first), §2.7 (don't break embedded devices), §3
  (evidence and history), §4.11 (don't overengineer), §5 (NOW-tier);
  `docs/architecture/m1-design.md` §2, §6; [ADR-0003](0003-nmap-orchestration.md).

## Context

P5 gave the nmap adapter two profiles. P6 decides which one each device gets, and when to stop
touching a device that is suffering. Both are judgment calls with a cost on each side, so the
numbers and defaults belong in the record rather than inside an `if`.

The estate this runs against is the reason: IP cameras, VoIP handsets, printers, UPSes and
badge readers, whose stacks fall over under scans a server would not notice. Breaking one is
not a failed scan — it is an outage the security team caused.

## Decision

**1. Unknown devices are scanned `GENTLE`.**

Classification reads, strongest signal first: an `asset_class` entity resolution already
settled, then the MAC vendor, then advertised mDNS service types, then observed ports. If
nothing positively identifies the device as robust, it gets `GENTLE`.

This mirrors deny-by-default: the burden of proof is on *"this host is robust"*, never on
*"this host is delicate"*. An embedded signal also beats a robust one — a camera with SSH open
is still a camera.

**2. Classification is data, not code.** Vendor markers, mDNS service types and port sets live
in a `ClassificationPolicy` dataclass an operator can inspect and replace. A new camera vendor
in the estate is a list entry, not a branch someone has to write and re-test.

**3. The breaker's defaults: 2 health-check attempts, 5 s backoff, halt after 3 consecutive
device failures.**

- *Two attempts* — one missed reply is a lost packet on a busy VLAN, not distress. Two
  distinguishes "quiet" from "gone" without a slow retry loop.
- *5 s backoff after a trip* — embedded devices on a segment often share an upstream that also
  struggles; a pause before the next device costs a scan minutes and can save an outage.
- *Halt after 3 consecutive failures* — m1-design §2 requires that one unresponsive device
  never aborts the run, and it does not. But three devices in a row failing is not bad luck, it
  is us; the run stops with `halted_reason` set rather than working through the estate the same
  way. Denials do **not** count toward the streak: a narrowly scoped run is not a malfunction.

**4. A trip is recorded as an observation, not just counted.** When the breaker fires, the
engine writes a `device_health` observation (`source='health_probe'`,
`collection_method='circuit_breaker'`) through the existing sink.

**5. Distress classification of scan errors.** A *retryable* `DependencyError` (a timeout) is
treated as distress and trips the breaker — that is what a device going quiet mid-scan looks
like from here. A *permanent* error (nmap exited non-zero) is recorded as an error against the
device but is not a trip: it is our problem, and marking a healthy device as damaged would be a
false accusation that outlives the run.

**6. A probe that cannot run is never read as health.** If the pre-check probe raises, the
device is not scanned. If the post-check probe raises, the device is treated as tripped.
"We could not check" resolves toward caution in both directions.

## Alternatives considered

| Option | Why not |
|---|---|
| **Default unknown devices to `STANDARD`** | Faster and more informative per scan, and wrong on this estate: AGENTS.md §2.7 says fragile stacks are the norm here, not the exception. The failure mode is an outage, against a saving of scan minutes. |
| **Ask the operator to classify each device up front** | An inventory nobody maintains. The whole premise is that we do not know what is on the network — that is the shadow-IT diff we are selling. |
| **Active fingerprinting (`-O`, NSE) before choosing the profile** | Circular: it probes the device to decide how gently to probe the device, using exactly the aggressive techniques `GENTLE` exists to avoid. |
| **Continuous health monitoring during the scan** | Real-time telemetry against every device mid-scan is a much larger machine (a scheduler, a watchdog process) than the risk needs today (§4.11). Before/after checks catch the case that matters: the device that does not come back. |
| **Retry a tripped device later in the run** | It just fell over. Touching it again to see if it is still down is the behaviour that turns one outage into a longer one. |
| **Abort the whole run on the first trip** | Contradicts m1-design §2, and makes a single fragile device on a /16 able to block visibility into the entire estate. |
| **Keep trips in memory only** | A counter in a run summary disappears with the process. The device that cannot survive a scan is the thing an operator most needs to know about next month. |
| **A dedicated `device_health` table** | A migration, a model, and a query surface for a fact the append-only observation spine already stores with full provenance. Revisit if health becomes a first-class current-state concept rather than an event. |
| **Discard observations from a scan that tripped the breaker** | The evidence is real, and dropping it would hide the scan that did the damage. Recorded, with the trip recorded alongside. |

## Trade-off accepted

**We will scan some robust servers gently.** Unknown hosts get a slower scan and a narrower
port set until something identifies them — a real cost in coverage and time, accepted because
the opposite error is an outage. As entity resolution classifies more of the estate, this
corrects itself automatically: `asset_class` is the first signal consulted.

**The breaker can be fooled by coincidence.** A device that reboots for unrelated reasons
during its scan is recorded as a trip. That is the conservative direction, and the trip is
evidence with a timestamp rather than a permanent verdict.

**`device_health` is an observation type with no schema-level meaning yet.** Nothing reads it
today; it is written so the data exists when something does. That is deliberate under §3
(evidence first), not a hidden TODO.

## Consequences

- The engine holds all of this; the adapter cannot bypass it and does not know it exists.
  Choosing a profile and stopping a scan are policy, and policy lives above the tool (ADR-0003).
- `ActiveScanOutcome` reports every way a device was *not* scanned — denied, unreachable,
  tripped, errored, skipped-credentialed — so a run that scanned nothing cannot be mistaken for
  a clean estate.
- The credentialed skip is a seam: a candidate carrying a `credential_ref` is not probed at
  all, and P7's `CredentialedInspector` plugs in there.
- Fixtures cannot prove a real camera survives `GENTLE`. That remains the manual real-target
  validation in m1-design §4, and it is still owed.
