# ADR-0007 — What the health probe does when it has no known-open port

- **Status:** accepted
- **Date:** 2026-08-16
- **Stage:** P9 (`HealthProbe` adapter).
- **Context refs:** AGENTS.md §2.7 (don't break embedded devices), §4.11 (don't overengineer),
  §67 (a failure is not an empty result); `docs/architecture/m1-design.md` §2;
  [ADR-0004](0004-scan-safety-policy.md); `docs/runbooks/validate-gentle-scan.md`.

## Context

The circuit breaker health-checks a device before and after scanning it. The probe that does
this must be *gentler than the scan it protects* — a heavy check would knock over the device it
exists to defend, which would be the most self-defeating bug this codebase could hold.

A single TCP connect to a port already known open, then close, is that: no data sent, no
application-layer conversation, no raw sockets, no root. A refusal (`RST`) counts as healthy —
something on that stack answered.

Which leaves one question the implementation cannot dodge: **what happens when we have no
known-open port for a target?** A device discovered by ARP alone has an address and a MAC and
nothing else. There is no port to connect to.

Three answers were available, and one of them is disqualified before the others are weighed: the
probe must never return `True`. That would tell the breaker a device is healthy on no evidence,
which is the precise failure this mechanism exists to prevent.

## Decision

**Raise `DependencyError(retryable=False)`. The probe never guesses a port, and never assumes
health.**

The engine already treats a probe error as "do not scan this device" (P6, `ActiveScanEngine`),
so the effect is: a device we cannot watch is a device we do not poke. That is the fail-safe
direction and it matches every other default in the system — deny-by-default scope, gentle-by-
default classification, "we could not check" never reading as "it is fine".

An operator-supplied `fallback_ports` exists for the by-hand case (the runbook, where you know
the camera's admin port). It is **empty by default**: guessing on behalf of a fragile device is
exactly the behaviour this class is the opposite of.

## Alternatives considered

| Option | Why not |
|---|---|
| **Return `False` (not responsive)** | Reads as "the device is down", which is a claim about the device we have not earned. In the *post*-scan check it is worse than useless: it would report every port-less device as having been killed by our scan, filling the record with false distress and making the breaker's signal meaningless. |
| **Return `True`** | Disqualified. Fabricated health is the one thing a safety mechanism may never produce. |
| **Try a small default port set (80, 443, 22)** | A probe that works down a list of ports is a small port scan — done *before* we have decided whether this device can tolerate scanning, and done twice per device. It inverts the entire mechanism. |
| **Fall back to ICMP** | Would answer the port-less case, needs raw sockets and therefore root, and many embedded devices and segment firewalls drop ICMP anyway — so it fails exactly where it is needed. Deferred until we can show devices that have no known-open TCP port *and* answer ICMP (§4.11: prove the need). |
| **Skip the health check when no port is known** (scan anyway, unprotected) | Contradicts AGENTS.md §2.7, which gates active scanning of embedded devices on a before/after health check. Scanning fragile hardware with the safety mechanism disabled is worse than not scanning it. |

## Trade-off accepted

**There is a chicken-and-egg case, and it is real.** A device seen only by ARP has no known-open
port, so the probe refuses, so the engine does not scan it, so we never learn its ports. Under
this decision, that device is never actively scanned.

That is a genuine coverage cost — and it lands on shadow-IT devices, which are the ones this
product most cares about. Three things make it acceptable rather than merely unfortunate:

1. **Passive discovery often supplies the port already.** mDNS advertises the service port, and
   the collector records it. Cameras, printers and phones announcing themselves come with a port
   attached.
2. **An operator can supply one**, per the runbook, for any device they can look at.
3. **The refusal is loud.** It surfaces in `ActiveScanOutcome.errored` with a message naming this
   ADR, rather than as a device silently missing from the results.

The honest summary: we would rather have a visible gap in coverage than an invisible gap in the
safety mechanism. When the coverage cost is measured and found to matter, the remedy is an ICMP
probe or a discovery step that establishes a port gently — both deliberate additions, not a
default that quietly relaxes.

**A TCP probe also cannot see an application dying.** A device whose kernel answers a SYN while
its video stream is dead reads as responsive. The breaker's job is to catch a device falling off
the network, and it does that; catching a degraded service is a different mechanism nobody has
asked for yet. The runbook says this plainly, which is why it still asks the operator to check
the device's actual function by hand.

## Consequences

- `TcpHealthProbe(known_ports)` consumes port knowledge; it never produces it. There is no code
  path in the probe that scans.
- One connect per call — `BreakerPolicy.health_check_attempts` owns retries, and a retry loop in
  both places would double the traffic and make the policy a lie.
- An unrecognised socket error raises rather than resolving to either verdict, so a case nobody
  anticipated fails closed.
- The `HealthProbe` port is unchanged; the engine needed no modification to consume this.
- Follow-up if measurement demands it: an ICMP probe behind the same port, selected by config,
  for devices with no TCP port at all.
