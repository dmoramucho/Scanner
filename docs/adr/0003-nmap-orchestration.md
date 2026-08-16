# ADR-0003 — How we invoke nmap, and how we parse its output

- **Status:** accepted
- **Date:** 2026-08-15
- **Stage:** P5 (`ActiveScanner` port + nmap adapter).
- **Context refs:** AGENTS.md §2.4 (read-only), §2.6 (correlation, not exploitation), §2.7
  (don't break embedded devices), §2.9 (all external input untrusted; no shell interpolation),
  §4.11 (don't overengineer), §6 (dependency justification);
  `docs/architecture/m1-design.md` §1, §2, §4.

## Context

P5 is the first code that emits packets at real hardware. Three decisions in it are material
enough to record, because each one is a place where a wrong choice is a security bug rather
than a style preference: how nmap is invoked, how its output is read, and how it is tested.

Scanning itself is commoditised — nmap has 25 years of solved edge cases and we orchestrate it
rather than reimplement it (AGENTS.md §78, m1-design). What we own is the judgment layer:
which flags a *profile* means, refusing to let anything near a shell, and normalising output
into provenance-complete observations.

## Decision

**1. Invocation: `subprocess.run` with an argument list, `shell=False`, XML to stdout.**

The command is built as `list[str]` and executed with no shell. The target is validated by
`ipaddress.ip_address()` *before* the argv exists, so a value shaped like `10.0.0.1; rm -rf /`
never reaches a command at all — it fails at the boundary. Output comes back via `-oX -`
(XML on stdout).

`stdin` is `DEVNULL`, because nmap reads keypresses for runtime status when it has one.

**2. Parsing: `defusedxml`, over nmap's XML, never its human-readable output.**

nmap's normal output is a display format that changes between releases; `-oX` is a documented,
versioned interface (`xmloutputversion`). And nmap's XML is *untrusted input*: it contains
strings an unknown device chose (service banners, hostnames), wrapped by a parser we did not
write. So it is parsed with `defusedxml`, which refuses external entities, entity expansion, and
DTD retrieval while still accepting the bare `<!DOCTYPE nmaprun>` nmap actually emits.

**3. Testing: fixtures, so CI needs neither the nmap binary nor a network.**

The adapter takes a `CommandRunner` seam. Tests drive the real parsing, normalisation and
error-mapping code through recorded XML (AGENTS.md §43, m1-design §4). The profile→flags
mapping is asserted directly against the built argv.

## Alternatives considered

| Option | Why not |
|---|---|
| **`shell=True` with a formatted command string** | The entire class of command injection, in exchange for nothing. The target comes from a database row that came from a network observation. |
| **`python-nmap` / `python-libnmap` wrappers** | `python-nmap` builds its command by string concatenation and has a history of exactly the injection issue above; both add a dependency whose job is to hide the one part we most need to see and test — the flags. The safety-critical property of P5 is "you can read and assert the exact argv", and a wrapper takes that away. |
| **Parsing nmap's stdout text** | Not an interface. It reflows between versions and locales, and a service banner containing a newline could forge a line. |
| **stdlib `xml.etree.ElementTree`** | Documented as vulnerable to entity-expansion ("billion laughs") attacks. It does resist XXE, so this was close — but hardening it means either pre-scanning the document for `DOCTYPE` internal subsets (a hand-rolled guard on untrusted input, which is how these bugs happen) or poking at expat internals through private attributes. |
| **`lxml`** | Can be configured safely, but it is a large compiled dependency pulling libxml2 into the deployment for one small parse. `defusedxml` is pure Python with zero transitive dependencies. |
| **Raw sockets / a hand-rolled port scanner** | Reimplementing the commoditised part, and getting the fragile-device edge cases wrong is precisely what AGENTS.md §2.7 forbids. |
| **`-oX <tempfile>` instead of stdout** | A temp file to create, secure, and clean up, plus a failure mode where the file is stale from a previous run. Stdout has none of that. |

## Trade-off accepted

**One new runtime dependency, `defusedxml`** (pure Python, no transitive dependencies, by a
CPython core developer, the standard remedy the Python documentation itself points to for
untrusted XML). It is a security-positive dependency: the alternative is hand-written
hardening around a parser documented as vulnerable.

**The adapter requires privileges.** `-sS` needs raw sockets, so nmap must run as root or with
`CAP_NET_RAW`. We do *not* silently fall back to `-sT` (connect scan): a connect scan completes
the handshake and leaves application-layer state on the device, which is the thing that wedges
fragile embedded stacks. Lacking privileges surfaces as a `DependencyError` carrying nmap's own
message, so the operator fixes the deployment rather than the scan quietly becoming rougher.

**Fixtures cannot prove a device survives.** They prove the *command* is gentle and the parsing
is correct; they cannot prove an actual camera stays up. That is the manual real-target
validation in m1-design §4, and it stays a documented operator step, not a CI gate.

## Consequences

- `ScanProfile → flags` lives in `adapters/scanner/nmap.py` and nowhere else. The port speaks
  intent; no caller can pass a flag. `FORBIDDEN_FLAGS` is checked against the built command as a
  last line of defence, so a bad edit fails the scan rather than running hot against a device.
- Every version signal from this adapter carries `version_source='banner'` — uncredentialed
  scanning infers, and saying so is what stops an OS-backported version string from becoming a
  false positive in M3 (AGENTS.md §3).
- A future scanner (masscan for sweeps, say) is another adapter behind the same port; nothing in
  the domain or the engine learns a flag.
- When the engine wires this up (P6), the circuit breaker and detect-then-adapt profile
  selection sit *above* the adapter, so the adapter cannot forget them.
