# ADR-0005 — SSH transport and device-output parsing for credentialed inspection

- **Status:** accepted
- **Date:** 2026-08-16
- **Stage:** P7 (`CredentialedInspector` + `InspectorRegistry` + generic SSH adapter).
- **Context refs:** AGENTS.md §2.4 (read-only against devices), §2.9 (untrusted input, no
  shell interpolation), §2.10 (secrets never touch logs or code), §4.5 (never weaken
  security to make something pass), §6 (dependency justification), §67 (failures are not
  empty results); `docs/architecture/m1-design.md` §1, §3, §4; `docs/architecture/ports.md`
  §2, §4.

## Context

P7 is the first code that holds a real credential against real hardware. Three decisions
determine whether the `Secret` primitive built in M0 actually protects anything: how we speak
SSH, how we constrain what we say, and how we treat what comes back.

The prize is `version_source='package_manager'`. A banner claiming `Apache/2.4.52` may be a
patched backport; `dpkg -l` cannot be. Credentialed inspection is what turns "probable" findings
into "confirmed" ones — but only if getting it costs nothing in credential safety.

## Decision

**1. SSH via `paramiko`, in-process, with the credential never leaving memory.**

The credential is resolved through `SecretsPort`, stays a redacting `Secret` everywhere, and is
revealed on exactly one line — the call that hands it to paramiko. A test greps the whole
`adapters/inspector` package and fails if `.reveal()` appears anywhere else.

Host-key policy is `RejectPolicy`, not configurable to anything weaker: accepting an unknown
key means handing a credential to whatever answered on that address. `allow_agent=False` and
`look_for_keys=False` are set explicitly so an inspection cannot succeed using the operator's
own ambient key instead of the vault's credential.

**2. Read-only enforced by an allowlist of complete commands, checked by verb *and*
arguments.**

There are five: `cat /etc/os-release`, `uname -sr`, `uname -n`, `dpkg -l`, `rpm -qa`. They are
constants — nothing in this system formats, joins, or parameterises a command, so there is no
expression for untrusted data to be interpolated into. The guard rejects shell metacharacters,
non-allow-listed verbs, and — crucially — argument forms outside a per-verb allowlist, because
`dpkg -l` lists and `dpkg --install` installs. It runs at import time and again immediately
before execution.

A canary test pins the allowlist to exactly those five strings. Widening what the scanner may
say to a device therefore cannot ride along with a feature; it has to be a deliberate diff.

**3. Errors are built from exception *types*, not library message text, on the auth path.**

An authentication error is the one message an SSH library might construct from the credential
itself. Auth and host-key failures report the exception class and our own context.
Socket-level failures (refused, no route, timeout) carry their message, because the socket layer
never sees the credential and that detail is what an operator needs.

**4. Device output is parsed with hand-written line parsers, capped in three dimensions.**

Bytes (1 MB at the transport), lines (20 000), components (5 000), plus per-field cleaning that
strips non-printable characters and truncates to 200 characters. A line that does not parse is
skipped, never guessed at.

## Alternatives considered

| Option | Why not |
|---|---|
| **`subprocess` to the OpenSSH client** | The precedent from ADR-0003 (orchestrate, don't reimplement) points here, and OpenSSH is better audited than any library. But it cannot take a credential safely: a password needs `sshpass` (argv/env exposure) and a key needs a file on disk. Writing a vault credential to a temp file, however briefly, is exactly what §2.10 exists to prevent. paramiko keeps it in memory. |
| **`asyncssh`** | Good library, but it drags an async story into an otherwise synchronous codebase for no measured benefit (§4.11). |
| **`fabric`** | A layer over paramiko oriented at *running things* on hosts, including writes. The wrong shape for a component whose defining property is that it cannot write. |
| **Parameterised commands (`rpm -q <name>`)** | Would introduce the one thing this design does not have: a command built from a value. Every read we need is available in a no-argument form. |
| **`shlex.quote` on interpolated arguments** | Quoting is a mitigation for a design that interpolates. Not interpolating is the design. |
| **Running a remote shell pipeline (`dpkg -l \| grep …`)** | Puts a shell in the loop and gives the remote sshd a compound command to interpret. The filtering belongs here, where it is testable. |
| **A JSON-emitting agent installed on devices** | Cleaner parsing, but installing software is a write, on hardware we do not own, and the embedded devices this product cares about could not run it anyway. |
| **`AutoAddPolicy` for host keys** | Convenient on first contact and equivalent to disabling certificate validation (§4.5). An unknown host is a hard failure, with a message that says what to do about it. |

## Trade-off accepted

**paramiko is a real dependency with real history.** It is a pure-Python SSH implementation with
past CVEs, and it pulls in `cryptography`, `bcrypt` and `pynacl`. Accepted because the
alternative — a credential on disk or in a process argument list — is a worse and *certain*
exposure rather than a possible one. The mitigation is version pinning, a committed lockfile,
and confinement: paramiko appears in one class, behind the `SSHCommandRunner` port.

**Known-hosts must be provisioned.** With `RejectPolicy`, a device whose key we have never seen
fails until an operator adds it. That is friction on first contact, and it is the correct
friction. This needs a runbook — currently owed, not written.

**Five commands is a thin read.** No firmware paths, no vendor APIs, no service configuration.
Device-family paths differ per vendor and belong in vendor adapters behind the registry
(m1-design §5), not as guesses in the generic one.

**Fixtures cannot prove this works against a real device.** They prove the credential does not
leak, the commands cannot write, and the output parses. Whether a real camera's BusyBox `dpkg`
behaves is the manual validation m1-design §4 describes — still owed, alongside the P5 one.

## Consequences

- `InspectorRegistry` selects by capability (`speaks_ssh`), never by brand. A VAPIX or ISAPI
  adapter registers ahead of generic SSH with its own capability predicate and no caller
  changes — that is the whole extension mechanism.
- `for_device` returning `None` is a normal answer: no credential path means the device keeps
  `version_source='banner'` and stays a known asset. Guessing credentials is default-credential
  probing, which is opt-in and out of scope.
- P8 wires inspection into the ingestion path and the ER; the `InspectionResult` is already
  shaped as `ObservationInput`s, so no part of the spine changes to accept it (m1-design §6).
