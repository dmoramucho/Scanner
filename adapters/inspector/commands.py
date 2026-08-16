"""The read-only command allowlist.

This is the whole of what the scanner is permitted to say to a device it has logged into.
It is a closed list of **constant strings**: nothing here is built, formatted, joined, or
parameterised, so there is no expression anywhere in this system that could interpolate an
untrusted value into a command (AGENTS.md §2.9 / §69). The commands take no arguments that
vary — and the guard below enforces that by allow-listing the exact argument forms, not
merely the verbs.

Read-only is absolute (AGENTS.md §2.4). Every command reads a package database or a file
that describes the system; none can change device or system state. The verb alone is not
enough to know that — `dpkg -l` lists and `dpkg --install` installs — so the guard checks
verb *and* arguments, and for `cat` the path as well. Adding a command means widening
`ALLOWED_ARGUMENTS` and adding a literal to `READ_COMMANDS`, and the guard runs at import
time, so a bad addition stops the process rather than reaching a device.

Deliberately absent: firmware-path reads for specific device families (OpenWrt, BusyBox
appliances, camera firmware blobs). Those paths differ per vendor, and a vendor inspector
behind the registry is the place for them — a deferred adapter, not a guess in the generic
one (m1-design §5).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, Literal

CommandKind = Literal["os_release", "kernel", "hostname", "packages_dpkg", "packages_rpm"]

#: The only verbs that may appear. Each of them reads and returns; none of them writes.
ALLOWED_VERBS: Final = frozenset({"cat", "uname", "dpkg", "rpm"})

#: Files this inspector may read. `cat` is a reading verb, but `cat /etc/shadow` is still
#: not something we do — the path is allow-listed too, not merely the command.
READABLE_PATHS: Final = frozenset({"/etc/os-release"})

#: The exact argument forms each verb may carry. A verb alone is not enough: `dpkg -l`
#: lists packages and `dpkg --install` installs one, and both start with an allowed verb.
#: Adding a command therefore means widening this map *and* the list below — a deliberate
#: speed bump on the one list in this system that can reach out and touch a device.
ALLOWED_ARGUMENTS: Final[dict[str, frozenset[str]]] = {
    "cat": READABLE_PATHS,
    "uname": frozenset({"-sr", "-n"}),
    "dpkg": frozenset({"-l"}),
    "rpm": frozenset({"-qa"}),
}

#: Anything that could chain, redirect, substitute, or glob. A command containing one of
#: these is refused even if it is otherwise in the list — the list and the shape are
#: independent checks, so one mistake is not enough to get a bad command out on the wire.
SHELL_METACHARACTERS: Final = frozenset(";&|><`$(){}[]!*?~\n\r\t\\'\"")

#: Belt to the metacharacter braces: a positive pattern for what a read command may look
#: like at all.
_SAFE_SHAPE: Final = re.compile(r"^[a-z]+(?: -{0,2}[A-Za-z-]+| /[A-Za-z0-9/._-]+)*$")


@dataclass(frozen=True, slots=True)
class ReadCommand:
    """One allow-listed read. `kind` selects the parser; `command` is sent verbatim."""

    kind: CommandKind
    command: str
    description: str


def assert_read_only(command: str) -> None:
    """Refuse anything that is not an obviously-reading command.

    Raises `ValueError` — this is a programming error, caught at import time, not a runtime
    condition an operator can hit.
    """
    if not command or command != command.strip():
        raise ValueError(f"malformed command: {command!r}")

    offending = sorted(set(command) & SHELL_METACHARACTERS)
    if offending:
        raise ValueError(f"command contains shell metacharacters {offending}: {command!r}")

    verb, _, arguments = command.partition(" ")
    if verb not in ALLOWED_VERBS:
        raise ValueError(f"command verb {verb!r} is not one of {sorted(ALLOWED_VERBS)}")

    permitted = ALLOWED_ARGUMENTS[verb]
    if arguments not in permitted:
        raise ValueError(
            f"{verb!r} may only be used as {sorted(f'{verb} {a}' for a in permitted)}; "
            f"got {command!r}"
        )

    if not _SAFE_SHAPE.match(command):
        raise ValueError(f"command does not match the read-only shape: {command!r}")


READ_COMMANDS: Final = (
    ReadCommand(
        kind="os_release",
        command="cat /etc/os-release",
        description="distribution and version, as the OS itself reports them",
    ),
    ReadCommand(
        kind="kernel",
        command="uname -sr",
        description="kernel name and release",
    ),
    ReadCommand(
        kind="hostname",
        command="uname -n",
        description="the device's own idea of its name — an identity anchor",
    ),
    ReadCommand(
        kind="packages_dpkg",
        command="dpkg -l",
        description="installed packages on a Debian-family system — the ground truth "
        "that ends the OS-backport false positive",
    ),
    ReadCommand(
        kind="packages_rpm",
        command="rpm -qa",
        description="installed packages on an RPM-family system",
    ),
)

#: Fast membership test for "did this really come from the list?" — used before execution
#: and again when interpreting results.
ALLOWED_COMMAND_STRINGS: Final = frozenset(entry.command for entry in READ_COMMANDS)

# Enforced at import: a command that does not pass the guard prevents the process from
# starting, which is the loudest and earliest place to fail.
for _entry in READ_COMMANDS:
    assert_read_only(_entry.command)
