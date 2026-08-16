"""Turning device output into normalized components — carefully.

Everything arriving here is untrusted (AGENTS.md §2.9): it is text produced by a device we
just logged into, and a compromised or simply broken device can return control characters,
megabytes of noise, or a package name designed to look like something else downstream. So:

* Output is **capped** — in bytes, in lines, and in the number of components — before it can
  become memory pressure or an unbounded row in the store.
* Every field is **cleaned**: non-printable characters removed, length bounded.
* A line that does not parse is **skipped**, never guessed at. A package list with three
  broken lines is a package list with three fewer packages, not three invented ones.

Nothing here executes anything, and nothing here treats device output as a path, a query,
or a format string.
"""

from __future__ import annotations

import re
from typing import Final

from domain.models import SoftwareComponent, VersionSource

#: A package database is the device telling us what it installed. It is the strongest
#: version evidence short of a signed manifest, and the reason `version_source` exists
#: (AGENTS.md §3) — but it is still a claim by the device, not a certainty.
PACKAGE_CONFIDENCE: Final = 0.95

MAX_FIELD_LENGTH: Final = 200
MAX_LINES: Final = 20_000
MAX_COMPONENTS: Final = 5_000

#: dpkg marks a fully installed package `ii`; `hi` is installed and held. Anything else
#: (`rc` — removed, config remaining; `iU` — half-configured) is not installed software and
#: must not become a component, or we would report vulnerabilities in packages that are not
#: there.
_INSTALLED_STATES: Final = frozenset({"ii", "hi"})

_DPKG_LINE: Final = re.compile(r"^(?P<state>[a-zA-Z]{2,3})\s+(?P<name>\S+)\s+(?P<version>\S+)")

#: `name-version-release.arch`, read from the right because a package name may contain
#: hyphens but a version and a release may not.
_RPM_LINE: Final = re.compile(
    r"^(?P<name>.+)-(?P<version>[^-\s]+)-(?P<release>[^-\s]+)\.(?P<arch>[A-Za-z0-9_]+)$"
)

_OS_RELEASE_LINE: Final = re.compile(r"^(?P<key>[A-Z_][A-Z0-9_]*)=(?P<value>.*)$")


def clean_field(value: str | None) -> str | None:
    """A field we are willing to store, or None. Never a coerced approximation."""
    if value is None:
        return None
    stripped = "".join(char for char in value if char.isprintable()).strip()
    return stripped[:MAX_FIELD_LENGTH] or None


def _significant_lines(text: str) -> list[str]:
    """Bounded, stripped, non-empty lines. The cap is the defence against a device that
    answers a five-line question with a hundred megabytes."""
    lines = []
    for raw_line in text.splitlines()[:MAX_LINES]:
        line = raw_line.strip()
        if line:
            lines.append(line)
    return lines


def _component(name: str | None, version: str | None) -> SoftwareComponent | None:
    cleaned_name = clean_field(name)
    if cleaned_name is None:
        return None
    return SoftwareComponent(
        cpe=None,  # CPE mapping is M3's job; inventing one here would be a guess
        name=cleaned_name,
        version=clean_field(version),
        version_source=VersionSource.PACKAGE_MANAGER,
        confidence=PACKAGE_CONFIDENCE,
    )


def parse_dpkg(text: str) -> list[SoftwareComponent]:
    """Parse `dpkg -l` output, keeping only genuinely installed packages."""
    components: list[SoftwareComponent] = []
    for line in _significant_lines(text):
        match = _DPKG_LINE.match(line)
        if match is None or match.group("state") not in _INSTALLED_STATES:
            continue
        # `libc6:amd64` — the architecture qualifier is not part of the package identity.
        name = match.group("name").split(":", 1)[0]
        component = _component(name, match.group("version"))
        if component is not None:
            components.append(component)
        if len(components) >= MAX_COMPONENTS:
            break
    return components


def parse_rpm(text: str) -> list[SoftwareComponent]:
    """Parse `rpm -qa` output (`name-version-release.arch` per line)."""
    components: list[SoftwareComponent] = []
    for line in _significant_lines(text):
        match = _RPM_LINE.match(line)
        if match is None:
            continue
        component = _component(
            match.group("name"), f"{match.group('version')}-{match.group('release')}"
        )
        if component is not None:
            components.append(component)
        if len(components) >= MAX_COMPONENTS:
            break
    return components


def parse_os_release(text: str) -> dict[str, str]:
    """Parse `/etc/os-release` into cleaned key/value pairs.

    Values may be quoted; quotes are stripped, and anything unparseable is dropped rather
    than half-read.
    """
    values: dict[str, str] = {}
    for line in _significant_lines(text):
        if line.startswith("#"):
            continue
        match = _OS_RELEASE_LINE.match(line)
        if match is None:
            continue
        raw = match.group("value").strip()
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in {'"', "'"}:
            raw = raw[1:-1]
        cleaned = clean_field(raw)
        if cleaned is not None:
            values[match.group("key")] = cleaned
    return values


def os_component(os_release: dict[str, str], kernel: str | None) -> SoftwareComponent | None:
    """The operating system itself, as a component.

    Vulnerability matching needs the OS as a versioned thing in its own right — a kernel
    CVE is not a package CVE. `ID`/`VERSION_ID` from os-release is the OS's own statement
    about itself; the kernel string is the fallback when os-release is absent, which is
    common on stripped-down embedded systems.
    """
    name = os_release.get("ID") or os_release.get("NAME")
    version = os_release.get("VERSION_ID") or os_release.get("VERSION")

    if name is None and kernel is not None:
        parts = clean_field(kernel)
        if parts is None:
            return None
        pieces = parts.split(" ", 1)
        name = pieces[0]
        version = pieces[1] if len(pieces) > 1 else None

    return _component(name, version)
