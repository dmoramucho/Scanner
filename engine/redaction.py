"""The redaction contract, in code: an allowlist, and a refusal to emit what escapes it.

This module is the reason a secret cannot reach the model. The dossier contract §4 divides
every field into *included*, *masked/summarised*, and *excluded entirely*, and closes with a
default-exclude rule: anything not named is excluded. That is an allowlist, and an allowlist
is only worth anything if it is one list, in one place, that a reviewer can read in a minute.
So it is below, in full.

Two layers, because one is not enough for a rule this consequential (AGENTS.md §2.10):

1. **Projection.** A collector's payload is a free-shaped dict written by code far from
   here. `project()` copies out only the keys this contract names, only scalar values, only
   bounded in length — and drops any value that is *shaped* like a credential even though
   its key was allowed. Everything else is dropped silently and counted. Fail-closed: an
   unknown observation type contributes nothing at all, rather than contributing everything.

2. **Refusal.** `assert_no_secrets()` walks the assembled dossier and raises if anything
   secret-shaped survived. Reaching that check means layer one has a hole, so it does not
   patch the hole — it refuses to emit the dossier. A dossier containing an excluded field
   is a P0 defect (contract §4), and a P0 defect should stop, loudly, at the boundary it was
   about to cross.

**The sweep covers the asset dossier, not the advisory.** Advisory text is public writing
about vulnerabilities, and a perfectly ordinary advisory says "default password" or
"api_key=" while describing the bug. It arrives already sanitised from P15 (ADR-0013); what
this module guards is the estate's own data, where those shapes mean what they look like.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from domain.errors import ValidationError

#: The only payload keys that may cross from an observation into a dossier, by observation
#: type. Read this as the allowlist it is: a field that is not here does not reach the model,
#: whatever a collector chooses to put in a payload (dossier contract §4).
INCLUDED_PAYLOAD_FIELDS: Final[Mapping[str, frozenset[str]]] = {
    # Network exposure: ports and normalized service names, never banners.
    "open_ports": frozenset({"port", "protocol", "service"}),
    "port": frozenset({"port", "protocol", "service"}),
    # Reachability class and a *label* for the segment — not topology detail.
    "network": frozenset({"reachability", "network_segment_label"}),
    "exposure": frozenset({"reachability", "network_segment_label"}),
    # Device identity, which the contract includes: vendor, model, firmware.
    "identity": frozenset(
        {"vendor", "model", "device_family", "firmware_version", "os_name", "os_version"}
    ),
    "firmware": frozenset({"vendor", "model", "device_family", "firmware_version"}),
    "os": frozenset({"os_name", "os_version"}),
    # A running service is a name. Its command line, its environment and its config are not.
    "service": frozenset({"name", "service"}),
    # Application shape — the architecture axis for `application` assets.
    "application": frozenset({"app_name", "behind_reverse_proxy", "behind_waf"}),
    # Configuration is *never* copied. Only the derived flags below are read from it, and
    # the empty set here is what makes that true rather than intended.
    "config": frozenset(),
    "configuration": frozenset(),
}

#: The derived, config-safe flags the contract permits in place of configuration. The
#: assembler reads these keys out of a config-derived observation and nothing else — the raw
#: file never leaves the observation table (contract §4, "masked / summarised").
SECURITY_FLAG_KEYS: Final = frozenset(
    {
        "telnet_enabled",
        "ssh_password_auth",
        "ssh_root_login",
        "smb_signing",
        "smb_v1_enabled",
        "tls_min_version",
        "default_credential_present",
        "anonymous_ftp_enabled",
        "snmp_v1_enabled",
        "upnp_enabled",
        "http_admin_exposed",
        "firmware_signed",
        "auto_update_enabled",
        "secure_boot_enabled",
    }
)

#: Observation types that may contribute security flags.
FLAG_SOURCE_TYPES: Final = frozenset({"config", "configuration", "security_flags", "hardening"})

#: A dossier value is a short fact, not a document. Anything longer is either the wrong
#: field or an attempt to smuggle a payload through a permitted one.
MAX_VALUE_CHARS: Final = 200

#: Shapes that mean "this is a credential or personal data", regardless of the key it
#: arrived under. Deliberately shape-based: a collector that writes a private key into a
#: field called `model` has still written a private key.
_SECRET_SHAPES: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    ("private-key", re.compile(r"-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----")),
    ("certificate-body", re.compile(r"-----BEGIN CERTIFICATE-----")),
    (
        "credential-assignment",
        re.compile(
            r"\b(?:password|passwd|pwd|secret|api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token"
            r"|bearer|client[_\-]?secret|private[_\-]?key|session[_\-]?id)\b\s*[:=]",
            re.IGNORECASE,
        ),
    ),
    ("bearer-token", re.compile(r"\b(?:authorization\s*[:=]|bearer\s+)\S{6,}", re.IGNORECASE)),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")),
    ("basic-auth-url", re.compile(r"\b[a-z][a-z0-9+.\-]{1,20}://[^/\s:@]{1,64}:[^/\s@]{1,64}@")),
    # PII: an email address identifies a person, and no dossier field is entitled to one.
    ("email-address", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
)


@dataclass(frozen=True, slots=True)
class Redaction:
    """What survived projection, and how much did not.

    `dropped` is not a diagnostic: a payload that loses most of itself on the way into a
    dossier is the allowlist working, and an operator should be able to see it working.
    """

    fields: Mapping[str, str]
    dropped: int = 0

    def get(self, key: str) -> str | None:
        return self.fields.get(key)


def project(observation_type: str, payload: Mapping[str, object]) -> Redaction:
    """Copy the allowlisted fields out of one observation payload. Nothing else.

    Fail-closed on three axes: an observation type nobody named contributes nothing, a key
    nobody named is dropped, and a value that is not a bounded scalar is dropped — a nested
    object is exactly how a raw config would arrive.
    """
    allowed = INCLUDED_PAYLOAD_FIELDS.get(observation_type.strip().lower())
    if not allowed:
        # Unknown type, or a type explicitly allowed to contribute nothing (`config`).
        return Redaction(fields={}, dropped=len(payload))

    fields: dict[str, str] = {}
    dropped = 0
    for key, value in payload.items():
        if key not in allowed:
            dropped += 1
            continue
        text = scalar(value)
        if text is None or looks_secret(text):
            # An allowed key whose value is secret-shaped is dropped, not passed: the key
            # was vetted, the value was not.
            dropped += 1
            continue
        fields[key] = text
    return Redaction(fields=fields, dropped=dropped)


def security_flags(observation_type: str, payload: Mapping[str, object]) -> Redaction:
    """The derived security flags in a config-derived payload — and never the config.

    The contract's "masked / summarised" bucket, implemented as a second allowlist rather
    than as a filter on the first, because these keys come from an observation type whose
    projection allowlist is deliberately empty.
    """
    if observation_type.strip().lower() not in FLAG_SOURCE_TYPES:
        return Redaction(fields={}, dropped=len(payload))

    fields: dict[str, str] = {}
    dropped = 0
    for key, value in payload.items():
        text = scalar(value)
        if key not in SECURITY_FLAG_KEYS or text is None or looks_secret(text):
            dropped += 1
            continue
        fields[key] = text
    return Redaction(fields=fields, dropped=dropped)


def scalar(value: object) -> str | None:
    """One bounded, printable scalar, or nothing.

    Lists and dicts are refused rather than flattened. A nested structure in a payload is
    how a raw config file or a log excerpt arrives, and flattening it would carry exactly
    what the contract excludes.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    if not isinstance(value, str):
        return None
    text = "".join(char for char in value if char.isprintable() or char == " ").strip()
    if not text or len(text) > MAX_VALUE_CHARS:
        return None
    return text


def looks_secret(text: str) -> bool:
    """Does this value have the shape of a credential or of personal data?"""
    return any(pattern.search(text) for _name, pattern in _SECRET_SHAPES)


def secret_shapes_in(text: str) -> list[str]:
    """Which shapes matched — used to name the defect when the sweep refuses a dossier."""
    return [name for name, pattern in _SECRET_SHAPES if pattern.search(text)]


def assert_no_secrets(document: object, *, where: str) -> None:
    """Refuse to emit a document containing anything secret-shaped.

    The second layer, and it is a refusal rather than a repair. If a secret reached here,
    the projection above has a hole, and the correct response to "we do not know what else
    got through" is to stop — not to strip this one value and hand over the rest
    (dossier contract §4, AGENTS.md §2.10).
    """
    for path, text in _strings(document, ""):
        shapes = secret_shapes_in(text)
        if shapes:
            # The offending value is deliberately not included in the message: it is the
            # secret. The path and the shape are enough to find it.
            raise ValidationError(
                f"refusing to emit {where}: {path or '<root>'} matched {', '.join(shapes)}; "
                "an excluded field reached an assembled dossier (contract §4 — P0)"
            )


def _strings(node: object, path: str) -> list[tuple[str, str]]:
    """Every string in a JSON-shaped document, with its dotted path."""
    if isinstance(node, str):
        return [(path, node)]
    if isinstance(node, Mapping):
        found: list[tuple[str, str]] = []
        for key, value in node.items():
            found.extend(_strings(value, f"{path}.{key}" if path else str(key)))
        return found
    if isinstance(node, Sequence) and not isinstance(node, str | bytes):
        found = []
        for index, value in enumerate(node):
            found.extend(_strings(value, f"{path}[{index}]"))
        return found
    return []


__all__: Sequence[str] = [
    "FLAG_SOURCE_TYPES",
    "INCLUDED_PAYLOAD_FIELDS",
    "MAX_VALUE_CHARS",
    "SECURITY_FLAG_KEYS",
    "Redaction",
    "assert_no_secrets",
    "looks_secret",
    "project",
    "scalar",
    "secret_shapes_in",
    "security_flags",
]
