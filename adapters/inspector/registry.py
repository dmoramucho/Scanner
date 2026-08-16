"""Choosing an inspector by capability, never by brand.

The core must never learn what an Axis camera is. It learns that *a device speaks SSH and
we hold a credential for it*, and a registry turns that into an adapter. A new vendor —
VAPIX, ISAPI, an embedded BusyBox variant — is a new adapter and one registration; no
caller changes, and no `if brand == …` appears anywhere (m1-design §1, §7).

Returning `None` is a first-class answer, not a failure: a device with no credentialed path
stays uncredentialed, keeps `version_source='banner'`, and is still an asset we know about.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Final

from domain.models import DeviceFingerprint
from domain.ports import CredentialedInspector

#: Ports and banner prefixes that mean "this device speaks SSH". Capability signals, all of
#: them observable without knowing who made the device.
SSH_PORTS: Final = frozenset({22, 2222})
SSH_BANNER_PREFIX: Final = "SSH-"


def speaks_ssh(fingerprint: DeviceFingerprint) -> bool:
    """Does this device offer SSH? A port we saw open, or a banner it gave us."""
    if set(fingerprint.open_ports) & SSH_PORTS:
        return True
    return any(
        banner.strip().upper().startswith(SSH_BANNER_PREFIX)
        for banner in fingerprint.service_banners
    )


@dataclass(frozen=True, slots=True)
class RegistryEntry:
    """One adapter and the capability test that selects it.

    `matches` receives the whole fingerprint and answers a capability question. It is a
    plain callable so a future vendor adapter registers itself with a predicate — "a VAPIX
    endpoint answered" — rather than a name comparison.
    """

    name: str
    matches: Callable[[DeviceFingerprint], bool]
    inspector: CredentialedInspector


class CapabilityInspectorRegistry:
    """`InspectorRegistry` that picks the first adapter whose capability test passes.

    Order is significant and explicit: a more specific vendor adapter registered ahead of
    generic SSH will win for the devices it understands, and generic SSH catches the rest.
    That is the whole extension mechanism.
    """

    def __init__(self, entries: Sequence[RegistryEntry]) -> None:
        self._entries = tuple(entries)

    def for_device(self, fingerprint: DeviceFingerprint) -> CredentialedInspector | None:
        """The inspector that can read this device, or None if we have no way in.

        A missing `credential_ref` short-circuits everything: without a credential there is
        no credentialed path, however capable the device looks. Probing for one is
        default-credential guessing, which is opt-in and out of scope (m1-design §5).
        """
        if not fingerprint.credential_ref:
            return None

        for entry in self._entries:
            if entry.matches(fingerprint):
                return entry.inspector
        return None

    @property
    def registered(self) -> tuple[str, ...]:
        """The adapters this registry knows about, in priority order."""
        return tuple(entry.name for entry in self._entries)


def ssh_entry(inspector: CredentialedInspector, *, name: str = "generic-ssh") -> RegistryEntry:
    """The one adapter M1 ships behind the registry."""
    return RegistryEntry(name=name, matches=speaks_ssh, inspector=inspector)
