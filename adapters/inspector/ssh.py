"""Generic SSH `CredentialedInspector` — read-only, and the credential stops at the wire.

This is the first code in the system that holds a real credential against real hardware, so
the bar is the scope gate's. Four properties, each with a test that fails if it decays:

1. **The secret reaches the transport and nothing else.** `SecretsPort` returns a redacting
   `Secret`; `reveal()` is called in exactly one place in this file — inside
   `ParamikoSSHRunner._authenticate`, the line that hands the credential to the SSH
   library. It is never logged, never interpolated into a message, never put in an
   observation, and never included in an exception (AGENTS.md §2.10).

2. **Read-only, absolutely.** Only the constant commands in `commands.READ_COMMANDS` are
   ever sent, checked against the allowlist again immediately before execution. There is no
   code path that builds a command string, so there is nothing for untrusted data to be
   interpolated into (AGENTS.md §2.4 / §2.9).

3. **Errors never carry the credential.** Authentication failures are reported by exception
   *type*, not by the library's message text, because an SSH library's auth error is the
   one place a credential could plausibly be echoed. Network-level errors (refused, no
   route, timeout) carry their message: those come from the socket layer, which never sees
   the credential.

4. **Device output is untrusted.** It is capped in the transport, parsed defensively in
   `parsing`, and only then becomes an observation with `version_source='package_manager'`.

Ambient credentials are disabled explicitly: no SSH agent, no `~/.ssh` key discovery. The
only credential that can be used is the one the vault handed us, so an inspection cannot
succeed by accident with the operator's own key.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Final, Protocol
from uuid import UUID

import paramiko

from adapters.inspector.commands import ALLOWED_COMMAND_STRINGS, READ_COMMANDS, assert_read_only
from adapters.inspector.parsing import os_component, parse_dpkg, parse_os_release, parse_rpm
from domain.errors import DependencyError, ValidationError
from domain.models import (
    AnchorObservation,
    InspectionResult,
    IPAddress,
    ObservationInput,
    SoftwareComponent,
    VersionSource,
)
from domain.ports import SecretsPort
from domain.secret import Secret

INSPECTOR_NAME: Final = "ssh-inspector"
INSPECTOR_VERSION: Final = "0.1.0"

SOURCE: Final = "ssh"
SOURCE_TYPE: Final = "credentialed"
COLLECTION_METHOD: Final = "ssh_read_only"

DEFAULT_PORT: Final = 22
DEFAULT_TIMEOUT_SECONDS: Final = 30.0

#: A device answering a five-line question with a hundred megabytes is either broken or
#: hostile; either way we stop reading at a bound.
MAX_OUTPUT_BYTES: Final = 1_000_000

#: What a package database says is installed is the device's own account of itself — the
#: strongest identity-free evidence we get without a signed manifest.
COMPONENT_CONFIDENCE: Final = 0.95
HOSTNAME_ANCHOR_CONFIDENCE: Final = 0.7


class SSHCommandRunner(Protocol):
    """The transport seam. One connection, the allow-listed commands, their output.

    Keeping this a port means the inspector's logic — and every leak test — runs without an
    SSH server anywhere (AGENTS.md §43), and it means only one class in the codebase ever
    touches a revealed credential.
    """

    def run(
        self,
        *,
        host: str,
        port: int,
        username: str,
        secret: Secret,
        commands: Sequence[str],
        timeout: float,
    ) -> Mapping[str, str]:
        """Return each command's stdout, keyed by the command. Raises `DependencyError`."""
        ...


@dataclass(frozen=True, slots=True)
class ParamikoSSHRunner:
    """The real transport.

    Host-key policy is `RejectPolicy` and is not configurable to anything weaker: accepting
    an unknown host key would mean handing a credential to whatever answered on that
    address, which is the SSH equivalent of disabling certificate validation (AGENTS.md
    §4.5). An unknown host is a hard failure with a message that says so.
    """

    known_hosts_path: str | None = None

    def run(
        self,
        *,
        host: str,
        port: int,
        username: str,
        secret: Secret,
        commands: Sequence[str],
        timeout: float,
    ) -> Mapping[str, str]:
        client = paramiko.SSHClient()
        # Explicit, and deliberately strict: an unknown host key aborts.
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        if self.known_hosts_path is not None:
            client.load_host_keys(self.known_hosts_path)
        else:
            client.load_system_host_keys()

        try:
            self._authenticate(client, host, port, username, secret, timeout)
            return {command: self._execute(client, command, timeout) for command in commands}
        finally:
            client.close()

    def _authenticate(
        self,
        client: paramiko.SSHClient,
        host: str,
        port: int,
        username: str,
        secret: Secret,
        timeout: float,
    ) -> None:
        """The one place in this codebase where a credential is in the clear.

        `reveal()` appears here and nowhere else in this file. The revealed value is passed
        straight to paramiko and is not stored, formatted, or logged; the local name goes
        out of scope with this function.
        """
        credential = secret.reveal()
        try:
            if credential.lstrip().startswith("-----BEGIN"):
                client.connect(
                    hostname=host,
                    port=port,
                    username=username,
                    pkey=_private_key(credential),
                    timeout=timeout,
                    banner_timeout=timeout,
                    auth_timeout=timeout,
                    allow_agent=False,  # never fall back to an ambient credential
                    look_for_keys=False,  # never read ~/.ssh
                )
            else:
                client.connect(
                    hostname=host,
                    port=port,
                    username=username,
                    password=credential,
                    timeout=timeout,
                    banner_timeout=timeout,
                    auth_timeout=timeout,
                    allow_agent=False,
                    look_for_keys=False,
                )
        except paramiko.AuthenticationException as exc:
            # By type only: an authentication error is the one message an SSH library might
            # build from the credential itself.
            raise DependencyError(
                f"ssh authentication rejected by {host}:{port} for user {username!r} "
                f"({type(exc).__name__})",
                retryable=False,
            ) from None
        except paramiko.BadHostKeyException as exc:
            raise DependencyError(
                f"ssh host key for {host}:{port} does not match the known-hosts entry; "
                f"refusing to hand over a credential ({type(exc).__name__})",
                retryable=False,
            ) from None
        except paramiko.SSHException as exc:
            raise DependencyError(
                f"ssh connection to {host}:{port} failed: unknown host key or protocol "
                f"error ({type(exc).__name__})",
                retryable=False,
            ) from None
        except TimeoutError as exc:
            raise DependencyError(
                f"ssh connection to {host}:{port} timed out after {timeout}s", retryable=True
            ) from exc
        except OSError as exc:
            # Socket-level: the credential is not involved, so the detail is safe and useful.
            raise DependencyError(
                f"ssh connection to {host}:{port} failed: {exc}", retryable=True
            ) from exc

    def _execute(self, client: paramiko.SSHClient, command: str, timeout: float) -> str:
        """Run one allow-listed command and read a bounded amount of its output."""
        # Checked again at the last possible moment, both ways: the command must be one we
        # published *and* must still look like a read.
        if command not in ALLOWED_COMMAND_STRINGS:
            raise ValidationError(
                f"refusing to run a command that is not allow-listed: {command!r}"
            )
        assert_read_only(command)
        try:
            _stdin, stdout, _stderr = client.exec_command(command, timeout=timeout)
            raw = stdout.read(MAX_OUTPUT_BYTES + 1)
        except TimeoutError as exc:
            raise DependencyError(
                f"ssh command timed out after {timeout}s", retryable=True
            ) from exc
        except paramiko.SSHException as exc:
            raise DependencyError(
                f"ssh command failed ({type(exc).__name__})", retryable=True
            ) from None

        return raw[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")


def _private_key(material: str) -> paramiko.PKey:
    """Load a private key from memory. It is never written to disk — a key on a temp file
    is a credential outside the vault's control, however briefly."""
    from io import StringIO

    for key_type in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return key_type.from_private_key(StringIO(material))
        except paramiko.SSHException:
            continue
    raise DependencyError(
        "the resolved credential is not a usable SSH private key", retryable=False
    )


class SSHInspector:
    """`CredentialedInspector` over generic SSH.

    Constructed per unit of work with the `run_id` that stamps its observations and the
    username it authenticates as. There is no default username: a credential without an
    account to use it with is a configuration gap, not something to guess at.
    """

    name = INSPECTOR_NAME

    def __init__(
        self,
        secrets: SecretsPort,
        *,
        run_id: UUID,
        username: str,
        runner: SSHCommandRunner | None = None,
        port: int = DEFAULT_PORT,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not username.strip():
            raise ValidationError("SSHInspector requires a username")
        self._secrets = secrets
        self._run_id = run_id
        self._username = username
        self._runner = runner if runner is not None else ParamikoSSHRunner()
        self._port = port
        self._timeout = timeout_seconds
        self._clock = clock

    def inspect(self, tenant_id: UUID, target: IPAddress, credential_ref: str) -> InspectionResult:
        """Read the device's package database and identity. See the port contract."""
        host = _validated_host(target)
        started_at = self._clock()

        # Raises SecretAccessError if the vault cannot resolve it — which propagates: an
        # unresolvable credential is not "no software found".
        secret = self._secrets.resolve(tenant_id, credential_ref)

        commands = [entry.command for entry in READ_COMMANDS]
        outputs = self._runner.run(
            host=host,
            port=self._port,
            username=self._username,
            secret=secret,
            commands=commands,
            timeout=self._timeout,
        )

        components, hostname = self._interpret(outputs)
        finished_at = self._clock()

        if not components:
            # Every command returned nothing usable. That is a device we could not read,
            # not a device with no software on it (AGENTS.md §67).
            raise ValidationError(
                f"ssh inspection of {host} produced no usable output from any read command"
            )

        return InspectionResult(
            target=host,
            inspector=self.name,
            observations=self._observations(tenant_id, host, components, hostname, finished_at),
            components=components,
            anchors=_anchors(hostname),
            started_at=started_at,
            finished_at=finished_at,
        )

    def _interpret(self, outputs: Mapping[str, str]) -> tuple[list[SoftwareComponent], str | None]:
        """Parse each allow-listed command's output. Anything we did not ask for is ignored
        rather than parsed — a runner returning unexpected keys does not get to choose what
        this code does with them."""
        by_kind = {
            entry.kind: outputs.get(entry.command, "")
            for entry in READ_COMMANDS
            if entry.command in ALLOWED_COMMAND_STRINGS
        }

        components: list[SoftwareComponent] = []
        components.extend(parse_dpkg(by_kind.get("packages_dpkg", "")))
        components.extend(parse_rpm(by_kind.get("packages_rpm", "")))

        os_release = parse_os_release(by_kind.get("os_release", ""))
        kernel = by_kind.get("kernel", "").strip() or None
        operating_system = os_component(os_release, kernel)
        if operating_system is not None:
            components.insert(0, operating_system)

        hostname = _clean_hostname(by_kind.get("hostname", ""))
        return components, hostname

    def _observations(
        self,
        tenant_id: UUID,
        host: str,
        components: Sequence[SoftwareComponent],
        hostname: str | None,
        collected_at: datetime,
    ) -> list[ObservationInput]:
        def observation(
            observation_type: str,
            payload: dict[str, object],
            version_source: VersionSource | None,
        ) -> ObservationInput:
            return ObservationInput(
                tenant_id=tenant_id,
                run_id=self._run_id,
                asset_id=None,  # resolution happens in the ingestion path (P8)
                observation_type=observation_type,
                payload=payload,
                source=SOURCE,
                source_type=SOURCE_TYPE,
                source_identifier=host,
                collector=INSPECTOR_NAME,
                collector_version=INSPECTOR_VERSION,
                collection_method=COLLECTION_METHOD,
                version_source=version_source,
                confidence=COMPONENT_CONFIDENCE,
                observed_at=collected_at,  # the device's state as of the read
                collected_at=collected_at,
                raw_record_ref=None,
            )

        observations = [
            observation(
                "software",
                {
                    "ip": host,
                    "components": [
                        {
                            "name": component.name,
                            "version": component.version,
                            "cpe": component.cpe,
                        }
                        for component in components
                    ],
                },
                # The point of the whole exercise: this came from the package database, not
                # from a banner, so a backported patch will not read as a vulnerability.
                VersionSource.PACKAGE_MANAGER,
            )
        ]
        if hostname is not None:
            observations.append(observation("identity", {"ip": host, "hostname": hostname}, None))
        return observations


def _anchors(hostname: str | None) -> list[AnchorObservation]:
    """A device's own name is a locator, not an identity — entity resolution will attach it
    without ever matching on it (AGENTS.md §3)."""
    if hostname is None:
        return []
    return [
        AnchorObservation(kind="hostname", value=hostname, confidence=HOSTNAME_ANCHOR_CONFIDENCE)
    ]


def _clean_hostname(raw: str) -> str | None:
    candidate = "".join(char for char in raw.strip() if char.isprintable())[:253]
    if not candidate or not all(char.isalnum() or char in "._-" for char in candidate):
        return None
    return candidate


def _validated_host(target: IPAddress | str) -> str:
    """An address, or nothing. The host goes to a network call rather than a shell, but it
    is validated on the same principle: a value that is not what it claims to be does not
    get to travel further into the system."""
    try:
        return str(ip_address(target))
    except (ValueError, TypeError) as exc:
        raise ValidationError(f"inspection target is not a valid IP address: {exc}") from exc
