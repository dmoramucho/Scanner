"""The credential must not leak. This is the safety-critical file of P7.

It mirrors the M0 `test_secret` leak tests, one layer up: there the primitive was proven to
redact, here the *adapter that uses it* is proven not to spill it — on success, on a refused
connection, on a rejected credential, and into anything it produces or writes.

The value under test is a distinctive string, so a single occurrence anywhere — a log
record, an exception message, a traceback, an observation payload, a repr of the adapter —
fails the test.
"""

from __future__ import annotations

import logging
import traceback
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from adapters.inspector.ssh import SSHInspector
from domain.errors import DependencyError, SecretAccessError
from domain.secret import Secret

TENANT = UUID("11111111-1111-1111-1111-111111111111")
RUN_ID = UUID("22222222-2222-2222-2222-222222222222")
NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
TARGET = ip_address("10.10.5.7")

#: Distinctive enough that any accidental appearance is unmistakable.
RAW_CREDENTIAL = "hunter2-correct-horse-battery-staple-8f3a"

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "ssh"


class FakeSecrets:
    """A `SecretsPort` that hands back a real `Secret` wrapping the value under test."""

    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.resolved: list[str] = []

    def resolve(self, tenant_id: UUID, ref: str) -> Secret:
        self.resolved.append(ref)
        if self.fail:
            raise SecretAccessError(f"no secret at {ref}")
        return Secret(RAW_CREDENTIAL)


class RecordingRunner:
    """A transport that records what it was handed and replays a scripted answer.

    It deliberately keeps the `Secret` object rather than a revealed string: the test then
    asserts the adapter passed the redacting wrapper, not a raw value.
    """

    def __init__(
        self, outputs: Mapping[str, str] | None = None, raises: Exception | None = None
    ) -> None:
        self.outputs = outputs or {}
        self.raises = raises
        self.received: list[Secret] = []
        self.commands: list[str] = []

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
        self.received.append(secret)
        self.commands.extend(commands)
        if self.raises is not None:
            raise self.raises
        return {command: self.outputs.get(command, "") for command in commands}


def working_outputs() -> dict[str, str]:
    return {
        "dpkg -l": (FIXTURES / "dpkg_l.txt").read_text(),
        "cat /etc/os-release": (FIXTURES / "os_release.txt").read_text(),
        "uname -sr": "Linux 5.15.0-91-generic",
        "uname -n": "app-01",
        "rpm -qa": "",
    }


def inspector(runner: RecordingRunner, *, secrets: FakeSecrets | None = None) -> SSHInspector:
    return SSHInspector(
        secrets or FakeSecrets(),
        run_id=RUN_ID,
        username="scanner",
        runner=runner,
        clock=lambda: NOW,
    )


def everything_rendered(obj: object) -> str:
    """Every string form something could reach a log or a report through."""
    return f"{obj!r} {obj!s}"


# ----------------------------------------------------------------- the happy path


def test_a_successful_inspection_never_exposes_the_credential(
    caplog: pytest.LogCaptureFixture,
) -> None:
    runner = RecordingRunner(working_outputs())

    with caplog.at_level(logging.DEBUG):
        result = inspector(runner).inspect(TENANT, TARGET, "vault://ssh/app-01")

    assert result.components  # it really did work
    assert RAW_CREDENTIAL not in caplog.text
    assert RAW_CREDENTIAL not in everything_rendered(result)
    for observation in result.observations:
        assert RAW_CREDENTIAL not in everything_rendered(observation)
        assert RAW_CREDENTIAL not in everything_rendered(observation.payload)


def test_the_adapter_hands_the_transport_a_redacting_secret_not_a_string() -> None:
    """The wrapper is what makes every downstream mistake survivable."""
    runner = RecordingRunner(working_outputs())

    inspector(runner).inspect(TENANT, TARGET, "vault://ssh/app-01")

    assert len(runner.received) == 1
    handed = runner.received[0]
    assert isinstance(handed, Secret)
    assert RAW_CREDENTIAL not in everything_rendered(handed)
    assert handed.reveal() == RAW_CREDENTIAL  # …and it is the real one


def test_the_inspector_itself_does_not_render_the_credential() -> None:
    """A repr of the adapter can end up in a debugger, a crash report, or a log line."""
    runner = RecordingRunner(working_outputs())
    inspection = inspector(runner)

    inspection.inspect(TENANT, TARGET, "vault://ssh/app-01")

    assert RAW_CREDENTIAL not in everything_rendered(inspection)
    assert RAW_CREDENTIAL not in everything_rendered(inspection.__dict__)


# ------------------------------------------------------------------ failure paths


@pytest.mark.parametrize(
    "failure",
    [
        DependencyError("ssh connection to 10.10.5.7:22 failed: refused", retryable=True),
        DependencyError("ssh authentication rejected by 10.10.5.7:22", retryable=False),
        DependencyError("ssh connection to 10.10.5.7:22 timed out", retryable=True),
    ],
    ids=["refused", "auth-failed", "timeout"],
)
def test_no_failure_path_leaks_the_credential(
    failure: DependencyError, caplog: pytest.LogCaptureFixture
) -> None:
    """Refused, rejected, timed out — the three ways this goes wrong in the field, and the
    moments when a careless error message would hand a credential to a log aggregator."""
    runner = RecordingRunner(raises=failure)

    with caplog.at_level(logging.DEBUG), pytest.raises(DependencyError) as exc_info:
        inspector(runner).inspect(TENANT, TARGET, "vault://ssh/app-01")

    rendered = "".join(traceback.format_exception(exc_info.value))
    assert RAW_CREDENTIAL not in rendered
    assert RAW_CREDENTIAL not in str(exc_info.value)
    assert RAW_CREDENTIAL not in caplog.text


def test_an_unresolvable_credential_fails_without_naming_a_secret() -> None:
    """The vault refusing is a `SecretAccessError` that propagates — never a quiet empty
    result that would read as "this device has no software on it"."""
    runner = RecordingRunner(working_outputs())

    with pytest.raises(SecretAccessError) as exc_info:
        inspector(runner, secrets=FakeSecrets(fail=True)).inspect(
            TENANT, TARGET, "vault://ssh/missing"
        )

    assert RAW_CREDENTIAL not in str(exc_info.value)
    assert runner.received == []  # nothing was attempted against the device


def test_a_traceback_through_the_transport_carries_no_credential() -> None:
    """An exception raised while the credential is in scope must not pin it into a frame
    that a traceback formatter would render."""
    runner = RecordingRunner(raises=RuntimeError("transport exploded"))

    with pytest.raises(RuntimeError) as exc_info:
        inspector(runner).inspect(TENANT, TARGET, "vault://ssh/app-01")

    assert RAW_CREDENTIAL not in "".join(traceback.format_exception(exc_info.value))


# --------------------------------------------------- reveal() lives in one place


def test_reveal_is_called_in_exactly_one_place_in_the_adapter() -> None:
    """`Secret.reveal()` exists to be greppable (ports.md §2). If it appears anywhere in
    this package except the single line that hands the credential to the SSH library, the
    guarantee "the credential reaches the transport and nothing else" is no longer true.
    """
    package = Path(__file__).resolve().parents[1] / "adapters" / "inspector"
    occurrences: list[tuple[str, int, str]] = []

    for module in sorted(package.rglob("*.py")):
        for lineno, line in enumerate(module.read_text(encoding="utf-8").splitlines(), start=1):
            code = line.split("#", 1)[0]
            if ".reveal()" in code:
                occurrences.append((module.name, lineno, line.strip()))

    assert len(occurrences) == 1, f"reveal() should appear once, found: {occurrences}"
    module_name, _, statement = occurrences[0]
    assert module_name == "ssh.py"
    assert statement == "credential = secret.reveal()"


def test_the_inspector_never_writes_the_credential_into_an_observation() -> None:
    """Belt to the braces of the leak tests: the payloads are inspected field by field."""
    runner = RecordingRunner(working_outputs())

    result = inspector(runner).inspect(TENANT, TARGET, "vault://ssh/app-01")

    for observation in result.observations:
        flattened = str(observation.model_dump())
        assert RAW_CREDENTIAL not in flattened
        assert "vault://" not in flattened or "vault://ssh/app-01" not in flattened


def test_the_credential_reference_is_not_a_secret_but_is_still_not_broadcast() -> None:
    """A `credential_ref` is an opaque handle and safe to log — but it does not belong in
    device-derived data either, where it would travel to a dossier and an LLM."""
    secrets = FakeSecrets()
    runner = RecordingRunner(working_outputs())

    result = inspector(runner, secrets=secrets).inspect(TENANT, TARGET, "vault://ssh/app-01")

    assert secrets.resolved == ["vault://ssh/app-01"]
    assert "vault://ssh/app-01" not in everything_rendered(result)


def test_a_uuid_shaped_credential_would_also_be_caught() -> None:
    """The leak tests must not pass merely because the fixture value is unusual: a short,
    ordinary-looking password is checked the same way."""
    ordinary = "password1"

    class OrdinarySecrets:
        def resolve(self, tenant_id: UUID, ref: str) -> Secret:
            return Secret(ordinary)

    runner = RecordingRunner(working_outputs())
    result = SSHInspector(
        OrdinarySecrets(), run_id=uuid4(), username="scanner", runner=runner, clock=lambda: NOW
    ).inspect(TENANT, TARGET, "vault://ssh/app-01")

    assert ordinary not in everything_rendered(result)
