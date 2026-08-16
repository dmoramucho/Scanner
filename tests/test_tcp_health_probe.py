"""The probe must be the lightest touch in the system, and must never invent a verdict.

Two kinds of test here, on purpose:

* **Real sockets against a listener on localhost** for the properties that are only true of
  the actual implementation — that a connect happens exactly once, that not one byte is
  sent, that a closed port is distinguished from an open one. No external network is
  involved (AGENTS.md §43).
* **A fake connector** for the error mapping, because arranging a genuinely blackholed
  route or an `EMFILE` inside a test is either flaky or impossible, and the mapping is the
  part where fabricating health would do the damage.
"""

from __future__ import annotations

import errno
import socket
import threading
import time
from collections.abc import Iterator
from ipaddress import ip_address

import pytest

from adapters.probe.tcp import (
    DEFAULT_TIMEOUT_SECONDS,
    SocketConnector,
    TcpHealthProbe,
)
from domain.errors import DependencyError, ValidationError
from domain.ports import HealthProbe

LOCALHOST = "127.0.0.1"


class Listener:
    """A socket that accepts connections and remembers what it was sent.

    `received` is the interesting field: a health probe that ever puts a byte on the wire
    is doing more than checking whether the stack is alive.
    """

    def __init__(self) -> None:
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((LOCALHOST, 0))
        self._server.listen(8)
        self.port: int = self._server.getsockname()[1]
        self.accepted = 0
        self.received: list[bytes] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        self._server.settimeout(0.2)
        while not self._stop.is_set():
            try:
                connection, _ = self._server.accept()
            except (TimeoutError, OSError):
                continue
            self.accepted += 1
            with connection:
                connection.settimeout(0.3)
                try:
                    self.received.append(connection.recv(4096))
                except (TimeoutError, OSError):
                    self.received.append(b"")

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._server.close()


@pytest.fixture
def listener() -> Iterator[Listener]:
    server = Listener()
    try:
        yield server
    finally:
        server.close()


def closed_port() -> int:
    """A port that was bound and released — nothing is listening, so a connect is refused."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe_socket:
        probe_socket.bind((LOCALHOST, 0))
        port: int = probe_socket.getsockname()[1]
    return port


class FakeConnector:
    """Records every connect, and fails however the test asks it to."""

    def __init__(self, raises: BaseException | None = None) -> None:
        self.raises = raises
        self.calls: list[tuple[str, int, float]] = []

    def connect(self, address: str, port: int, timeout: float) -> None:
        self.calls.append((address, port, timeout))
        if self.raises is not None:
            raise self.raises


def probe(
    *,
    port: int | None = None,
    connector: FakeConnector | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> TcpHealthProbe:
    known = {LOCALHOST: port} if port is not None else {}
    return TcpHealthProbe(known, timeout_seconds=timeout, connector=connector)


# ------------------------------------------------------------------- real sockets


def test_an_open_port_reports_responsive(listener: Listener) -> None:
    assert probe(port=listener.port).is_responsive(ip_address(LOCALHOST)) is True


def test_a_refused_connection_still_counts_as_responsive() -> None:
    """A `RST` proves the TCP stack is answering. The breaker watches for a device falling
    off the network, not for a service being down — those are different findings."""
    assert probe(port=closed_port()).is_responsive(ip_address(LOCALHOST)) is True


def test_the_probe_sends_no_application_data(listener: Listener) -> None:
    """Connect and close. Anything sent would be an application-layer interaction with a
    device we are supposed to be treating as fragile (AGENTS.md §2.7)."""
    probe(port=listener.port).is_responsive(ip_address(LOCALHOST))
    time.sleep(0.4)  # let the listener finish its read attempt

    assert listener.accepted == 1
    assert listener.received == [b""]


def test_one_call_is_exactly_one_connect(listener: Listener) -> None:
    """Retries belong to `BreakerPolicy.health_check_attempts`. A retry loop in here as
    well would double the traffic and make the policy a lie."""
    health = probe(port=listener.port)

    health.is_responsive(ip_address(LOCALHOST))
    time.sleep(0.3)
    assert listener.accepted == 1

    health.is_responsive(ip_address(LOCALHOST))
    time.sleep(0.3)
    assert listener.accepted == 2  # one per call, never more


def test_the_connector_leaves_no_socket_behind(listener: Listener) -> None:
    """Fifty checks in a row must not exhaust file descriptors — the probe runs before and
    after every device in a run."""
    health = probe(port=listener.port)

    for _ in range(50):
        assert health.is_responsive(ip_address(LOCALHOST)) is True


def test_the_real_connector_reaches_an_open_port(listener: Listener) -> None:
    SocketConnector().connect(LOCALHOST, listener.port, 1.0)  # must not raise


def test_the_real_connector_raises_on_a_closed_port() -> None:
    with pytest.raises(OSError, match=r"refused|Connection"):
        SocketConnector().connect(LOCALHOST, closed_port(), 1.0)


# ------------------------------------------------------------------ error mapping


@pytest.mark.parametrize(
    "code", [errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN]
)
def test_silence_and_unreachability_report_not_responsive(code: int) -> None:
    connector = FakeConnector(raises=OSError(code, "gone"))

    assert probe(port=80, connector=connector).is_responsive(ip_address(LOCALHOST)) is False


def test_a_socket_timeout_reports_not_responsive() -> None:
    """The case the breaker is actually for: the device stopped answering."""
    connector = FakeConnector(raises=TimeoutError("timed out"))

    assert probe(port=80, connector=connector).is_responsive(ip_address(LOCALHOST)) is False


@pytest.mark.parametrize("code", [errno.ECONNREFUSED, errno.ECONNRESET])
def test_an_answering_stack_reports_responsive(code: int) -> None:
    connector = FakeConnector(raises=OSError(code, "refused"))

    assert probe(port=80, connector=connector).is_responsive(ip_address(LOCALHOST)) is True


@pytest.mark.parametrize(
    "code", [errno.EMFILE, errno.EACCES, errno.EPERM, errno.EAFNOSUPPORT, errno.ENOBUFS]
)
def test_a_probe_that_cannot_run_raises_rather_than_guessing(code: int) -> None:
    """Our problem, not the device's. "Responsive" would hide a dead device; "not
    responsive" would accuse a healthy one of dying under our scan. Neither is ours to say."""
    connector = FakeConnector(raises=OSError(code, "cannot"))

    with pytest.raises(DependencyError, match="could not be performed"):
        probe(port=80, connector=connector).is_responsive(ip_address(LOCALHOST))


def test_an_unrecognised_socket_error_raises_too() -> None:
    """Fail closed on the unknown: the engine treats an error as "do not scan", and that is
    the right default for a case nobody anticipated."""
    connector = FakeConnector(raises=OSError(errno.EIO, "something new"))

    with pytest.raises(DependencyError):
        probe(port=80, connector=connector).is_responsive(ip_address(LOCALHOST))


def test_no_error_path_ever_returns_responsive_by_accident() -> None:
    """Sweep every errno the platform defines: each one must map to a verdict we chose, or
    raise. Nothing may silently fall through to True."""
    fabricated: list[int] = []
    for code in sorted(errno.errorcode):
        connector = FakeConnector(raises=OSError(code, errno.errorcode[code]))
        try:
            verdict = probe(port=80, connector=connector).is_responsive(ip_address(LOCALHOST))
        except DependencyError:
            continue
        if verdict and code not in {errno.ECONNREFUSED, errno.ECONNRESET}:
            fabricated.append(code)

    assert fabricated == [], f"these errnos produced an unearned 'responsive': {fabricated}"


# --------------------------------------------------------------- no known-open port


def test_a_target_with_no_known_port_raises_rather_than_assuming_health() -> None:
    """ADR-0007. The probe checks a port discovery already found; it does not scan for one,
    because a probe that scanned would be the aggressive thing it exists to be the opposite
    of. The engine reads this error as "do not scan", which is the fail-safe direction."""
    connector = FakeConnector()

    with pytest.raises(DependencyError, match="no known-open TCP port") as exc_info:
        TcpHealthProbe({}, connector=connector).is_responsive(ip_address("10.10.5.31"))

    assert exc_info.value.retryable is False  # retrying without a port will not help
    assert connector.calls == []  # nothing was attempted


def test_an_operator_supplied_fallback_port_is_honoured() -> None:
    """For the by-hand validation in the runbook, where the operator knows the device's
    admin port. Empty by default: guessing on behalf of a fragile device is the behaviour
    this class exists to avoid."""
    connector = FakeConnector()
    health = TcpHealthProbe({}, fallback_ports=(80,), connector=connector)

    assert health.is_responsive(ip_address("10.10.5.31")) is True
    assert connector.calls == [("10.10.5.31", 80, DEFAULT_TIMEOUT_SECONDS)]


def test_a_known_port_beats_the_fallback() -> None:
    connector = FakeConnector()
    health = TcpHealthProbe({"10.10.5.31": 554}, fallback_ports=(80,), connector=connector)

    health.is_responsive(ip_address("10.10.5.31"))

    assert connector.calls[0][1] == 554


def test_several_known_ports_use_the_first() -> None:
    """One connect per call means one port per call — the probe does not work down a list,
    which would be a small port scan."""
    connector = FakeConnector()
    health = TcpHealthProbe({LOCALHOST: (443, 80, 22)}, connector=connector)

    health.is_responsive(ip_address(LOCALHOST))

    assert [call[1] for call in connector.calls] == [443]


# ------------------------------------------------------------------- the boundary


@pytest.mark.parametrize(
    "hostile",
    [
        "10.10.5.31; rm -rf /",
        "camera.example.com",  # a name could resolve anywhere, including out of scope
        "10.10.5.0/24",
        "010.010.005.031",  # leading zeros: octal ambiguity
        "",
        "not-an-address",
    ],
)
def test_a_target_that_is_not_an_address_is_refused_before_any_socket(hostile: str) -> None:
    connector = FakeConnector()
    health = TcpHealthProbe({LOCALHOST: 80}, fallback_ports=(80,), connector=connector)

    with pytest.raises(ValidationError, match="not a valid IP address"):
        health.is_responsive(hostile)  # type: ignore[arg-type]

    assert connector.calls == []


def test_a_non_positive_timeout_is_refused() -> None:
    """A zero timeout would report every device on the estate as dead."""
    with pytest.raises(ValidationError, match="timeout must be positive"):
        TcpHealthProbe({LOCALHOST: 80}, timeout_seconds=0)


# ---------------------------------------------------------------------- timeouts


def test_the_configured_timeout_reaches_the_socket() -> None:
    connector = FakeConnector()
    TcpHealthProbe({LOCALHOST: 80}, timeout_seconds=0.75, connector=connector).is_responsive(
        ip_address(LOCALHOST)
    )

    assert connector.calls == [(LOCALHOST, 80, 0.75)]


def test_a_blackholed_address_does_not_hang() -> None:
    """A device that vanished mid-scan is exactly a blackholed address: the SYN goes out
    and nothing ever comes back. The probe must give up, not stall the run.

    198.51.100.0/24 is TEST-NET-2 (RFC 5737) — reserved, never routed. Either the network
    drops the SYN (the timeout fires) or it answers "unreachable" immediately; both are
    "not responsive", and both must return promptly.
    """
    health = TcpHealthProbe({"198.51.100.1": 80}, timeout_seconds=0.5)

    started = time.monotonic()
    verdict = health.is_responsive(ip_address("198.51.100.1"))
    elapsed = time.monotonic() - started

    assert verdict is False
    assert elapsed < 5.0


# -------------------------------------------------------------------- conformance


def test_the_adapter_satisfies_the_port() -> None:
    health: HealthProbe = TcpHealthProbe({LOCALHOST: 80})

    assert callable(health.is_responsive)
