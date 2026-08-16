"""TCP-connect `HealthProbe` — the lightest touch in the system.

The circuit breaker's job is to notice when a scan has hurt a device (m1-design §2). The
probe it uses to notice must therefore be gentler than the scan itself, by a wide margin —
a heavy health check would knock over the device it exists to protect, which is the most
self-defeating bug this codebase could contain (AGENTS.md §2.7).

So this is the smallest thing that proves a TCP stack is alive:

* **One connect, to a port already known open, then close.** No data is sent, no
  application-layer conversation happens, nothing is read. The device's TCP stack answers
  a SYN — which is the same thing it does thousands of times a day — and we hang up.
* **No ICMP, and therefore no raw sockets and no root.** That is deliberate: a component
  running as an ordinary user cannot do anything privileged even if it is wrong.
* **One attempt per call.** `BreakerPolicy.health_check_attempts` owns retries; a retry
  loop here as well would multiply the traffic and make the policy a lie.
* **It never guesses a port.** The probe checks a port that discovery already found open.
  It does not scan to find one — a probe that scanned would be the aggressive thing it is
  supposed to be the opposite of. A target with no known-open port raises, because refusing
  to check is honest and "assume healthy" is not (ADR-0007).

The three answers a connect can give, kept distinct:

| What happened | Verdict | Why |
|---|---|---|
| Connected | responsive | The stack completed a handshake |
| Refused (`RST`) | **responsive** | Something is listening on that stack to say no |
| Timed out, host/net unreachable | not responsive | Silence, or the network says it is gone |
| Anything else | raises | We could not perform the check — never a fabricated verdict |

That second row matters: a device whose service died but whose kernel still sends `RST` is
*answering*. It is not the breaker's job to decide the application is unhealthy; it is the
breaker's job to notice the device fell off the network.
"""

from __future__ import annotations

import errno
import socket
from collections.abc import Mapping
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Final, Protocol

from domain.errors import DependencyError, ValidationError
from domain.models import IPAddress

#: Long enough for a busy embedded device to answer a SYN, short enough that a blackholed
#: address does not stall a run. The breaker retries; this is one attempt's patience.
DEFAULT_TIMEOUT_SECONDS: Final = 2.0

#: A refusal proves the stack is answering, so it counts as health.
_ANSWERING_ERRNOS: Final = frozenset({errno.ECONNREFUSED, errno.ECONNRESET})

#: Silence, or the network telling us the device is gone. Both mean "not responsive" — a
#: verdict about the device, not about us.
_SILENT_ERRNOS: Final = frozenset(
    {
        errno.ETIMEDOUT,
        errno.EHOSTUNREACH,
        errno.ENETUNREACH,
        errno.EHOSTDOWN,
        errno.ENETDOWN,
        errno.ECONNABORTED,
    }
)


class TcpConnector(Protocol):
    """The socket seam: connect, then close. Nothing else.

    Separated so the error mapping above can be tested exhaustively without arranging a
    real device in each of those states (AGENTS.md §43).
    """

    def connect(self, address: str, port: int, timeout: float) -> None:
        """Open and immediately close a TCP connection. Raises `OSError` on failure."""
        ...


@dataclass(frozen=True, slots=True)
class SocketConnector:
    """The real connector: one socket, one connect, one close, zero bytes.

    `socket.create_connection` is deliberately not used — it resolves names, and this probe
    never accepts a name. The address it is given has already been validated as a literal
    IP, and `AF_INET`/`AF_INET6` is chosen from that, so no resolver is ever consulted and
    there is no path by which a DNS answer could redirect a probe (AGENTS.md §2.9).
    """

    def connect(self, address: str, port: int, timeout: float) -> None:
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        try:
            sock.settimeout(timeout)
            sock.connect((address, port))
            # Nothing is sent and nothing is read. The handshake is the whole message.
        finally:
            sock.close()


class TcpHealthProbe:
    """`HealthProbe` over a single TCP connect to a known-open port.

    `known_ports` maps a target address to the ports discovery already found open on it —
    the probe consumes that knowledge, it does not produce it. `fallback_ports` is for the
    operator who knows a device's admin port and is running a one-off validation by hand;
    it is empty by default, because guessing on behalf of a fragile device is exactly the
    behaviour this class exists to avoid.
    """

    def __init__(
        self,
        known_ports: Mapping[str, int | tuple[int, ...]] | None = None,
        *,
        fallback_ports: tuple[int, ...] = (),
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        connector: TcpConnector | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValidationError("health probe timeout must be positive")
        self._known_ports = {
            address: (ports,) if isinstance(ports, int) else tuple(ports)
            for address, ports in (known_ports or {}).items()
        }
        self._fallback_ports = fallback_ports
        self._timeout = timeout_seconds
        self._connector = connector if connector is not None else SocketConnector()

    def is_responsive(self, target: IPAddress) -> bool:
        """One connect to one known-open port. See the port contract in `domain.ports`.

        Raises `DependencyError` when the check could not be performed at all — including
        when this target has no known-open port. The engine reads that as "do not scan",
        which is the point: a device we cannot watch is a device we must not poke
        (m1-design §2).
        """
        address = _validated_target(target)
        port = self._port_for(address)

        try:
            self._connector.connect(address, port, self._timeout)
        except TimeoutError:
            return False  # silence
        except OSError as exc:
            return self._verdict_from(exc, address, port)

        return True

    def _port_for(self, address: str) -> int:
        """The first known-open port for this target, or a clear refusal to guess."""
        ports = self._known_ports.get(address) or self._fallback_ports
        if not ports:
            raise DependencyError(
                f"no known-open TCP port for {address}: the health probe checks a port "
                "discovery already found, and will not scan for one (ADR-0007)",
                retryable=False,
            )
        return ports[0]

    def _verdict_from(self, exc: OSError, address: str, port: int) -> bool:
        """Map a socket failure onto health, or refuse to have an opinion.

        The refusal is the important branch. An error we do not recognise means the check
        did not happen, and reporting either verdict from that would be a fabrication —
        "responsive" would hide a dead device, "not responsive" would accuse a healthy one
        of dying under our scan.
        """
        if exc.errno in _ANSWERING_ERRNOS:
            return True
        if exc.errno in _SILENT_ERRNOS:
            return False
        raise DependencyError(
            f"tcp health probe of {address}:{port} could not be performed: "
            f"{type(exc).__name__} (errno {exc.errno})",
            retryable=True,
        ) from exc


def _validated_target(target: IPAddress | str) -> str:
    """A literal address, or nothing. Same boundary discipline as the scanner and the SSH
    inspector: a value that is not what it claims to be goes no further."""
    try:
        return str(ip_address(target))
    except (ValueError, TypeError) as exc:
        raise ValidationError(f"health probe target is not a valid IP address: {exc}") from exc
