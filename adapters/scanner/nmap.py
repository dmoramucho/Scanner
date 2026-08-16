"""nmap-orchestrating `ActiveScanner`.

We orchestrate nmap; we do not reimplement it (m1-design, AGENTS.md §78). The value this
module adds is the judgment layer around it: which flags a *profile* means, refusing to
put anything near a shell, and turning nmap's XML into provenance-complete observations.

Four safety properties, each with a test that fails if it decays:

1. **`GENTLE` is gentle, and only this module knows what that means.** No `-A`, no
   `--version-all`, `--version-intensity 0`, SYN rather than connect, a `-T2` ceiling, a
   scan delay, capped rate and parallelism, and a curated port set instead of all 65535
   (AGENTS.md §2.7, m1-design §2). Callers pass intent; they cannot pass flags.
2. **No shell, ever.** The command is an argument list handed to `subprocess.run` with
   `shell=False`. The target is validated as a well-formed IP address *before* it can
   reach the command, so a value shaped like `10.0.0.1; rm -rf /` is rejected at the door
   rather than quoted somewhere downstream (AGENTS.md §2.9 / §69).
3. **nmap's output is untrusted input.** It is XML from a process that just talked to an
   untrusted device, so it is parsed with `defusedxml` (no external entities, no entity
   expansion — ADR-0003) and read defensively: every attribute is optional until proven
   otherwise, and anything unparseable is skipped rather than guessed at.
4. **A failure is never an empty success.** A missing binary, a non-zero exit, a timeout,
   or unparseable output raises. `host_up=False` with no observations means the host was
   checked and was not there — which is a finding, not a failure (AGENTS.md §67).

Everything an active scan learns about versions is *inferred from a banner*, so every
version-shaped observation carries `version_source='banner'`. That flag is what stops an
OS-backported `Apache/2.4.52` header from becoming a false positive later (AGENTS.md §3).
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import TYPE_CHECKING, Any, Final, Protocol
from uuid import UUID

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import ParseError, fromstring

from domain.errors import DependencyError, ValidationError
from domain.models import (
    AnchorObservation,
    IPAddress,
    ObservationInput,
    ScanProfile,
    ScanResult,
    VersionSource,
)

if TYPE_CHECKING:
    # Type only. Parsing goes through defusedxml (ADR-0003); the stdlib parser is never
    # instantiated here, and this import exists solely to name the element type.
    from xml.etree.ElementTree import Element

COLLECTOR_NAME: Final = "nmap-scanner"
COLLECTOR_VERSION: Final = "0.1.0"

SOURCE: Final = "nmap"
SOURCE_TYPE: Final = "active_scan"

DEFAULT_NMAP_PATH: Final = "nmap"
DEFAULT_TIMEOUT_SECONDS: Final = 900.0

#: The ports that matter on the devices `GENTLE` exists for — cameras, VoIP handsets,
#: printers, UPSes, badge readers — plus the handful of admin services they expose. A
#: full 65535-port sweep is the thing that knocks these stacks over, and it buys us almost
#: nothing: an embedded device with a service on a random high port is rare, and finding it
#: is not worth taking the device down (AGENTS.md §2.7).
IOT_PORTS: Final = (
    21,  # ftp — firmware upload endpoints on older cameras
    22,  # ssh
    23,  # telnet — still the default on a depressing number of devices
    25,  # smtp — printers and cameras that email alerts
    53,  # dns
    80,  # http — the admin UI
    81,  # http-alt — common second camera UI
    88,  # http alt / Hikvision, Axis
    443,  # https
    445,  # smb — printers with scan-to-share
    515,  # lpr
    554,  # rtsp — the video stream itself
    631,  # ipp
    1883,  # mqtt
    2000,  # sip / cisco skinny
    3389,  # rdp
    5000,  # upnp / embedded http
    5060,  # sip
    5061,  # sips
    7547,  # tr-069 cwmp
    8000,  # http-alt / Hikvision
    8008,  # http-alt
    8080,  # http-alt
    8081,  # http-alt
    8443,  # https-alt
    8554,  # rtsp-alt
    8883,  # mqtt over tls
    9100,  # jetdirect — raw printing
    37777,  # dahua
    49152,  # upnp dynamic
)

#: Flags no profile may ever carry. `-A` turns on OS detection, NSE scripts and traceroute
#: in one go; `--version-all` runs every version probe regardless of rarity. Both are ways
#: to hammer a device, and `-A`'s script engine also drifts toward the exploitation line
#: this product does not cross (AGENTS.md §2.6, §2.7).
FORBIDDEN_FLAGS: Final = ("-A", "--version-all", "--script", "-O")

_GENTLE_FLAGS: Final = (
    "-sS",  # SYN scan: never completes the handshake, no application-layer state
    "-sV",  # service detection, but…
    "--version-intensity",
    "0",  # …at the lightest possible probe set (banner only)
    "-T2",  # timing ceiling — polite
    "--scan-delay",
    "200ms",  # never faster than five probes a second at this device
    "--max-rate",
    "50",
    "--max-parallelism",
    "1",  # one probe at a time per device (AGENTS.md §2.7)
    "--max-retries",
    "1",
    "--host-timeout",
    "300s",
)

_STANDARD_FLAGS: Final = (
    "-sS",
    "-sV",  # normal version detection: default intensity
    "-T3",
    "--max-retries",
    "2",
    "--host-timeout",
    "600s",
    "--top-ports",
    "1000",
)

#: nmap reports service-detection certainty as 1–10; we carry it as a 0–1 confidence
#: rather than inventing a constant. A `method="table"` guess (port 80 ⇒ "http") comes
#: back as 3, a probed banner as 10 — exactly the distinction that should survive.
_DEFAULT_SERVICE_CONFIDENCE: Final = 0.3

#: A port answering a SYN probe is strong, direct evidence that something is listening.
_PORT_STATE_CONFIDENCE: Final = 0.9


class CommandRunner(Protocol):
    """How the adapter reaches the outside world — one seam, so tests do not need nmap.

    CI is hermetic (AGENTS.md §43, m1-design §4): the tests drive the real parsing,
    normalization and error mapping through a runner that replays recorded XML.
    """

    def __call__(
        self, command: Sequence[str], timeout: float
    ) -> subprocess.CompletedProcess[str]: ...


def run_subprocess(command: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
    """The real runner. `shell=False` is the default and is what we rely on: the argument
    list goes to `execve` untouched, so no element of it is ever interpreted by a shell."""
    return subprocess.run(  # noqa: S603 — argument list, shell=False, target validated as an IP
        list(command),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        stdin=subprocess.DEVNULL,
    )


def validated_target(target: IPAddress | str) -> str:
    """The canonical string form of a real IP address, or `ValidationError`.

    This is the command-injection boundary (AGENTS.md §2.9). The port types the target as
    an `IPAddress`, but types are not a runtime guarantee at a boundary an adapter may be
    handed anything through, so the value is re-parsed here. `ip_address()` accepts only
    an address — anything carrying a shell metacharacter, a flag, a hostname, or a CIDR
    range fails to parse and never reaches the command.
    """
    try:
        return str(ip_address(target))
    except (ValueError, TypeError) as exc:
        raise ValidationError(f"scan target is not a valid IP address: {exc}") from exc


def build_command(
    target: IPAddress | str,
    profile: ScanProfile,
    *,
    nmap_path: str = DEFAULT_NMAP_PATH,
) -> list[str]:
    """The exact argv for a scan. Pure, so the safety-critical mapping is directly testable.

    `-oX -` sends XML to stdout: no temporary file to create, secure, or clean up, and no
    parsing of nmap's human-readable output, which is not a stable interface.
    """
    address = validated_target(target)

    if profile is ScanProfile.GENTLE:
        flags: tuple[str, ...] = (*_GENTLE_FLAGS, "-p", ",".join(str(port) for port in IOT_PORTS))
    elif profile is ScanProfile.STANDARD:
        flags = _STANDARD_FLAGS
    else:  # pragma: no cover — unreachable while ScanProfile has two members
        raise ValidationError(f"unknown scan profile: {profile!r}")

    command = [nmap_path, *flags, "-oX", "-", address]

    # A last line of defence rather than a comment: if a flag list is ever edited to
    # include one of these, the scan fails instead of running hot against a device.
    forbidden = [flag for flag in command if flag in FORBIDDEN_FLAGS]
    if forbidden:
        raise ValidationError(f"refusing to run nmap with forbidden flags: {forbidden}")

    return command


class NmapActiveScanner:
    """`ActiveScanner` backed by the nmap binary.

    One instance per run: `run_id` stamps every observation this scanner produces, the
    same way the collector and the scope authority are constructed per unit of work.
    """

    def __init__(
        self,
        run_id: UUID,
        *,
        nmap_path: str = DEFAULT_NMAP_PATH,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        runner: CommandRunner | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._run_id = run_id
        self._nmap_path = nmap_path
        self._timeout = timeout_seconds
        self._run = runner if runner is not None else run_subprocess
        self._clock = clock

    def scan(self, tenant_id: UUID, target: IPAddress, profile: ScanProfile) -> ScanResult:
        """Scan one target under `profile`. See the port contract in `domain.ports`."""
        command = build_command(target, profile, nmap_path=self._nmap_path)
        started_at = self._clock()
        completed = self._execute(command)
        finished_at = self._clock()

        parsed = parse_scan_xml(completed.stdout)
        address = command[-1]

        return ScanResult(
            target=address,
            profile=profile,
            host_up=parsed.host_up,
            observations=self._observations(tenant_id, parsed, address, profile, finished_at),
            anchors=_anchors_of(parsed),
            started_at=started_at,
            finished_at=finished_at,
        )

    def _execute(self, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        """Run nmap, mapping every way it can fail onto a domain error."""
        try:
            completed = self._run(command, self._timeout)
        except FileNotFoundError as exc:
            raise DependencyError(
                f"nmap binary not found at {self._nmap_path!r}; active scanning is unavailable",
                retryable=False,
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise DependencyError(
                f"nmap timed out after {self._timeout}s scanning {command[-1]}", retryable=True
            ) from exc
        except OSError as exc:
            raise DependencyError(f"could not execute nmap: {exc}", retryable=True) from exc

        if completed.returncode != 0:
            raise DependencyError(
                f"nmap exited {completed.returncode} scanning {command[-1]}: "
                f"{_short(completed.stderr)}",
                retryable=False,
            )
        return completed

    def _observations(
        self,
        tenant_id: UUID,
        parsed: ParsedScan,
        address: str,
        profile: ScanProfile,
        collected_at: datetime,
    ) -> list[ObservationInput]:
        observed_at = parsed.observed_at or collected_at
        method = f"nmap_{profile.value}"
        observations: list[ObservationInput] = []

        def observation(
            observation_type: str,
            payload: dict[str, Any],
            confidence: float,
            version_source: VersionSource | None = None,
        ) -> ObservationInput:
            return ObservationInput(
                tenant_id=tenant_id,
                run_id=self._run_id,
                asset_id=None,  # resolution happens in the engine, after the scope gate
                observation_type=observation_type,
                payload=payload,
                source=SOURCE,
                source_type=SOURCE_TYPE,
                source_identifier=address,
                collector=COLLECTOR_NAME,
                collector_version=COLLECTOR_VERSION,
                collection_method=method,
                version_source=version_source,
                confidence=confidence,
                observed_at=observed_at,
                collected_at=collected_at,
                raw_record_ref=None,
            )

        identity = _identity_payload(parsed, address)
        if len(identity) > 1:  # more than the address itself
            observations.append(observation("identity", identity, _PORT_STATE_CONFIDENCE))

        if parsed.ports:
            observations.append(
                observation(
                    "open_ports",
                    {
                        "ip": address,
                        "ports": [port.as_payload() for port in parsed.ports],
                    },
                    _PORT_STATE_CONFIDENCE,
                )
            )

        components = [port.as_component() for port in parsed.ports if port.has_version]
        if components:
            observations.append(
                observation(
                    "software",
                    {"ip": address, "components": components},
                    max(float(port.confidence) for port in parsed.ports if port.has_version),
                    # Everything an uncredentialed scan learns about a version is read off
                    # a banner. Saying so is what keeps a backported package from becoming
                    # a false positive downstream (AGENTS.md §3).
                    VersionSource.BANNER,
                )
            )

        return observations


# --------------------------------------------------------------------------- parsing


class ParsedPort:
    """One open port as nmap reported it, already validated."""

    __slots__ = ("confidence", "port", "product", "protocol", "service", "version")

    def __init__(
        self,
        port: int,
        protocol: str,
        service: str | None,
        product: str | None,
        version: str | None,
        confidence: float,
    ) -> None:
        self.port = port
        self.protocol = protocol
        self.service = service
        self.product = product
        self.version = version
        self.confidence = confidence

    @property
    def has_version(self) -> bool:
        return self.product is not None or self.version is not None

    def as_payload(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "confidence": self.confidence,
        }

    def as_component(self) -> dict[str, Any]:
        """Shaped like a `SoftwareComponent`, minus the fields only the store can supply."""
        return {
            "name": self.product or self.service,
            "version": self.version,
            "cpe": None,  # CPE mapping is M3's job; claiming one here would be a guess
            "port": self.port,
            "protocol": self.protocol,
            "confidence": self.confidence,
        }


class ParsedScan:
    """What we were willing to believe from one nmap run."""

    __slots__ = ("host_up", "hostname", "mac", "observed_at", "ports", "vendor")

    def __init__(
        self,
        host_up: bool,
        ports: list[ParsedPort],
        mac: str | None,
        vendor: str | None,
        hostname: str | None,
        observed_at: datetime | None,
    ) -> None:
        self.host_up = host_up
        self.ports = ports
        self.mac = mac
        self.vendor = vendor
        self.hostname = hostname
        self.observed_at = observed_at


def parse_scan_xml(xml_text: str) -> ParsedScan:
    """Parse nmap's `-oX` output defensively.

    Raises `ValidationError` on anything that is not parseable nmap XML — including an
    empty document, which is what a crashed or killed nmap tends to leave behind. Silently
    returning "no ports found" for that would be indistinguishable from a clean scan of a
    quiet host, which is exactly the failure mode this refuses to have.
    """
    if not xml_text.strip():
        raise ValidationError("nmap produced no XML output")

    try:
        root = fromstring(xml_text)
    except (ParseError, DefusedXmlException, ValueError) as exc:
        raise ValidationError(f"nmap XML output could not be parsed: {exc}") from exc

    if root.tag != "nmaprun":
        raise ValidationError(f"unexpected root element in nmap output: {root.tag!r}")

    host = root.find("host")
    if host is None:
        # A well-formed run that reached no host: nmap says so in runstats. That is a
        # result ("nothing there"), not a parse failure.
        return ParsedScan(False, [], None, None, None, _runstats_time(root))

    status = host.find("status")
    host_up = status is not None and status.get("state") == "up"

    return ParsedScan(
        host_up=host_up,
        ports=_parse_ports(host),
        mac=_address_of(host, "mac"),
        vendor=_vendor_of(host),
        hostname=_hostname_of(host),
        observed_at=_host_time(host) or _runstats_time(root),
    )


def _parse_ports(host: Element) -> list[ParsedPort]:
    ports: list[ParsedPort] = []
    container = host.find("ports")
    if container is None:
        return ports

    for element in container.findall("port"):
        state = element.find("state")
        if state is None or state.get("state") != "open":
            continue

        portid = _int_or_none(element.get("portid"))
        protocol = element.get("protocol")
        if portid is None or not 1 <= portid <= 65535 or protocol not in ("tcp", "udp"):
            continue  # not something we are willing to record

        service = element.find("service")
        ports.append(
            ParsedPort(
                port=portid,
                protocol=protocol,
                service=_clean(service.get("name")) if service is not None else None,
                product=_clean(service.get("product")) if service is not None else None,
                version=_clean(service.get("version")) if service is not None else None,
                confidence=_service_confidence(service),
            )
        )
    return ports


def _service_confidence(service: Element | None) -> float:
    """nmap's own 1–10 certainty, carried through as 0.1–1.0."""
    if service is None:
        return _DEFAULT_SERVICE_CONFIDENCE
    conf = _int_or_none(service.get("conf"))
    if conf is None or not 0 < conf <= 10:
        return _DEFAULT_SERVICE_CONFIDENCE
    return round(conf / 10, 2)


def _identity_payload(parsed: ParsedScan, address: str) -> dict[str, Any]:
    payload: dict[str, Any] = {"ip": address}
    if parsed.mac is not None:
        payload["mac"] = parsed.mac
    if parsed.vendor is not None:
        payload["mac_vendor"] = parsed.vendor
    if parsed.hostname is not None:
        payload["hostname"] = parsed.hostname
    return payload


def _anchors_of(parsed: ParsedScan) -> list[AnchorObservation]:
    """A MAC seen on the same segment is a strong anchor; a PTR hostname is a locator."""
    anchors: list[AnchorObservation] = []
    if parsed.mac is not None:
        anchors.append(
            AnchorObservation(kind="mac", value=parsed.mac, confidence=_PORT_STATE_CONFIDENCE)
        )
    if parsed.hostname is not None:
        anchors.append(AnchorObservation(kind="hostname", value=parsed.hostname, confidence=0.5))
    return anchors


def _address_of(host: Element, addrtype: str) -> str | None:
    for element in host.findall("address"):
        if element.get("addrtype") == addrtype:
            value = _clean(element.get("addr"))
            return value.lower() if value else None
    return None


def _vendor_of(host: Element) -> str | None:
    for element in host.findall("address"):
        if element.get("addrtype") == "mac":
            return _clean(element.get("vendor"))
    return None


def _hostname_of(host: Element) -> str | None:
    hostnames = host.find("hostnames")
    if hostnames is None:
        return None
    for element in hostnames.findall("hostname"):
        name = _clean(element.get("name"))
        if name:
            return name
    return None


def _host_time(host: Element) -> datetime | None:
    return _epoch_or_none(host.get("endtime")) or _epoch_or_none(host.get("starttime"))


def _runstats_time(root: Element) -> datetime | None:
    finished = root.find("./runstats/finished")
    if finished is None:
        return None
    return _epoch_or_none(finished.get("time"))


def _epoch_or_none(value: str | None) -> datetime | None:
    """nmap stamps epoch seconds; we store UTC-aware datetimes and never a naive one."""
    seconds = _int_or_none(value)
    if seconds is None or seconds <= 0:
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _int_or_none(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


#: Long enough to be useful in a log line, short enough that a device cannot use a banner
#: to flood one. Control characters go: this text came from an untrusted device.
_MAX_FIELD_LENGTH: Final = 200


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = "".join(char for char in value if char.isprintable()).strip()
    return stripped[:_MAX_FIELD_LENGTH] or None


def _short(text: str | None, limit: int = 300) -> str:
    return (_clean(text) or "")[:limit] if text else ""


#: Exported for tests that want to assert the mapping without importing internals.
PROFILE_FLAGS: Final[Mapping[ScanProfile, tuple[str, ...]]] = {
    ScanProfile.GENTLE: _GENTLE_FLAGS,
    ScanProfile.STANDARD: _STANDARD_FLAGS,
}
