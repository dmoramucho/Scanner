"""The demo seeder's gate: what it lets through, and everything it does not.

These tests are the reason the guard is its own module. The seeder writes fabricated findings,
and a fabricated finding in a real estate is indistinguishable from a real one once it is a
row — so the interesting assertions here are all *refusals*, and each one names a way an
operator could plausibly end up pointed at the wrong database.
"""

from __future__ import annotations

import inspect

import pytest

from tools.demo.guard import ALLOW_REMOTE_VAR, ENV_VAR, SeedRefusedError, require_dev_environment

DEV_ENV = {ENV_VAR: "dev"}


def test_dev_environment_is_allowed() -> None:
    """The one case that proceeds. Without this the suite would pass on a guard that
    refuses everything, which is safe and useless."""
    require_dev_environment(DEV_ENV)


@pytest.mark.parametrize(
    ("value", "why"),
    [
        ("prod", "the obvious one"),
        ("staging", "shared, real data, and not dev"),
        ("", "set to empty — a half-written .env"),
        ("dev ", "trailing whitespace is stripped, so this one actually passes on strip"),
        ("Dev", "case differs; the check is exact rather than forgiving"),
        ("development", "a reasonable synonym that is still not the configured value"),
    ],
)
def test_refuses_every_environment_but_dev(value: str, why: str) -> None:
    """Deny-by-default: the guard names the one value it accepts, not the ones it rejects.

    `"dev "` is in this list deliberately — it is stripped and therefore *allowed*, and the
    parametrisation records that as a decision rather than leaving it to be discovered.
    """
    env = {ENV_VAR: value}
    if value.strip() == "dev":
        require_dev_environment(env)
        return
    with pytest.raises(SeedRefusedError, match=ENV_VAR):
        require_dev_environment(env)


def test_refuses_when_the_variable_is_absent() -> None:
    """Unset is not permission. An empty mapping must fail closed, not fall through."""
    with pytest.raises(SeedRefusedError, match="unset"):
        require_dev_environment({})


def test_refuses_a_dev_environment_that_is_exposed() -> None:
    """The second, independent check.

    `SCANNER_ENV=dev` is a label a copied `.env` carries with it. `SCANNER_API_ALLOW_REMOTE=1`
    is set only by someone who deliberately exposed this deployment beyond loopback, and a
    reachable deployment must not be filled with fiction however it is labelled.
    """
    with pytest.raises(SeedRefusedError, match=ALLOW_REMOTE_VAR):
        require_dev_environment({ENV_VAR: "dev", ALLOW_REMOTE_VAR: "1"})


def test_allows_dev_when_remote_access_is_explicitly_off() -> None:
    """`0` and absent both mean loopback-only, and neither should block the seeder."""
    require_dev_environment({ENV_VAR: "dev", ALLOW_REMOTE_VAR: "0"})
    require_dev_environment({ENV_VAR: "dev", ALLOW_REMOTE_VAR: ""})


def test_the_guard_signals_by_raising_rather_than_by_returning() -> None:
    """A guard that returns a boolean is one a caller can forget to check.

    Asserted on the annotation rather than on a call, because the failure this prevents is a
    future refactor "simplifying" it into `-> bool` while every existing call site keeps
    compiling and silently becomes a no-op. `assert f(...) is None` would not catch that —
    mypy rightly rejects it as a comparison that can only ever be true.
    """
    assert inspect.signature(require_dev_environment).return_annotation in (None, "None")
