"""`Secret` must be structurally unable to leak (ports.md §2, AGENTS.md §2.10)."""

from __future__ import annotations

import logging
import traceback
from collections.abc import Callable

import pytest

from domain.secret import Secret

RAW = "hunter2-correct-horse"


@pytest.fixture
def secret() -> Secret:
    return Secret(RAW)


def test_repr_redacts(secret: Secret) -> None:
    assert repr(secret) == "Secret(***redacted***)"
    assert RAW not in repr(secret)


def test_str_redacts(secret: Secret) -> None:
    assert str(secret) == "Secret(***redacted***)"
    assert RAW not in str(secret)


def test_reveal_is_the_only_path_to_the_value(secret: Secret) -> None:
    assert secret.reveal() == RAW


RENDERERS: list[Callable[[Secret], str]] = [
    lambda s: "{}".format(s),  # noqa: UP032 — str.format → __format__ → __str__
    lambda s: f"{s}",  # f-string
    lambda s: f"{s!r}",  # explicit repr conversion
    lambda s: "%s" % (s,),  # noqa: UP031 — printf-style
    lambda s: str([s]),  # nested in a container → repr of the element
    lambda s: str({"password": s}),
]


@pytest.mark.parametrize("render", RENDERERS)
def test_no_interpolation_form_leaks(secret: Secret, render: Callable[[Secret], str]) -> None:
    assert RAW not in render(secret)


def test_does_not_leak_through_logging(secret: Secret, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.INFO):
        logging.getLogger("scanner.test").info("connecting with %s", secret)
    assert RAW not in caplog.text
    assert "***redacted***" in caplog.text


def test_does_not_leak_through_a_traceback(secret: Secret) -> None:
    def blow_up(value: Secret) -> None:
        raise RuntimeError(f"failed with {value}")

    with pytest.raises(RuntimeError) as exc_info:
        blow_up(secret)

    rendered = "".join(traceback.format_exception(exc_info.value))
    assert RAW not in rendered
    assert "***redacted***" in rendered


def test_has_no_instance_dict(secret: Secret) -> None:
    """__slots__ keeps the value off any generic __dict__ dump."""
    assert not hasattr(secret, "__dict__")
