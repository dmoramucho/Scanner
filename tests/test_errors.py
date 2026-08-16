"""The error contract (ports.md §1). `DependencyError.retryable` is the one distinction
that drives retry behaviour, so it is the one worth a test at P1."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from domain.errors import (
    ConflictError,
    DependencyError,
    DomainError,
    GroundingError,
    NotFoundError,
    ScopeViolation,
    SecretAccessError,
    ValidationError,
)


@pytest.mark.parametrize(
    "error_type",
    [
        ValidationError,
        NotFoundError,
        ConflictError,
        ScopeViolation,
        GroundingError,
        SecretAccessError,
        DependencyError,
    ],
)
def test_every_error_is_a_domain_error(error_type: type[DomainError]) -> None:
    """A single `except DomainError` at a boundary must catch all of them."""
    assert issubclass(error_type, DomainError)
    assert issubclass(error_type, Exception)


def test_dependency_error_carries_retryable_true() -> None:
    err = DependencyError("NVD timed out", retryable=True)
    assert err.retryable is True
    assert str(err) == "NVD timed out"


def test_dependency_error_carries_retryable_false() -> None:
    err = DependencyError("advisory 404", retryable=False)
    assert err.retryable is False


#: An untyped view of the constructor. These two tests assert the *runtime* signature,
#: so the call has to get past the type checker — and a `type: ignore` would be the
#: wrong tool: mypy 1.x reports this as [misc], 2.x as [call-arg], so whichever code we
#: pin becomes an "unused ignore" error under the other version.
_unchecked: Callable[..., DependencyError] = DependencyError


def test_retryable_is_keyword_only() -> None:
    """Positional use would make `retryable` easy to invert by accident at a call site."""
    with pytest.raises(TypeError):
        _unchecked("boom", True)


def test_dependency_error_requires_retryable() -> None:
    """No default: the caller must decide whether a failure is temporary."""
    with pytest.raises(TypeError):
        _unchecked("boom")


def test_dependency_error_is_raisable_and_catchable_as_domain_error() -> None:
    with pytest.raises(DomainError) as exc_info:
        raise DependencyError("vault unreachable", retryable=True)
    caught = exc_info.value
    assert isinstance(caught, DependencyError)
    assert caught.retryable is True
