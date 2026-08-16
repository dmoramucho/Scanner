"""The shared error hierarchy raised across port boundaries.

Source of truth: `docs/architecture/ports.md` §1. Pure domain — no infrastructure
imports (AGENTS.md §2.1). The one distinction that drives retry behaviour is
`DependencyError.retryable`.
"""

from __future__ import annotations


class DomainError(Exception):
    """Base for all domain-level errors."""


class ValidationError(DomainError):
    """Input failed validation at a boundary."""


class NotFoundError(DomainError):
    """A referenced entity does not exist."""


class ConflictError(DomainError):
    """A uniqueness/idempotency constraint was violated in a way the caller must handle."""


class ScopeViolation(DomainError):
    """A target fell outside authorized scope. Safety-critical — never swallowed."""


class GroundingError(DomainError):
    """An insight was produced without citations. Rejected before it can be persisted."""


class SecretAccessError(DomainError):
    """A secret could not be resolved."""


class DependencyError(DomainError):
    """An external dependency failed. `retryable` separates temporary from permanent."""

    def __init__(self, message: str, *, retryable: bool) -> None:
        super().__init__(message)
        self.retryable = retryable
