"""The `Secret` primitive.

Source of truth: `docs/architecture/ports.md` §2. `SecretsPort` returns this, not a
bare `str`: its `repr`/`str` redact, so a secret can never land in a log line, a stack
trace, or a dossier by accident (AGENTS.md §2.10). The raw value is reachable only
through an explicit `reveal()` — which greppably marks every place a secret is used.
"""

from __future__ import annotations


class Secret:
    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        """The ONLY path to the raw value. Never pass the result to a logger or an LLM."""
        return self._value

    def __repr__(self) -> str:
        return "Secret(***redacted***)"

    __str__ = __repr__
