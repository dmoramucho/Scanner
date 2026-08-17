"""Operator-facing tooling. Never imported by `api/` or `engine/`.

Nothing under `tools/` is part of the running system. It is where things an operator runs
*at* the system live — and keeping them out of the import graph of the things that serve
traffic is what stops a development convenience from becoming a production capability
(AGENTS.md §2.1). `tests/test_tooling_boundary.py` enforces the direction.
"""

from __future__ import annotations

from collections.abc import Sequence

__all__: Sequence[str] = []
