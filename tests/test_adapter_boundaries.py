"""Boundaries inside `adapters/`, enforced the same way the domain boundary is.

Two properties that are easy to state and easy to erode:

1. **The collector is read-only against target infrastructure** (AGENTS.md §2.4). It is,
   today, because it only ever parses text handed to it — no sockets, no subprocesses, no
   files. That is a much stronger guarantee than "we intend not to write", and it is worth
   a test that fails the moment someone imports `socket` to add "just a quick ping".
2. **The collector is separable** (P3: structure it so the outbound/mTLS boundary can be
   drawn later). It must not reach for the database or any other adapter package.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
COLLECTOR_ROOT = REPO_ROOT / "adapters" / "collector"

#: Importing any of these from the collector would break a stated guarantee, whatever the
#: intent: the first three reach the outside world, the rest reach the store.
FORBIDDEN_IN_COLLECTOR = frozenset(
    {"socket", "subprocess", "asyncio", "http", "urllib", "ftplib", "telnetlib", "psycopg"}
)

ALLOWED_ROOTS = frozenset(sys.stdlib_module_names) | {"domain", "adapters"}

COLLECTOR_MODULES = sorted(COLLECTOR_ROOT.rglob("*.py"))


def imported_roots(module_path: Path) -> list[tuple[str, int]]:
    tree = ast.parse(module_path.read_text(encoding="utf-8"), filename=str(module_path))
    roots: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.extend((alias.name.split(".")[0], node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.append((node.module.split(".")[0], node.lineno))
    return roots


def test_collector_modules_are_discovered() -> None:
    assert COLLECTOR_MODULES, f"no collector modules found under {COLLECTOR_ROOT}"


@pytest.mark.parametrize("module_path", COLLECTOR_MODULES, ids=lambda p: p.name)
def test_collector_cannot_reach_the_network_or_the_store(module_path: Path) -> None:
    offenders = [
        f"{module_path.relative_to(REPO_ROOT)}:{lineno} imports {root!r}"
        for root, lineno in imported_roots(module_path)
        if root in FORBIDDEN_IN_COLLECTOR
    ]
    assert not offenders, (
        "the passive collector is read-only and store-free by construction "
        "(AGENTS.md §2.4): " + "; ".join(offenders)
    )


@pytest.mark.parametrize("module_path", COLLECTOR_MODULES, ids=lambda p: p.name)
def test_collector_imports_only_stdlib_domain_and_itself(module_path: Path) -> None:
    offenders = [
        f"{module_path.relative_to(REPO_ROOT)}:{lineno} imports {root!r}"
        for root, lineno in imported_roots(module_path)
        if root not in ALLOWED_ROOTS
    ]
    assert not offenders, "collector dependencies must stay extractable: " + "; ".join(offenders)


@pytest.mark.parametrize("module_path", COLLECTOR_MODULES, ids=lambda p: p.name)
def test_collector_does_not_import_the_postgres_adapters(module_path: Path) -> None:
    """`adapters` is allowed as a root (the collector imports its own modules); this
    pins down that the allowance is not a doorway to the store."""
    source = module_path.read_text(encoding="utf-8")

    assert "adapters.postgres" not in source
