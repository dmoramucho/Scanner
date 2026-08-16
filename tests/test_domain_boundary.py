"""The `domain/` ↔ `adapters/` boundary, enforced mechanically (AGENTS.md §2.1).

Prose does not stop a DB driver from appearing in a model file six months from now; this
test does. It parses every module under `domain/` and rejects any import that is not
stdlib, pydantic, or `domain` itself. If a domain module ever *needs* an infrastructure
package, the abstraction is in the wrong layer (ports.md §9) — move it to `adapters/`
rather than widening the allowlist.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
DOMAIN_ROOT = REPO_ROOT / "domain"

#: pydantic is the one third-party package the domain may see: it is the validation
#: vocabulary the contracts are written in, not infrastructure.
ALLOWED_THIRD_PARTY = frozenset({"pydantic"})
ALLOWED_FIRST_PARTY = frozenset({"domain"})
ALLOWED_ROOTS = frozenset(sys.stdlib_module_names) | ALLOWED_THIRD_PARTY | ALLOWED_FIRST_PARTY

DOMAIN_MODULES = sorted(DOMAIN_ROOT.rglob("*.py"))


def _imported_roots(module_path: Path) -> list[tuple[str, int]]:
    """Every top-level package name imported by a module, with its line number."""
    tree = ast.parse(module_path.read_text(encoding="utf-8"), filename=str(module_path))
    roots: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.extend((alias.name.split(".")[0], node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.append((node.module.split(".")[0], node.lineno))
    return roots


def test_domain_modules_are_discovered() -> None:
    """Guard against the scan silently passing because it found nothing."""
    assert DOMAIN_MODULES, f"no domain modules found under {DOMAIN_ROOT}"


@pytest.mark.parametrize("module_path", DOMAIN_MODULES, ids=lambda p: p.name)
def test_domain_imports_no_infrastructure(module_path: Path) -> None:
    offenders = [
        f"{module_path.relative_to(REPO_ROOT)}:{lineno} imports {root!r}"
        for root, lineno in _imported_roots(module_path)
        if root not in ALLOWED_ROOTS
    ]
    assert not offenders, "domain/ must not import infrastructure (AGENTS.md §2.1): " + "; ".join(
        offenders
    )


@pytest.mark.parametrize("module_path", DOMAIN_MODULES, ids=lambda p: p.name)
def test_domain_does_not_import_adapters_or_engine(module_path: Path) -> None:
    """Dependencies point inward: adapters and the engine know the domain, never the
    reverse. (`adapters` and `engine` are not stdlib, so the test above already catches
    this — asserted separately because it is the failure mode most likely to be argued
    for as an exception.)"""
    forbidden = {"adapters", "engine", "config", "migrations"}
    imported = {root for root, _ in _imported_roots(module_path)}
    assert not (imported & forbidden), f"{module_path.name} imports {imported & forbidden}"
