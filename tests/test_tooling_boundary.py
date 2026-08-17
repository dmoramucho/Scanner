"""`tools/` may import the system; the system may never import `tools/` (AGENTS.md §2.1).

The direction is the whole point. `tools/demo/` fabricates assets, findings and AI proposals,
and it is allowed to — it is an operator's script, run deliberately, behind a dev-only gate.
What must never happen is a module that serves traffic gaining a path to it, because then
"seed the demo estate" stops being something an operator does and becomes something the
application *can do*, one refactor away from doing it somewhere real.

`tools/__init__.py` claims this boundary in prose. This test is what makes the claim true.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

#: Everything that is part of the running system. A `tools` import in any of these is a bug.
SHIPPED_PACKAGES = ("api", "domain", "adapters", "engine", "config")

SHIPPED_MODULES = sorted(
    path
    for package in SHIPPED_PACKAGES
    for path in (REPO_ROOT / package).rglob("*.py")
    if "__pycache__" not in path.parts
)

TOOLS_ROOT = REPO_ROOT / "tools"
TOOLS_MODULES = sorted(path for path in TOOLS_ROOT.rglob("*.py") if "__pycache__" not in path.parts)

#: What `tools/` is allowed to reach for. It sits outside the system and may use all of it,
#: plus psycopg to open its own connections — but *not* `tests`, which would make a fixture
#: for the demo estate and a fixture for the test suite the same object and let a change to
#: one silently rewrite the other.
TOOLS_ALLOWED = (
    frozenset(sys.stdlib_module_names)
    | frozenset(SHIPPED_PACKAGES)
    | frozenset({"tools", "psycopg", "pydantic"})
)


#: Spelled out for the failure message; the stdlib half is too long to be useful there.
_NON_STDLIB_ALLOWED = TOOLS_ALLOWED - frozenset(sys.stdlib_module_names)


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


def test_shipped_modules_are_discovered() -> None:
    """Guard against the scan passing because it found nothing to scan."""
    assert SHIPPED_MODULES, "no shipped modules found; the boundary test is scanning nothing"
    assert TOOLS_MODULES, f"no tooling modules found under {TOOLS_ROOT}"


@pytest.mark.parametrize("module_path", SHIPPED_MODULES, ids=lambda p: p.name)
def test_shipped_code_never_imports_tools(module_path: Path) -> None:
    """No module that serves traffic may reach the demo seeder."""
    offenders = [
        f"{module_path.relative_to(REPO_ROOT)}:{lineno} imports 'tools'"
        for root, lineno in _imported_roots(module_path)
        if root == "tools"
    ]
    assert not offenders, (
        "shipped code imports tooling:\n  "
        + "\n  ".join(offenders)
        + "\ntools/ fabricates data behind a dev-only gate. Nothing that serves traffic may "
        "be able to call it."
    )


@pytest.mark.parametrize("module_path", TOOLS_MODULES, ids=lambda p: p.name)
def test_tools_never_imports_tests(module_path: Path) -> None:
    """The seeder owns its fixtures. Sharing them with the suite couples the two."""
    offenders = [
        f"{module_path.relative_to(REPO_ROOT)}:{lineno} imports {root!r}"
        for root, lineno in _imported_roots(module_path)
        if root not in TOOLS_ALLOWED
    ]
    assert not offenders, (
        "tooling imports something it should not:\n  "
        + "\n  ".join(offenders)
        + f"\nallowed roots: stdlib, {', '.join(sorted(_NON_STDLIB_ALLOWED))}"
    )
