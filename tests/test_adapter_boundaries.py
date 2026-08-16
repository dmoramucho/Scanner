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
SCANNER_ROOT = REPO_ROOT / "adapters" / "scanner"
FEED_ROOT = REPO_ROOT / "adapters" / "feed"

#: Importing any of these from the collector would break a stated guarantee, whatever the
#: intent: the first three reach the outside world, the rest reach the store.
FORBIDDEN_IN_COLLECTOR = frozenset(
    {"socket", "subprocess", "asyncio", "http", "urllib", "ftplib", "telnetlib", "psycopg"}
)

ALLOWED_ROOTS = frozenset(sys.stdlib_module_names) | {"domain", "adapters"}

COLLECTOR_MODULES = sorted(COLLECTOR_ROOT.rglob("*.py"))
SCANNER_MODULES = sorted(SCANNER_ROOT.rglob("*.py"))
FEED_MODULES = sorted(FEED_ROOT.rglob("*.py"))

#: Half A's deterministic core: the correlator and the version arithmetic under it. The
#: safety assertion m3-design §4 asks for covers the whole path, not only the feed.
CORRELATION_MODULES = [
    REPO_ROOT / "engine" / "correlation.py",
    REPO_ROOT / "engine" / "cpe.py",
]

#: Half A of M3 is deterministic by construction (m3-design §1). A model's CVE knowledge is
#: stale and hallucinated CVE ids are its most characteristic failure (AGENTS.md §4.8), so
#: the feed must never acquire one — not even "just to summarise a description".
MODEL_PACKAGES = frozenset(
    {
        "openai",
        "anthropic",
        "transformers",
        "torch",
        "llama_cpp",
        "ollama",
        "langchain",
        "sentence_transformers",
        "google",
        "cohere",
        "mistralai",
    }
)


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


@pytest.mark.parametrize("module_path", SCANNER_MODULES, ids=lambda p: p.name)
def test_the_scanner_adapter_stays_out_of_the_store(module_path: Path) -> None:
    """The scanner legitimately runs a subprocess — that is its job. It has no business
    touching the database: an adapter that both emits packets and writes rows is two
    responsibilities and one place for a scope check to be skipped."""
    imported = {root for root, _ in imported_roots(module_path)}

    assert "psycopg" not in imported
    assert "adapters.postgres" not in module_path.read_text(encoding="utf-8")


@pytest.mark.parametrize("module_path", SCANNER_MODULES, ids=lambda p: p.name)
def test_the_scanner_never_reaches_for_a_shell(module_path: Path) -> None:
    """`os.system`, `subprocess` with `shell=True`, and `popen` all reintroduce the shell
    the argv-based invocation exists to avoid (AGENTS.md §2.9)."""
    source = module_path.read_text(encoding="utf-8")

    assert "shell=True" not in source
    assert "os.system" not in source
    assert "os.popen" not in source


@pytest.mark.parametrize("module_path", FEED_MODULES, ids=lambda p: p.name)
def test_the_vulnerability_feed_imports_no_model(module_path: Path) -> None:
    """The safety assertion m3-design §4 asks for: no code path in Half A can produce a CVE
    from anything but the deterministic feed. An LLM client in this package would be the
    way that stops being true."""
    imported = {root for root, _ in imported_roots(module_path)}

    assert imported & MODEL_PACKAGES == set()


@pytest.mark.parametrize("module_path", FEED_MODULES, ids=lambda p: p.name)
def test_the_vulnerability_feed_stays_out_of_the_store(module_path: Path) -> None:
    """The feed fetches; the cache persists. Keeping psycopg out of here is what makes the
    NVD adapter testable without a database, and what keeps one class from being both the
    thing that talks to the internet and the thing that writes rows."""
    imported = {root for root, _ in imported_roots(module_path)}

    assert "psycopg" not in imported
    assert "adapters.postgres" not in module_path.read_text(encoding="utf-8")


@pytest.mark.parametrize("module_path", CORRELATION_MODULES, ids=lambda p: p.name)
def test_the_correlator_imports_no_model(module_path: Path) -> None:
    """No code path in Half A produces a match from anything but the deterministic feed
    (m3-design §1, §4). A model here could decide that a vulnerability exists, which is the
    one thing this architecture is built to make impossible (AGENTS.md §2.8, §4.8)."""
    imported = {root for root, _ in imported_roots(module_path)}

    assert imported & MODEL_PACKAGES == set()


@pytest.mark.parametrize("module_path", CORRELATION_MODULES, ids=lambda p: p.name)
def test_the_correlator_depends_on_ports_not_adapters(module_path: Path) -> None:
    """The engine names no adapter: it takes `VulnerabilityFeed`, `KevSource`, `EpssSource`
    and `VulnerabilityMatchStore`, and would work the same over a different feed."""
    source = module_path.read_text(encoding="utf-8")

    assert "adapters" not in source
    assert "psycopg" not in source
