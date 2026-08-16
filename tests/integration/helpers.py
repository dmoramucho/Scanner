"""Shared plumbing for the integration tests: DSN surgery and the Alembic CLI.

Kept out of `conftest.py` so both the fixtures and the migration-cycle tests can import
it without importing a conftest module directly.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

REPO_ROOT = Path(__file__).resolve().parents[2]

MAINTENANCE_DBNAME = "postgres"


def dbname_of(url: str) -> str:
    return urlsplit(url).path.lstrip("/")


def with_dbname(url: str, dbname: str) -> str:
    """The same server and credentials, a different database.

    URI surgery rather than a parse-and-rebuild through libpq keyword form: the DSN has to
    survive the round trip into `migrations/env.py`, which takes a `postgresql://` URI (the
    one canonical form, per .env.example) and hands it to SQLAlchemy. Editing only the path
    also leaves an already percent-encoded password untouched.
    """
    return urlunsplit(urlsplit(url)._replace(path=f"/{dbname}"))


def maintenance_dsn(url: str) -> str:
    """Connected to a database we are not about to drop."""
    return with_dbname(url, MAINTENANCE_DBNAME)


def alembic(*args: str, url: str) -> subprocess.CompletedProcess[str]:
    """Run the Alembic CLI against `url`, the way an operator would.

    A subprocess rather than the Python API on purpose: it exercises `alembic.ini`,
    `migrations/env.py`, and the config-driven URL lookup — the parts an in-process call
    would bypass. The URL is passed as `SCANNER_DATABASE_URL` because that is the only
    input `env.py` accepts; there is no way to point a migration somewhere the application
    could not itself be pointed.
    """
    return subprocess.run(  # noqa: S603 — fixed argv, no shell, URL passed via the environment
        [sys.executable, "-m", "alembic", *args],
        cwd=REPO_ROOT,
        env={**os.environ, "SCANNER_DATABASE_URL": url},
        capture_output=True,
        text=True,
        check=False,
    )
