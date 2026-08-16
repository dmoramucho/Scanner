"""Shared test setup.

The only thing that belongs here is making the local `.env` visible to the test process,
so `uv run pytest` works straight after `cp .env.example .env` without the caller having
to remember `set -a; . ./.env; set +a`. Nothing here invents configuration: values
already present in the environment always win, and a missing `.env` is not an error.
"""

from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_dotenv(path: Path) -> None:
    """Populate `os.environ` from a `KEY=value` file, without overriding what is set.

    A deliberately small parser for a developer convenience — it understands comments,
    blank lines, `export ` prefixes, and surrounding quotes. It does not understand
    multi-line values or a literal ` #` inside an unquoted value; quote the value if you
    need one. Production configuration comes from the real environment, not from here.
    """
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        line = line.removeprefix("export ").strip()
        key, separator, value = line.partition("=")
        if not separator:
            continue
        value = value.strip()
        if value[:1] in {"'", '"'} and value[-1:] == value[:1] and len(value) > 1:
            value = value[1:-1]
        else:
            value = value.split(" #")[0].rstrip()
        os.environ.setdefault(key.strip(), value)


_load_dotenv(REPO_ROOT / ".env")
