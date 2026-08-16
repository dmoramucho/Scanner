"""${message}

Write the DDL by hand as raw SQL via `op.execute(""\"...""\")`, mirroring
`docs/data/data-model.md`. There are no SQLAlchemy models: `--autogenerate` is not a
supported workflow in this repo (ADR-0001).

`downgrade()` must be a real rollback path, in reverse dependency order — the database is
never reset to repair a migration (AGENTS.md §5).

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = ${repr(up_revision)}
down_revision: str | None = ${repr(down_revision)}
branch_labels: str | Sequence[str] | None = ${repr(branch_labels)}
depends_on: str | Sequence[str] | None = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "raise NotImplementedError"}


def downgrade() -> None:
    ${downgrades if downgrades else "raise NotImplementedError"}
