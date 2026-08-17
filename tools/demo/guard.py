"""The gate in front of the demo seeder, and the reason it is its own module.

The seeder writes fabricated assets, fabricated vulnerability matches and fabricated AI
proposals into whatever database it is pointed at. That is exactly what you want while
building the UI and exactly what must never happen anywhere else: an invented finding in a
real estate is worse than no finding at all, because it is indistinguishable from a real one
once it is a row.

So the gate is **deny-by-default and fail-closed**, the same shape as the scope gate
(AGENTS.md §2.5): the seeder does not ask "is this production?" and refuse when the answer is
yes — it asks "is this provably the local dev environment?" and refuses on anything else,
including an unset variable, a typo, and an environment name nobody has thought of yet.

**Two independent checks, not one.** `SCANNER_ENV` is a label an operator sets, so a single
copied `.env` defeats it. `SCANNER_API_ALLOW_REMOTE` is set only by someone who has exposed
this deployment beyond loopback (ADR-0016), and a reachable deployment is not one to fill
with fiction. Either check failing is a refusal. Two cheap, independent signals catch the
copied-config mistake that either alone would wave through.
"""

from __future__ import annotations

import os
from collections.abc import Mapping, Sequence
from typing import Final

#: The only environment the seeder will write to. Not a list, deliberately: every additional
#: permitted value is another place a real estate could hide.
DEV: Final = "dev"

ENV_VAR: Final = "SCANNER_ENV"
ALLOW_REMOTE_VAR: Final = "SCANNER_API_ALLOW_REMOTE"


class SeedRefusedError(Exception):
    """The seeder refused to run. Never caught inside the seeder — it ends the process."""


def require_dev_environment(env: Mapping[str, str] | None = None) -> None:
    """Refuse unless this is provably the local dev environment.

    `env` defaults to the real environment; passing a mapping keeps this testable without
    mutating the process, the same pattern `config.load_config` uses.

    Raises `SeedRefusedError` — never returns a boolean. A guard that returns a value is a guard
    a caller can forget to check, and this one is the only thing between a demo fixture and
    a production table.
    """
    source = os.environ if env is None else env

    environment = source.get(ENV_VAR, "").strip()
    if environment != DEV:
        raise SeedRefusedError(
            f"refusing to seed: {ENV_VAR} is {environment or '(unset)'!r}, and the demo "
            f"seeder writes fabricated assets, findings and AI proposals. It runs only "
            f"where {ENV_VAR}={DEV!r}. This is a gate, not a check to work around — if you "
            f"need demo data somewhere else, the answer is a separate database, not a "
            f"wider gate."
        )

    if source.get(ALLOW_REMOTE_VAR, "").strip() == "1":
        raise SeedRefusedError(
            f"refusing to seed: {ALLOW_REMOTE_VAR}=1 means this deployment is reachable "
            f"beyond loopback (ADR-0016). Fabricated findings do not belong in a database "
            f"something else can read. Unset it, or point the seeder at a local database."
        )


__all__: Sequence[str] = [
    "ALLOW_REMOTE_VAR",
    "DEV",
    "ENV_VAR",
    "SeedRefusedError",
    "require_dev_environment",
]
