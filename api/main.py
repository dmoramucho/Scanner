"""The server entrypoint: `uvicorn api.main:app --host 127.0.0.1 --port 8000`.

Separate from `api.app` on purpose. Importing *this* module loads and validates
configuration, which is what a server should do at startup and what a test should never be
forced to do — `api.app.create_app(config)` takes its configuration as an argument, so the
suite builds an app without a live environment (AGENTS.md §43).

**Bind it to loopback.** There is no authentication yet (m4-design §5). The app refuses
non-loopback callers regardless of what it is bound to, but the two together are the point:
the bind is the intent, the refusal is the guarantee.
"""

from __future__ import annotations

from collections.abc import Sequence

from api.app import create_app

app = create_app()

__all__: Sequence[str] = ["app"]
