"""The application object, and the shape of the boundary it sits on.

`create_app()` wires four things and nothing else: configuration loaded once at startup, the
loopback gate, the error handlers, and the read routes. Everything security-relevant is a
dependency rather than something a handler remembers to call, because a rule that has to be
remembered in each of N places is a rule that survives N−1 refactors.

**Run it on loopback.** Authentication is deferred (m4-design §5), so this API has none:

    uvicorn api.app:app --host 127.0.0.1 --port 8000

The app refuses non-loopback callers by default regardless of what it is bound to, so a
mistake in a deployment command is not a disclosure. `SCANNER_API_ALLOW_REMOTE=1` turns that
off, and must not be set until there is a real auth story — which is a gate, not a to-do
(ADR-0016).
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from fastapi import Depends, FastAPI

from api import errors, routes
from api.security import configured, require_local_client
from config.settings import AppConfig

TITLE = "Corporate Asset Scanner API"
VERSION = "0.1.0"

DESCRIPTION = """\
Read-only backend-for-frontend for the analyst UI.

Every endpoint is scoped to the configured tenant; the tenant cannot be selected by a
caller. Asset facts are served from the redacted dossier (allowlist, fail-closed). There is
no authentication yet — the API answers loopback clients only.
"""


def create_app(config: AppConfig | None = None) -> FastAPI:
    """Build the app. Pass `config` in tests; production loads and validates it here."""
    settings = config if config is not None else configured()

    app = FastAPI(
        title=TITLE,
        version=VERSION,
        description=DESCRIPTION,
        # The loopback gate is a router-level dependency rather than middleware so it runs
        # for every route that exists now and every route added later, without anyone
        # remembering to add it (m4-design §1).
        dependencies=[Depends(require_local_client)],
        # No docs in a deployment: an unauthenticated schema browser is a map of the
        # attack surface. Enabled explicitly in dev by an operator who wants it.
        docs_url="/docs" if settings.environment == "dev" else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.environment == "dev" else None,
    )
    app.state.config = settings

    errors.install(app)
    for router in routes.routers():
        app.include_router(router)

    @app.get("/health", include_in_schema=False)
    def health() -> dict[str, Any]:
        """Liveness only. Deliberately says nothing about the estate, the database, the
        tenant or the version of anything — a health check is not a reconnaissance tool."""
        return {"status": "ok"}

    return app


__all__: Sequence[str] = ["DESCRIPTION", "TITLE", "VERSION", "create_app"]
