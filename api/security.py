"""The API's security boundary: who is asking, which tenant they get, and what they may see.

Until P18 this platform ran unexposed — code an operator executed. An HTTP listener puts
everything M0–M3 protected behind a new front door, so this module is written with the same
care as the scope gate, and for the same reason: it is the one place where an outsider's
input meets the estate's data (m4-design §1).

Three rules, and none of them trust the caller:

**The tenant comes from the server, never from the request.** `tenant_context()` reads the
tenant from configuration. There is no header, query parameter or body field that can select
one, so tenant scoping cannot be bypassed by asking nicely — the usual failure mode of an
`X-Tenant-Id` header on an unauthenticated API. When authentication lands, this function is
where the tenant starts coming from the session instead; nothing above it changes.

**Non-loopback callers are refused.** Authentication is deferred (m4-design §5), which means
anything that can reach this API is authenticated by nothing at all. So the API answers
loopback only, unless an operator explicitly sets `SCANNER_API_ALLOW_REMOTE=1`. That turns
"do not expose this beyond localhost" from a sentence in a README into behaviour: bind it to
`0.0.0.0` by mistake and remote clients still get a 403.

**Read paths are read-only at the database.** Every read request runs on a connection with
`read_only = True`, so Postgres refuses a mutation on it and a bug cannot become one. P19
adds exactly one write endpoint, and it takes a *separate* writable connection
(`write_connection`) — the capability is granted to one route rather than to the app, so
widening it is a visible change to a dependency rather than an invisible consequence of
adding a handler (ADR-0017).

**The reviewer is server-side, like the tenant.** With no authentication, a caller-supplied
name in an immutable audit trail is worse than a placeholder that says what it is: anyone
could write a colleague's name into the review history. `reviewer_context()` is the other
half of the auth seam, and it starts returning the authenticated principal at the same
moment `tenant_context()` does.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from ipaddress import ip_address
from typing import Annotated, Final
from uuid import UUID

import psycopg
from fastapi import Depends, HTTPException, Request, status

from adapters.postgres.read_model import PostgresReadModel
from adapters.postgres.triage_store import PostgresDossierSource, PostgresTriageStore
from config.settings import AppConfig, ConfigError, load_config
from engine.dossier import DossierAssembler

#: Addresses a request may arrive from while authentication is deferred. A unix socket has
#: no peer address and is loopback by construction, so an empty client is allowed too.
_LOOPBACK_HOSTS: Final = frozenset({"127.0.0.1", "::1", "localhost", "testclient", ""})


def app_config(request: Request) -> AppConfig:
    """The configuration this app was created with.

    Loaded once at startup and stashed on the app, rather than re-read per request: config
    that can change between two requests in the same run is config nobody can reason about.
    """
    config = getattr(request.app.state, "config", None)
    if not isinstance(config, AppConfig):  # pragma: no cover — set in `create_app`
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="service not configured"
        )
    return config


def require_local_client(
    request: Request, config: Annotated[AppConfig, Depends(app_config)]
) -> None:
    """Refuse a request from anywhere but this machine, unless explicitly permitted.

    The gate that stands in for authentication, and it is deliberately blunt. It is not a
    substitute for auth — it is the smallest honest guard for an API that has none, and it
    is removed by an operator who has read what they are turning off (m4-design §5).
    """
    if config.api_allow_remote:
        return
    host = request.client.host if request.client is not None else ""
    if not _is_loopback(host):
        # No detail about what would have been served, and no hint that the address is the
        # reason: a rejected caller learns nothing about the estate behind this.
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")


def tenant_context(config: Annotated[AppConfig, Depends(app_config)]) -> UUID:
    """The tenant every query in this request is scoped to.

    **The auth seam.** Today it is a configured value — a placeholder, and marked as one.
    When sessions exist, the tenant will be derived from the authenticated principal here,
    and every endpoint keeps working unchanged because none of them accept a tenant from the
    caller (m4-design §1, §5).
    """
    if config.tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="service not configured",
        )
    return config.tenant_id


def read_connection(
    config: Annotated[AppConfig, Depends(app_config)],
) -> Iterator[psycopg.Connection[tuple[object, ...]]]:
    """One read-only connection per request, closed when it ends.

    `read_only` is set on the connection, so the *database* refuses a write on this path
    rather than the API promising not to attempt one. P19 adds the single write endpoint
    with its own connection, deliberately and visibly.
    """
    with psycopg.connect(config.database_url.reveal()) as conn:
        conn.read_only = True
        yield conn


def write_connection(
    config: Annotated[AppConfig, Depends(app_config)],
) -> Iterator[psycopg.Connection[tuple[object, ...]]]:
    """A writable connection, for the one route that writes.

    Deliberately not the default. P19 adds a single write — the analyst's review decision —
    and giving that route its own connection keeps "this endpoint can mutate the estate" a
    thing you can see in a signature rather than a property of the whole app. Committed on a
    clean return, rolled back on any exception, by psycopg's context manager.
    """
    with psycopg.connect(config.database_url.reveal()) as conn:
        yield conn


def reviewer_context(config: Annotated[AppConfig, Depends(app_config)]) -> str:
    """Who a review is recorded as.

    **The auth seam, second half.** Today it is a configured placeholder — `local-operator`
    by default — and it is deliberately *not* taken from the request body: on an
    unauthenticated API that would let any caller attribute a decision to a named colleague,
    in an append-only history that cannot be corrected (m4-design §5, ADR-0017).
    """
    reviewer = config.api_reviewer.strip()
    if not reviewer:  # pragma: no cover — config supplies a default
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="unavailable")
    return reviewer


def review_store(
    conn: Annotated[psycopg.Connection[tuple[object, ...]], Depends(write_connection)],
) -> PostgresTriageStore:
    """The only write-capable store the API exposes."""
    return PostgresTriageStore(conn)


def read_model(
    conn: Annotated[psycopg.Connection[tuple[object, ...]], Depends(read_connection)],
) -> PostgresReadModel:
    return PostgresReadModel(conn)


def dossier_assembler(
    conn: Annotated[psycopg.Connection[tuple[object, ...]], Depends(read_connection)],
    config: Annotated[AppConfig, Depends(app_config)],
) -> DossierAssembler:
    """The assembler the API serves asset facts through.

    This is how the redaction contract reaches HTTP: an asset's own facts are *only* ever
    read as a redacted `AssetDossier` (allowlist, then a refusal sweep — dossier contract §4,
    ADR-0014). There is no second path that reads observation payloads and shapes them into
    a response.
    """
    return DossierAssembler(PostgresDossierSource(conn), segments=config.vlan_map)


def configured() -> AppConfig:
    """Load configuration for `create_app`, failing loudly rather than starting half-set-up."""
    config = load_config()
    if config.tenant_id is None:
        raise ConfigError(
            "SCANNER_TENANT_ID is required to serve the API: every query is tenant-scoped, "
            "and the tenant is server-side configuration rather than something a request "
            "may choose (see .env.example)."
        )
    return config


def _is_loopback(host: str) -> bool:
    candidate = host.strip().lower()
    if candidate in _LOOPBACK_HOSTS:
        return True
    try:
        return ip_address(candidate).is_loopback
    except ValueError:
        return False


TenantId = Annotated[UUID, Depends(tenant_context)]
Reviewer = Annotated[str, Depends(reviewer_context)]
ReviewStore = Annotated[PostgresTriageStore, Depends(review_store)]
Reads = Annotated[PostgresReadModel, Depends(read_model)]
Dossiers = Annotated[DossierAssembler, Depends(dossier_assembler)]

__all__: Sequence[str] = [
    "Dossiers",
    "Reads",
    "ReviewStore",
    "Reviewer",
    "TenantId",
    "app_config",
    "configured",
    "dossier_assembler",
    "read_connection",
    "read_model",
    "require_local_client",
    "review_store",
    "reviewer_context",
    "tenant_context",
    "write_connection",
]
