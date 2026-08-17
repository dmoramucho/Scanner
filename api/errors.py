"""Turning failures into responses that say what happened and nothing else.

An error response is an information disclosure channel — often the most productive one an
attacker has. So this module has one job on the way out: **a client learns the *kind* of
failure and an id to quote, never the machinery**. No stack trace, no exception class, no
SQL, no DSN, no filesystem path (AGENTS.md §2.10, m4-design §1).

The mapping itself is the domain's own vocabulary, which is why it is small: the error
hierarchy already distinguishes "you asked for something that does not exist" from "a
dependency is down", and that distinction is exactly what an HTTP status is for.

Every unhandled exception becomes a 500 with a generic body, and the real thing is logged
server-side under the same `request_id` the caller is given. That is the trade: the operator
can find the failure in the log; the caller cannot read it off the wire.
"""

from __future__ import annotations

import logging
import re
import uuid
from collections.abc import Awaitable, Callable, Sequence
from typing import Final

from fastapi import FastAPI, Request, Response, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from domain.errors import (
    ConflictError,
    DependencyError,
    DomainError,
    GroundingError,
    NotFoundError,
    ScopeViolation,
    SecretAccessError,
    ValidationError,
)
from engine.redaction import secret_shapes_in

logger: Final = logging.getLogger("api")

#: Starlette renamed this constant; the number is the contract and does not move.
HTTP_422: Final = 422

#: Any identifier in an outbound message is an internal one — the caller already knows the
#: ids they sent, and the rest are ours. Scrubbed rather than trusted to never appear.
_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)

#: Domain error → status. Ordered most specific first, because `DependencyError` and the
#: rest share a base class.
_STATUS: Final[tuple[tuple[type[DomainError], int, str], ...]] = (
    (NotFoundError, status.HTTP_404_NOT_FOUND, "not_found"),
    (ValidationError, HTTP_422, "invalid_request"),
    (ConflictError, status.HTTP_409_CONFLICT, "conflict"),
    (ScopeViolation, status.HTTP_403_FORBIDDEN, "forbidden"),
    (GroundingError, HTTP_422, "ungrounded"),
    # A credential failure is *never* described to a caller. That it happened is an
    # operational fact; what it was about is not (AGENTS.md §2.10).
    (SecretAccessError, status.HTTP_503_SERVICE_UNAVAILABLE, "unavailable"),
)

#: Detail text for the failures whose own message must never be forwarded.
_OPAQUE: Final = "the request could not be completed"

#: A constant, so "you asked for something in another tenant" and "you asked for something
#: nobody has" are the same sentence. A distinguishable 404 is a membership oracle over
#: every id in the estate (m4-design §1).
_NOT_FOUND: Final = "the requested resource was not found"


def install(app: FastAPI) -> None:
    """Attach the handlers and the request-id middleware."""

    @app.middleware("http")
    async def _request_id(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        request.state.request_id = uuid.uuid4().hex
        response = await call_next(request)
        response.headers["X-Request-Id"] = request.state.request_id
        return response

    @app.exception_handler(DomainError)
    async def _domain(request: Request, exc: Exception) -> JSONResponse:
        code, http_status, detail = _translate(exc)
        # Logged whole, server-side, with the id the caller was given: the operator can find
        # it, the caller cannot read it.
        logger.warning(
            "domain error on %s %s: %s", request.method, request.url.path, exc, exc_info=exc
        )
        return _response(request, http_status, code, detail)

    @app.exception_handler(RequestValidationError)
    async def _validation(request: Request, exc: Exception) -> JSONResponse:
        """Malformed input is a 422 that names the field and nothing else.

        FastAPI's own body includes the offending *input* by default; it is dropped here so
        a reflected value cannot carry anything back out (§68).
        """
        fields = []
        if isinstance(exc, RequestValidationError):
            fields = [
                ".".join(str(part) for part in error.get("loc", ())[1:]) for error in exc.errors()
            ]
        named = ", ".join(field for field in fields if field) or "request"
        return _response(
            request,
            HTTP_422,
            "invalid_request",
            f"invalid or unknown parameter: {named}",
        )

    # Registered on Starlette's base class, not FastAPI's subclass: an unmatched route and a
    # wrong method are raised by the router itself, and they must come back in the same
    # shape as everything else rather than in the framework's default body.
    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: Exception) -> JSONResponse:
        http_exc = exc if isinstance(exc, StarletteHTTPException) else None
        code = _http_code(http_exc.status_code if http_exc else 500)
        detail = str(http_exc.detail) if http_exc else _OPAQUE
        return _response(
            request,
            http_exc.status_code if http_exc else status.HTTP_500_INTERNAL_SERVER_ERROR,
            code,
            _safe(detail),
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        """Anything unanticipated — including a driver error carrying SQL in its message.

        The one rule that matters here: whatever this was, the caller is told nothing about
        it beyond an id. A psycopg error quotes the failing statement; a config error can
        quote a path; neither goes out.
        """
        logger.exception("unhandled error on %s %s", request.method, request.url.path)
        return _response(request, status.HTTP_500_INTERNAL_SERVER_ERROR, "internal_error", _OPAQUE)


def _translate(exc: Exception) -> tuple[str, int, str]:
    """The status, the machine code, and a detail that is safe to send."""
    if isinstance(exc, DependencyError):
        # Retryable means "ask again": 503 with a Retry-After is the honest answer, and a
        # permanent dependency failure is a bad gateway rather than a temporary one.
        retry_status = (
            status.HTTP_503_SERVICE_UNAVAILABLE if exc.retryable else status.HTTP_502_BAD_GATEWAY
        )
        return "dependency_unavailable", retry_status, "an upstream dependency is unavailable"

    for error_type, http_status, code in _STATUS:
        if isinstance(exc, error_type):
            return code, http_status, _detail_for(error_type, exc)

    return "internal_error", status.HTTP_500_INTERNAL_SERVER_ERROR, _OPAQUE


def _detail_for(error_type: type[DomainError], exc: Exception) -> str:
    """What this failure may say to a caller.

    Two error types never speak for themselves: a not-found is always the same sentence, and
    a credential failure says nothing at all. Everything else forwards its own message,
    swept first.
    """
    if error_type is NotFoundError:
        return _NOT_FOUND
    if error_type is SecretAccessError:
        return _OPAQUE
    return _safe(str(exc))


def _safe(detail: str) -> str:
    """A message the caller may see.

    Bounded, single-line, and swept for anything credential- or PII-shaped using the same
    matcher the dossier redaction uses. A domain message is written by us and should never
    contain a secret — this is the check that the "should" is true (ADR-0016).
    """
    text = _UUID.sub("<id>", " ".join(str(detail).split()))[:300]
    if secret_shapes_in(text):
        return _OPAQUE
    return text or _OPAQUE


def _http_code(http_status: int) -> str:
    return {
        status.HTTP_403_FORBIDDEN: "forbidden",
        status.HTTP_404_NOT_FOUND: "not_found",
        status.HTTP_405_METHOD_NOT_ALLOWED: "method_not_allowed",
        HTTP_422: "invalid_request",
        status.HTTP_503_SERVICE_UNAVAILABLE: "unavailable",
    }.get(http_status, "error")


def _response(request: Request, http_status: int, code: str, detail: str) -> JSONResponse:
    request_id = str(getattr(request.state, "request_id", "") or uuid.uuid4().hex)
    return JSONResponse(
        status_code=http_status,
        content=jsonable_encoder({"error": code, "detail": detail, "request_id": request_id}),
        headers={"X-Request-Id": request_id},
    )


__all__: Sequence[str] = ["install"]
