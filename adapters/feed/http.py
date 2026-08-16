"""The HTTP seam every vulnerability feed shares.

One GET, no session state, no redirects followed. Everything that makes a feed a feed —
rate limits, retries, caching, parsing — sits above this and is therefore testable without a
network (AGENTS.md §43).

httpx is used for three properties rather than for convenience: it ships its own CA bundle
(so certificate verification does not depend on the host's Python TLS store), it decompresses
`Content-Encoding: gzip` transparently, and it requires an explicit timeout rather than
defaulting to none (ADR-0010).
"""

from __future__ import annotations

import gzip
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Protocol

from domain.errors import ValidationError

#: Past this, a response is not an answer, it is a denial of service.
MAX_RESPONSE_BYTES: Final = 32 * 1024 * 1024

#: A gzip member that expands past this is a decompression bomb, whatever it claims to be.
MAX_DECOMPRESSED_BYTES: Final = 128 * 1024 * 1024

_GZIP_MAGIC: Final = b"\x1f\x8b"


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """The little of an HTTP response this adapter needs."""

    status_code: int
    body: bytes
    headers: Mapping[str, str]

    def json(self) -> object:
        """Parse the body, or raise `ValueError`.

        Returns `object`, not `Any`: the payload is untrusted, and a type that forces every
        field access through an `isinstance` check is the point rather than an inconvenience
        (AGENTS.md §2.9).
        """
        parsed: object = json.loads(self.body)
        return parsed


class HttpClient(Protocol):
    """The network seam. One GET, no redirects to follow, no session state.

    Everything about NVD's behaviour that matters — rate limits, retries, backoff — is
    implemented above this, so it is all testable without a network (AGENTS.md §43).
    """

    def get(
        self, url: str, *, params: Mapping[str, str], headers: Mapping[str, str], timeout: float
    ) -> HttpResponse:
        """Perform the request. Raises `OSError` (or a subclass) on a transport failure."""
        ...


class HttpxClient:
    """The real client.

    httpx is used for three properties rather than for convenience: it ships its own CA
    bundle (so certificate verification does not depend on the host's Python TLS store), it
    decompresses gzip transparently (NVD responses are large), and it requires an explicit
    timeout rather than defaulting to none (ADR-0010).
    """

    def get(
        self, url: str, *, params: Mapping[str, str], headers: Mapping[str, str], timeout: float
    ) -> HttpResponse:
        import httpx

        try:
            response = httpx.get(
                url,
                params=dict(params),
                headers=dict(headers),
                timeout=timeout,
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            # Normalised to OSError so the seam has one failure type and a fake does not
            # have to import httpx to imitate it.
            raise OSError(f"nvd request failed: {type(exc).__name__}") from exc

        return HttpResponse(
            status_code=response.status_code,
            body=response.content[: MAX_RESPONSE_BYTES + 1],
            headers={key.lower(): value for key, value in response.headers.items()},
        )


def decompress_if_gzipped(body: bytes) -> bytes:
    """Expand a gzip *file* body, bounded.

    Distinct from `Content-Encoding: gzip`, which the client already handles: EPSS publishes
    a `.csv.gz` artifact, so the bytes themselves are a gzip member. The bound is the point —
    a small download that expands to gigabytes is the classic way to take a process down
    (AGENTS.md §2.9).
    """
    if not body.startswith(_GZIP_MAGIC):
        return body
    try:
        expanded = gzip.decompress(body)
    except (OSError, EOFError) as exc:
        raise ValidationError(f"response claimed to be gzip and was not: {exc}") from exc
    if len(expanded) > MAX_DECOMPRESSED_BYTES:
        raise ValidationError(
            f"gzip body expanded past {MAX_DECOMPRESSED_BYTES} bytes; refusing to read it"
        )
    return expanded
