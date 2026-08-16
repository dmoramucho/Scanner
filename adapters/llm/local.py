"""A `ModelClient` for a local or self-hosted model, and a refusal to be anything else.

The dossier is corporate asset data: hostnames, serials, firmware versions, open ports, and
the fact that a particular device is unmanaged and vulnerable. AGENTS.md §2.10 says that
does not leave the perimeter, and this adapter is where that stops being a policy and starts
being a constructor argument that raises.

`_require_local_endpoint` refuses any base URL that is not loopback, a private or
link-local address, or an explicitly internal hostname. Point this at `api.example-ai.com`
and it will not start. That check is the reason this file exists as a separate adapter
rather than as a generic HTTP client with a URL from config.

The wire format is OpenAI-compatible `/v1/chat/completions`, which Ollama, llama.cpp's
server, vLLM, LM Studio and text-generation-webui all speak. That is a deliberate choice of
*protocol* over *vendor*: no client library is added, no vendor SDK is imported, and swapping
the runtime is a URL change (ADR-0014).
"""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Mapping, Sequence
from typing import Final, Protocol
from urllib.parse import urlsplit

from domain.errors import DependencyError, ValidationError
from domain.models import ModelCompletion

#: Hostnames that are local by definition, plus the suffixes an on-prem deployment uses.
_LOCAL_HOSTS: Final = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})  # noqa: S104
_LOCAL_SUFFIXES: Final = (".local", ".internal", ".lan", ".home.arpa")

#: A model reply is a paragraph of JSON. Anything larger is a runaway generation.
MAX_COMPLETION_BYTES: Final = 256 * 1024

#: Statuses worth trying again: the model is loading, or the queue is full.
_RETRYABLE_STATUSES: Final = frozenset({408, 409, 425, 429, 500, 502, 503, 504})


class ChatTransport(Protocol):
    """One POST. The seam that keeps every test in this milestone model-free."""

    def post_json(
        self,
        url: str,
        *,
        payload: Mapping[str, object],
        headers: Mapping[str, str],
        timeout: float,
    ) -> tuple[int, bytes]:
        """Perform the request. Raises `OSError` (or a subclass) on a transport failure."""
        ...


class HttpxChatTransport:
    """The real transport. httpx for the same reasons the feeds use it (ADR-0010)."""

    def post_json(
        self,
        url: str,
        *,
        payload: Mapping[str, object],
        headers: Mapping[str, str],
        timeout: float,
    ) -> tuple[int, bytes]:
        import httpx

        try:
            response = httpx.post(
                url,
                json=dict(payload),
                headers=dict(headers),
                timeout=timeout,
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            raise OSError(f"model request failed: {type(exc).__name__}") from exc
        return response.status_code, response.content[: MAX_COMPLETION_BYTES + 1]


class LocalChatModelClient:
    """`ModelClient` over an OpenAI-compatible endpoint that must be local."""

    def __init__(
        self,
        base_url: str,
        model: str,
        *,
        transport: ChatTransport | None = None,
        timeout_seconds: float = 120.0,
        temperature: float = 0.0,
        max_tokens: int = 800,
    ) -> None:
        self._base_url = _require_local_endpoint(base_url)
        self._model = model.strip()
        if not self._model:
            raise ValidationError("a model name is required")
        self._transport = transport if transport is not None else HttpxChatTransport()
        self._timeout = timeout_seconds
        # Zero temperature by default: the same dossier should produce the same insight, and
        # a triage system that says something different every night is not auditable.
        self._temperature = temperature
        self._max_tokens = max_tokens

    def complete(self, *, system: str, user: str) -> ModelCompletion:
        """One completion. See the port contract in `domain.ports`."""
        payload: dict[str, object] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": self._temperature,
            "max_tokens": self._max_tokens,
            "stream": False,
        }

        try:
            status, body = self._transport.post_json(
                f"{self._base_url}/v1/chat/completions",
                payload=payload,
                headers={"Content-Type": "application/json", "Accept": "application/json"},
                timeout=self._timeout,
            )
        except OSError as exc:
            raise DependencyError(
                f"could not reach the local model: {type(exc).__name__}", retryable=True
            ) from exc

        if status in _RETRYABLE_STATUSES:
            raise DependencyError(f"model returned {status}; it may be loading", retryable=True)
        if status != 200:
            raise DependencyError(f"model rejected the request with {status}", retryable=False)
        if len(body) > MAX_COMPLETION_BYTES:
            raise ValidationError(f"model reply exceeded {MAX_COMPLETION_BYTES} bytes")

        return ModelCompletion(text=_completion_text(body), model_version=self._model)


def _completion_text(body: bytes) -> str:
    """Pull the message out of an OpenAI-compatible reply, defensively.

    A local runtime is still an external process returning JSON we did not write, so every
    step is checked. An empty completion raises rather than becoming an empty insight
    (AGENTS.md §67).
    """
    try:
        parsed: object = json.loads(body)
    except ValueError as exc:
        raise ValidationError(f"model reply was not JSON: {exc}") from exc

    if not isinstance(parsed, dict):
        raise ValidationError("model reply was not a JSON object")
    choices = parsed.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValidationError("model reply contained no choices")
    first = choices[0]
    if not isinstance(first, dict):
        raise ValidationError("model reply choice was not an object")
    message = first.get("message")
    if not isinstance(message, dict):
        raise ValidationError("model reply had no message")
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise ValidationError("model returned an empty completion")
    return content


def _require_local_endpoint(base_url: str) -> str:
    """Accept a local model endpoint; refuse anything that would leave the perimeter.

    This is AGENTS.md §2.10 as code. The dossier is redacted, but "redacted" is not
    "publishable": it still says which of this company's devices are unmanaged and
    vulnerable, and that is not a thing to hand to a third party because a URL in a config
    file changed.
    """
    url = base_url.strip().rstrip("/")
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValidationError(f"not a usable model endpoint: {base_url[:80]!r}")

    host = parts.hostname.lower()
    if host in _LOCAL_HOSTS or host.endswith(_LOCAL_SUFFIXES):
        return url

    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValidationError(
            f"refusing a non-local model endpoint: {host!r}. The asset dossier does not "
            f"leave the perimeter (AGENTS.md §2.10) — use a loopback, private-network or "
            f".internal address."
        ) from exc

    if not (address.is_private or address.is_loopback or address.is_link_local):
        raise ValidationError(
            f"refusing a public model endpoint: {host!r}. The asset dossier does not leave "
            f"the perimeter (AGENTS.md §2.10)."
        )
    return url


__all__: Sequence[str] = [
    "ChatTransport",
    "HttpxChatTransport",
    "LocalChatModelClient",
]
