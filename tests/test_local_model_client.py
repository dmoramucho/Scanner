"""The local model client: where "the dossier stays inside the perimeter" is enforced.

AGENTS.md §2.10 says corporate asset data does not reach a third party. A redacted dossier
is still a list of this company's devices, which of them nobody manages, and which of those
are exploitable — "redacted" is not "publishable". So the endpoint check is a constructor
argument that raises, not a comment in a config file.

No network here either: `FakeTransport` stands in for the POST (AGENTS.md §43).
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence

import pytest

from adapters.llm.local import LocalChatModelClient
from domain.errors import DependencyError, ValidationError
from domain.ports import ModelClient


class FakeTransport:
    def __init__(
        self, replies: Sequence[tuple[int, bytes]] = (), *, raises: Exception | None = None
    ) -> None:
        self.replies = list(replies)
        self.raises = raises
        self.requests: list[tuple[str, Mapping[str, object]]] = []

    def post_json(
        self,
        url: str,
        *,
        payload: Mapping[str, object],
        headers: Mapping[str, str],
        timeout: float,
    ) -> tuple[int, bytes]:
        self.requests.append((url, payload))
        if self.raises is not None:
            raise self.raises
        if not self.replies:
            raise AssertionError(f"unscripted request to {url}")
        return self.replies.pop(0)


def chat_reply(content: str) -> bytes:
    return json.dumps(
        {"choices": [{"message": {"role": "assistant", "content": content}}]}
    ).encode()


def client(
    transport: FakeTransport, base_url: str = "http://127.0.0.1:11434"
) -> LocalChatModelClient:
    return LocalChatModelClient(base_url, "llama3.3:70b", transport=transport)


# ------------------------------------------------------------------ the perimeter


@pytest.mark.parametrize(
    "base_url",
    [
        "https://api.openai.com",
        "https://generativelanguage.googleapis.com",
        "http://8.8.8.8:11434",
        "http://model.example.com",
        "ftp://127.0.0.1",
        "",
    ],
)
def test_a_non_local_model_endpoint_is_refused_at_construction(base_url: str) -> None:
    """The safety property of this adapter, and the reason it exists separately from a
    generic HTTP client with a URL from config. Point it at a hosted API and it does not
    start (AGENTS.md §2.10)."""
    with pytest.raises(ValidationError):
        LocalChatModelClient(base_url, "llama3.3:70b", transport=FakeTransport())


@pytest.mark.parametrize(
    "base_url",
    [
        "http://localhost:11434",
        "http://127.0.0.1:8080",
        "http://[::1]:11434",
        "http://10.0.4.12:8000",
        "http://192.168.1.50:11434",
        "http://172.16.9.9:11434",
        "http://gpu-box.internal:8000",
        "https://llm.home.arpa",
    ],
)
def test_a_local_or_self_hosted_endpoint_is_accepted(base_url: str) -> None:
    """The other half: an on-prem GPU box is exactly the intended deployment."""
    client = LocalChatModelClient(base_url, "llama3.3:70b", transport=FakeTransport())

    assert client is not None


def test_the_model_name_is_required() -> None:
    with pytest.raises(ValidationError):
        LocalChatModelClient("http://127.0.0.1:11434", "  ", transport=FakeTransport())


# ------------------------------------------------------------------ the completion


def test_a_completion_round_trips() -> None:
    transport = FakeTransport([(200, chat_reply('{"recommendation": "maintain"}'))])

    completion = client(transport).complete(system="rules", user="dossier")

    assert completion.text == '{"recommendation": "maintain"}'
    assert completion.model_version == "llama3.3:70b"
    url, payload = transport.requests[0]
    assert url == "http://127.0.0.1:11434/v1/chat/completions"
    assert payload["messages"] == [
        {"role": "system", "content": "rules"},
        {"role": "user", "content": "dossier"},
    ]


def test_the_default_temperature_is_zero() -> None:
    """The same dossier should produce the same insight. A triage system that says something
    different every night is not auditable."""
    transport = FakeTransport([(200, chat_reply("{}"))])

    client(transport).complete(system="s", user="u")

    assert transport.requests[0][1]["temperature"] == 0.0


def test_the_client_satisfies_the_port() -> None:
    transport = FakeTransport([(200, chat_reply("{}"))])

    port: ModelClient = client(transport)

    assert port.complete(system="s", user="u").text == "{}"


# ------------------------------------------------------------------ failure handling


def test_an_unreachable_model_is_a_retryable_dependency_failure() -> None:
    transport = FakeTransport(raises=OSError("connection refused"))

    with pytest.raises(DependencyError) as raised:
        client(transport).complete(system="s", user="u")

    assert raised.value.retryable


@pytest.mark.parametrize(
    ("status", "retryable"), [(503, True), (429, True), (400, False), (404, False)]
)
def test_http_failures_separate_retryable_from_permanent(status: int, retryable: bool) -> None:
    """A local runtime returns 503 while it loads a 40GB model; that is worth retrying. A 400
    means the request is wrong and will be wrong next time."""
    transport = FakeTransport([(status, b"")])

    with pytest.raises(DependencyError) as raised:
        client(transport).complete(system="s", user="u")

    assert raised.value.retryable is retryable


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"{}",
        json.dumps({"choices": []}).encode(),
        json.dumps({"choices": [{"message": {}}]}).encode(),
        json.dumps({"choices": [{"message": {"content": "   "}}]}).encode(),
        json.dumps({"choices": ["a string"]}).encode(),
    ],
)
def test_a_malformed_or_empty_reply_raises_rather_than_becoming_an_empty_insight(
    body: bytes,
) -> None:
    """A local runtime is still an external process returning JSON we did not write. An
    empty completion is a failure, never an insight with nothing in it (AGENTS.md §67)."""
    transport = FakeTransport([(200, body)])

    with pytest.raises(ValidationError):
        client(transport).complete(system="s", user="u")


def test_an_oversized_reply_is_refused() -> None:
    transport = FakeTransport([(200, b"x" * (300 * 1024))])

    with pytest.raises(ValidationError):
        client(transport).complete(system="s", user="u")
