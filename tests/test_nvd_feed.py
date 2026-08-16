"""The NVD adapter: cache-first, rate-limited, defensive — and never silently empty.

Fixtures and a fake HTTP client; CI never touches the real NVD (AGENTS.md §43, m3-design §4).

The assertion that carries this file is the last section: **a feed failure and a feed
answering "none" must never be the same value.** If they collapse, a component reads as
clean when nobody checked it — a false negative this system would have created
(AGENTS.md §67, §4.9).
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from adapters.feed.http import HttpResponse
from adapters.feed.nvd import RETRYABLE_STATUSES, NvdVulnerabilityFeed
from domain.errors import DependencyError, ValidationError
from domain.models import CveQueryCacheEntry, CveRecord, CvssSeverity
from domain.ports import VulnerabilityFeed

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "nvd"

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
APACHE = "cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*"
OBSCURE = "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"


def fixture(name: str) -> bytes:
    return (FIXTURES / f"{name}.json").read_bytes()


class FakeHttp:
    """Replays scripted responses and records every request it was asked to make."""

    def __init__(
        self,
        responses: Sequence[HttpResponse] | None = None,
        *,
        raises: Exception | None = None,
    ) -> None:
        self.responses = list(responses or [])
        self.raises = raises
        self.calls: list[tuple[str, Mapping[str, str], Mapping[str, str]]] = []

    def get(
        self, url: str, *, params: Mapping[str, str], headers: Mapping[str, str], timeout: float
    ) -> HttpResponse:
        self.calls.append((url, dict(params), dict(headers)))
        if self.raises is not None:
            raise self.raises
        if not self.responses:
            raise AssertionError("the adapter made more requests than the test scripted")
        return self.responses.pop(0)

    @property
    def call_count(self) -> int:
        return len(self.calls)


class FakeCache:
    """An in-memory `CveCache`, so the adapter's cache logic is what is under test."""

    def __init__(self) -> None:
        self.queries: dict[tuple[str, str], CveQueryCacheEntry] = {}
        self.stored: dict[tuple[str, str], CveRecord] = {}
        self.store_calls = 0

    def query_entry(self, source: str, cpe: str) -> CveQueryCacheEntry | None:
        return self.queries.get((source, cpe))

    def records(self, source: str, cve_ids: Sequence[str]) -> Sequence[CveRecord]:
        return [self.stored[(source, cid)] for cid in cve_ids if (source, cid) in self.stored]

    def store(self, records: Sequence[CveRecord]) -> int:
        self.store_calls += 1
        created = 0
        for record in records:
            key = (record.source, record.cve_id)
            if key not in self.stored:
                created += 1
            self.stored[key] = record
        return created

    def store_query(self, entry: CveQueryCacheEntry) -> None:
        self.queries[(entry.source, entry.cpe)] = entry


def ok(body: bytes, headers: Mapping[str, str] | None = None) -> HttpResponse:
    return HttpResponse(status_code=200, body=body, headers=dict(headers or {}))


def status(code: int, headers: Mapping[str, str] | None = None) -> HttpResponse:
    return HttpResponse(status_code=code, body=b"{}", headers=dict(headers or {}))


def feed(
    http: FakeHttp,
    cache: FakeCache | None = None,
    *,
    slept: list[float] | None = None,
    now: datetime = NOW,
    **kwargs: object,
) -> NvdVulnerabilityFeed:
    return NvdVulnerabilityFeed(
        cache or FakeCache(),
        base_url="https://nvd.example/rest/json/cves/2.0",
        client=http,
        clock=lambda: now,
        sleep=(slept.append if slept is not None else lambda _: None),
        monotonic=lambda: 0.0,  # every request looks instantaneous unless a test says otherwise
        **kwargs,  # type: ignore[arg-type]
    )


# ------------------------------------------------------------------ normalization


def test_a_cpe_with_cves_normalizes_into_records() -> None:
    http = FakeHttp([ok(fixture("cpe_with_cves"))])

    records = feed(http).cves_for_cpe(APACHE)

    assert [record.cve_id for record in records] == [
        "CVE-2024-27316",
        "CVE-2023-45802",
        "CVE-2006-20001",
    ]
    first = records[0]
    assert first.cvss_score == 7.5
    assert first.severity is CvssSeverity.HIGH
    assert first.cvss_version == "3.1"
    assert "widget handler" in first.description  # the English one, not the Spanish
    assert first.published_at == datetime(2024, 1, 15, 10, 15, 7, tzinfo=UTC)
    assert APACHE in first.cpe_criteria


def test_records_carry_provenance_and_a_reference_to_the_raw_response() -> None:
    """A match must always be traceable back to what the feed actually said, rather than to
    what we made of it (AGENTS.md §3)."""
    records = feed(FakeHttp([ok(fixture("cpe_with_cves"))])).cves_for_cpe(APACHE)

    for record in records:
        assert record.source == "nvd"
        assert record.fetched_at == NOW
        assert record.fetched_at.tzinfo is not None
        assert record.raw_record_ref == f"nvd:{record.cve_id}"


def test_older_cvss_versions_are_read_too() -> None:
    """NVD nests the same information under three different keys depending on the CVSS
    version; a record scored only under v2 still has a score."""
    records = feed(FakeHttp([ok(fixture("cpe_with_cves"))])).cves_for_cpe(APACHE)

    by_id = {record.cve_id: record for record in records}
    assert by_id["CVE-2023-45802"].cvss_score == 5.9
    assert by_id["CVE-2006-20001"].cvss_score == 7.5


def test_junk_references_are_dropped() -> None:
    records = feed(FakeHttp([ok(fixture("cpe_with_cves"))])).cves_for_cpe(APACHE)

    for record in records:
        for url in record.references:
            assert url.startswith(("http://", "https://"))


# ------------------------------------------------------------- untrusted parsing


def test_a_malformed_record_is_skipped_with_a_reason_and_the_batch_survives() -> None:
    """One bad record never costs the other ninety-nine (AGENTS.md §2.9, §4.4)."""
    nvd = feed(FakeHttp([ok(fixture("malformed_records"))]))

    records = nvd.cves_for_cpe(APACHE)

    assert [record.cve_id for record in records] == ["CVE-2024-99999", "CVE-2024-27316"]
    report = nvd.fetch_report()
    assert report.skipped_count == 4
    assert set(report.skip_reasons) == {
        "missing or malformed CVE id",
        "entry has no 'cve' object",
        "entry is not an object",
    }


def test_a_record_with_renamed_or_wrongly_typed_fields_still_yields_what_it_can() -> None:
    """NVD renames things between API versions. A record whose `descriptions` is a string
    rather than a list is not a crash — it is a record with no description."""
    records = feed(FakeHttp([ok(fixture("malformed_records"))])).cves_for_cpe(APACHE)

    salvaged = next(record for record in records if record.cve_id == "CVE-2024-99999")
    assert salvaged.description == ""
    assert salvaged.cvss_score is None
    assert salvaged.cpe_criteria == []
    assert salvaged.published_at is None


def test_a_skip_never_echoes_the_record_itself() -> None:
    nvd = feed(FakeHttp([ok(fixture("malformed_records"))]))
    nvd.cves_for_cpe(APACHE)

    for skipped in nvd.fetch_report().skipped:
        assert "bare string" not in str(skipped.model_dump())


def test_an_unrecognised_response_shape_raises_rather_than_reporting_none() -> None:
    """A body we do not understand is not evidence that there are no CVEs."""
    with pytest.raises(ValidationError, match="no 'vulnerabilities' field"):
        feed(FakeHttp([ok(fixture("unexpected_shape"))])).cves_for_cpe(APACHE)


def test_an_oversized_response_is_refused() -> None:
    from adapters.feed.http import MAX_RESPONSE_BYTES

    huge = ok(b"{" + b"x" * (MAX_RESPONSE_BYTES + 10))

    with pytest.raises(ValidationError, match="exceeded"):
        feed(FakeHttp([huge])).cves_for_cpe(APACHE)


@pytest.mark.parametrize("hostile", ["not-a-cpe", "cpe:2.3:a:x\ny", "", "a" * 600])
def test_a_target_that_is_not_a_cpe_is_refused_before_any_request(hostile: str) -> None:
    http = FakeHttp([])

    with pytest.raises(ValidationError):
        feed(http).cves_for_cpe(hostile)

    assert http.call_count == 0


# ----------------------------------------------------------------- cache-first


def test_a_second_fetch_inside_the_window_never_touches_nvd() -> None:
    """The property NVD's rate limit makes non-negotiable: asking twice costs one request."""
    cache = FakeCache()
    http = FakeHttp([ok(fixture("cpe_with_cves"))])
    nvd = feed(http, cache)

    first = nvd.cves_for_cpe(APACHE)
    second = nvd.cves_for_cpe(APACHE)

    assert http.call_count == 1  # the second was served from cache
    assert [r.cve_id for r in second] == [r.cve_id for r in first]
    report = nvd.fetch_report()
    assert (report.fetched_from_feed, report.served_from_cache) == (1, 1)


def test_a_cached_empty_answer_is_still_an_answer() -> None:
    """The subtle half of cache-first: "NVD says this CPE has no CVEs" is cacheable, and
    must not be mistaken for "we never asked" (m3-design §2)."""
    cache = FakeCache()
    http = FakeHttp([ok(fixture("cpe_with_no_cves"))])
    nvd = feed(http, cache)

    assert nvd.cves_for_cpe(OBSCURE) == []
    assert nvd.cves_for_cpe(OBSCURE) == []

    assert http.call_count == 1
    entry = cache.query_entry("nvd", OBSCURE)
    assert entry is not None
    assert entry.cve_ids == []  # asked, and the answer was none


def test_a_stale_cache_entry_is_refetched() -> None:
    cache = FakeCache()
    cache.store_query(
        CveQueryCacheEntry(
            cpe=APACHE, source="nvd", cve_ids=[], fetched_at=NOW - timedelta(days=30)
        )
    )
    http = FakeHttp([ok(fixture("cpe_with_cves"))])

    records = feed(http, cache, cache_ttl_hours=24).cves_for_cpe(APACHE)

    assert http.call_count == 1
    assert len(records) == 3


def test_fetching_by_cve_id_is_cached_too() -> None:
    cache = FakeCache()
    http = FakeHttp([ok(fixture("cpe_with_cves"))])
    nvd = feed(http, cache)

    first = nvd.cve("CVE-2024-27316")
    second = nvd.cve("cve-2024-27316")  # case-insensitive

    assert first is not None
    assert second is not None
    assert second.cve_id == first.cve_id
    assert http.call_count == 1


def test_an_unknown_cve_id_returns_none_rather_than_raising() -> None:
    """NVD answered; its answer is that it has no such CVE."""
    result = feed(FakeHttp([ok(fixture("cpe_with_no_cves"))])).cve("CVE-1999-99999")

    assert result is None


@pytest.mark.parametrize("hostile", ["CVE-XXXX-1", "2024-27316", "'; drop table", ""])
def test_a_malformed_cve_id_is_refused_before_any_request(hostile: str) -> None:
    http = FakeHttp([])

    with pytest.raises(ValidationError, match="not a CVE id"):
        feed(http).cve(hostile)

    assert http.call_count == 0


# ------------------------------------------------------------------ rate limits


def test_a_429_is_retried_after_backing_off() -> None:
    slept: list[float] = []
    http = FakeHttp([status(429), ok(fixture("cpe_with_cves"))])
    nvd = feed(http, slept=slept)

    records = nvd.cves_for_cpe(APACHE)

    assert len(records) == 3  # the retry succeeded
    assert http.call_count == 2
    assert nvd.fetch_report().rate_limited_retries == 1
    assert any(pause > 0 for pause in slept)


def test_nvds_own_retry_after_is_honoured() -> None:
    """A server that tells us when to come back knows better than our formula."""
    slept: list[float] = []
    http = FakeHttp([status(429, {"retry-after": "17"}), ok(fixture("cpe_with_cves"))])

    feed(http, slept=slept).cves_for_cpe(APACHE)

    assert 17.0 in slept


@pytest.mark.parametrize("code", sorted(RETRYABLE_STATUSES))
def test_every_retryable_status_backs_off_and_retries(code: int) -> None:
    http = FakeHttp([status(code), ok(fixture("cpe_with_cves"))])

    records = feed(http).cves_for_cpe(APACHE)

    assert len(records) == 3
    assert http.call_count == 2


def test_a_persistent_429_gives_up_and_says_the_feed_is_unavailable() -> None:
    """Exhausting the retries is a failure, not an empty result — and it is retryable, so a
    caller knows it is worth trying again later."""
    http = FakeHttp([status(429), status(429), status(429), status(429)])

    with pytest.raises(DependencyError, match="not the same as having no results") as exc_info:
        feed(http, max_retries=3).cves_for_cpe(APACHE)

    assert exc_info.value.retryable is True
    assert http.call_count == 4  # the original plus three retries


def test_the_request_cap_is_respected_between_calls() -> None:
    """The interval is enforced *before* each request rather than after a rejection:
    discovering the limit by being told off is how a client gets banned."""
    slept: list[float] = []
    elapsed = [0.0]
    http = FakeHttp([ok(fixture("cpe_with_cves")), ok(fixture("cpe_with_no_cves"))])
    nvd = NvdVulnerabilityFeed(
        FakeCache(),
        base_url="https://nvd.example/api",
        client=http,
        clock=lambda: NOW,
        sleep=slept.append,
        monotonic=lambda: elapsed[0],
        rate_limit_requests=5,
        rate_limit_window_seconds=30.0,  # ⇒ 6 seconds between requests
    )

    nvd.cves_for_cpe(APACHE)
    nvd.cves_for_cpe(OBSCURE)  # immediately after, on the same clock

    assert slept == [6.0]


def test_an_api_key_travels_in_a_header_not_a_query_parameter() -> None:
    """A key in the query string lands in NVD's access logs, and in any proxy's."""
    http = FakeHttp([ok(fixture("cpe_with_cves"))])

    feed(http, api_key="secret-key-value").cves_for_cpe(APACHE)

    _, params, headers = http.calls[0]
    assert headers["apiKey"] == "secret-key-value"
    assert "secret-key-value" not in json.dumps(params)


def test_a_nonsensical_rate_limit_is_refused() -> None:
    with pytest.raises(ValidationError, match="rate limit"):
        NvdVulnerabilityFeed(FakeCache(), base_url="https://nvd.example", rate_limit_requests=0)


# ------------------------------ FAILURE IS NEVER AN EMPTY ANSWER (the safety net)


def test_a_network_failure_raises_a_retryable_error_rather_than_returning_nothing() -> None:
    """The assertion this whole module exists to satisfy. If a transport failure returned
    `[]`, the component would later read as clean when nobody had checked it."""
    http = FakeHttp(raises=OSError("connection reset"))

    with pytest.raises(DependencyError, match="could not reach NVD") as exc_info:
        feed(http).cves_for_cpe(APACHE)

    assert exc_info.value.retryable is True


def test_a_timeout_is_retryable_and_not_an_empty_result() -> None:
    http = FakeHttp(raises=TimeoutError("timed out"))

    with pytest.raises(DependencyError) as exc_info:
        feed(http).cves_for_cpe(APACHE)

    assert exc_info.value.retryable is True


@pytest.mark.parametrize("code", [400, 403, 404])
def test_a_permanent_rejection_is_not_retryable_and_not_an_empty_result(code: int) -> None:
    """Our request is wrong, or the key is. Retrying identically would fail identically —
    but it is still emphatically not "there are no CVEs"."""
    with pytest.raises(DependencyError, match="rejected the request") as exc_info:
        feed(FakeHttp([status(code)])).cves_for_cpe(APACHE)

    assert exc_info.value.retryable is False


def test_a_body_that_is_not_json_raises() -> None:
    """A 200 whose body is a proxy error page is not an answer about CVEs."""
    http = FakeHttp([ok(b"<html>502 Bad Gateway</html>")])

    with pytest.raises(ValidationError, match="not JSON"):
        feed(http).cves_for_cpe(APACHE)


def test_a_failure_caches_nothing() -> None:
    """The most dangerous version of the bug: a failure recorded as "asked, none found"
    would poison the cache and keep reading as clean for the whole TTL."""
    cache = FakeCache()

    with pytest.raises(DependencyError):
        feed(FakeHttp(raises=OSError("down")), cache).cves_for_cpe(APACHE)

    assert cache.query_entry("nvd", APACHE) is None
    assert cache.store_calls == 0


def test_a_real_empty_answer_and_a_failure_are_distinguishable_to_a_caller() -> None:
    """Side by side, because the distinction is the point: one returns, one raises."""
    empty = feed(FakeHttp([ok(fixture("cpe_with_no_cves"))])).cves_for_cpe(OBSCURE)
    assert empty == []

    with pytest.raises(DependencyError):
        feed(FakeHttp(raises=OSError("down"))).cves_for_cpe(OBSCURE)


# ------------------------------------------------------------------ conformance


def test_the_adapter_satisfies_the_port() -> None:
    nvd: VulnerabilityFeed = NvdVulnerabilityFeed(FakeCache(), base_url="https://nvd.example")

    assert callable(nvd.cves_for_cpe)
    assert callable(nvd.cve)
    assert callable(nvd.fetch_report)
