"""NVD-API `VulnerabilityFeed` — fetch, cache, and refuse to guess.

NVD is authoritative and it is slow, rate-limited, and inconsistent. m3-design §2 says to
treat it accordingly, and that shapes every decision here:

**Cache first, always.** A CPE we asked about inside the TTL is answered from the local
cache without a single HTTP request. That is not an optimisation — a correlation run over a
few hundred components would otherwise take hours and risk a ban.

**A failure is never an empty answer.** This is the property this module exists to get
right. NVD returning `totalResults: 0` means *there are no CVEs for this CPE*, and that
answer is cached. NVD timing out, refusing, rate-limiting, or returning something that is
not JSON means *we do not know*, and that raises `DependencyError`. If those two collapsed
into "no rows", a component would later read as clean when nobody had checked it — a false
negative this system created (AGENTS.md §67, §4.9).

**Rate limits are honoured, not discovered.** A minimum interval between requests keeps us
inside NVD's documented cap; a 429 or 503 is retried with backoff, honouring `Retry-After`
when NVD sends one. Every parameter comes from config, not from a constant in here
(m3-design §2).

**Responses are untrusted input** (AGENTS.md §2.9). NVD renames fields between API
versions, nests CVSS three different ways, and occasionally returns records missing the
things the schema says are required. Each record is parsed defensively and a bad one is
skipped *with a reason and a count* — one malformed record never costs the other ninety-nine.

No model, no LLM, no inference: Half A is deterministic by construction, and
`tests/test_adapter_boundaries.py` fails if that ever stops being true (m3-design §1).
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Final

from adapters.feed.http import MAX_RESPONSE_BYTES, HttpClient, HttpResponse, HttpxClient
from domain.errors import DependencyError, ValidationError
from domain.models import (
    CpeMatch,
    CveQueryCacheEntry,
    CveRecord,
    CvssSeverity,
    FeedFetchReport,
    SkippedRecord,
)
from domain.ports import CveCache

SOURCE: Final = "nvd"

#: NVD's own cap on results per page. Asking for more is refused by the API.
MAX_RESULTS_PER_PAGE: Final = 2000

MAX_DESCRIPTION_LENGTH: Final = 4000
MAX_REFERENCES: Final = 50
MAX_CPE_CRITERIA: Final = 500

#: Statuses that mean "ask again later" rather than "this will always fail".
RETRYABLE_STATUSES: Final = frozenset({429, 500, 502, 503, 504})


class NvdVulnerabilityFeed:
    """`VulnerabilityFeed` over the NVD 2.0 API, with a local cache in front of it."""

    def __init__(
        self,
        cache: CveCache,
        *,
        base_url: str,
        api_key: str | None = None,
        rate_limit_requests: int = 5,
        rate_limit_window_seconds: float = 30.0,
        timeout_seconds: float = 30.0,
        max_retries: int = 3,
        cache_ttl_hours: float = 24.0,
        client: HttpClient | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if rate_limit_requests < 1 or rate_limit_window_seconds <= 0:
            raise ValidationError("the NVD rate limit must allow at least one request per window")
        self._cache = cache
        self._base_url = base_url
        self._api_key = api_key
        self._min_interval = rate_limit_window_seconds / rate_limit_requests
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._ttl = timedelta(hours=cache_ttl_hours)
        self._client = client if client is not None else HttpxClient()
        self._clock = clock
        self._sleep = sleep
        self._monotonic = monotonic
        self._last_request_at: float | None = None
        self._report = FeedFetchReport()

    # ------------------------------------------------------------------- the port

    def cves_for_cpe(self, cpe: str) -> Sequence[CveRecord]:
        """Every CVE NVD associates with this CPE. See the port contract in `domain.ports`."""
        criteria = _validated_cpe(cpe)
        self._report.queries += 1

        cached = self._cache.query_entry(SOURCE, criteria)
        if cached is not None and self._is_fresh(cached.fetched_at):
            # Includes the case that matters: an entry with no CVE ids means NVD said
            # "none", and that answer is as cacheable as any other.
            self._report.served_from_cache += 1
            return self._cache.records(SOURCE, cached.cve_ids)

        payload = self._request({"cpeName": criteria, "resultsPerPage": str(MAX_RESULTS_PER_PAGE)})
        records = self._normalize(payload)
        fetched_at = self._clock()

        self._cache.store(records)
        self._cache.store_query(
            CveQueryCacheEntry(
                cpe=criteria,
                source=SOURCE,
                cve_ids=[record.cve_id for record in records],
                fetched_at=fetched_at,
            )
        )
        self._report.fetched_from_feed += 1
        return records

    def cve(self, cve_id: str) -> CveRecord | None:
        """One CVE by id, or None if NVD does not know it."""
        identifier = _validated_cve_id(cve_id)
        self._report.queries += 1

        cached = self._cache.records(SOURCE, [identifier])
        if cached:
            self._report.served_from_cache += 1
            return cached[0]

        payload = self._request({"cveId": identifier})
        records = self._normalize(payload)
        if not records:
            # NVD answered, and its answer is that it has no such CVE. That is a fact, not
            # a failure — and it is different from the exceptions `_request` raises.
            return None

        self._cache.store(records)
        self._report.fetched_from_feed += 1
        return records[0]

    def fetch_report(self) -> FeedFetchReport:
        """What the fetches since construction did. See the port contract."""
        return self._report

    # ------------------------------------------------------------------ the network

    def _request(self, params: Mapping[str, str]) -> object:
        """One NVD call, with the rate limit respected and retryable failures retried.

        Every path out of here is either a parsed payload or an exception. There is no
        branch that returns an empty result because something went wrong — that is the
        whole point of this method (AGENTS.md §67).
        """
        headers = {"Accept": "application/json"}
        if self._api_key:
            # The one place the key is used. It is a header, never a query parameter, so it
            # does not land in NVD's access logs or in ours.
            headers["apiKey"] = self._api_key

        attempt = 0
        while True:
            self._respect_rate_limit()
            try:
                response = self._client.get(
                    self._base_url, params=params, headers=headers, timeout=self._timeout
                )
            except OSError as exc:
                # A transport failure: DNS, TLS, connection reset, timeout. The network may
                # well work in a minute, so this is retryable — but it is emphatically not
                # "NVD has no CVEs".
                raise DependencyError(
                    f"could not reach NVD: {type(exc).__name__}", retryable=True
                ) from exc

            if response.status_code in RETRYABLE_STATUSES:
                attempt += 1
                if attempt > self._max_retries:
                    raise DependencyError(
                        f"NVD returned {response.status_code} after {self._max_retries} "
                        "retries; the feed is unavailable, which is not the same as having "
                        "no results",
                        retryable=True,
                    )
                self._report.rate_limited_retries += 1
                self._sleep(self._backoff_for(response, attempt))
                continue

            if response.status_code != 200:
                # 400, 403, 404: our request is wrong, or the key is. Retrying an identical
                # request would fail identically.
                raise DependencyError(
                    f"NVD rejected the request with {response.status_code}", retryable=False
                )

            if len(response.body) > MAX_RESPONSE_BYTES:
                raise ValidationError(
                    f"NVD response exceeded {MAX_RESPONSE_BYTES} bytes; refusing to parse it"
                )

            try:
                return response.json()
            except ValueError as exc:
                # A 200 whose body is not JSON is a proxy error page or a truncated
                # response. Treating it as "no CVEs" would be the false negative.
                raise ValidationError(f"NVD returned a body that is not JSON: {exc}") from exc

    def _respect_rate_limit(self) -> None:
        """Wait out the remainder of the minimum interval, if any.

        Enforced before every request rather than after a rejection: discovering the limit
        by being told off is how a client gets banned (m3-design §2).
        """
        if self._last_request_at is not None:
            elapsed = self._monotonic() - self._last_request_at
            if elapsed < self._min_interval:
                self._sleep(self._min_interval - elapsed)
        self._last_request_at = self._monotonic()

    def _backoff_for(self, response: HttpResponse, attempt: int) -> float:
        """NVD's own `Retry-After` if it sent one, else exponential backoff.

        A server that tells us when to come back knows better than our formula does.
        """
        retry_after = response.headers.get("retry-after")
        if retry_after:
            try:
                requested = float(retry_after)
            except ValueError:
                requested = None  # a date-formatted Retry-After; fall through to the formula
            if requested is not None:
                return max(0.0, requested)
        return self._min_interval * (2.0 ** (attempt - 1))

    def _is_fresh(self, fetched_at: datetime) -> bool:
        return self._clock() - fetched_at < self._ttl

    # ---------------------------------------------------------------- normalization

    def _normalize(self, payload: object) -> list[CveRecord]:
        """Turn NVD's JSON into records, skipping anything unusable.

        Defensive throughout: the payload may not be a dict, `vulnerabilities` may be
        missing or not a list, and any individual entry may be missing the fields NVD's own
        schema says are required. One bad record is skipped with a reason; the run
        continues (AGENTS.md §2.9, §4.4).
        """
        fetched_at = self._clock()

        if not isinstance(payload, dict):
            raise ValidationError("NVD response was not a JSON object")

        vulnerabilities = payload.get("vulnerabilities")
        if vulnerabilities is None:
            # A well-formed response with no results says so explicitly; a response with no
            # `vulnerabilities` key at all is a shape we do not recognise.
            if "totalResults" in payload:
                return []
            raise ValidationError("NVD response has no 'vulnerabilities' field")
        if not isinstance(vulnerabilities, list):
            raise ValidationError("NVD 'vulnerabilities' was not a list")

        records: list[CveRecord] = []
        for entry in vulnerabilities:
            record = self._normalize_one(entry, fetched_at)
            if record is not None:
                records.append(record)
        self._report.records_normalized += len(records)
        return records

    def _normalize_one(self, entry: object, fetched_at: datetime) -> CveRecord | None:
        if not isinstance(entry, dict):
            self._skip(None, "entry is not an object")
            return None

        cve = entry.get("cve")
        if not isinstance(cve, dict):
            self._skip(None, "entry has no 'cve' object")
            return None

        cve_id = _clean(cve.get("id"), 32)
        if not cve_id or not cve_id.upper().startswith("CVE-"):
            self._skip(cve_id, "missing or malformed CVE id")
            return None

        try:
            score, vector, version, severity = _cvss(cve.get("metrics"))
            return CveRecord(
                cve_id=cve_id.upper(),
                source=SOURCE,
                description=_description(cve.get("descriptions")),
                published_at=_timestamp(cve.get("published")),
                last_modified_at=_timestamp(cve.get("lastModified")),
                cvss_score=score,
                cvss_vector=vector,
                cvss_version=version,
                severity=severity,
                cpe_matches=_cpe_matches(cve.get("configurations")),
                references=_references(cve.get("references")),
                fetched_at=fetched_at,
                # The normalized record always points back at what the feed actually said
                # (AGENTS.md §3). Until the raw store is wired, that is the feed's own
                # canonical URL for this record rather than an object key.
                raw_record_ref=f"nvd:{cve_id.upper()}",
            )
        except (TypeError, ValueError) as exc:
            self._skip(cve_id, f"record did not normalize: {type(exc).__name__}")
            return None

    def _skip(self, identifier: str | None, reason: str) -> None:
        self._report.skipped.append(SkippedRecord(identifier=identifier, reason=reason))


# --------------------------------------------------------------------- field parsing


def _clean(value: object, limit: int) -> str | None:
    """Printable, trimmed, bounded. NVD text is untrusted like any other feed's."""
    if not isinstance(value, str):
        return None
    text = "".join(char for char in value if char.isprintable() or char == " ").strip()
    return text[:limit] or None


def _description(descriptions: object) -> str:
    """The English description, or the first one, or nothing. NVD sends a list of
    translations and does not guarantee an English entry."""
    if not isinstance(descriptions, list):
        return ""
    english = ""
    fallback = ""
    for item in descriptions:
        if not isinstance(item, dict):
            continue
        value = _clean(item.get("value"), MAX_DESCRIPTION_LENGTH) or ""
        if not value:
            continue
        if item.get("lang") == "en":
            english = value
            break
        fallback = fallback or value
    return english or fallback


def _timestamp(value: object) -> datetime | None:
    """NVD sends ISO-8601 without a zone designator. Read as UTC — which is what it is —
    rather than as the host's local time (AGENTS.md §5)."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _cvss(metrics: object) -> tuple[float | None, str | None, str | None, CvssSeverity | None]:
    """The base score, from whichever CVSS version this record carries.

    NVD nests the same information under `cvssMetricV31`, `cvssMetricV30` and
    `cvssMetricV2`, with different shapes. Newest first; a record with none is not an error,
    it is a CVE without a score yet.
    """
    if not isinstance(metrics, dict):
        return None, None, None, None

    for key, version in (
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2", "2.0"),
    ):
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        first = entries[0]
        if not isinstance(first, dict):
            continue
        data = first.get("cvssData")
        if not isinstance(data, dict):
            continue

        score = data.get("baseScore")
        if not isinstance(score, int | float) or not 0.0 <= float(score) <= 10.0:
            continue

        severity_text = data.get("baseSeverity") or first.get("baseSeverity")
        severity = None
        if isinstance(severity_text, str):
            try:
                severity = CvssSeverity(severity_text.strip().lower())
            except ValueError:
                severity = None

        return float(score), _clean(data.get("vectorString"), 200), version, severity

    return None, None, None, None


def _cpe_matches(configurations: object) -> list[CpeMatch]:
    """Every CPE criterion this CVE applies to, **with its version bounds**.

    The bounds are the whole point. NVD publishes most criteria with a wildcard version and
    the real range in sibling fields; reading only the criterion string would make every
    version of the product look affected. Walked defensively rather than trusted:
    `configurations` is the most deeply nested part of NVD's schema and the part most likely
    to be shaped differently than expected (AGENTS.md §2.9).
    """
    matches: list[CpeMatch] = []
    if not isinstance(configurations, list):
        return matches

    seen: set[tuple[str, str, str, str, str]] = set()
    for configuration in configurations:
        if not isinstance(configuration, dict):
            continue
        nodes = configuration.get("nodes")
        for node in nodes if isinstance(nodes, list) else []:
            if not isinstance(node, dict):
                continue
            entries = node.get("cpeMatch")
            if not isinstance(entries, list):
                continue
            for entry in entries:
                match = _cpe_match(entry)
                if match is None:
                    continue
                key = (
                    match.criteria,
                    match.version_start_including or "",
                    match.version_start_excluding or "",
                    match.version_end_including or "",
                    match.version_end_excluding or "",
                )
                if key in seen:
                    continue
                seen.add(key)
                matches.append(match)
                if len(matches) >= MAX_CPE_CRITERIA:
                    return matches
    return matches


def _cpe_match(entry: object) -> CpeMatch | None:
    if not isinstance(entry, dict):
        return None
    criteria = _clean(entry.get("criteria"), 500)
    if not criteria or not criteria.startswith("cpe:"):
        return None

    vulnerable = entry.get("vulnerable")
    return CpeMatch(
        criteria=criteria,
        # NVD marks some criteria as the *platform* a vulnerable component runs on rather
        # than the vulnerable thing itself. Only an explicit `false` excludes it.
        vulnerable=vulnerable is not False,
        version_start_including=_clean(entry.get("versionStartIncluding"), 100),
        version_start_excluding=_clean(entry.get("versionStartExcluding"), 100),
        version_end_including=_clean(entry.get("versionEndIncluding"), 100),
        version_end_excluding=_clean(entry.get("versionEndExcluding"), 100),
    )


def _references(references: object) -> list[str]:
    """Reference URLs, bounded in count and length. Stored as text and never fetched here —
    that is the `AdvisoryRetriever`'s job, in Half B."""
    urls: list[str] = []
    if not isinstance(references, list):
        return urls
    for reference in references[: MAX_REFERENCES * 2]:
        if not isinstance(reference, dict):
            continue
        url = _clean(reference.get("url"), 500)
        if url and url.startswith(("http://", "https://")):
            urls.append(url)
        if len(urls) >= MAX_REFERENCES:
            break
    return urls


def _validated_cpe(cpe: str) -> str:
    """A CPE 2.3 string, or nothing. It becomes a query parameter, so it is validated at the
    boundary like every other value that leaves this process (AGENTS.md §2.9)."""
    candidate = cpe.strip()
    if not candidate.startswith("cpe:2.3:") or len(candidate) > 500:
        raise ValidationError(f"not a CPE 2.3 string: {candidate[:80]!r}")
    if any(char in candidate for char in "\n\r\t"):
        raise ValidationError("CPE contains control characters")
    return candidate


def _validated_cve_id(cve_id: str) -> str:
    candidate = cve_id.strip().upper()
    parts = candidate.split("-")
    if len(parts) != 3 or parts[0] != "CVE" or not parts[1].isdigit() or not parts[2].isdigit():
        raise ValidationError(f"not a CVE id: {cve_id[:40]!r}")
    return candidate
