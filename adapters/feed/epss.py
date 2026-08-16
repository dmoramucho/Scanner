"""EPSS — how likely is this CVE to be exploited in the next 30 days?

FIRST publishes a daily snapshot as a gzipped CSV: one row per scored CVE, a probability and
a percentile, both 0–1. It is the gradient that ranks everything KEV does not flag
(m3-design §2).

The same discipline as the KEV adapter, one step softer in consequence:

**`None` means FIRST has not scored this CVE. A snapshot we could not fetch raises.** If a
failed download returned `None`, an unscored CVE and an unfetchable one would rank
identically — and the second is not a fact about the CVE at all (AGENTS.md §67).

The snapshot is fetched whole and replaced, rather than queried per CVE: it is one request
per day for a file that answers every question we will ask of it, which is a great deal
kinder to FIRST than a few hundred individual lookups.

Rows are untrusted input (AGENTS.md §2.9). A score that is not a number, is outside 0–1, or
is NaN is refused with a reason — the same treatment the observation sink gives a NaN
payload, for the same reason: a score that cannot be compared cannot rank anything.
"""

from __future__ import annotations

import csv
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from math import isfinite
from typing import Final

from adapters.feed.http import HttpClient, HttpxClient, decompress_if_gzipped
from domain.errors import DependencyError, ValidationError
from domain.models import EpssScore, FeedFetchReport, FeedSnapshot, SkippedRecord
from domain.ports import EpssCache

SOURCE: Final = "epss"

DEFAULT_SNAPSHOT_URL: Final = "https://epss.cyentia.com/epss_scores-current.csv.gz"

#: FIRST publishes once a day. Asking more often gets the same file back.
DEFAULT_TTL_HOURS: Final = 24.0

DEFAULT_TIMEOUT_SECONDS: Final = 60.0

#: The real snapshot is a few hundred thousand rows. Past this it is not the snapshot.
MAX_ROWS: Final = 1_000_000

RETRYABLE_STATUSES: Final = frozenset({429, 500, 502, 503, 504})


class FirstEpssSource:
    """`EpssSource` over FIRST's daily CSV snapshot, cached locally."""

    def __init__(
        self,
        cache: EpssCache,
        *,
        snapshot_url: str = DEFAULT_SNAPSHOT_URL,
        ttl_hours: float = DEFAULT_TTL_HOURS,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = 2,
        client: HttpClient | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        sleep: Callable[[float], None] = lambda _: None,
    ) -> None:
        self._cache = cache
        self._url = snapshot_url
        self._ttl = timedelta(hours=ttl_hours)
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._client = client if client is not None else HttpxClient()
        self._clock = clock
        self._sleep = sleep
        self._report = FeedFetchReport()

    # ------------------------------------------------------------------- the port

    def score_for(self, cve_id: str) -> EpssScore | None:
        """The EPSS score, or None if FIRST has not scored this CVE.

        `_ensure_snapshot` either leaves a usable snapshot in the cache or raises, so a
        `None` here can only mean "not in the snapshot".
        """
        identifier = _validated_cve_id(cve_id)
        self._ensure_snapshot()
        self._report.queries += 1
        return self._cache.score(SOURCE, identifier)

    def refresh(self) -> FeedFetchReport:
        """Reload the current snapshot now, whatever the cache says."""
        self._load()
        return self._report

    def fetch_report(self) -> FeedFetchReport:
        return self._report

    # ------------------------------------------------------------------ internals

    def _ensure_snapshot(self) -> None:
        snapshot = self._cache.snapshot(SOURCE)
        if snapshot is not None and self._clock() - snapshot.fetched_at < self._ttl:
            self._report.served_from_cache += 1
            return
        self._load()

    def _load(self) -> None:
        body = self._request()
        fetched_at = self._clock()
        model_version, scored_at = _header_metadata(body)
        scores = list(self._parse(body, fetched_at, model_version, scored_at))

        if not scores:
            # An empty snapshot is not a world in which nothing is exploitable; it is a
            # download that went wrong. Replacing a good snapshot with it would erase every
            # score we have.
            raise ValidationError(
                "EPSS snapshot contained no usable rows; refusing to replace the cache "
                "with an empty one"
            )

        self._cache.replace(
            SOURCE,
            scores,
            FeedSnapshot(
                source=SOURCE,
                fetched_at=fetched_at,
                record_count=len(scores),
                raw_record_ref=self._url,
            ),
        )
        self._report.fetched_from_feed += 1
        self._report.records_normalized += len(scores)

    def _request(self) -> str:
        """One GET, retried on transient statuses. Returns the CSV text or raises."""
        attempt = 0
        while True:
            try:
                response = self._client.get(
                    self._url, params={}, headers={"Accept": "text/csv"}, timeout=self._timeout
                )
            except OSError as exc:
                raise DependencyError(
                    f"could not reach the EPSS snapshot: {type(exc).__name__}", retryable=True
                ) from exc

            if response.status_code in RETRYABLE_STATUSES:
                attempt += 1
                if attempt > self._max_retries:
                    raise DependencyError(
                        f"EPSS snapshot returned {response.status_code} after "
                        f"{self._max_retries} retries; not having a score is not the same "
                        "as a CVE having none",
                        retryable=True,
                    )
                self._report.rate_limited_retries += 1
                self._sleep(float(attempt))
                continue

            if response.status_code != 200:
                raise DependencyError(
                    f"EPSS snapshot request rejected with {response.status_code}",
                    retryable=False,
                )

            # The artifact is a gzip *file*, not a gzip-encoded response, so it is expanded
            # here — bounded, because a small download that expands to gigabytes is the
            # classic way to take a process down.
            return decompress_if_gzipped(response.body).decode("utf-8", errors="replace")

    def _parse(
        self,
        body: str,
        fetched_at: datetime,
        model_version: str | None,
        scored_at: datetime | None,
    ) -> Iterator[EpssScore]:
        """Read the CSV, refusing any row that cannot be trusted to rank anything."""
        rows = csv.DictReader(_data_lines(body))
        if rows.fieldnames is None or "cve" not in rows.fieldnames:
            raise ValidationError("EPSS snapshot has no 'cve' column")

        for index, row in enumerate(rows):
            if index >= MAX_ROWS:
                raise ValidationError(f"EPSS snapshot exceeded {MAX_ROWS} rows")

            cve_id = (row.get("cve") or "").strip().upper()
            if not _is_cve_id(cve_id):
                self._skip(cve_id or None, "malformed CVE id")
                continue

            score = _probability(row.get("epss"))
            if score is None:
                # A row whose probability is missing, unparseable, out of range, or NaN.
                self._skip(cve_id, "score is not a probability between 0 and 1")
                continue

            yield EpssScore(
                cve_id=cve_id,
                source=SOURCE,
                score=score,
                percentile=_probability(row.get("percentile")),
                model_version=model_version,
                scored_at=scored_at,
                fetched_at=fetched_at,
                raw_record_ref=f"{SOURCE}:{cve_id}",
            )

    def _skip(self, identifier: str | None, reason: str) -> None:
        self._report.skipped.append(SkippedRecord(identifier=identifier, reason=reason))


# ------------------------------------------------------------------- field parsing


def _data_lines(body: str) -> Iterator[str]:
    """The CSV rows, without the `#model_version:…` comment FIRST prefixes the file with."""
    for line in body.splitlines():
        if line.startswith("#"):
            continue
        if line.strip():
            yield line


def _header_metadata(body: str) -> tuple[str | None, datetime | None]:
    """Read the model version and score date out of FIRST's comment line.

    Provenance for a number whose meaning depends on which model produced it: an EPSS score
    from two model generations ago is not comparable to today's.
    """
    for line in body.splitlines():
        if not line.startswith("#"):
            break
        parts = dict(item.split(":", 1) for item in line.lstrip("#").split(",") if ":" in item)
        model = parts.get("model_version", "").strip() or None
        scored = parts.get("score_date", "").strip()
        stamp: datetime | None = None
        if scored:
            try:
                parsed = datetime.fromisoformat(scored.replace("Z", "+00:00"))
                stamp = parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
            except ValueError:
                stamp = None
        return (model[:50] if model else None), stamp
    return None, None


def _probability(value: object) -> float | None:
    """A real number in 0–1, or nothing.

    NaN and infinity are refused explicitly: they compare false against everything, so a
    NaN score would sort unpredictably and silently misrank a finding.
    """
    if not isinstance(value, str):
        return None
    try:
        number = float(value.strip())
    except (TypeError, ValueError):
        return None
    if not isfinite(number) or not 0.0 <= number <= 1.0:
        return None
    return number


def _is_cve_id(value: str) -> bool:
    parts = value.strip().upper().split("-")
    return len(parts) == 3 and parts[0] == "CVE" and parts[1].isdigit() and parts[2].isdigit()


def _validated_cve_id(cve_id: str) -> str:
    if not _is_cve_id(cve_id):
        raise ValidationError(f"not a CVE id: {cve_id[:40]!r}")
    return cve_id.strip().upper()
