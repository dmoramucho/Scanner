"""CISA KEV — is this CVE being exploited in the wild?

The most consequential boolean in the product. A KEV listing is the override that keeps a
finding visible regardless of how confident the version match was (dossier contract §7,
m3-design §2), so this adapter is written around one rule:

**A lookup that could not be performed raises. It never returns `False`.**

`False` means CISA published a catalog and this CVE is not in it — a real answer, and a
useful one. If a failed fetch also produced `False`, an actively-exploited vulnerability
would be silently de-prioritised, which is the worst false negative this system could
produce (AGENTS.md §4.9, §67). Every path below either answers from a catalog we actually
have, or raises.

The catalog is small (a couple of thousand entries) and changes slowly, so it is fetched
whole and cached with a TTL, not queried per CVE. A refresh *replaces* the cached catalog
rather than adding to it: CISA does withdraw entries, and a catalog we only ever appended to
would keep asserting an exploitation that has been retracted.

Entries are untrusted input (AGENTS.md §2.9): a malformed one is skipped with a reason and
counted, and the rest of the catalog still loads.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Final

from adapters.feed.http import MAX_RESPONSE_BYTES, HttpClient, HttpxClient, decompress_if_gzipped
from domain.errors import DependencyError, ValidationError
from domain.models import FeedFetchReport, FeedSnapshot, KevEntry, SkippedRecord
from domain.ports import KevCache

SOURCE: Final = "cisa_kev"

DEFAULT_CATALOG_URL: Final = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

#: CISA adds to the catalog when it learns of exploitation — irregularly, but rarely more
#: than a few times a week. Six hours keeps us current without hammering a static file.
DEFAULT_TTL_HOURS: Final = 6.0

DEFAULT_TIMEOUT_SECONDS: Final = 30.0

#: A catalog this small cannot legitimately have more entries than this. A response that
#: does is not the catalog.
MAX_ENTRIES: Final = 100_000

_MAX_FIELD: Final = 500

#: Statuses worth trying again. CISA serves a static file from a CDN, so a 5xx is transient
#: far more often than it is meaningful.
RETRYABLE_STATUSES: Final = frozenset({429, 500, 502, 503, 504})


class CisaKevSource:
    """`KevSource` over CISA's published catalog, cached locally."""

    def __init__(
        self,
        cache: KevCache,
        *,
        catalog_url: str = DEFAULT_CATALOG_URL,
        ttl_hours: float = DEFAULT_TTL_HOURS,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = 2,
        client: HttpClient | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        sleep: Callable[[float], None] = lambda _: None,
    ) -> None:
        self._cache = cache
        self._url = catalog_url
        self._ttl = timedelta(hours=ttl_hours)
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._client = client if client is not None else HttpxClient()
        self._clock = clock
        self._sleep = sleep
        self._report = FeedFetchReport()

    # ------------------------------------------------------------------- the port

    def is_known_exploited(self, cve_id: str) -> bool:
        """True if CISA lists this CVE as exploited in the wild.

        The `False` this returns always means "CISA published a catalog and this CVE is not
        in it". It never means "we could not find out" — that raises.
        """
        return self.entry(cve_id) is not None

    def entry(self, cve_id: str) -> KevEntry | None:
        """The catalog entry, or None if this CVE is not listed.

        `_ensure_catalog` either leaves a usable catalog in the cache or raises, so by the
        time the lookup happens, `None` can only mean "not in the catalog".
        """
        identifier = _validated_cve_id(cve_id)
        self._ensure_catalog()
        self._report.queries += 1
        return self._cache.entry(SOURCE, identifier)

    def refresh(self) -> FeedFetchReport:
        """Reload the catalog now, whatever the cache says."""
        self._load()
        return self._report

    def fetch_report(self) -> FeedFetchReport:
        return self._report

    # ------------------------------------------------------------------ internals

    def _ensure_catalog(self) -> None:
        """Guarantee a usable catalog, or raise.

        The absence of a snapshot is the case that matters: an empty cache means the
        catalog has never been loaded, and answering "not listed" from it would be
        answering from nothing at all.
        """
        snapshot = self._cache.snapshot(SOURCE)
        if snapshot is not None and self._clock() - snapshot.fetched_at < self._ttl:
            self._report.served_from_cache += 1
            return
        self._load()

    def _load(self) -> None:
        """Fetch the catalog and swap it in. Every failure raises; none returns quietly."""
        payload = self._request()
        fetched_at = self._clock()
        entries = self._normalize(payload, fetched_at)

        # Only after a successful parse: a half-read catalog must never replace a good one.
        self._cache.replace(
            SOURCE,
            entries,
            FeedSnapshot(
                source=SOURCE,
                fetched_at=fetched_at,
                record_count=len(entries),
                raw_record_ref=self._url,
            ),
        )
        self._report.fetched_from_feed += 1
        self._report.records_normalized += len(entries)

    def _request(self) -> object:
        """One GET, retried on transient statuses. Returns a payload or raises.

        There is no branch here that returns an empty catalog because something went
        wrong — that is the property this module exists to hold (AGENTS.md §67).
        """
        attempt = 0
        while True:
            try:
                response = self._client.get(
                    self._url,
                    params={},
                    headers={"Accept": "application/json"},
                    timeout=self._timeout,
                )
            except OSError as exc:
                raise DependencyError(
                    f"could not reach the KEV catalog: {type(exc).__name__}", retryable=True
                ) from exc

            if response.status_code in RETRYABLE_STATUSES:
                attempt += 1
                if attempt > self._max_retries:
                    raise DependencyError(
                        f"KEV catalog returned {response.status_code} after "
                        f"{self._max_retries} retries; not knowing whether a CVE is "
                        "exploited is not the same as it not being exploited",
                        retryable=True,
                    )
                self._report.rate_limited_retries += 1
                self._sleep(float(attempt))
                continue

            if response.status_code != 200:
                raise DependencyError(
                    f"KEV catalog request rejected with {response.status_code}",
                    retryable=False,
                )

            body = decompress_if_gzipped(response.body)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ValidationError("KEV catalog exceeded the maximum response size")

            try:
                parsed: object = json.loads(body)
            except ValueError as exc:
                # A body that is not JSON is a CDN error page. Treating it as an empty
                # catalog would mark every CVE as un-exploited.
                raise ValidationError(f"KEV catalog was not JSON: {exc}") from exc
            return parsed

    def _normalize(self, payload: object, fetched_at: datetime) -> list[KevEntry]:
        """Parse the catalog defensively. A malformed entry is skipped, not fatal."""
        if not isinstance(payload, dict):
            raise ValidationError("KEV catalog was not a JSON object")

        vulnerabilities = payload.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            # Not a shape we recognise. Refusing is the only safe reading: an empty catalog
            # would silently clear every known exploitation.
            raise ValidationError("KEV catalog has no 'vulnerabilities' list")

        if len(vulnerabilities) > MAX_ENTRIES:
            raise ValidationError(f"KEV catalog claimed more than {MAX_ENTRIES} entries")

        entries: list[KevEntry] = []
        seen: set[str] = set()
        for item in vulnerabilities:
            entry = self._normalize_one(item, fetched_at)
            if entry is None or entry.cve_id in seen:
                continue
            seen.add(entry.cve_id)
            entries.append(entry)
        return entries

    def _normalize_one(self, item: object, fetched_at: datetime) -> KevEntry | None:
        if not isinstance(item, dict):
            self._skip(None, "entry is not an object")
            return None

        cve_id = _clean(item.get("cveID"), 32)
        if not cve_id or not _is_cve_id(cve_id):
            self._skip(cve_id, "missing or malformed CVE id")
            return None

        return KevEntry(
            cve_id=cve_id.upper(),
            source=SOURCE,
            vendor=_clean(item.get("vendorProject"), _MAX_FIELD),
            product=_clean(item.get("product"), _MAX_FIELD),
            name=_clean(item.get("vulnerabilityName"), _MAX_FIELD),
            date_added=_date(item.get("dateAdded")),
            due_date=_date(item.get("dueDate")),
            known_ransomware=_ransomware_flag(item.get("knownRansomwareCampaignUse")),
            fetched_at=fetched_at,
            raw_record_ref=f"{SOURCE}:{cve_id.upper()}",
        )

    def _skip(self, identifier: str | None, reason: str) -> None:
        self._report.skipped.append(SkippedRecord(identifier=identifier, reason=reason))


# ------------------------------------------------------------------- field parsing


def _clean(value: object, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    text = "".join(char for char in value if char.isprintable() or char == " ").strip()
    return text[:limit] or None


def _date(value: object) -> datetime | None:
    """CISA publishes plain `YYYY-MM-DD`. Read as UTC rather than as the host's local day."""
    if not isinstance(value, str):
        return None
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError:
        return None


def _ransomware_flag(value: object) -> bool | None:
    """CISA writes "Known" / "Unknown". Anything else is not a claim either way."""
    if not isinstance(value, str):
        return None
    normalized = value.strip().casefold()
    if normalized == "known":
        return True
    if normalized == "unknown":
        return False
    return None


def _is_cve_id(value: str) -> bool:
    parts = value.strip().upper().split("-")
    return len(parts) == 3 and parts[0] == "CVE" and parts[1].isdigit() and parts[2].isdigit()


def _validated_cve_id(cve_id: str) -> str:
    if not _is_cve_id(cve_id):
        raise ValidationError(f"not a CVE id: {cve_id[:40]!r}")
    return cve_id.strip().upper()
