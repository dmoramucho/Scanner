"""KEV and EPSS: cache-first, defensive — and never a quiet "not exploited".

Fixtures and a fake HTTP client; CI never touches CISA or FIRST (AGENTS.md §43).

The section that carries this file is the last one. **A KEV lookup that could not be
performed must raise, never return `False`.** A `False` on a failed fetch would silently
de-prioritise an actively-exploited vulnerability, which is the worst false negative this
system could produce (AGENTS.md §4.9, §67). EPSS carries the same rule one step softer:
`None` means FIRST has not scored the CVE, never that we could not ask.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from adapters.feed.epss import FirstEpssSource
from adapters.feed.http import HttpResponse
from adapters.feed.kev import CisaKevSource
from domain.errors import DependencyError, ValidationError
from domain.models import EpssScore, FeedSnapshot, KevEntry
from domain.ports import EpssSource, KevSource

KEV_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "kev"
EPSS_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "epss"

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)

EXPLOITED = "CVE-2021-44228"  # Log4Shell — in the fixture catalog
NOT_EXPLOITED = "CVE-2019-11111"  # not in it


def kev_fixture(name: str) -> bytes:
    return (KEV_FIXTURES / f"{name}.json").read_bytes()


def epss_fixture(name: str) -> bytes:
    return (EPSS_FIXTURES / name).read_bytes()


class FakeHttp:
    def __init__(
        self, responses: Sequence[HttpResponse] | None = None, *, raises: Exception | None = None
    ) -> None:
        self.responses = list(responses or [])
        self.raises = raises
        self.calls = 0

    def get(
        self, url: str, *, params: Mapping[str, str], headers: Mapping[str, str], timeout: float
    ) -> HttpResponse:
        self.calls += 1
        if self.raises is not None:
            raise self.raises
        if not self.responses:
            raise AssertionError("the adapter made more requests than the test scripted")
        return self.responses.pop(0)


class FakeKevCache:
    def __init__(self) -> None:
        self.entries: dict[tuple[str, str], KevEntry] = {}
        self.snapshots: dict[str, FeedSnapshot] = {}
        self.replacements = 0

    def snapshot(self, source: str) -> FeedSnapshot | None:
        return self.snapshots.get(source)

    def entry(self, source: str, cve_id: str) -> KevEntry | None:
        return self.entries.get((source, cve_id))

    def replace(self, source: str, entries: Sequence[KevEntry], snapshot: FeedSnapshot) -> int:
        self.replacements += 1
        self.entries = {(source, entry.cve_id): entry for entry in entries}
        self.snapshots[source] = snapshot
        return len(entries)


class FakeEpssCache:
    def __init__(self) -> None:
        self.scores: dict[tuple[str, str], EpssScore] = {}
        self.snapshots: dict[str, FeedSnapshot] = {}
        self.replacements = 0

    def snapshot(self, source: str) -> FeedSnapshot | None:
        return self.snapshots.get(source)

    def score(self, source: str, cve_id: str) -> EpssScore | None:
        return self.scores.get((source, cve_id))

    def replace(self, source: str, scores: Sequence[EpssScore], snapshot: FeedSnapshot) -> int:
        self.replacements += 1
        self.scores = {(source, score.cve_id): score for score in scores}
        self.snapshots[source] = snapshot
        return len(scores)


def ok(body: bytes) -> HttpResponse:
    return HttpResponse(status_code=200, body=body, headers={})


def status(code: int) -> HttpResponse:
    return HttpResponse(status_code=code, body=b"{}", headers={})


def kev(
    http: FakeHttp, cache: FakeKevCache | None = None, *, now: datetime = NOW, **kwargs: object
) -> CisaKevSource:
    return CisaKevSource(
        cache or FakeKevCache(),
        catalog_url="https://cisa.example/kev.json",
        client=http,
        clock=lambda: now,
        **kwargs,  # type: ignore[arg-type]
    )


def epss(
    http: FakeHttp, cache: FakeEpssCache | None = None, *, now: datetime = NOW, **kwargs: object
) -> FirstEpssSource:
    return FirstEpssSource(
        cache or FakeEpssCache(),
        snapshot_url="https://first.example/epss.csv.gz",
        client=http,
        clock=lambda: now,
        **kwargs,  # type: ignore[arg-type]
    )


# ------------------------------------------------------------------------- KEV


def test_a_catalogued_cve_reports_exploited() -> None:
    assert kev(FakeHttp([ok(kev_fixture("catalog"))])).is_known_exploited(EXPLOITED) is True


def test_a_cve_not_in_the_catalog_reports_not_exploited() -> None:
    """A real answer: CISA published a catalog and this CVE is not in it."""
    assert kev(FakeHttp([ok(kev_fixture("catalog"))])).is_known_exploited(NOT_EXPLOITED) is False


def test_the_catalog_entry_carries_cisas_metadata_and_provenance() -> None:
    entry = kev(FakeHttp([ok(kev_fixture("catalog"))])).entry(EXPLOITED)

    assert entry is not None
    assert entry.source == "cisa_kev"
    assert entry.vendor == "Apache"
    assert entry.product == "Log4j2"
    assert entry.date_added == datetime(2021, 12, 10, tzinfo=UTC)
    assert entry.due_date == datetime(2021, 12, 24, tzinfo=UTC)
    assert entry.known_ransomware is True
    assert entry.fetched_at == NOW
    assert entry.raw_record_ref == f"cisa_kev:{EXPLOITED}"


def test_cisas_ransomware_flag_is_read_as_a_tri_state() -> None:
    """ "Known" and "Unknown" are claims; anything else is not a claim either way."""
    source = kev(FakeHttp([ok(kev_fixture("catalog"))]))

    listed = source.entry("CVE-2023-4966")
    assert listed is not None
    assert listed.known_ransomware is False  # CISA wrote "Unknown"


def test_a_second_lookup_is_served_from_cache() -> None:
    http = FakeHttp([ok(kev_fixture("catalog"))])
    source = kev(http, FakeKevCache())

    source.is_known_exploited(EXPLOITED)
    source.is_known_exploited(NOT_EXPLOITED)

    assert http.calls == 1
    assert source.fetch_report().served_from_cache == 1


def test_a_stale_catalog_is_refetched() -> None:
    cache = FakeKevCache()
    cache.snapshots["cisa_kev"] = FeedSnapshot(
        source="cisa_kev", fetched_at=NOW - timedelta(days=3), record_count=0
    )
    http = FakeHttp([ok(kev_fixture("catalog"))])

    assert kev(http, cache, ttl_hours=6).is_known_exploited(EXPLOITED) is True
    assert http.calls == 1


def test_a_refresh_replaces_the_catalog_rather_than_adding_to_it() -> None:
    """CISA withdraws entries. A catalog we only appended to would keep asserting an
    exploitation that has been retracted."""
    cache = FakeKevCache()
    http = FakeHttp([ok(kev_fixture("catalog")), ok(kev_fixture("malformed"))])
    source = kev(http, cache)

    source.refresh()
    assert source.is_known_exploited("CVE-2023-4966") is True

    source.refresh()  # the second catalog does not contain CVE-2023-4966
    assert source.is_known_exploited("CVE-2023-4966") is False
    assert cache.replacements == 2


def test_a_malformed_entry_is_skipped_and_the_catalog_still_loads() -> None:
    source = kev(FakeHttp([ok(kev_fixture("malformed"))]))

    source.refresh()

    report = source.fetch_report()
    assert report.skipped_count == 4
    assert source.is_known_exploited(EXPLOITED) is True  # the good entry landed
    salvaged = source.entry("CVE-2024-27316")
    assert salvaged is not None
    assert salvaged.date_added is None  # "not-a-date" became nothing rather than a guess
    assert salvaged.known_ransomware is None  # 42 is not a claim


def test_a_skip_never_echoes_the_entry() -> None:
    source = kev(FakeHttp([ok(kev_fixture("malformed"))]))
    source.refresh()

    for skipped in source.fetch_report().skipped:
        assert "bare string" not in str(skipped.model_dump())


@pytest.mark.parametrize("hostile", ["not-a-cve", "", "CVE-XXXX-1", "'; drop table"])
def test_a_malformed_cve_id_is_refused_before_any_request(hostile: str) -> None:
    http = FakeHttp([])

    with pytest.raises(ValidationError, match="not a CVE id"):
        kev(http).is_known_exploited(hostile)

    assert http.calls == 0


# ------------------------------------------------------------------------ EPSS


def test_a_scored_cve_returns_its_score_and_percentile() -> None:
    score = epss(FakeHttp([ok(epss_fixture("scores.csv"))])).score_for(EXPLOITED)

    assert score is not None
    assert score.score == pytest.approx(0.94366)
    assert score.percentile == pytest.approx(0.99942)
    assert score.source == "epss"


def test_the_gzipped_artifact_is_read_too() -> None:
    """FIRST publishes a `.csv.gz`: the bytes themselves are a gzip member, which is not the
    same thing as a gzip-encoded response."""
    score = epss(FakeHttp([ok(epss_fixture("scores.csv.gz"))])).score_for(EXPLOITED)

    assert score is not None
    assert score.score == pytest.approx(0.94366)


def test_the_model_version_and_score_date_are_carried_as_provenance() -> None:
    """An EPSS score from two model generations ago is not comparable to today's, so which
    model produced it is part of the fact (AGENTS.md §2.2)."""
    score = epss(FakeHttp([ok(epss_fixture("scores.csv"))])).score_for(EXPLOITED)

    assert score is not None
    assert score.model_version == "v2025.03.14"
    assert score.scored_at == datetime(2026, 8, 16, tzinfo=UTC)
    assert score.fetched_at == NOW
    assert score.raw_record_ref == f"epss:{EXPLOITED}"


def test_an_unscored_cve_returns_none() -> None:
    """A real answer about a real absence: FIRST has not scored this CVE."""
    assert epss(FakeHttp([ok(epss_fixture("scores.csv"))])).score_for(NOT_EXPLOITED) is None


def test_a_second_lookup_is_served_from_the_snapshot() -> None:
    http = FakeHttp([ok(epss_fixture("scores.csv"))])
    source = epss(http, FakeEpssCache())

    source.score_for(EXPLOITED)
    source.score_for("CVE-2024-27316")

    assert http.calls == 1
    assert source.fetch_report().served_from_cache == 1


@pytest.mark.parametrize(
    "cve_id",
    ["CVE-2024-11111", "CVE-2024-22222", "CVE-2024-33333", "CVE-2024-44444", "CVE-2024-55555"],
)
def test_a_score_that_is_not_a_probability_is_refused(cve_id: str) -> None:
    """Unparseable, out of range, NaN, negative, empty. A score that cannot be compared
    cannot rank anything, and a NaN would sort unpredictably."""
    source = epss(FakeHttp([ok(epss_fixture("messy.csv"))]))

    assert source.score_for(cve_id) is None
    assert source.fetch_report().skipped_count == 6  # five bad scores plus the bad id


def test_the_good_rows_in_a_messy_snapshot_still_land() -> None:
    source = epss(FakeHttp([ok(epss_fixture("messy.csv"))]))

    assert source.score_for(EXPLOITED) is not None
    assert source.score_for("CVE-2023-4966") is not None


def test_a_snapshot_without_a_cve_column_is_refused() -> None:
    with pytest.raises(ValidationError, match="no 'cve' column"):
        epss(FakeHttp([ok(epss_fixture("no_cve_column.csv"))])).score_for(EXPLOITED)


def test_a_snapshot_with_no_usable_rows_does_not_replace_a_good_one() -> None:
    """An empty snapshot is not a world in which nothing is exploitable; it is a download
    that went wrong. Replacing the cache with it would erase every score we have."""
    cache = FakeEpssCache()
    good = FakeHttp([ok(epss_fixture("scores.csv"))])
    epss(good, cache).score_for(EXPLOITED)
    assert cache.scores

    empty = FakeHttp([ok(b"#model_version:v1\ncve,epss,percentile\n")])
    with pytest.raises(ValidationError, match="refusing to replace"):
        epss(empty, cache).refresh()

    assert cache.scores  # untouched


# --------------------- FAILURE IS NEVER "NOT EXPLOITED" (the safety net)


def test_a_kev_fetch_failure_raises_rather_than_returning_false() -> None:
    """The assertion this whole file exists for. A `False` here would silently
    de-prioritise an actively-exploited vulnerability."""
    http = FakeHttp(raises=OSError("connection reset"))

    with pytest.raises(DependencyError, match="could not reach the KEV catalog") as exc_info:
        kev(http).is_known_exploited(EXPLOITED)

    assert exc_info.value.retryable is True


def test_a_persistent_kev_outage_raises_rather_than_returning_false() -> None:
    http = FakeHttp([status(503), status(503), status(503)])

    with pytest.raises(DependencyError, match="not the same as it not being exploited"):
        kev(http, max_retries=2).is_known_exploited(EXPLOITED)


@pytest.mark.parametrize("code", [400, 403, 404])
def test_a_permanent_kev_rejection_raises_rather_than_returning_false(code: int) -> None:
    with pytest.raises(DependencyError, match="rejected") as exc_info:
        kev(FakeHttp([status(code)])).is_known_exploited(EXPLOITED)

    assert exc_info.value.retryable is False


def test_a_kev_body_that_is_not_json_raises() -> None:
    """A CDN error page is not an empty catalog."""
    with pytest.raises(ValidationError, match="not JSON"):
        kev(FakeHttp([ok(b"<html>502 Bad Gateway</html>")])).is_known_exploited(EXPLOITED)


def test_an_unrecognised_kev_shape_raises_rather_than_clearing_the_catalog() -> None:
    """An empty catalog would mark every CVE in existence as un-exploited."""
    with pytest.raises(ValidationError, match="no 'vulnerabilities' list"):
        kev(FakeHttp([ok(kev_fixture("unexpected_shape"))])).is_known_exploited(EXPLOITED)


def test_a_failed_kev_fetch_leaves_the_cache_untouched() -> None:
    """The dangerous variant: a failure recorded as a snapshot would answer "not exploited"
    for everything, from cache, for the whole TTL."""
    cache = FakeKevCache()

    with pytest.raises(DependencyError):
        kev(FakeHttp(raises=OSError("down")), cache).is_known_exploited(EXPLOITED)

    assert cache.snapshot("cisa_kev") is None
    assert cache.replacements == 0


def test_not_listed_and_could_not_check_are_distinguishable_to_a_caller() -> None:
    """Side by side, because the distinction is the entire point: one returns False, the
    other raises."""
    assert kev(FakeHttp([ok(kev_fixture("catalog"))])).is_known_exploited(NOT_EXPLOITED) is False

    with pytest.raises(DependencyError):
        kev(FakeHttp(raises=OSError("down"))).is_known_exploited(NOT_EXPLOITED)


def test_an_epss_fetch_failure_raises_rather_than_returning_none() -> None:
    http = FakeHttp(raises=TimeoutError("timed out"))

    with pytest.raises(DependencyError, match="could not reach the EPSS snapshot") as exc_info:
        epss(http).score_for(EXPLOITED)

    assert exc_info.value.retryable is True


def test_no_score_and_could_not_check_are_distinguishable_to_a_caller() -> None:
    assert epss(FakeHttp([ok(epss_fixture("scores.csv"))])).score_for(NOT_EXPLOITED) is None

    with pytest.raises(DependencyError):
        epss(FakeHttp(raises=OSError("down"))).score_for(NOT_EXPLOITED)


def test_a_failed_epss_fetch_leaves_the_cache_untouched() -> None:
    cache = FakeEpssCache()

    with pytest.raises(DependencyError):
        epss(FakeHttp(raises=OSError("down")), cache).score_for(EXPLOITED)

    assert cache.snapshot("epss") is None
    assert cache.replacements == 0


# ------------------------------------------------------------------ conformance


def test_the_adapters_satisfy_their_ports() -> None:
    known_exploited: KevSource = CisaKevSource(FakeKevCache())
    scores: EpssSource = FirstEpssSource(FakeEpssCache())

    assert callable(known_exploited.is_known_exploited)
    assert callable(known_exploited.refresh)
    assert callable(scores.score_for)
    assert callable(scores.refresh)
