"""KEV and EPSS caches against the real store.

The adapters' fetch logic is covered hermetically in `tests/test_kev_epss_feeds.py`. This
file asserts what only the database can show: that a refresh swaps the whole snapshot
atomically, and that the snapshot marker makes "not listed" distinguishable from "never
loaded" across a round trip (m3-design §2).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
import pytest

from adapters.feed.epss import FirstEpssSource
from adapters.feed.http import HttpResponse
from adapters.feed.kev import CisaKevSource
from adapters.postgres.signal_cache import PostgresEpssCache, PostgresKevCache
from domain.errors import DependencyError
from domain.models import EpssScore, FeedSnapshot, KevEntry

pytestmark = pytest.mark.integration

#: These tables are deliberately not tenant-scoped, so the usual per-tenant isolation cannot
#: work — and the rolling-back `conn` fixture cannot either: `replace()` opens its own
#: transaction, which *commits* when it happens to be the outermost one. So the isolation is
#: explicit: truncate the three cache tables before each test. That is a fair thing to do to
#: a cache, and it makes the isolation visible rather than dependent on transaction nesting.

Connection = psycopg.Connection[tuple[Any, ...]]

KEV_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "kev"
EPSS_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "epss"
NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
EXPLOITED = "CVE-2021-44228"


class ScriptedHttp:
    def __init__(self, bodies: list[bytes], *, raises: Exception | None = None) -> None:
        self.bodies = bodies
        self.raises = raises
        self.calls = 0

    def get(
        self, url: str, *, params: Mapping[str, str], headers: Mapping[str, str], timeout: float
    ) -> HttpResponse:
        self.calls += 1
        if self.raises is not None:
            raise self.raises
        return HttpResponse(status_code=200, body=self.bodies.pop(0), headers={})


@pytest.fixture(autouse=True)
def empty_caches(autocommit_conn: Connection) -> None:
    autocommit_conn.execute("truncate kev_cache, epss_cache, feed_snapshot")


def test_a_kev_entry_round_trips(autocommit_conn: Connection) -> None:
    cache = PostgresKevCache(autocommit_conn)

    cache.replace(
        "cisa_kev",
        [
            KevEntry(
                cve_id=EXPLOITED,
                vendor="Apache",
                product="Log4j2",
                name="Log4Shell",
                date_added=datetime(2021, 12, 10, tzinfo=UTC),
                due_date=datetime(2021, 12, 24, tzinfo=UTC),
                known_ransomware=True,
                fetched_at=NOW,
                raw_record_ref=f"cisa_kev:{EXPLOITED}",
            )
        ],
        FeedSnapshot(source="cisa_kev", fetched_at=NOW, record_count=1),
    )

    entry = cache.entry("cisa_kev", EXPLOITED)
    assert entry is not None
    assert entry.product == "Log4j2"
    assert entry.known_ransomware is True
    assert entry.date_added == datetime(2021, 12, 10, tzinfo=UTC)


def test_an_unloaded_catalog_has_no_snapshot(autocommit_conn: Connection) -> None:
    """The distinction the marker exists for: no snapshot means nobody ever loaded the
    catalog, which is not the same as a CVE not being in it."""
    assert PostgresKevCache(autocommit_conn).snapshot("cisa_kev") is None


def test_a_refresh_swaps_the_whole_catalog(autocommit_conn: Connection) -> None:
    cache = PostgresKevCache(autocommit_conn)
    snapshot = FeedSnapshot(source="cisa_kev", fetched_at=NOW, record_count=1)

    cache.replace("cisa_kev", [KevEntry(cve_id="CVE-2020-1", fetched_at=NOW)], snapshot)
    cache.replace("cisa_kev", [KevEntry(cve_id="CVE-2021-2", fetched_at=NOW)], snapshot)

    assert cache.entry("cisa_kev", "CVE-2020-1") is None  # withdrawn by CISA, gone from here
    assert cache.entry("cisa_kev", "CVE-2021-2") is not None
    row = autocommit_conn.execute("select count(*) from kev_cache").fetchone()
    assert row is not None
    assert row[0] == 1


def test_an_epss_score_round_trips(autocommit_conn: Connection) -> None:
    cache = PostgresEpssCache(autocommit_conn)

    cache.replace(
        "epss",
        [
            EpssScore(
                cve_id=EXPLOITED,
                score=0.94366,
                percentile=0.99942,
                model_version="v2025.03.14",
                scored_at=NOW,
                fetched_at=NOW,
            )
        ],
        FeedSnapshot(source="epss", fetched_at=NOW, record_count=1),
    )

    score = cache.score("epss", EXPLOITED)
    assert score is not None
    assert score.score == pytest.approx(0.94366)
    assert score.percentile == pytest.approx(0.99942)
    assert score.model_version == "v2025.03.14"


def test_the_two_snapshots_are_independent(autocommit_conn: Connection) -> None:
    kev_cache = PostgresKevCache(autocommit_conn)
    epss_cache = PostgresEpssCache(autocommit_conn)

    kev_cache.replace(
        "cisa_kev",
        [KevEntry(cve_id=EXPLOITED, fetched_at=NOW)],
        FeedSnapshot(source="cisa_kev", fetched_at=NOW, record_count=1),
    )

    assert kev_cache.snapshot("cisa_kev") is not None
    assert epss_cache.snapshot("epss") is None  # loading one says nothing about the other


def test_the_kev_source_and_the_real_cache_work_together(autocommit_conn: Connection) -> None:
    http = ScriptedHttp([(KEV_FIXTURES / "catalog.json").read_bytes()])
    source = CisaKevSource(
        PostgresKevCache(autocommit_conn),
        catalog_url="https://cisa.example/kev.json",
        client=http,
        clock=lambda: NOW,
    )

    assert source.is_known_exploited(EXPLOITED) is True
    assert source.is_known_exploited("CVE-2019-11111") is False
    assert http.calls == 1  # the second answer came from the database


def test_the_epss_source_and_the_real_cache_work_together(autocommit_conn: Connection) -> None:
    http = ScriptedHttp([(EPSS_FIXTURES / "scores.csv.gz").read_bytes()])
    source = FirstEpssSource(
        PostgresEpssCache(autocommit_conn),
        snapshot_url="https://first.example/epss.csv.gz",
        client=http,
        clock=lambda: NOW,
    )

    score = source.score_for(EXPLOITED)
    assert score is not None
    assert score.score == pytest.approx(0.94366)
    assert source.score_for("CVE-2019-11111") is None
    assert http.calls == 1


def test_a_failed_refresh_leaves_the_stored_catalog_intact(autocommit_conn: Connection) -> None:
    """The one that would hurt: a failure must not clear the catalog, or every CVE would
    answer "not exploited" from a cache that had been emptied."""
    cache = PostgresKevCache(autocommit_conn)
    good = ScriptedHttp([(KEV_FIXTURES / "catalog.json").read_bytes()])
    CisaKevSource(cache, client=good, clock=lambda: NOW).refresh()
    assert cache.entry("cisa_kev", EXPLOITED) is not None

    broken = ScriptedHttp([], raises=OSError("down"))
    with pytest.raises(DependencyError):
        CisaKevSource(cache, client=broken, clock=lambda: NOW).refresh()

    assert cache.entry("cisa_kev", EXPLOITED) is not None  # still there
    snapshot = cache.snapshot("cisa_kev")
    assert snapshot is not None
    assert snapshot.fetched_at == NOW  # and still the good one


def test_a_stale_snapshot_triggers_a_refetch(autocommit_conn: Connection) -> None:
    cache = PostgresKevCache(autocommit_conn)
    cache.replace(
        "cisa_kev",
        [],
        FeedSnapshot(source="cisa_kev", fetched_at=NOW - timedelta(days=2), record_count=0),
    )
    http = ScriptedHttp([(KEV_FIXTURES / "catalog.json").read_bytes()])

    source = CisaKevSource(cache, client=http, clock=lambda: NOW, ttl_hours=6)

    assert source.is_known_exploited(EXPLOITED) is True
    assert http.calls == 1


def test_neither_cache_is_tenant_scoped(autocommit_conn: Connection) -> None:
    """KEV and EPSS are facts about software in the world, identical for every tenant. The
    tenant-scoped conclusions live in `vulnerability_match` (P14)."""
    columns = autocommit_conn.execute(
        """
        select column_name from information_schema.columns
        where table_name in ('kev_cache', 'epss_cache', 'feed_snapshot')
        """
    ).fetchall()

    assert "tenant_id" not in {str(row[0]) for row in columns}
