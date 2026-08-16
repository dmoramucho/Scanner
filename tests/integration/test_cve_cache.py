"""The CVE cache against the real store.

The adapter's fetch logic is covered hermetically in `tests/test_nvd_feed.py`. This file
asserts what only the database can show: that a re-fetch refreshes rather than duplicating,
and — the one that matters — that *"we asked NVD about this CPE and the answer was none"*
survives a round trip, distinguishable from "nobody ever asked" (m3-design §2).
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import psycopg
import pytest

from adapters.feed.http import HttpResponse
from adapters.feed.nvd import NvdVulnerabilityFeed
from adapters.postgres.cve_cache import PostgresCveCache
from domain.models import CveQueryCacheEntry, CveRecord, CvssSeverity

pytestmark = pytest.mark.integration

#: These tests use the rolling-back `conn` fixture rather than `autocommit_conn`. Every
#: other integration suite isolates itself with a fresh `tenant_id`, which cannot work here:
#: the CVE cache is deliberately *not* tenant-scoped, so two tests would see each other's
#: rows. Rollback is the isolation, and it costs nothing — the cache needs no autocommit.

Connection = psycopg.Connection[tuple[Any, ...]]

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "nvd"
NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)
APACHE = "cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*"
OBSCURE = "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"


class ScriptedHttp:
    def __init__(self, bodies: list[bytes]) -> None:
        self.bodies = bodies
        self.calls = 0

    def get(
        self,
        url: str,
        *,
        params: Mapping[str, str],
        headers: Mapping[str, str],
        timeout: float,
    ) -> HttpResponse:
        self.calls += 1
        if not self.bodies:
            raise AssertionError("the adapter made more requests than the test scripted")
        return HttpResponse(status_code=200, body=self.bodies.pop(0), headers={})


def fixture(name: str) -> bytes:
    return (FIXTURES / f"{name}.json").read_bytes()


def record(cve_id: str, *, score: float = 7.5, fetched_at: datetime = NOW) -> CveRecord:
    return CveRecord(
        cve_id=cve_id,
        source="nvd",
        description="a flaw",
        published_at=datetime(2024, 1, 15, tzinfo=UTC),
        last_modified_at=datetime(2024, 6, 2, tzinfo=UTC),
        cvss_score=score,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        cvss_version="3.1",
        severity=CvssSeverity.HIGH,
        cpe_criteria=[APACHE],
        references=["https://example.invalid/advisory"],
        fetched_at=fetched_at,
        raw_record_ref=f"nvd:{cve_id}",
    )


def stored_count(conn: Connection, table: str) -> int:
    row = conn.execute(f"select count(*) from {table}").fetchone()  # noqa: S608
    assert row is not None
    return int(row[0])


def test_a_record_round_trips_through_the_cache(conn: Connection) -> None:
    cache = PostgresCveCache(conn)

    created = cache.store([record("CVE-2024-27316")])

    assert created == 1
    [restored] = cache.records("nvd", ["CVE-2024-27316"])
    assert restored.cve_id == "CVE-2024-27316"
    assert restored.cvss_score == 7.5
    assert restored.severity is CvssSeverity.HIGH
    assert restored.cpe_criteria == [APACHE]
    assert restored.raw_record_ref == "nvd:CVE-2024-27316"
    assert restored.fetched_at == NOW


def test_re_storing_a_cve_refreshes_it_rather_than_duplicating(
    conn: Connection,
) -> None:
    """A CVE's contents genuinely change — a score is revised, a CPE range corrected — so a
    re-fetch updates the row it already has."""
    cache = PostgresCveCache(conn)

    assert cache.store([record("CVE-2024-11111", score=5.0)]) == 1
    assert cache.store([record("CVE-2024-11111", score=9.8)]) == 0  # known, refreshed

    [restored] = cache.records("nvd", ["CVE-2024-11111"])
    assert restored.cvss_score == 9.8
    assert stored_count(conn, "cve_cache") >= 1


def test_the_content_hash_changes_when_the_record_does(conn: Connection) -> None:
    """Tamper-evidence, and a cheap way to see whether a re-fetch actually changed anything
    (AGENTS.md §3)."""
    cache = PostgresCveCache(conn)

    cache.store([record("CVE-2024-22222", score=5.0)])
    before = conn.execute(
        "select content_hash from cve_cache where cve_id = 'CVE-2024-22222'"
    ).fetchone()
    cache.store([record("CVE-2024-22222", score=9.8)])
    after = conn.execute(
        "select content_hash from cve_cache where cve_id = 'CVE-2024-22222'"
    ).fetchone()

    assert before is not None
    assert after is not None
    assert bytes(before[0]) != bytes(after[0])


def test_an_empty_answer_survives_the_round_trip(conn: Connection) -> None:
    """The distinction the second table exists for: an entry with no CVE ids means the feed
    said "none"; `None` means nobody ever asked. Collapsing them is a false-negative path —
    a component would read as clean when it had never been checked."""
    cache = PostgresCveCache(conn)

    assert cache.query_entry("nvd", OBSCURE) is None  # never asked

    cache.store_query(CveQueryCacheEntry(cpe=OBSCURE, source="nvd", cve_ids=[], fetched_at=NOW))

    entry = cache.query_entry("nvd", OBSCURE)
    assert entry is not None  # asked
    assert entry.cve_ids == []  # and the answer was none
    assert entry.fetched_at == NOW


def test_re_asking_about_a_cpe_updates_the_entry_in_place(conn: Connection) -> None:
    cache = PostgresCveCache(conn)
    later = NOW + timedelta(days=1)

    cache.store_query(CveQueryCacheEntry(cpe=APACHE, source="nvd", cve_ids=[], fetched_at=NOW))
    cache.store_query(
        CveQueryCacheEntry(cpe=APACHE, source="nvd", cve_ids=["CVE-2024-27316"], fetched_at=later)
    )

    entry = cache.query_entry("nvd", APACHE)
    assert entry is not None
    assert entry.cve_ids == ["CVE-2024-27316"]
    assert entry.fetched_at == later
    assert stored_count(conn, "cve_query_cache") == 1


def test_the_feed_and_the_real_cache_work_together(conn: Connection) -> None:
    """End to end with a scripted NVD: the first call fetches, the second is served from
    the database without a request."""
    http = ScriptedHttp([fixture("cpe_with_cves")])
    cache = PostgresCveCache(conn)
    feed = NvdVulnerabilityFeed(
        cache,
        base_url="https://nvd.example/api",
        client=http,
        clock=lambda: NOW,
        sleep=lambda _: None,
        monotonic=lambda: 0.0,
    )

    first = feed.cves_for_cpe(APACHE)
    second = feed.cves_for_cpe(APACHE)

    assert http.calls == 1
    assert {r.cve_id for r in second} == {r.cve_id for r in first}
    report = feed.fetch_report()
    assert (report.fetched_from_feed, report.served_from_cache) == (1, 1)

    entry = cache.query_entry("nvd", APACHE)
    assert entry is not None
    assert sorted(entry.cve_ids) == sorted(r.cve_id for r in first)


def test_a_cpe_nvd_knows_nothing_about_is_cached_as_such(
    conn: Connection,
) -> None:
    """The same path for the answer that matters most, through the real store."""
    http = ScriptedHttp([fixture("cpe_with_no_cves")])
    feed = NvdVulnerabilityFeed(
        PostgresCveCache(conn),
        base_url="https://nvd.example/api",
        client=http,
        clock=lambda: NOW,
        sleep=lambda _: None,
        monotonic=lambda: 0.0,
    )

    assert feed.cves_for_cpe(OBSCURE) == []
    assert feed.cves_for_cpe(OBSCURE) == []

    assert http.calls == 1  # the "none" answer was cached, not re-asked


def test_the_cache_is_not_tenant_scoped(conn: Connection) -> None:
    """A CVE is a fact about software in the world, identical for every tenant. Scoping it
    would multiply the fetching by the number of tenants for nothing — and the tenant-scoped
    conclusions live in `vulnerability_match`, which is P14's (m3-design §2)."""
    columns = conn.execute(
        """
        select column_name from information_schema.columns
        where table_name in ('cve_cache', 'cve_query_cache')
        """
    ).fetchall()

    assert "tenant_id" not in {str(row[0]) for row in columns}
