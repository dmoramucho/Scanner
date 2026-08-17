"""What the API actually serves: the surfaces, in the order and shape the UI needs.

The security properties are asserted in `test_api_security.py`. This file is the contract:
the worklist comes back KEV-first with the reason each band was given, an asset carries its
VLAN *marked inferred*, its version-source badges and its priority evidence, and every error
maps to the status an HTTP client can act on.

It is the P17 alignment being validated end to end (m4-design §6): if a surface needs a field
the data model does not carry, it shows up here rather than in the frontend.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from api.security import read_connection
from config.settings import AppConfig
from tests.integration.estate import api_config, seed_asset, seed_match

pytestmark = pytest.mark.integration

Connection = psycopg.Connection[tuple[Any, ...]]
NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)


@pytest.fixture
def tenant() -> UUID:
    return uuid4()


@pytest.fixture
def config(tenant: UUID, migrated_database: str) -> AppConfig:
    return api_config(tenant, migrated_database)


@pytest.fixture
def client(config: AppConfig, conn: Connection) -> Iterator[TestClient]:
    app = create_app(config)
    app.dependency_overrides[read_connection] = lambda: conn
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def estate(conn: Connection, tenant: UUID) -> dict[str, UUID]:
    """A small estate with one of each thing the worklist ranks."""
    camera = seed_asset(conn, tenant, hostname="camera-01", address="10.0.60.14")
    server = seed_asset(conn, tenant, hostname="app-server-02", address="10.0.99.4")

    seed_match(conn, tenant, camera, cve_id="CVE-2023-25690", kev=True)
    seed_match(conn, tenant, server, cve_id="CVE-2024-27316", kev=False)
    conn.execute(
        """
        insert into vulnerability_match (tenant_id, asset_id, cve_id, matched_cpe,
            version_source, confidence_state, kev, epss, cvss_score, priority,
            priority_rule, priority_reason, derivation)
        values (%s, %s, 'CVE-2024-0001', 'cpe:2.3:a:v:p:1:*:*:*:*:*:*:*', 'banner',
                'probable', false, 0.02, 8.1, 'p3', 'probable-severe-unverified',
                'CVE-2024-0001 would matter if it is really installed, but the version is '
                'inferred from a banner.', 'deterministic')
        """,
        (tenant, server),
    )
    conn.execute(
        """
        insert into software_component (tenant_id, asset_id, cpe, name, version,
            version_source, confidence, is_current, first_seen_at, last_seen_at)
        values (%s, %s, 'cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*',
                'apache http_server', '2.4.53', 'package_manager', 0.95, true, %s, %s)
        """,
        (tenant, camera, NOW, NOW),
    )
    return {"camera": camera, "server": server}


# ------------------------------------------------------------------------ the worklist


def test_the_worklist_puts_kev_first(client: TestClient, estate: dict[str, UUID]) -> None:
    """The order is the product's opinion, and it comes from the store — the API does not
    re-rank, so what an analyst sees at the top is what `engine/priority.py` decided
    (ux-design §3.1)."""
    findings = client.get("/api/worklist").json()["findings"]

    assert findings[0]["cve_id"] == "CVE-2023-25690"
    assert findings[0]["kev"] is True
    assert findings[0]["priority"] == "p1"


def test_every_finding_carries_the_reason_for_its_band(
    client: TestClient, estate: dict[str, UUID]
) -> None:
    """P17's whole point, reaching the interface. A UI can show *why* something is P1
    without knowing the rules exist (ADR-0015)."""
    findings = client.get("/api/worklist").json()["findings"]

    for finding in findings:
        assert finding["priority_rule"]
        assert finding["cve_id"] in finding["priority_reason"]
    assert findings[0]["priority_rule"] == "kev-actively-exploited"
    assert "CISA" in findings[0]["priority_reason"]


def test_the_needs_verification_queue_holds_only_probable_findings(
    client: TestClient, estate: dict[str, UUID]
) -> None:
    """`probable` is a work queue — "verify by logging in" — not noise mixed in with
    confirmed findings (ux-design §2)."""
    body = client.get("/api/worklist").json()

    assert [item["cve_id"] for item in body["needs_verification"]] == ["CVE-2024-0001"]
    assert body["needs_verification"][0]["version_source"] == "banner"
    assert body["summary"]["needs_verification"] == 1


def test_the_summary_separates_shadow_it_from_unknown(
    client: TestClient, estate: dict[str, UUID]
) -> None:
    """Two assets, both unmanaged, neither ambiguous. The counts are reported separately so
    a UI cannot accidentally present "unknown" as shadow IT (ADR-0009)."""
    summary = client.get("/api/worklist").json()["summary"]

    assert summary["shadow_it_assets"] == 2
    assert summary["unknown_management_assets"] == 0
    assert summary["kev_findings"] == 1
    assert summary["p1_findings"] == 1


def test_the_worklist_limit_is_honoured_and_bounded(
    client: TestClient, estate: dict[str, UUID]
) -> None:
    assert len(client.get("/api/worklist?limit=1").json()["findings"]) == 1
    assert client.get("/api/worklist?limit=500").status_code == 422


# ------------------------------------------------------------------------ the inventory


def test_the_inventory_lists_assets_with_their_finding_counts(
    client: TestClient, estate: dict[str, UUID]
) -> None:
    body = client.get("/api/assets").json()

    assert body["total"] == 2
    by_label = {item["label"]: item for item in body["items"]}
    assert by_label["camera-01"]["kev_findings"] == 1
    assert by_label["camera-01"]["highest_priority"] == "p1"
    assert by_label["app-server-02"]["probable_findings"] == 1
    assert by_label["app-server-02"]["confirmed_findings"] == 1


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("has_kev=true", ["camera-01"]),
        ("has_kev=false", ["app-server-02"]),
        ("management_state=unmanaged", ["app-server-02", "camera-01"]),
        ("management_state=managed", []),
        ("asset_class=server", ["app-server-02", "camera-01"]),
        ("asset_class=embedded", []),
        ("q=camera", ["camera-01"]),
        ("q=10.0.99", ["app-server-02"]),
    ],
)
def test_the_inventory_filters(
    client: TestClient, estate: dict[str, UUID], query: str, expected: list[str]
) -> None:
    """A closed set of filters, each doing exactly what it says."""
    items = client.get(f"/api/assets?{query}").json()["items"]

    assert sorted(item["label"] for item in items) == sorted(expected)


def test_the_inventory_paginates(client: TestClient, estate: dict[str, UUID]) -> None:
    first = client.get("/api/assets?limit=1&offset=0").json()
    second = client.get("/api/assets?limit=1&offset=1").json()

    assert first["total"] == second["total"] == 2
    assert len(first["items"]) == len(second["items"]) == 1
    assert first["items"][0]["asset_id"] != second["items"][0]["asset_id"]


# --------------------------------------------------------------------- the asset view


def test_asset_detail_marks_the_vlan_as_inferred(
    client: TestClient, estate: dict[str, UUID]
) -> None:
    """P17's inferred VLAN, reaching the UI with its marker intact.

    There is no switch to ask, so the label is derived from the operator's subnet map. The
    response says so — `inferred: true` and a confidence below 1.0 — because a UI that
    rendered it as measured would be asserting something nobody established (ADR-0015).
    """
    segment = client.get(f"/api/assets/{estate['camera']}").json()["exposure"]["network_segment"]

    assert segment is not None
    assert segment["value"] == "VLAN 60 (IoT)"
    assert segment["inferred"] is True
    assert segment["provenance"]["source_type"] == "inferred"
    assert segment["provenance"]["confidence"] < 1.0


def test_an_asset_outside_every_mapped_subnet_has_no_segment(
    client: TestClient, estate: dict[str, UUID]
) -> None:
    """Unknown, not guessed — served as `null` rather than as a plausible VLAN."""
    detail = client.get(f"/api/assets/{estate['server']}").json()

    assert detail["exposure"]["network_segment"] is None


def test_asset_detail_carries_the_version_source_of_every_component(
    client: TestClient, estate: dict[str, UUID]
) -> None:
    """The badge that stops a backport from reading as a false positive (AGENTS.md §3)."""
    software = client.get(f"/api/assets/{estate['camera']}").json()["software"]

    assert software[0]["name"] == "apache http_server"
    assert software[0]["version_source"] == "package_manager"


def test_asset_detail_carries_the_full_finding_evidence(
    client: TestClient, estate: dict[str, UUID]
) -> None:
    """Priority with its reason, CVSS, KEV and EPSS — everything the Asset Analysis view
    shows beside a vulnerability (ux-design §3.3)."""
    finding = client.get(f"/api/assets/{estate['camera']}").json()["findings"][0]

    assert finding["cve_id"] == "CVE-2023-25690"
    assert finding["kev"] is True
    assert finding["priority"] == "p1"
    assert finding["priority_rule"] == "kev-actively-exploited"
    assert finding["cvss_score"] == 9.8
    assert finding["epss"] == 0.42
    assert finding["confidence_state"] == "confirmed"


def test_asset_detail_includes_the_observation_timeline(
    client: TestClient, estate: dict[str, UUID]
) -> None:
    """Who saw this asset, how, and when — the provenance made visible (ux-design §3.3)."""
    timeline = client.get(f"/api/assets/{estate['camera']}").json()["timeline"]

    assert timeline
    assert timeline[0]["source"] == "ssh"
    assert timeline[0]["source_type"] == "credentialed"
    assert timeline[0]["collection_method"] == "ssh_read_only"


def test_asset_detail_reports_the_management_state_and_who_manages_it(
    client: TestClient, estate: dict[str, UUID]
) -> None:
    detail = client.get(f"/api/assets/{estate['camera']}").json()

    assert detail["management_state"] == "unmanaged"
    assert detail["managed_by"] == []  # nothing manages it — the shadow-IT signal


# ---------------------------------------------------------------------- error mapping


def test_a_missing_asset_is_404(client: TestClient) -> None:
    response = client.get(f"/api/assets/{uuid4()}")

    assert response.status_code == 404
    assert response.json()["error"] == "not_found"


def test_a_malformed_asset_id_is_422(client: TestClient) -> None:
    response = client.get("/api/assets/not-a-uuid")

    assert response.status_code == 422
    assert response.json()["error"] == "invalid_request"


def test_every_response_carries_a_request_id(client: TestClient, estate: dict[str, UUID]) -> None:
    """The id in an error body is the id in the log. It is how an operator finds the failure
    a caller is complaining about without the caller being told anything."""
    ok = client.get("/api/worklist")
    missing = client.get(f"/api/assets/{uuid4()}")

    assert ok.headers["X-Request-Id"]
    assert missing.headers["X-Request-Id"] == missing.json()["request_id"]


def test_an_unknown_route_is_404_with_the_api_error_shape(client: TestClient) -> None:
    response = client.get("/api/nope")

    assert response.status_code == 404
    assert set(response.json()) == {"error", "detail", "request_id"}


def test_the_schema_is_not_served_outside_dev(config: AppConfig, conn: Connection) -> None:
    """An unauthenticated schema browser is a map of the attack surface. It exists in dev,
    for the operator, and nowhere else."""
    from dataclasses import replace

    app = create_app(replace(config, environment="prod"))
    app.dependency_overrides[read_connection] = lambda: conn

    with TestClient(app) as client:
        assert client.get("/openapi.json").status_code == 404
        assert client.get("/docs").status_code == 404
