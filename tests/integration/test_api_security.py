"""The API as a security boundary: tenant scope, redaction, and untrusted input.

P18 opens the platform to network requests for the first time, so everything M0–M3 protected
now has a front door. This file is that door's test, and it is written the way the scope
gate's was: the properties are asserted from the *outside*, over HTTP, against a real
database, with data planted specifically to leak if the boundary is wrong.

Two assertions carry it — **a caller cannot read another tenant's data**, and **no secret,
raw config or PII can appear in any response** — and both are stated over every endpoint
rather than over a sample, because a boundary that holds on three of four routes is not a
boundary (m4-design §1).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from typing import Any
from uuid import UUID, uuid4

import psycopg
import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from api.security import read_connection
from config.settings import AppConfig
from tests.integration.estate import (
    OTHER_CVE,
    OTHER_HOSTNAME,
    SECRETS,
    api_config,
    seed_asset,
    seed_match,
)

pytestmark = pytest.mark.integration

Connection = psycopg.Connection[tuple[Any, ...]]


@pytest.fixture
def tenant() -> UUID:
    return uuid4()


@pytest.fixture
def other_tenant() -> UUID:
    return uuid4()


@pytest.fixture
def config(tenant: UUID, migrated_database: str) -> AppConfig:
    return api_config(tenant, migrated_database)


@pytest.fixture
def client(config: AppConfig, conn: Connection) -> Iterator[TestClient]:
    """A client whose requests run on the *test transaction*.

    The connection dependency is overridden so the API sees the rows this test planted and
    rolls them back afterwards. Everything above the connection — routing, dependencies,
    scoping, redaction, error handling — is the real thing.
    """
    app = create_app(config)
    app.dependency_overrides[read_connection] = lambda: conn
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def planted(conn: Connection, tenant: UUID, other_tenant: UUID) -> dict[str, UUID]:
    """One asset in our tenant carrying secrets; one in another tenant carrying nothing we
    are allowed to see."""
    ours = seed_asset(conn, tenant, hostname="camera-01", payload=SECRETS)
    theirs = seed_asset(conn, other_tenant, hostname=OTHER_HOSTNAME, address="10.9.9.9")
    seed_match(conn, tenant, ours, cve_id="CVE-2023-25690", kev=True)
    seed_match(conn, other_tenant, theirs, cve_id=OTHER_CVE, kev=True)
    return {"ours": ours, "theirs": theirs}


# =========================================================== security-critical: tenancy


def test_no_endpoint_returns_another_tenants_data(
    client: TestClient, planted: dict[str, UUID]
) -> None:
    """The assertion the whole boundary rests on.

    Both tenants hold a KEV finding, and both assets are named distinctively. Every read
    endpoint is called, and the other tenant's asset, hostname and CVE must appear in none
    of them — not in a list, not in a count, not in an error message (m4-design §1).
    """
    responses = [
        client.get("/api/worklist"),
        client.get("/api/assets"),
        client.get("/api/assets?has_kev=true"),
        client.get(f"/api/assets/{planted['ours']}"),
        client.get(f"/api/assets/{planted['ours']}/findings"),
    ]

    for response in responses:
        assert response.status_code == 200, response.text
        body = response.text
        assert OTHER_HOSTNAME not in body
        assert OTHER_CVE not in body
        assert str(planted["theirs"]) not in body


def test_another_tenants_asset_is_not_found_rather_than_forbidden(
    client: TestClient, planted: dict[str, UUID]
) -> None:
    """Asking for an asset id from another tenant must be indistinguishable from asking for
    one that does not exist. A 403 here would confirm the id is real somewhere, which is a
    membership oracle over the whole estate."""
    theirs = client.get(f"/api/assets/{planted['theirs']}")
    nobodys = client.get(f"/api/assets/{uuid4()}")

    assert theirs.status_code == 404
    assert nobodys.status_code == 404
    assert theirs.json()["error"] == nobodys.json()["error"]
    assert theirs.json()["detail"] == nobodys.json()["detail"]
    # A constant sentence, not the domain message: a 404 that described what it looked for
    # would differ between the two cases and become a membership oracle again.
    assert theirs.json()["detail"] == "the requested resource was not found"
    # And no internal identifier travels with it — not the asset's, not the tenant's.
    assert str(planted["theirs"]) not in theirs.text


def test_another_tenants_findings_are_not_served(
    client: TestClient, planted: dict[str, UUID]
) -> None:
    response = client.get(f"/api/assets/{planted['theirs']}/findings")

    assert response.status_code == 404
    assert OTHER_CVE not in response.text


@pytest.mark.parametrize(
    "attempt",
    [
        "/api/worklist?tenant_id={other}",
        "/api/assets?tenant_id={other}",
        "/api/assets?tenant={other}",
    ],
)
def test_a_caller_cannot_select_a_tenant_by_query_parameter(
    client: TestClient, planted: dict[str, UUID], other_tenant: UUID, attempt: str
) -> None:
    """The tenant is server-side configuration, so there is no parameter that names one.

    An unknown parameter is refused outright rather than ignored: a caller who thinks they
    switched tenants and silently did not is the *lucky* case, and relying on luck is not a
    boundary (AGENTS.md §68).
    """
    response = client.get(attempt.format(other=other_tenant))

    assert response.status_code == 422
    assert OTHER_HOSTNAME not in response.text


@pytest.mark.parametrize("header", ["X-Tenant-Id", "X-Tenant", "Tenant-Id"])
def test_a_caller_cannot_select_a_tenant_by_header(
    client: TestClient, planted: dict[str, UUID], other_tenant: UUID, header: str
) -> None:
    """The classic failure of an unauthenticated multi-tenant API: a tenant header the
    server believes. These are simply not read — the request is served for the configured
    tenant exactly as if the header were absent."""
    response = client.get("/api/worklist", headers={header: str(other_tenant)})

    assert response.status_code == 200
    assert OTHER_HOSTNAME not in response.text
    assert OTHER_CVE not in response.text


def test_the_summary_counts_only_this_tenant(client: TestClient, planted: dict[str, UUID]) -> None:
    """A count is a read too. Two tenants each hold one KEV finding and one unmanaged asset;
    the numbers this tenant sees are its own."""
    summary = client.get("/api/worklist").json()["summary"]

    assert summary["kev_findings"] == 1
    assert summary["shadow_it_assets"] == 1
    assert summary["total_findings"] == 1


# ========================================================= security-critical: redaction


def test_no_response_ever_carries_a_secret_from_an_observation(
    client: TestClient, planted: dict[str, UUID]
) -> None:
    """The second assertion this file exists for.

    The asset in our tenant has a private key, a password, an API token, a person's email
    address, a raw config and a raw banner sitting in an observation payload — all of them
    fields the dossier contract excludes. Every endpoint is called and none of it comes back,
    because asset facts are served from the *redacted* dossier rather than from observations
    (contract §4, ADR-0014).
    """
    responses = [
        client.get("/api/worklist"),
        client.get("/api/assets"),
        client.get(f"/api/assets/{planted['ours']}"),
        client.get(f"/api/assets/{planted['ours']}/findings"),
    ]

    for response in responses:
        assert response.status_code == 200, response.text
        body = response.text
        for excluded in (
            "PRIVATE KEY",
            "hunter2-do-not-leak",
            "ghp_abcdefghijklmnopqrstuvwxyz",
            "maria.garcia@corp.example",
            "snmp_community",
            "SSH-2.0-OpenSSH",
            "AAAAB3NzaC1yc2E",
        ):
            assert excluded not in body, f"{excluded!r} was served by {response.url}"


def test_the_asset_response_carries_no_observation_payload_at_all(
    client: TestClient, planted: dict[str, UUID]
) -> None:
    """Not "no secrets we thought of" — no payload. The timeline is provenance (who saw
    this, how, when), and the facts come from the allowlist projection. A payload key in a
    response would mean a second path around the redaction."""
    detail = client.get(f"/api/assets/{planted['ours']}").json()

    assert detail["timeline"], "the timeline should still be served"
    for entry in detail["timeline"]:
        assert "payload" not in entry
        assert set(entry) == {
            "observation_id",
            "observation_type",
            "source",
            "source_type",
            "collector",
            "collection_method",
            "confidence",
            "observed_at",
        }
    # The allowlisted facts did survive — a redaction that empties the response is safe and
    # useless (contract §4).
    assert detail["identifiers"]
    assert detail["exposure"]["reachability"]


def test_an_error_response_never_leaks_internals(client: TestClient) -> None:
    """Error bodies are the most productive disclosure channel an attacker has. Whatever
    failed, a caller gets a code, a safe sentence and an id to quote."""
    response = client.get(f"/api/assets/{uuid4()}")

    body = response.json()
    assert response.status_code == 404
    assert set(body) == {"error", "detail", "request_id"}
    for leak in ("Traceback", "psycopg", "select ", "postgresql://", ".py", "password"):
        assert leak not in response.text


def test_a_database_failure_becomes_a_generic_500(
    config: AppConfig, conn: Connection, planted: dict[str, UUID]
) -> None:
    """A driver error quotes the failing statement in its message. That must never reach a
    caller — the SQL is the schema, and the schema is a map."""
    app = create_app(config)

    def broken() -> Iterator[Connection]:
        conn.execute("select 1 from a_table_that_does_not_exist")  # pragma: no cover
        yield conn

    app.dependency_overrides[read_connection] = broken
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/api/worklist")

    assert response.status_code == 500
    assert response.json()["detail"] == "the request could not be completed"
    assert "a_table_that_does_not_exist" not in response.text
    assert "select" not in response.text.lower()


# ============================================================= untrusted input (§68)


@pytest.mark.parametrize(
    "path",
    [
        "/api/assets/not-a-uuid",
        "/api/assets/1%20OR%201=1",
        "/api/assets/../../etc/passwd",
        "/api/assets?limit=0",
        "/api/assets?limit=99999",
        "/api/assets?limit=abc",
        "/api/assets?offset=-1",
        "/api/assets?asset_class=; drop table asset;--",
        "/api/assets?management_state=whatever",
        "/api/assets?has_kev=maybe",
        "/api/assets?unknown_filter=1",
        "/api/worklist?limit=-5",
        "/api/assets?q=" + "x" * 500,
    ],
)
def test_malformed_input_is_a_clean_4xx_never_a_500(client: TestClient, path: str) -> None:
    """Every malformed shape a caller can send: a bounded 4xx with a safe body. Never a 500,
    never a stack trace, and never a query built from the input."""
    response = client.get(path)

    assert 400 <= response.status_code < 500, f"{path} → {response.status_code}"
    assert "Traceback" not in response.text
    assert "drop table" not in response.text.lower()


def test_a_sql_shaped_search_term_is_a_bound_parameter_not_a_query(
    client: TestClient, planted: dict[str, UUID]
) -> None:
    """The search box is the one place caller text reaches a `where` clause. It arrives as a
    parameter: the injection attempt matches nothing and the table is still there."""
    response = client.get("/api/assets", params={"q": "' or 1=1; drop table asset;--"})

    assert response.status_code == 200
    assert response.json()["items"] == []
    assert client.get("/api/assets").json()["total"] == 1  # our tenant's asset survived


def test_a_wildcard_in_the_search_box_is_a_literal_character(
    client: TestClient, planted: dict[str, UUID]
) -> None:
    """`%` is a character an analyst may type, not an instruction to match everything."""
    assert client.get("/api/assets", params={"q": "%"}).json()["items"] == []
    assert client.get("/api/assets", params={"q": "camera"}).json()["total"] == 1


# ===================================================== the gate that stands in for auth


def test_a_non_loopback_client_is_refused(config: AppConfig, conn: Connection) -> None:
    """Authentication is deferred, so anything that can reach this API is authenticated by
    nothing. Until that changes, only this machine may ask (m4-design §5)."""
    app = create_app(config)
    app.dependency_overrides[read_connection] = lambda: conn

    with TestClient(app, client=("203.0.113.9", 51234)) as client:
        response = client.get("/api/worklist")

    assert response.status_code == 403
    assert response.json()["error"] == "forbidden"


def test_the_loopback_gate_can_be_lifted_explicitly(config: AppConfig, conn: Connection) -> None:
    """A deployment behind its own authenticating proxy can turn the gate off — deliberately,
    in configuration, having read what it is for."""
    remote_ok = replace(config, api_allow_remote=True)
    app = create_app(remote_ok)
    app.dependency_overrides[read_connection] = lambda: conn

    with TestClient(app, client=("203.0.113.9", 51234)) as client:
        assert client.get("/api/worklist").status_code == 200


def test_health_says_nothing_about_the_estate(client: TestClient) -> None:
    """A health check is not a reconnaissance tool: no version, no tenant, no counts."""
    body = client.get("/health").json()

    assert body == {"status": "ok"}


def test_the_api_serves_requests_on_a_read_only_connection(config: AppConfig) -> None:
    """P18 has no write endpoints, and the *database* is what enforces that.

    Asserted on the real dependency rather than on a promise: every request runs on a
    connection with `read_only = True`, so a handler that attempted a mutation — today, or
    after some future refactor — is refused by Postgres rather than by review.
    """
    connection = read_connection(config)
    conn = next(iter(connection))

    try:
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            conn.execute("delete from vulnerability_match")
    finally:
        conn.close()
