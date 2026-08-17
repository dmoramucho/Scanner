"""Planting an estate for the API tests: the rows, and the ones designed to leak.

Shared by the security and contract suites so both exercise the same data — a boundary test
that plants different rows from the contract test is asserting about a different system.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import psycopg

from config.settings import AppConfig, NvdSettings
from domain.secret import Secret
from engine.segments import SubnetVlanMap

Connection = psycopg.Connection[tuple[Any, ...]]

NOW = datetime(2026, 8, 16, 12, 0, tzinfo=UTC)

#: Planted in an observation payload of the tenant we *do* serve. Every one of these is a
#: field the dossier contract excludes (§4), and none may appear in any response.
PRIVATE_KEY = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\n-----END"
SECRETS = {
    "ssh_private_key": PRIVATE_KEY,
    "admin_password": "hunter2-do-not-leak",
    "api_token": "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "last_login_user": "maria.garcia@corp.example",
    "raw_config": "auth_password=hunter2-do-not-leak\nsnmp_community=public",
    "banner": "SSH-2.0-OpenSSH_8.9p1 key=AAAAB3NzaC1yc2EAAAADAQAB",
}

#: Data planted in the *other* tenant. If any of it comes back, the scoping is broken.
OTHER_HOSTNAME = "other-tenant-crown-jewels"
OTHER_CVE = "CVE-1999-0001"


def seed_asset(
    conn: Connection,
    tenant: UUID,
    *,
    hostname: str,
    address: str = "10.0.60.14",
    payload: dict[str, Any] | None = None,
) -> UUID:
    row = conn.execute(
        """
        insert into asset (tenant_id, asset_class, management_state,
                           identification_confidence, first_seen_at, last_seen_at)
        values (%s, 'server', 'unmanaged', 0.9, %s, %s) returning id
        """,
        (tenant, NOW, NOW),
    ).fetchone()
    assert row is not None
    asset_id: UUID = row[0]

    for kind, value in (("hostname", hostname), ("ip", address)):
        conn.execute(
            """
            insert into asset_identifier (tenant_id, asset_id, kind, value, confidence,
                                          first_seen_at, last_seen_at)
            values (%s, %s, %s, %s, 0.9, %s, %s)
            """,
            (tenant, asset_id, kind, value, NOW, NOW),
        )

    conn.execute(
        """
        insert into observation (tenant_id, asset_id, observation_type, payload, source,
            source_type, collector, collector_version, collection_method, confidence,
            content_hash, observed_at, collected_at, run_id)
        values (%s, %s, 'identity', %s::jsonb, 'ssh', 'credentialed', 'ssh-inspector',
                '0.1.0', 'ssh_read_only', 0.95, sha256(%s), %s, %s, %s)
        """,
        (
            tenant,
            asset_id,
            json.dumps({"vendor": "axis", "model": "p3245-lve", **(payload or {})}),
            uuid4().bytes,
            NOW,
            NOW,
            uuid4(),
        ),
    )
    return asset_id


def seed_match(conn: Connection, tenant: UUID, asset_id: UUID, *, cve_id: str, kev: bool) -> UUID:
    row = conn.execute(
        """
        insert into vulnerability_match (tenant_id, asset_id, cve_id, matched_cpe,
            version_source, confidence_state, kev, epss, cvss_score, priority,
            priority_rule, priority_reason, derivation)
        values (%s, %s, %s, 'cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*',
                'package_manager', 'confirmed', %s, 0.42, 9.8, %s, %s, %s, 'deterministic')
        returning id
        """,
        (
            tenant,
            asset_id,
            cve_id,
            kev,
            "p1" if kev else "p2",
            "kev-actively-exploited" if kev else "actionable-critical-cvss",
            f"CISA lists {cve_id} as known exploited." if kev else f"CVSS rates {cve_id} critical.",
        ),
    ).fetchone()
    assert row is not None
    match_id: UUID = row[0]
    return match_id


def api_config(tenant: UUID, database_url: str) -> AppConfig:
    """The configuration the API is created with in tests.

    A real `AppConfig`, so the app under test is wired exactly as a running one is — the
    tenant comes from configuration, and the loopback gate is on by default.
    """
    return AppConfig(
        environment="dev",
        database_url=Secret(database_url),
        raw_store_endpoint_url="http://localhost:9000",
        raw_store_bucket="raw",
        raw_store_access_key_id="key",
        raw_store_secret_access_key=Secret("secret"),
        secrets_endpoint_url="http://localhost:4566",
        region="us-east-1",
        log_level="INFO",
        nvd=NvdSettings(
            base_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
            api_key=None,
            rate_limit_requests=5,
            rate_limit_window_seconds=30.0,
            timeout_seconds=30.0,
            max_retries=3,
            cache_ttl_hours=24.0,
        ),
        vlan_map=SubnetVlanMap.from_mapping({"10.0.60.0/24": "VLAN 60 (IoT)"}),
        tenant_id=tenant,
        api_allow_remote=False,
    )
