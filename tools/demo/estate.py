"""What the demo estate *is*: the ranges, the software, and the CVE knowledge.

Data only — no behaviour. Every value here is a declaration of what the seeded network looks
like; how it gets planted is `seed.py`, and the offline stand-ins that serve this data through
the real ports are `sources.py`.

**On provenance and honesty.** The CVE ids below are real, because correlating real ids is
what the system does and a demo with invented ones would exercise nothing. The advisory
*text* attached to them is not — it is written for this fixture. So every record here carries
`source="demo-fixture"` rather than `"nvd"` or `"cisa-kev"`. The estate is fabricated and the
rows say so; a demo that lies about where its data came from has broken the one property this
system is built to have (AGENTS.md §8).

**What the estate is shaped to show.** Three distinctions the UI draws (ADR-0018), each with
at least one asset that makes it visible:

* **Confidence** — `web-01` reports Apache from its package manager; `cam-lobby-01` reports
  firmware from a banner. Same pipeline, two very different warrants for believing a version,
  and the difference has to reach the analyst.
* **Management** — `10.10.60.88` answers ARP and announces nothing. No hostname, no software,
  no CMDB record: the unidentified, unmanaged shape that shadow-IT triage exists for.
* **Fact vs. AI** — every match below is derived deterministically by the correlator. The
  proposals attached to them come from the model and are marked as proposals. `CVE-2023-25690`
  is in the KEV set, so its floor holds no matter what the model says about it.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Final, NamedTuple
from uuid import UUID

from domain.models import CpeMatch, CveRecord, CvssSeverity, EpssScore, KevEntry, VersionSource

#: A fixed instant, so re-running the seeder produces the same estate. Real `now()` would
#: make two demo databases differ in ways that look like findings.
SEEDED_AT: Final = datetime(2026, 8, 16, 9, 30, tzinfo=UTC)

#: The sweep's run id. Fixed rather than fresh per run: the observation dedup index is keyed
#: on `run_id`, so a new id each time would record identical content as a new sighting. That is
#: right for a real sweep and noise for a demo estate.
RUN_ID: Final = UUID("00000000-0000-0000-0000-0000000decaf")

#: The source label on every fabricated record. Greppable, and visible in the UI: an analyst
#: looking at demo data can tell that is what they are looking at.
DEMO_SOURCE: Final = "demo-fixture"

#: The one authorized range. 192.168.99.0/24 appears in the captures and is deliberately
#: absent here — deny-by-default means the gate refuses it without being told to.
AUTHORIZED_CIDRS: Final[tuple[str, ...]] = ("10.10.0.0/16",)

#: The paper trail every authorization must cite. Not nullable in the schema, and not a
#: placeholder here either: a range authorized by nothing is the failure mode the column exists
#: to prevent.
WRITTEN_AUTH_REF: Final = "DEMO-AUTH-2026-001 (fabricated: local demo estate only)"

#: Subnet → VLAN, for the inferred-segment column (P17). Set the same mapping in
#: `SCANNER_VLAN_MAP` so the API infers what the seeder planted.
VLAN_MAP: Final[dict[str, str]] = {
    "10.10.10.0/24": "VLAN 10 (Servers)",
    "10.10.60.0/24": "VLAN 60 (IoT)",
}


class DemoComponent(NamedTuple):
    """A software component to attach to a resolved asset.

    `version_source` is the confidence story: a version read from a package manager is a fact
    the host asserted about itself, a version scraped from a banner is a guess from a string
    that anyone can set. The correlator treats them differently and so must the UI.
    """

    name: str
    version: str
    cpe: str
    version_source: VersionSource
    confidence: float


class DemoHost(NamedTuple):
    """A host to attach software to, addressed by its MAC.

    Keyed by MAC and not by hostname because that is how the resolver works: only a serial,
    a certificate fingerprint or a MAC is a strong anchor, and `resolve()` returns no asset
    for a hostname on purpose — "a rotating locator is not an identity". `label` is here for
    error messages only; nothing resolves by it.
    """

    mac: str
    label: str
    components: tuple[DemoComponent, ...]


#: Software per host. A host absent from this list gets no components and therefore no
#: findings — the correct picture for `10.10.60.88`, which we have only ever seen answer ARP.
SOFTWARE: Final[tuple[DemoHost, ...]] = (
    DemoHost(
        mac="00:50:56:a1:00:11",
        label="web-01.corp.example",
        components=(
            DemoComponent(
                name="apache http server",
                version="2.4.53",
                cpe="cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*",
                version_source=VersionSource.PACKAGE_MANAGER,
                confidence=0.95,
            ),
        ),
    ),
    DemoHost(
        mac="00:50:56:a1:00:12",
        label="db-01.corp.example",
        components=(
            DemoComponent(
                name="openssh",
                version="8.9p1",
                cpe="cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*",
                version_source=VersionSource.PACKAGE_MANAGER,
                confidence=0.95,
            ),
        ),
    ),
    DemoHost(
        mac="00:40:8c:9d:1e:2f",
        label="cam-lobby-01.corp.example",
        components=(
            DemoComponent(
                name="axis p3245-lve firmware",
                version="10.12.0",
                # Read off an HTTP banner: believable, unverified, and the UI must say so.
                cpe="cpe:2.3:o:axis:p3245-lve_firmware:10.12.0:*:*:*:*:*:*:*",
                version_source=VersionSource.BANNER,
                confidence=0.55,
            ),
        ),
    ),
)

#: CVE knowledge, keyed by the CPE the correlator will look up. This stands in for NVD.
CVES: Final[dict[str, tuple[CveRecord, ...]]] = {
    "cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*": (
        CveRecord(
            cve_id="CVE-2023-25690",
            source=DEMO_SOURCE,
            # This *is* the grounding material. The real `HttpAdvisoryRetriever` sources
            # advisory text from the feed record's description (offline, no fix-document
            # fetch), so putting the text anywhere else would mean stubbing a retriever we
            # already have working. It runs its sanitizer over this on the way through.
            description=(
                "Demo fixture advisory. Some mod_proxy configurations on Apache HTTP Server "
                "2.4.0 through 2.4.55 are vulnerable to HTTP request smuggling. When a "
                "RewriteRule or ProxyPassMatch pattern captures part of the request target "
                "and substitutes it into the proxied request, an attacker can split the "
                "request and poison the response cache or bypass access control at the "
                "origin. The fix rejects requests whose target contains encoded characters "
                "that would change meaning after substitution. Upgrade to 2.4.56. Where an "
                "upgrade is not immediately possible, removing the capturing RewriteRule "
                "from the proxy configuration removes the exposure."
            ),
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_version="3.1",
            severity=CvssSeverity.CRITICAL,
            cpe_matches=[CpeMatch(criteria="cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*")],
            references=["https://httpd.apache.org/security/vulnerabilities_24.html"],
            fetched_at=SEEDED_AT,
        ),
    ),
    "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*": (
        CveRecord(
            cve_id="CVE-2024-6387",
            source=DEMO_SOURCE,
            description=(
                "Demo fixture advisory. A signal handler race condition in OpenSSH's sshd "
                "allows a remote unauthenticated attacker to execute code as root on "
                "glibc-based Linux systems. Exploitation requires winning a narrow timing "
                "window and, in published work, several hours of repeated connection "
                "attempts against a default LoginGraceTime of 120 seconds. Setting "
                "LoginGraceTime to 0 disables the vulnerable path at the cost of exposing "
                "the daemon to connection exhaustion. Upgrade to OpenSSH 9.8p1."
            ),
            cvss_score=8.1,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cvss_version="3.1",
            severity=CvssSeverity.HIGH,
            cpe_matches=[CpeMatch(criteria="cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*")],
            references=["https://www.openssh.com/security.html"],
            fetched_at=SEEDED_AT,
        ),
    ),
    "cpe:2.3:o:axis:p3245-lve_firmware:10.12.0:*:*:*:*:*:*:*": (
        CveRecord(
            cve_id="CVE-2023-21414",
            source=DEMO_SOURCE,
            # Deliberately empty. The retriever will raise `NotFoundError`, the triage
            # pipeline will count it as `skipped_no_advisory`, and no insight is produced —
            # the system declining to reason because it has nothing to reason *from*. The
            # deterministic finding still stands, and the UI has to render that state
            # (AGENTS.md §4.8).
            description="",
            cvss_score=6.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
            cvss_version="3.1",
            severity=CvssSeverity.MEDIUM,
            cpe_matches=[
                CpeMatch(criteria="cpe:2.3:o:axis:p3245-lve_firmware:10.12.0:*:*:*:*:*:*:*")
            ],
            references=["https://www.axis.com/support/cybersecurity/advisories"],
            fetched_at=SEEDED_AT,
        ),
    ),
}

#: The KEV set. Exactly one entry, so the demo has a finding whose floor is non-negotiable and
#: findings around it that are not — otherwise "KEV cannot be hidden" is untestable by eye.
KEV: Final[dict[str, KevEntry]] = {
    "CVE-2023-25690": KevEntry(
        cve_id="CVE-2023-25690",
        source=DEMO_SOURCE,
        vendor="Apache",
        product="HTTP Server",
        name="Apache HTTP Server HTTP Request Smuggling Vulnerability",
        date_added=datetime(2026, 3, 2, tzinfo=UTC),
        due_date=datetime(2026, 3, 23, tzinfo=UTC),
        known_ransomware=False,
        fetched_at=SEEDED_AT,
    ),
}

#: EPSS. The camera's score is deliberately tiny and the Apache one large: the demo should
#: show a high-CVSS finding that EPSS agrees about and a mid-CVSS one it does not.
EPSS: Final[dict[str, EpssScore]] = {
    "CVE-2023-25690": EpssScore(
        cve_id="CVE-2023-25690",
        source=DEMO_SOURCE,
        score=0.9421,
        percentile=0.9993,
        scored_at=SEEDED_AT,
        fetched_at=SEEDED_AT,
    ),
    "CVE-2024-6387": EpssScore(
        cve_id="CVE-2024-6387",
        source=DEMO_SOURCE,
        score=0.4312,
        percentile=0.9712,
        scored_at=SEEDED_AT,
        fetched_at=SEEDED_AT,
    ),
    "CVE-2023-21414": EpssScore(
        cve_id="CVE-2023-21414",
        source=DEMO_SOURCE,
        score=0.0007,
        percentile=0.2814,
        scored_at=SEEDED_AT,
        fetched_at=SEEDED_AT,
    ),
}

#: The scripted model replies, as raw JSON — the exact shape a real model must return, so the
#: real parser and the real containment checks do real work on them.
#:
#: Every `quote` below is an exact substring of the advisory text it cites. That is not a
#: nicety: `ContainedInsightGenerator` drops a citation whose quote does not appear in what it
#: claims to quote, and an insight left with no resolving citation is refused as ungrounded.
#: These replies are written to *pass* honestly rather than to be waved through.
#:
#: The two recommendations are deliberately different, because the pair is the demo:
#:
#: * `CVE-2023-25690` is KEV, and the reply says `maintain`. Had it said `lower_priority`,
#:   the generator would have refused it — the floor is enforced in code, not in the prompt.
#: * `CVE-2024-6387` is not KEV, and the reply argues *down* from exploitation difficulty.
#:   That is a real, defensible opinion an analyst should weigh and either accept or reject,
#:   which is what gives the review queue something worth reviewing.
#: Serialized rather than hand-written, because hand-written JSON with prose in it is how you
#: get a literal newline inside a string literal and a reply the parser correctly rejects.
#: `json.dumps` makes the fixture valid by construction; the parser still does all its work.
MODEL_REPLIES: Final[dict[str, str]] = {
    cve: json.dumps(reply)
    for cve, reply in (
        (
            "CVE-2023-25690",
            {
                "recommendation": "maintain",
                "rationale": (
                    "The advisory describes request smuggling reachable through a proxy "
                    "configuration this host is running, and the fix is a version upgrade "
                    "rather than a configuration change, so the exposure persists until the "
                    "package is updated. The priority already reflects active exploitation "
                    "and nothing in the advisory argues for moving it."
                ),
                "confidence": 0.78,
                "cited_sources": [
                    {
                        "kind": "advisory",
                        "ref": "CVE-2023-25690",
                        "quote": "Upgrade to 2.4.56",
                    }
                ],
            },
        ),
        (
            "CVE-2024-6387",
            {
                "recommendation": "lower_priority",
                "rationale": (
                    "The advisory is explicit that exploitation requires winning a narrow "
                    "timing window over a long period of repeated connections, which makes "
                    "opportunistic exploitation of this host unlikely relative to findings "
                    "that need a single request. A mitigation is also available without an "
                    "upgrade. This argues for scheduling the patch rather than treating it "
                    "as an emergency; it does not argue that the finding is wrong."
                ),
                "confidence": 0.64,
                "cited_sources": [
                    {
                        "kind": "advisory",
                        "ref": "CVE-2024-6387",
                        "quote": "several hours of repeated connection attempts",
                    }
                ],
            },
        ),
        # CVE-2023-21414 has no reply and needs none: with no advisory text, triage never
        # reaches the model for it.
    )
}


__all__: Sequence[str] = [
    "AUTHORIZED_CIDRS",
    "CVES",
    "DEMO_SOURCE",
    "EPSS",
    "KEV",
    "MODEL_REPLIES",
    "RUN_ID",
    "SEEDED_AT",
    "SOFTWARE",
    "VLAN_MAP",
    "WRITTEN_AUTH_REF",
    "DemoComponent",
]
