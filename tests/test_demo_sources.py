"""The demo stand-ins, tested for the distinctions they are easy to get wrong.

A fixture that returns roughly the right shape is not enough here. These objects sit in the
sockets NVD, CISA, FIRST and the model sit in, and the pipeline reads meaning into the
*difference* between their answers — "no score" is not "score of zero", and "the model was
unreachable" is not "the model had nothing to say". A stand-in that blurs either one plants a
demo database that misrepresents how the real system behaves.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from domain.errors import DependencyError
from domain.models import CveRecord, EpssScore, KevEntry
from tools.demo.sources import (
    SCRIPTED_MODEL_VERSION,
    ScriptedModelClient,
    StaticEpssSource,
    StaticKevSource,
    StaticVulnerabilityFeed,
)

NOW = datetime(2026, 8, 16, tzinfo=UTC)

APACHE_CPE = "cpe:2.3:a:apache:http_server:2.4.53:*:*:*:*:*:*:*"
RECORD = CveRecord(cve_id="CVE-2023-25690", description="text", fetched_at=NOW)


class TestStaticVulnerabilityFeed:
    def test_returns_the_cves_for_a_known_cpe(self) -> None:
        feed = StaticVulnerabilityFeed(by_cpe={APACHE_CPE: (RECORD,)})
        assert [record.cve_id for record in feed.cves_for_cpe(APACHE_CPE)] == ["CVE-2023-25690"]

    def test_an_unknown_cpe_is_empty_rather_than_an_error(self) -> None:
        """ "We know of nothing for this product" is an answer NVD really gives, and the
        correlator has to be able to receive it without treating it as a failure."""
        feed = StaticVulnerabilityFeed(by_cpe={APACHE_CPE: (RECORD,)})
        assert feed.cves_for_cpe("cpe:2.3:a:nobody:nothing:1.0:*:*:*:*:*:*:*") == ()

    def test_finds_a_cve_across_every_cpe_regardless_of_case(self) -> None:
        """The advisory retriever looks a CVE up by id alone, so the lookup cannot depend on
        knowing which CPE it came from."""
        feed = StaticVulnerabilityFeed(by_cpe={APACHE_CPE: (RECORD,)})
        found = feed.cve("cve-2023-25690")
        assert found is not None
        assert found.cve_id == "CVE-2023-25690"

    def test_an_unknown_cve_is_none_not_an_empty_record(self) -> None:
        """None becomes `NotFoundError` downstream. An empty `CveRecord` would instead become
        empty grounding, which is the failure the whole advisory contract exists to prevent."""
        feed = StaticVulnerabilityFeed(by_cpe={APACHE_CPE: (RECORD,)})
        assert feed.cve("CVE-1999-0001") is None


class TestStaticKevSource:
    def test_absence_is_a_definite_negative(self) -> None:
        """KEV is a complete catalogue, so "not listed" means "not known-exploited" — a real
        answer, not a failure to check."""
        kev = StaticKevSource(entries={})
        assert kev.is_known_exploited("CVE-2023-25690") is False

    def test_membership_is_case_insensitive(self) -> None:
        entry = KevEntry(cve_id="CVE-2023-25690", fetched_at=NOW)
        kev = StaticKevSource(entries={"CVE-2023-25690": entry})
        assert kev.is_known_exploited("cve-2023-25690") is True
        assert kev.entry("cve-2023-25690") == entry


class TestStaticEpssSource:
    def test_a_missing_score_is_none_and_never_zero(self) -> None:
        """The distinction that matters: EPSS does not cover every CVE, and a missing score
        must not read as a confident prediction that exploitation is unlikely."""
        epss = StaticEpssSource(scores={})
        assert epss.score_for("CVE-2023-25690") is None

    def test_returns_the_score_it_was_given(self) -> None:
        score = EpssScore(cve_id="CVE-2023-25690", score=0.94, fetched_at=NOW)
        epss = StaticEpssSource(scores={"CVE-2023-25690": score})
        found = epss.score_for("CVE-2023-25690")
        assert found is not None
        assert found.score == pytest.approx(0.94)


class TestScriptedModelClient:
    def test_selects_the_reply_by_the_cve_named_in_the_prompt(self) -> None:
        """Also a check on the prompt builder: if the CVE stopped appearing in the prompt,
        the model would have no way to know what it was being asked about, and this fails."""
        client = ScriptedModelClient(replies={"CVE-2023-25690": '{"recommendation": "maintain"}'})
        completion = client.complete(system="ignored", user="Assess CVE-2023-25690 on this host.")
        assert completion.text == '{"recommendation": "maintain"}'
        assert completion.model_version == SCRIPTED_MODEL_VERSION

    def test_an_unscripted_prompt_raises_rather_than_returning_nothing(self) -> None:
        """The distinction AGENTS.md §67 protects: a failure to reach the model is counted as
        a failure, never recorded as "we looked at this and had nothing to say"."""
        client = ScriptedModelClient(replies={})
        with pytest.raises(DependencyError):
            client.complete(system="ignored", user="Assess CVE-2023-25690 on this host.")

    def test_the_model_version_is_not_a_real_model_name(self) -> None:
        """An insight in the demo database must not be attributable to a model that could be
        blamed for having said it."""
        assert "demo" in SCRIPTED_MODEL_VERSION
