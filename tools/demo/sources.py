"""Offline stand-ins for the four things outside this system: NVD, KEV, EPSS, and the model.

Everything here implements a port the real pipeline already talks to, so nothing downstream
knows it is being seeded. That is the whole design: the correlator that runs against these is
the correlator, not a copy of it, and the containment rules that judge the model's replies are
the real ones — `ContainedInsightGenerator` sits in front of `ScriptedModelClient` exactly as
it sits in front of a real model.

**The line these draw.** A stand-in replaces a network call, never a decision. None of these
classes decides a priority, a KEV state, a confidence band or whether an insight is grounded;
they hand over the same shape NVD, CISA, FIRST and a model would hand over, and every judgment
about that data is made by code that ships.

`ScriptedModelClient` is the one worth reading twice. It returns canned JSON, and that JSON is
then parsed, sanitized, checked for foreign CVE ids, checked for citations that resolve, and
checked against the KEV floor — by `adapters/llm/generator.py`. A scripted reply that broke a
rule would be refused here just as a real model's would, which is why the replies below are
written to be *plausible* rather than convenient.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from adapters.llm.prompt import cve_ids_in
from domain.errors import DependencyError
from domain.models import (
    CveRecord,
    EpssScore,
    FeedFetchReport,
    KevEntry,
    ModelCompletion,
)


@dataclass(frozen=True, slots=True)
class StaticVulnerabilityFeed:
    """`VulnerabilityFeed` over a fixed mapping. Stands in for NVD."""

    by_cpe: Mapping[str, Sequence[CveRecord]]
    _report: FeedFetchReport = field(default_factory=FeedFetchReport)

    def cves_for_cpe(self, cpe: str) -> Sequence[CveRecord]:
        """Every CVE this fixture associates with the CPE. An unknown CPE is an empty
        sequence, not an error: "we know of nothing here" is a real answer NVD gives."""
        return self.by_cpe.get(cpe, ())

    def cve(self, cve_id: str) -> CveRecord | None:
        """One CVE by id, or None. None means the feed answered and has no such record —
        which the advisory retriever turns into `NotFoundError`, not into empty grounding."""
        wanted = cve_id.upper()
        for records in self.by_cpe.values():
            for record in records:
                if record.cve_id.upper() == wanted:
                    return record
        return None

    def fetch_report(self) -> FeedFetchReport:
        return self._report


@dataclass(frozen=True, slots=True)
class StaticKevSource:
    """`KevSource` over a fixed mapping. Stands in for the CISA KEV catalog.

    Absence is a definite negative here, and that is correct: the catalog is a complete list,
    so "not in it" means "not known-exploited" rather than "we could not check". A source that
    could not check must raise, which is why `refresh` is not silently a no-op.
    """

    entries: Mapping[str, KevEntry]
    _report: FeedFetchReport = field(default_factory=FeedFetchReport)

    def is_known_exploited(self, cve_id: str) -> bool:
        return cve_id.upper() in {key.upper() for key in self.entries}

    def entry(self, cve_id: str) -> KevEntry | None:
        for key, value in self.entries.items():
            if key.upper() == cve_id.upper():
                return value
        return None

    def refresh(self) -> FeedFetchReport:
        """A fixture has nothing to refresh from. Reported as zero fetches rather than
        pretending a round trip happened."""
        return self._report

    def fetch_report(self) -> FeedFetchReport:
        return self._report


@dataclass(frozen=True, slots=True)
class StaticEpssSource:
    """`EpssSource` over a fixed mapping. Stands in for FIRST's EPSS feed.

    Unlike KEV, absence here is genuinely "no score", not "score of zero" — EPSS does not
    cover every CVE, and a missing score must not read as a safe one.
    """

    scores: Mapping[str, EpssScore]
    _report: FeedFetchReport = field(default_factory=FeedFetchReport)

    def score_for(self, cve_id: str) -> EpssScore | None:
        for key, value in self.scores.items():
            if key.upper() == cve_id.upper():
                return value
        return None

    def refresh(self) -> FeedFetchReport:
        return self._report

    def fetch_report(self) -> FeedFetchReport:
        return self._report


#: The model version stamped on every scripted proposal. Not a real model name: an insight in
#: the demo database must not be attributable to a model that could be blamed for it.
SCRIPTED_MODEL_VERSION = "demo-scripted/0"


@dataclass(frozen=True, slots=True)
class ScriptedModelClient:
    """`ModelClient` returning a canned reply per CVE. Stands in for the local model.

    The reply is selected by reading the CVE id out of the prompt the generator built — the
    same way a real model would learn which CVE it is being asked about, and a check that the
    prompt builder actually put it there.

    A CVE with no scripted reply raises `DependencyError`, which the triage pipeline counts as
    a *failure* rather than a silent absence. That distinction is the one AGENTS.md §67 exists
    to protect, and a seeder that blurred it would plant a database where "the model was
    unreachable" and "the model had nothing to say" look identical.
    """

    replies: Mapping[str, str]

    def complete(self, *, system: str, user: str) -> ModelCompletion:
        """Answer the prompt. `system` is accepted and unread — a scripted client has no use
        for instructions it cannot follow, and silently ignoring them is honest here in a way
        it would not be in a real client."""
        del system

        mentioned = cve_ids_in(user)
        for cve_id, reply in self.replies.items():
            if cve_id.upper() in mentioned:
                return ModelCompletion(text=reply, model_version=SCRIPTED_MODEL_VERSION)

        seen = ", ".join(sorted(mentioned)) or "none"
        raise DependencyError(
            f"no scripted reply for this prompt (CVEs seen: {seen})", retryable=False
        )


__all__: Sequence[str] = [
    "SCRIPTED_MODEL_VERSION",
    "ScriptedModelClient",
    "StaticEpssSource",
    "StaticKevSource",
    "StaticVulnerabilityFeed",
]
