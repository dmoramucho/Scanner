"""`InsightGenerator` — the LLM boundary, and every rule that holds it.

This is the only place in the system where a model reasons, and the last one built. Every
containment decision made since M0 converges here; none of them originate here. The model
gets one input, produces one candidate, and that candidate has to survive checks that do not
take its word for anything.

**It cannot invent a vulnerability.** The match is decided in `engine/correlation.py` with
no model anywhere near it, and arrives as settled fact (AGENTS.md §2.8). Nothing this
adapter returns can create, alter or delete a match.

**It cannot know a CVE it was not given.** The generator holds a `ModelClient` and nothing
else — no feed, no cache, no retriever. Its entire knowledge of the CVE is the
`AdvisoryEvidence` inside the dossier it is handed (AGENTS.md §4.8). And because a model's
signature failure is a confident reference to a CVE nobody mentioned, a rationale naming any
other CVE id is rejected outright.

**It cannot claim without citing.** No citations → `GroundingError`. Citations are then
*resolved*: an advisory citation must name the advisory we supplied, a dossier citation must
name a path that exists in the dossier, and a quote must actually appear in the text it
claims to quote. A fabricated citation is a hallucination wearing a footnote, and dropping
it can leave the insight with nothing left — in which case it is ungrounded, and refused.

**It cannot bury an exploited finding.** If the match is KEV, `kev_locked_visible` is set
and `lower_priority` is refused with `ValidationError`. CISA is saying this is being
exploited right now; no model gets to argue it down the page. The database CHECK
`insight_kev_not_hidden` says the same thing one layer down (dossier contract §7).

**It cannot close anything.** `derivation` is always `llm_generated` and `state` always
starts `proposed`. The output is a recommendation for a human, and the asymmetry is
deliberate: `lower_priority` — the only direction that can make a finding less visible —
additionally requires a citation of the advisory text itself. Raising or maintaining a
finding is cheap to be wrong about; lowering one is not (AGENTS.md §4.9).

Failure is conservative throughout. An unreachable model, an unparseable reply, an
ungrounded answer: all of them produce *no insight*, which leaves the deterministic finding
exactly as visible as it already was.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Final
from uuid import UUID, uuid4

from adapters.llm.prompt import (
    SYSTEM_PROMPT,
    ParsedCitation,
    ParsedInsight,
    build_user_prompt,
    cve_ids_in,
    parse_completion,
)
from domain.errors import GroundingError, ValidationError
from domain.models import (
    CitedSource,
    InsightProposal,
    ModelCompletion,
    Recommendation,
    TriageDossier,
)
from domain.ports import ModelClient

#: Recommendations that can make a finding less visible. Held to a higher standard than the
#: others, because they are the only ones that can hide something (AGENTS.md §4.9).
SUPPRESSING_RECOMMENDATIONS: Final = frozenset({"lower_priority"})

#: The parsed string, narrowed to the contract's type. A lookup rather than a cast: the only
#: way into an `InsightProposal` is through a value that was already in this table.
_RECOMMENDATIONS: Final[Mapping[str, Recommendation]] = {
    "raise_priority": "raise_priority",
    "lower_priority": "lower_priority",
    "maintain": "maintain",
}


class ContainedInsightGenerator:
    """`InsightGenerator` over any `ModelClient`, with the contract enforced in code."""

    def __init__(
        self,
        model: ModelClient,
        *,
        new_id: Callable[[], UUID] = uuid4,
    ) -> None:
        self._model = model
        self._new_id = new_id

    def generate(self, triage: TriageDossier) -> InsightProposal:
        """Produce a grounded, advisory proposal. See the port contract in `domain.ports`.

        Raises `GroundingError` when the model cites nothing that can be resolved, and
        `ValidationError` when it breaks a rule — a KEV-hiding recommendation, a CVE it was
        not given, a reply that does not parse. `DependencyError` propagates from the model
        client. Every one of those produces no insight rather than a weak one.
        """
        completion = self._model.complete(system=SYSTEM_PROMPT, user=build_user_prompt(triage))
        parsed = parse_completion(completion.text)
        return self._validated(triage, parsed, completion)

    # ------------------------------------------------------------------ validation

    def _validated(
        self, triage: TriageDossier, parsed: ParsedInsight, completion: ModelCompletion
    ) -> InsightProposal:
        """Turn a candidate into a proposal, or refuse it. Order matters only in that the
        cheapest refusals come first; every check below is independent."""
        self._refuse_foreign_cve(triage, parsed)

        cited = self._resolved_citations(triage, parsed.citations)
        if not cited:
            # Either the model cited nothing, or nothing it cited exists. The two are the
            # same failure from here: there is no evidence behind this claim (contract §7).
            raise GroundingError(
                f"insight for {triage.match.cve_id} cites nothing that resolves to the "
                f"advisory or the dossier; refusing to persist an ungrounded claim"
            )

        recommendation = self._checked_recommendation(triage, parsed, cited)

        return InsightProposal(
            insight_id=self._new_id(),
            triage_id=triage.triage_id,
            recommendation=recommendation,
            rationale=parsed.rationale,
            cited_sources=cited,
            confidence=parsed.confidence,
            # Not read from the model: the model does not get to describe its own output as
            # anything other than what it is.
            model_version=completion.model_version,
            state="proposed",
            kev_locked_visible=triage.match.kev,
        )

    def _refuse_foreign_cve(self, triage: TriageDossier, parsed: ParsedInsight) -> None:
        """A rationale may discuss the CVE it was given. Any other is recalled, not read.

        This is the cheapest possible detector for the model's most characteristic failure,
        and it is exact rather than heuristic: we know precisely which CVE this insight is
        about (AGENTS.md §4.8).
        """
        mentioned = cve_ids_in(parsed.rationale)
        foreign = mentioned - {triage.match.cve_id.upper()}
        if foreign:
            raise ValidationError(
                f"insight for {triage.match.cve_id} referenced CVEs it was never given: "
                f"{', '.join(sorted(foreign))}; this is recall, not grounding"
            )

    def _resolved_citations(
        self, triage: TriageDossier, citations: Sequence[ParsedCitation]
    ) -> list[CitedSource]:
        """Keep the citations that point at something real; drop the rest.

        A citation is not a claim of provenance — it is a check we perform. An advisory
        citation has to name the advisory we supplied; a dossier citation has to name a path
        that exists; and a quote has to appear in what it claims to quote. Anything else is
        a footnote to a document nobody has.
        """
        dossier = triage.asset.model_dump(mode="json")
        advisory_text = triage.advisory.advisory_text
        advisory_refs = {
            triage.advisory.advisory_id.upper(),
            triage.advisory.advisory_source.upper(),
            triage.match.cve_id.upper(),
        }

        resolved: list[CitedSource] = []
        for citation in citations:
            if citation.kind == "advisory":
                if citation.ref.upper() not in advisory_refs:
                    continue
                if citation.quote and not _quotes(advisory_text, citation.quote):
                    # The model attributed words to the advisory that are not in it.
                    continue
                resolved.append(
                    CitedSource(kind="advisory", ref=citation.ref, quote=citation.quote)
                )
                continue

            value = _resolve_path(dossier, citation.ref)
            if value is None:
                continue
            if citation.quote and not _quotes(str(value), citation.quote):
                continue
            resolved.append(
                CitedSource(kind="dossier_field", ref=citation.ref, quote=citation.quote)
            )
        return resolved

    def _checked_recommendation(
        self, triage: TriageDossier, parsed: ParsedInsight, cited: Sequence[CitedSource]
    ) -> Recommendation:
        """The recommendation, if the model is allowed to make it."""
        recommendation = _RECOMMENDATIONS.get(parsed.recommendation)
        if recommendation is None:  # pragma: no cover — the parser already refused these
            raise ValidationError(f"unknown recommendation {parsed.recommendation!r}")
        if recommendation not in SUPPRESSING_RECOMMENDATIONS:
            return recommendation

        if triage.match.kev:
            # The single loudest rule in the system. CISA says this vulnerability is being
            # exploited in the wild; an insight that argues it down the page would be the
            # AI introducing a false negative into a security tool (AGENTS.md §4.9).
            raise ValidationError(
                f"insight for {triage.match.cve_id} recommended lower_priority on a "
                f"KEV-listed match; a finding CISA says is actively exploited cannot be "
                f"de-prioritised by a model"
            )

        if not any(source.kind == "advisory" for source in cited):
            # Asymmetric on purpose: to argue a finding down, cite the advisory that says
            # so. Raising or maintaining may rest on the dossier alone.
            raise ValidationError(
                f"insight for {triage.match.cve_id} recommended lower_priority without "
                f"citing the advisory text; lowering a finding requires advisory grounding"
            )
        return recommendation


# --------------------------------------------------------------------- resolution


def _resolve_path(document: Mapping[str, object], ref: str) -> object | None:
    """Walk a dotted path into the dossier, or return None.

    Accepts `asset.` and `dossier.` prefixes because a model will use them, and indexes
    (`software[0].cpe`) because the dossier has lists. Returns None for anything that does
    not resolve — which is what makes a fabricated citation detectable.
    """
    node: object = document
    cleaned = ref.strip().removeprefix("asset.").removeprefix("dossier.")
    if not cleaned:
        return None

    for raw_part in cleaned.split("."):
        part, _, index_text = raw_part.partition("[")
        if part:
            if not isinstance(node, Mapping):
                return None
            if part not in node:
                return None
            node = node[part]
        if index_text:
            try:
                index = int(index_text.rstrip("]"))
            except ValueError:
                return None
            if not isinstance(node, list) or not -len(node) <= index < len(node):
                return None
            node = node[index]
    return node


def _quotes(source: str, quote: str) -> bool:
    """Does this quote actually appear in this text?

    Whitespace-insensitive, because a model re-wraps lines; otherwise exact. A quote that
    only nearly matches is a paraphrase presented as a quotation, which is the thing being
    checked for.
    """
    normalized_source = " ".join(source.split()).lower()
    normalized_quote = " ".join(quote.split()).lower()
    return bool(normalized_quote) and normalized_quote in normalized_source


__all__: Sequence[str] = [
    "SUPPRESSING_RECOMMENDATIONS",
    "ContainedInsightGenerator",
]
