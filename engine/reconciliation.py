"""Matching the CMDB against what we found, and computing the shadow-IT diff.

This is the product's headline claim — *"you list 300 assets; we found 347; here are the 47
nobody registered"* — and the governing risk is that **weak matching makes the diff lie**.
A server that IS in the CMDB but whose hostname was typed differently would be reported as
shadow IT, and one obvious false positive in the first demo discredits the entire system
(m2-design §3).

So the design is built around refusing to overclaim:

* **`unmanaged` counts only assets we could have matched and did not.** An asset with no
  comparable anchor — known only by its address — is not evidence of anything, and lands in
  `ambiguous` rather than inflating the number.
* **Ambiguity is a category, not a rounding error.** Two plausible assets, a hostname that
  only matches once you delete its punctuation, strong anchors that disagree: each is
  reported as unresolved, and every asset touched by an unresolved case resolves to
  `management_state = unknown`, never `unmanaged`.
* **Deterministic only.** The anchor priority is the entity resolution's own — `serial ›
  mac › hostname` (AGENTS.md §3) — because this is the same "is this the same real thing?"
  problem, now crossing management records against discovered assets. Nothing is inferred,
  nothing is force-matched.

**The LLM seam, deliberately left empty (AGENTS.md §5, m2-design §3).** The ambiguous
findings carry their candidate assets, which is exactly the queue an M3 proposer would
reason over — through the existing propose/dispose pattern, with `ReconciliationLink.
derivation` already able to say `llm_proposed`. Nothing here calls a model. First
*measure* how many ambiguous cases a real CMDB produces (the runbook does that), then
decide whether a proposer is warranted.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import UTC, datetime
from uuid import UUID

from domain.models import (
    AssetAnchorSet,
    DiffCategory,
    DiffFinding,
    ManagedRecordSnapshot,
    ManagementState,
    MatchStrength,
    ReconciliationLink,
    ShadowItDiff,
)

#: A serial or MAC agreeing is the same evidence entity resolution treats as identity.
STRONG_LINK_CONFIDENCE = 0.95

#: A hostname is a label a person typed, and people rename machines. Enough to link, not
#: enough to be sure — which is why it is reported with its strength attached.
WEAK_LINK_CONFIDENCE = 0.6

#: An asset with a serial or MAC that matched nothing in the CMDB is a real finding: we had
#: something durable to look up and the authoritative source did not know it.
SHADOW_IT_STRONG_CONFIDENCE = 0.9

#: An asset we could only look up by name. Still a finding, but the CMDB might simply spell
#: it differently — so it is reported softer, and the operator sees why.
SHADOW_IT_WEAK_CONFIDENCE = 0.5

#: A CMDB row nothing on the network matches. The device may be off, not gone — a candidate
#: for the CMDB owner to check, never a claim that it does not exist.
STALE_CONFIDENCE = 0.6

AMBIGUOUS_CONFIDENCE = 0.3

_HOSTNAME_SEPARATORS = re.compile(r"[^a-z0-9]+")


def normalize_hostname(value: str) -> str:
    """The comparable form of a hostname: lower-cased, no trailing dot, no DNS domain.

    `SRV-APP-03`, `srv-app-03.corp.local.` and `srv-app-03` are the same machine written
    three ways, and a CMDB will contain all three. Taking the short name is the one
    normalisation that is safe to do silently: a domain suffix is a location, not a name.
    """
    short = value.strip().lower().rstrip(".").split(".")[0]
    return short


def squash_hostname(value: str) -> str:
    """The same name with its punctuation removed — `srv-app-03` and `srvapp03`.

    Deliberately **not** used to link, only to detect ambiguity. Squashing is where false
    matches come from: `a-b1` and `ab-1` squash identically and are not obviously the same
    machine. So a squash-only similarity means "a human should look at this", which is
    exactly what the ambiguous queue is for (ADR-0009).
    """
    return _HOSTNAME_SEPARATORS.sub("", normalize_hostname(value))


def normalize_serial(value: str) -> str:
    """Case-insensitive: the same serial is upper-case on the label the CMDB was typed from
    and lower-case in whatever the device reported."""
    return value.strip().upper()


def normalize_mac(value: str) -> str:
    return value.strip().lower()


class Reconciliation:
    """The result of matching one tenant's CMDB records against its assets."""

    def __init__(
        self,
        links: Sequence[ReconciliationLink],
        findings: Sequence[DiffFinding],
        states: Mapping[UUID, ManagementState],
    ) -> None:
        self.links = tuple(links)
        self.findings = tuple(findings)
        self.states = dict(states)

    def diff(self, tenant_id: UUID, *, computed_at: datetime | None = None) -> ShadowItDiff:
        """Group the findings into the four categories the operator sees."""
        by_category: dict[DiffCategory, list[DiffFinding]] = {
            category: [] for category in DiffCategory
        }
        for finding in self.findings:
            by_category[finding.category].append(finding)

        return ShadowItDiff(
            tenant_id=tenant_id,
            computed_at=computed_at or datetime.now(UTC),
            matched=by_category[DiffCategory.MATCHED],
            unmanaged=by_category[DiffCategory.UNMANAGED],
            stale=by_category[DiffCategory.STALE],
            ambiguous=by_category[DiffCategory.AMBIGUOUS],
        )


class _AssetIndex:
    """Assets indexed by every anchor they can be matched on."""

    def __init__(self, assets: Iterable[AssetAnchorSet]) -> None:
        self.assets = {asset.asset_id: asset for asset in assets}
        self.by_serial = self._index(lambda a: a.serials, normalize_serial)
        self.by_mac = self._index(lambda a: a.macs, normalize_mac)
        self.by_hostname = self._index(lambda a: a.hostnames, normalize_hostname)
        self.by_squashed = self._index(lambda a: a.hostnames, squash_hostname)

    def _index(
        self,
        select: Callable[[AssetAnchorSet], Iterable[str]],
        normalize: Callable[[str], str],
    ) -> dict[str, set[UUID]]:
        index: dict[str, set[UUID]] = {}
        for asset in self.assets.values():
            for raw in select(asset):
                key = normalize(raw)
                if key:
                    index.setdefault(key, set()).add(asset.asset_id)
        return index


def reconcile(
    records: Sequence[ManagedRecordSnapshot], assets: Sequence[AssetAnchorSet]
) -> Reconciliation:
    """Match records to assets, and categorise everything on both sides.

    Deterministic and ambiguity-preserving. The order of the checks is the anchor priority
    from AGENTS.md §3: a serial or MAC settles it; a hostname is only allowed to settle it
    when exactly one asset answers to that name; anything else is left for a human.
    """
    index = _AssetIndex(assets)

    links: list[ReconciliationLink] = []
    findings: list[DiffFinding] = []
    #: Assets any unresolved case touched. These can never be called shadow IT, whatever
    #: else is true of them — the single most important rule in this module.
    entangled: set[UUID] = set()
    linked_assets: set[UUID] = set()

    for record in records:
        outcome = _match_record(record, index)
        if outcome.link is not None:
            links.append(outcome.link)
            linked_assets.add(outcome.link.asset_id)
        findings.extend(outcome.findings)
        entangled.update(outcome.entangled)

    findings.extend(_asset_findings(index, linked_assets, entangled, links))
    states = _management_states(index, linked_assets, entangled)
    return Reconciliation(links, findings, states)


class _RecordOutcome:
    __slots__ = ("entangled", "findings", "link")

    def __init__(
        self,
        link: ReconciliationLink | None = None,
        findings: Sequence[DiffFinding] = (),
        entangled: Iterable[UUID] = (),
    ) -> None:
        self.link = link
        self.findings = tuple(findings)
        self.entangled = set(entangled)


def _match_record(record: ManagedRecordSnapshot, index: _AssetIndex) -> _RecordOutcome:
    """One authoritative record against every asset. See `reconcile` for the ordering."""
    strong_hits: dict[UUID, list[str]] = {}
    if record.serial:
        for asset_id in index.by_serial.get(normalize_serial(record.serial), set()):
            strong_hits.setdefault(asset_id, []).append("serial")
    if record.mac:
        for asset_id in index.by_mac.get(normalize_mac(record.mac), set()):
            strong_hits.setdefault(asset_id, []).append("mac")

    if len(strong_hits) == 1:
        asset_id, matched_on = next(iter(strong_hits.items()))
        return _linked(record, asset_id, matched_on, MatchStrength.STRONG)

    if len(strong_hits) > 1:
        # A record whose serial names one asset and whose MAC names another. Deterministic
        # anchors disagreeing is a data-quality problem in the CMDB — a swapped NIC, a
        # mistyped row — and picking a winner would be inventing a fact.
        return _ambiguous(
            record,
            sorted(strong_hits),
            "strong anchors disagree: this record's serial and MAC point at different assets",
        )

    if record.hostname:
        name = normalize_hostname(record.hostname)
        by_name = index.by_hostname.get(name, set())
        if len(by_name) == 1:
            return _linked(record, next(iter(by_name)), ["hostname"], MatchStrength.WEAK)
        if len(by_name) > 1:
            return _ambiguous(
                record,
                sorted(by_name),
                f"several assets answer to the name {name!r}; a name is not an identity",
            )

        squashed = index.by_squashed.get(squash_hostname(record.hostname), set())
        if squashed:
            # `srvapp03` in the CMDB, `srv-app-03` on the network. Probably the same
            # machine; "probably" is not something this layer is allowed to conclude.
            return _ambiguous(
                record,
                sorted(squashed),
                "hostname matches only after punctuation is removed — likely the same "
                "device, but not deterministically",
            )

    return _RecordOutcome(
        findings=[
            DiffFinding(
                category=DiffCategory.STALE,
                confidence=STALE_CONFIDENCE,
                reason=(
                    "no discovered asset matches this record; the device may be switched "
                    "off rather than gone"
                ),
                record_id=record.record_id,
                external_id=record.external_id,
            )
        ]
    )


def _linked(
    record: ManagedRecordSnapshot,
    asset_id: UUID,
    matched_on: Sequence[str],
    strength: MatchStrength,
) -> _RecordOutcome:
    confidence = (
        STRONG_LINK_CONFIDENCE if strength is MatchStrength.STRONG else WEAK_LINK_CONFIDENCE
    )
    link = ReconciliationLink(
        record_id=record.record_id,
        asset_id=asset_id,
        strength=strength,
        matched_on=list(matched_on),
        confidence=confidence,
    )
    finding = DiffFinding(
        category=DiffCategory.MATCHED,
        confidence=confidence,
        reason=f"matched on {', '.join(matched_on)}",
        asset_id=asset_id,
        record_id=record.record_id,
        external_id=record.external_id,
        matched_on=list(matched_on),
    )
    return _RecordOutcome(link=link, findings=[finding])


def _ambiguous(
    record: ManagedRecordSnapshot, candidates: Sequence[UUID], reason: str
) -> _RecordOutcome:
    finding = DiffFinding(
        category=DiffCategory.AMBIGUOUS,
        confidence=AMBIGUOUS_CONFIDENCE,
        reason=reason,
        record_id=record.record_id,
        external_id=record.external_id,
        candidate_asset_ids=list(candidates),
    )
    return _RecordOutcome(findings=[finding], entangled=candidates)


def _asset_findings(
    index: _AssetIndex,
    linked_assets: set[UUID],
    entangled: set[UUID],
    links: Sequence[ReconciliationLink],
) -> list[DiffFinding]:
    """Categorise every asset the records did not account for.

    The two guards here are what make the headline number defensible: an asset caught up in
    an unresolved case is never called shadow IT, and neither is one we had no way to look
    up in the first place.
    """
    matched_on_by_asset: dict[UUID, list[str]] = {}
    for link in links:
        matched_on_by_asset.setdefault(link.asset_id, []).extend(link.matched_on)

    findings: list[DiffFinding] = []
    for asset_id, asset in index.assets.items():
        if asset_id in linked_assets:
            continue  # already reported as MATCHED by the record that linked it

        if asset_id in entangled:
            findings.append(
                DiffFinding(
                    category=DiffCategory.AMBIGUOUS,
                    confidence=AMBIGUOUS_CONFIDENCE,
                    reason=(
                        "a CMDB record may refer to this asset but could not be matched "
                        "confidently; not counted as unmanaged"
                    ),
                    asset_id=asset_id,
                )
            )
            continue

        if not asset.is_matchable:
            # Only an address. There is no anchor a CMDB row could ever agree with, so
            # "nobody manages it" would be a claim about a test we never ran.
            findings.append(
                DiffFinding(
                    category=DiffCategory.AMBIGUOUS,
                    confidence=AMBIGUOUS_CONFIDENCE,
                    reason=(
                        "no serial, MAC or hostname for this asset, so it cannot be looked "
                        "up in the CMDB at all; not counted as unmanaged"
                    ),
                    asset_id=asset_id,
                )
            )
            continue

        strong = asset.has_strong_anchor
        findings.append(
            DiffFinding(
                category=DiffCategory.UNMANAGED,
                confidence=(SHADOW_IT_STRONG_CONFIDENCE if strong else SHADOW_IT_WEAK_CONFIDENCE),
                reason=(
                    "no CMDB record matches this asset's serial or MAC"
                    if strong
                    else "no CMDB record matches this asset's hostname, and it has no "
                    "serial or MAC to check — the CMDB may simply spell it differently"
                ),
                asset_id=asset_id,
            )
        )

    return findings


def _management_states(
    index: _AssetIndex, linked_assets: set[UUID], entangled: set[UUID]
) -> dict[UUID, ManagementState]:
    """`managed` / `unmanaged` / `unknown` for every asset.

    Ambiguity resolves to `unknown`, never `unmanaged` (m2-design §4). The field on the
    asset and the headline count therefore agree by construction — there is no path that
    marks an asset unmanaged without also listing it as shadow IT, or the reverse.
    """
    states: dict[UUID, ManagementState] = {}
    for asset_id, asset in index.assets.items():
        if asset_id in linked_assets:
            states[asset_id] = ManagementState.MANAGED
        elif asset_id in entangled or not asset.is_matchable:
            states[asset_id] = ManagementState.UNKNOWN
        else:
            states[asset_id] = ManagementState.UNMANAGED
    return states
