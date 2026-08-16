"""Postgres-backed `AssetRepository` — entity resolution and reversible merges.

This is the moat (AGENTS.md §3): the same device seen by ARP, DHCP and mDNS is *one*
asset with many observations, and getting that wrong in either direction — one asset split
into three, or three devices collapsed into one — is the failure Rapid7 is bad at and the
reason this project exists.

The rules it encodes:

* **Deterministic anchors only.** A hard match comes from `serial`, `cert_fingerprint` or
  `mac`, in that order, and from nothing else. Those three are unique per tenant in the
  schema, which is what makes them identity. `hostname` and `ip` rotate — they are
  locators, and this repository will attach them to an asset but will never *identify* one
  from them. Nothing inferred, and nothing LLM-proposed, is ever a hard match (ports.md §6).
* **An anchor never changes owner.** The upsert refreshes an existing identifier's
  freshness and provenance, but its `asset_id` is untouched. If a strong anchor already
  belongs to a different asset, that is a genuine identity conflict — it raises, rather
  than silently re-pointing evidence at another entity. Resolving it is a merge decision.
* **Merged assets are followed, never returned.** After a merge, the merged asset keeps its
  identifiers; resolving one of them yields the *survivor*, walked through the
  `merged_into` chain.
* **Merge and reversal are atomic and append-only.** The event row and the
  `status`/`merged_into` change commit together or not at all, and a reversal is a new
  event, never an edit — `asset_merge_event` carries `forbid_mutation()`.
* **Merges are always reversible**, and an LLM-proposed merge without a rationale is
  rejected here as well as by the `merge_llm_has_rationale` CHECK. Nothing produces
  `llm_proposed` yet (that generator is M3); the path exists so that when it does, the
  guard is already load-bearing.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, Final
from uuid import UUID

import psycopg

from domain.errors import ConflictError, NotFoundError, ValidationError
from domain.models import (
    AnchorObservation,
    AssetResolution,
    AssetView,
    MergeRequest,
    SoftwareComponent,
)

Connection = psycopg.Connection[tuple[Any, ...]]

#: Identity, strongest first. A serial is stamped on the device; a certificate fingerprint
#: is cryptographic but re-issuable; a MAC is durable in practice yet spoofable and
#: sometimes randomised. `hostname` and `ip` are deliberately absent — see the module
#: docstring.
STRONG_ANCHOR_PRIORITY: Final = ("serial", "cert_fingerprint", "mac")

#: How much identity each anchor kind carries when it matches. The resolution's confidence
#: is this weight scaled by how sure the *observation* was that it read the anchor right,
#: so a half-trusted MAC reading does not produce a fully-trusted identification.
STRONG_ANCHOR_WEIGHT: Final = {
    "serial": 0.99,
    "cert_fingerprint": 0.97,
    "mac": 0.90,
}

#: Guards against a `merged_into` cycle turning resolution into an infinite walk. A chain
#: this deep is already pathological; refusing to loop forever is the point.
_MAX_MERGE_DEPTH: Final = 16

_LOOKUP_ANCHOR_SQL: Final = """
    select asset_id from asset_identifier
    where tenant_id = %(tenant_id)s and kind = %(kind)s and value = %(value)s
    limit 1
"""

#: Walk `merged_into` to the surviving asset. Bounded, and tenant-scoped at every hop.
_SURVIVOR_SQL: Final = """
    with recursive chain(id, merged_into, depth) as (
        select id, merged_into, 0
        from asset
        where id = %(asset_id)s and tenant_id = %(tenant_id)s
        union all
        select a.id, a.merged_into, c.depth + 1
        from asset a
        join chain c on a.id = c.merged_into
        where a.tenant_id = %(tenant_id)s and c.depth < %(max_depth)s
    )
    select id from chain where merged_into is null limit 1
"""

_CREATE_ASSET_SQL: Final = """
    insert into asset (tenant_id, identification_confidence, first_seen_at, last_seen_at)
    values (%(tenant_id)s, %(confidence)s, now(), now())
    returning id
"""

#: `do update` deliberately does NOT touch `asset_id`: an anchor keeps the asset it first
#: identified, and the returned `asset_id` tells the caller who actually owns it.
_CLAIM_STRONG_ANCHOR_SQL: Final = """
    insert into asset_identifier (
        tenant_id, asset_id, kind, value, confidence, observation_id,
        first_seen_at, last_seen_at
    ) values (
        %(tenant_id)s, %(asset_id)s, %(kind)s, %(value)s, %(confidence)s, %(observation_id)s,
        now(), now()
    )
    on conflict (tenant_id, kind, value) where kind in ('serial','cert_fingerprint','mac')
    do update set
        last_seen_at = now(),
        confidence = greatest(asset_identifier.confidence, excluded.confidence),
        observation_id = coalesce(excluded.observation_id, asset_identifier.observation_id)
    returning asset_id
"""

_ATTACH_WEAK_ANCHOR_SQL: Final = """
    insert into asset_identifier (
        tenant_id, asset_id, kind, value, confidence, observation_id,
        first_seen_at, last_seen_at
    )
    select %(tenant_id)s, %(asset_id)s, %(kind)s, %(value)s, %(confidence)s,
           %(observation_id)s, now(), now()
    where not exists (
        select 1 from asset_identifier
        where tenant_id = %(tenant_id)s and asset_id = %(asset_id)s
          and kind = %(kind)s and value = %(value)s
    )
    returning id
"""

_REFRESH_WEAK_ANCHOR_SQL: Final = """
    update asset_identifier set
        last_seen_at = now(),
        confidence = greatest(confidence, %(confidence)s),
        observation_id = coalesce(%(observation_id)s, observation_id)
    where tenant_id = %(tenant_id)s and asset_id = %(asset_id)s
      and kind = %(kind)s and value = %(value)s
"""

_TOUCH_ASSET_SQL: Final = """
    update asset set
        last_seen_at = now(),
        updated_at = now(),
        identification_confidence = greatest(identification_confidence, %(confidence)s)
    where id = %(asset_id)s
"""

_GET_ASSET_SQL: Final = """
    select id, tenant_id, asset_class, management_state, identification_confidence, status
    from asset
    where tenant_id = %(tenant_id)s and id = %(asset_id)s
"""

_ASSET_STATE_SQL: Final = """
    select tenant_id, status from asset where id = %(asset_id)s
"""

_INSERT_MERGE_EVENT_SQL: Final = """
    insert into asset_merge_event (
        tenant_id, kind, survivor_id, merged_id, reverses_id,
        derivation, rationale, confidence, model_version
    ) values (
        %(tenant_id)s, %(kind)s, %(survivor_id)s, %(merged_id)s, %(reverses_id)s,
        %(derivation)s, %(rationale)s, %(confidence)s, %(model_version)s
    )
    returning id
"""

_MARK_MERGED_SQL: Final = """
    update asset set status = 'merged', merged_into = %(survivor_id)s, updated_at = now()
    where id = %(merged_id)s
"""

_MARK_ACTIVE_SQL: Final = """
    update asset set status = 'active', merged_into = null, updated_at = now()
    where id = %(merged_id)s
"""

_GET_MERGE_EVENT_SQL: Final = """
    select tenant_id, kind, survivor_id, merged_id from asset_merge_event
    where id = %(merge_id)s
"""

_EXISTING_REVERSAL_SQL: Final = """
    select id from asset_merge_event where kind = 'reversal' and reverses_id = %(merge_id)s
"""

_ASSET_TENANT_SQL: Final = "select tenant_id from asset where id = %(asset_id)s"

#: Assets currently carrying a given locator. Used only for get-or-create idempotency,
#: never for identity — see `_unidentified_candidate`.
_ASSETS_WITH_ANCHOR_SQL: Final = """
    select ai.asset_id
    from asset_identifier ai
    join asset a on a.id = ai.asset_id
    where ai.tenant_id = %(tenant_id)s and ai.kind = %(kind)s and ai.value = %(value)s
      and a.status = 'active'
"""

_HAS_STRONG_ANCHOR_SQL: Final = """
    select 1 from asset_identifier
    where asset_id = %(asset_id)s and kind in ('serial','cert_fingerprint','mac')
    limit 1
"""

_UPSERT_COMPONENT_SQL: Final = """
    insert into software_component (
        tenant_id, asset_id, cpe, name, version, version_source, confidence,
        is_current, first_seen_at, last_seen_at
    ) values (
        %(tenant_id)s, %(asset_id)s, %(cpe)s, %(name)s, %(version)s, %(version_source)s,
        %(confidence)s, true, now(), now()
    )
    on conflict (tenant_id, asset_id, coalesce(cpe, name), coalesce(version, ''))
        where is_current
    do update set
        last_seen_at = now(),
        confidence = excluded.confidence,
        version_source = excluded.version_source,
        name = excluded.name
    returning id
"""

#: Retire, never delete: a component that is no longer installed stays queryable as
#: history with `is_current = false` (AGENTS.md §3).
_RETIRE_COMPONENTS_SQL: Final = """
    update software_component set is_current = false, last_seen_at = last_seen_at
    where asset_id = %(asset_id)s and is_current and not (id = any(%(keep)s))
"""


class PostgresAssetRepository:
    """`AssetRepository` over `asset` / `asset_identifier` / `asset_merge_event`.

    The multi-statement operations open `conn.transaction()`, which is a transaction on an
    autocommit connection and a savepoint inside a caller's transaction — atomic either
    way, so the caller chooses the unit of work without being able to break the invariant.
    """

    def __init__(self, conn: Connection) -> None:
        self._conn = conn

    # ------------------------------------------------------------------ resolution

    def resolve(self, tenant_id: UUID, anchors: Sequence[AnchorObservation]) -> AssetResolution:
        """Match observed anchors to an asset. Strong anchors first; deterministic only.

        Returns `asset_id=None` when no strong anchor matches — a new-asset candidate. A
        set of only hostnames and IPs always lands here, on purpose: a rotating locator is
        not an identity, and inventing a match from one is how two devices become one.

        When strong anchors disagree (a serial says asset A, a MAC says asset B), the
        stronger anchor wins and only the anchors agreeing with it appear in `matched_on`.
        The disagreement is left visible rather than resolved silently — deciding it is a
        merge, which is a separate, reversible, recorded act.
        """
        matches: list[tuple[str, UUID, float]] = []

        for kind in STRONG_ANCHOR_PRIORITY:
            for anchor in anchors:
                if anchor.kind != kind:
                    continue
                owner = self._owner_of(tenant_id, kind, anchor.value)
                if owner is not None:
                    matches.append((kind, owner, STRONG_ANCHOR_WEIGHT[kind] * anchor.confidence))

        if not matches:
            return AssetResolution(asset_id=None, confidence=0.0, matched_on=[])

        _, best_asset_id, _ = matches[0]
        agreeing = [match for match in matches if match[1] == best_asset_id]
        matched_on = list(dict.fromkeys(kind for kind, _, _ in agreeing))
        confidence = max(score for _, _, score in agreeing)

        return AssetResolution(
            asset_id=best_asset_id, confidence=min(confidence, 1.0), matched_on=matched_on
        )

    def get(self, tenant_id: UUID, asset_id: UUID) -> AssetView | None:
        row = self._conn.execute(
            _GET_ASSET_SQL, {"tenant_id": tenant_id, "asset_id": asset_id}
        ).fetchone()
        if row is None:
            return None
        return AssetView(
            id=UUID(str(row[0])),
            tenant_id=UUID(str(row[1])),
            asset_class=row[2],
            management_state=row[3],
            identification_confidence=row[4],
            status=row[5],
        )

    def upsert_from_anchors(
        self, tenant_id: UUID, anchors: Sequence[AnchorObservation], observation_id: UUID
    ) -> UUID:
        """Get-or-create by strong anchors, idempotent. Links the asserting observation.

        Idempotency is the unique index doing the work, not a preceding existence check
        (AGENTS.md §62): the strong-anchor insert is `ON CONFLICT … DO UPDATE … RETURNING
        asset_id`, so whoever already owns the anchor is reported by the same statement
        that would have created it.

        Raises `ValidationError` with no anchors — an asset with no way to recognise it
        again is not an asset, it is a leak. Raises `ConflictError` if a strong anchor is
        already owned by a different asset.
        """
        if not anchors:
            raise ValidationError("cannot upsert an asset from an empty anchor set")

        with self._conn.transaction():
            resolution = self.resolve(tenant_id, anchors)
            asset_id = resolution.asset_id
            if asset_id is None and not any(
                anchor.kind in STRONG_ANCHOR_PRIORITY for anchor in anchors
            ):
                asset_id = self._unidentified_candidate(tenant_id, anchors)
            if asset_id is None:
                asset_id = self._create_asset(tenant_id, resolution.confidence)

            for anchor in anchors:
                if anchor.kind in STRONG_ANCHOR_PRIORITY:
                    self._claim_strong_anchor(tenant_id, asset_id, anchor, observation_id)
                else:
                    self._attach_weak_anchor(tenant_id, asset_id, anchor, observation_id)

            self._conn.execute(
                _TOUCH_ASSET_SQL, {"asset_id": asset_id, "confidence": resolution.confidence}
            )
            return asset_id

    # -------------------------------------------------------------- current state

    def set_current_software(self, asset_id: UUID, components: Sequence[SoftwareComponent]) -> None:
        """Project current-state software; history remains in `observation`.

        Components not in `components` are retired (`is_current = false`), never deleted.
        Two shapes come from the port signature rather than from choice: `tenant_id` is
        read from the asset (one source of truth, and it cannot disagree), and the
        `first_seen_at`/`last_seen_at` stamps use the database clock because the contract
        passes no timestamp. `observation_id` is left null for the same reason — the
        asserting observation is not part of this call, and inventing a link would be worse
        than an honest null.
        """
        with self._conn.transaction():
            tenant_id = self._tenant_of(asset_id)

            kept: list[UUID] = []
            for component in components:
                row = self._conn.execute(
                    _UPSERT_COMPONENT_SQL,
                    {
                        "tenant_id": tenant_id,
                        "asset_id": asset_id,
                        "cpe": component.cpe,
                        "name": component.name,
                        "version": component.version,
                        "version_source": component.version_source.value,
                        "confidence": component.confidence,
                    },
                ).fetchone()
                if row is not None:
                    kept.append(UUID(str(row[0])))

            self._conn.execute(_RETIRE_COMPONENTS_SQL, {"asset_id": asset_id, "keep": kept})

    # --------------------------------------------------------------------- merges

    def record_merge(self, req: MergeRequest) -> UUID:
        """Append a merge event and mark the merged asset 'merged' → survivor, atomically.

        Rejected before the database is touched: a self-merge, a cross-tenant merge, a
        merge of an asset that is already merged, and an LLM-proposed merge with no
        rationale. That last one is also a CHECK constraint — belt and suspenders, because
        it is the rule an AI-driven caller is most likely to get wrong (AGENTS.md §2.8).
        """
        if req.survivor_id == req.merged_id:
            raise ValidationError("an asset cannot be merged into itself")
        if req.derivation == "llm_proposed" and not req.rationale:
            raise ValidationError("an llm_proposed merge requires a rationale")

        with self._conn.transaction():
            survivor_tenant, survivor_status = self._state_of(req.survivor_id, "survivor")
            merged_tenant, merged_status = self._state_of(req.merged_id, "merged")

            if survivor_tenant != merged_tenant:
                raise ValidationError(
                    "refusing to merge assets belonging to different tenants "
                    f"({survivor_tenant} and {merged_tenant})"
                )
            if merged_status != "active":
                raise ConflictError(f"asset {req.merged_id} is already merged")
            if survivor_status != "active":
                raise ConflictError(f"survivor {req.survivor_id} is not an active asset")

            merge_id = self._insert_event(
                tenant_id=merged_tenant,
                kind="merge",
                survivor_id=req.survivor_id,
                merged_id=req.merged_id,
                reverses_id=None,
                derivation=req.derivation,
                rationale=req.rationale,
                confidence=req.confidence,
                model_version=req.model_version,
            )
            self._conn.execute(
                _MARK_MERGED_SQL,
                {"survivor_id": req.survivor_id, "merged_id": req.merged_id},
            )
            return merge_id

    def reverse_merge(self, merge_id: UUID, *, rationale: str | None = None) -> UUID:
        """Append a reversal event and restore the merged asset to 'active', atomically.

        The reversal is a new row; the original merge event is never edited or removed, so
        the record shows that a merge happened *and* that it was undone (AGENTS.md §3).
        """
        with self._conn.transaction():
            row = self._conn.execute(_GET_MERGE_EVENT_SQL, {"merge_id": merge_id}).fetchone()
            if row is None:
                raise NotFoundError(f"merge event {merge_id} does not exist")

            tenant_id, kind, survivor_id, merged_id = (
                UUID(str(row[0])),
                str(row[1]),
                UUID(str(row[2])),
                UUID(str(row[3])),
            )
            if kind != "merge":
                raise ValidationError(f"event {merge_id} is a {kind}, not a merge")

            already = self._conn.execute(_EXISTING_REVERSAL_SQL, {"merge_id": merge_id}).fetchone()
            if already is not None:
                raise ConflictError(f"merge {merge_id} has already been reversed")

            reversal_id = self._insert_event(
                tenant_id=tenant_id,
                kind="reversal",
                survivor_id=survivor_id,
                merged_id=merged_id,
                reverses_id=merge_id,
                # The reversal is an operator act, not a model's; a reversal that cited a
                # model as its derivation would misattribute who undid the merge.
                derivation="deterministic",
                rationale=rationale,
                confidence=None,
                model_version=None,
            )
            self._conn.execute(_MARK_ACTIVE_SQL, {"merged_id": merged_id})
            return reversal_id

    # ---------------------------------------------------------------- internals

    def _owner_of(self, tenant_id: UUID, kind: str, value: str) -> UUID | None:
        """The surviving asset an anchor currently identifies, or None."""
        row = self._conn.execute(
            _LOOKUP_ANCHOR_SQL, {"tenant_id": tenant_id, "kind": kind, "value": value}
        ).fetchone()
        if row is None:
            return None
        return self._survivor_of(tenant_id, UUID(str(row[0])))

    def _survivor_of(self, tenant_id: UUID, asset_id: UUID) -> UUID:
        row = self._conn.execute(
            _SURVIVOR_SQL,
            {"tenant_id": tenant_id, "asset_id": asset_id, "max_depth": _MAX_MERGE_DEPTH},
        ).fetchone()
        if row is None:
            raise ConflictError(
                f"asset {asset_id} has no surviving asset within {_MAX_MERGE_DEPTH} merge hops"
            )
        return UUID(str(row[0]))

    def _unidentified_candidate(
        self, tenant_id: UUID, anchors: Sequence[AnchorObservation]
    ) -> UUID | None:
        """The existing new-asset candidate this locator-only sighting already produced.

        **Idempotency, not identity.** An mDNS record gives a hostname and an address and
        nothing else. `resolve` correctly refuses to identify a device from those, but
        without this, every sweep would mint another asset for the same unidentifiable
        sighting and the graph would inflate exactly where we claim to reduce noise.

        The reuse is deliberately narrow: *every* locator must match, and the candidate
        must carry no strong anchor of its own. So this can never pull a sighting into an
        identified asset (that would be a merge decision, and a merge is reversible and
        recorded — this is neither), and an address reassigned to a device we *have*
        identified cannot capture it. Ambiguity — several candidates — creates a new one
        rather than guessing between them.
        """
        matching: set[UUID] | None = None
        for anchor in anchors:
            rows = self._conn.execute(
                _ASSETS_WITH_ANCHOR_SQL,
                {"tenant_id": tenant_id, "kind": anchor.kind, "value": anchor.value},
            ).fetchall()
            owners = {UUID(str(row[0])) for row in rows}
            matching = owners if matching is None else matching & owners
            if not matching:
                return None

        unidentified = [
            asset_id for asset_id in (matching or set()) if not self._has_strong_anchor(asset_id)
        ]
        return unidentified[0] if len(unidentified) == 1 else None

    def _has_strong_anchor(self, asset_id: UUID) -> bool:
        return (
            self._conn.execute(_HAS_STRONG_ANCHOR_SQL, {"asset_id": asset_id}).fetchone()
            is not None
        )

    def _create_asset(self, tenant_id: UUID, confidence: float) -> UUID:
        row = self._conn.execute(
            _CREATE_ASSET_SQL, {"tenant_id": tenant_id, "confidence": confidence}
        ).fetchone()
        assert row is not None  # noqa: S101 — an INSERT … RETURNING always returns a row
        return UUID(str(row[0]))

    def _claim_strong_anchor(
        self, tenant_id: UUID, asset_id: UUID, anchor: AnchorObservation, observation_id: UUID
    ) -> None:
        row = self._conn.execute(
            _CLAIM_STRONG_ANCHOR_SQL,
            {
                "tenant_id": tenant_id,
                "asset_id": asset_id,
                "kind": anchor.kind,
                "value": anchor.value,
                "confidence": anchor.confidence,
                "observation_id": observation_id,
            },
        ).fetchone()
        assert row is not None  # noqa: S101 — DO UPDATE always returns the surviving row
        owner = self._survivor_of(tenant_id, UUID(str(row[0])))
        if owner != asset_id:
            raise ConflictError(
                f"{anchor.kind} anchor {anchor.value!r} already identifies asset {owner}; "
                f"it will not be re-pointed at {asset_id} — resolve this with a merge"
            )

    def _attach_weak_anchor(
        self, tenant_id: UUID, asset_id: UUID, anchor: AnchorObservation, observation_id: UUID
    ) -> None:
        """Locators are attached, not claimed: the same IP may legitimately be attached to
        another asset tomorrow, so there is no uniqueness to enforce and nothing to steal."""
        params = {
            "tenant_id": tenant_id,
            "asset_id": asset_id,
            "kind": anchor.kind,
            "value": anchor.value,
            "confidence": anchor.confidence,
            "observation_id": observation_id,
        }
        inserted = self._conn.execute(_ATTACH_WEAK_ANCHOR_SQL, params).fetchone()
        if inserted is None:
            self._conn.execute(_REFRESH_WEAK_ANCHOR_SQL, params)

    def _tenant_of(self, asset_id: UUID) -> UUID:
        row = self._conn.execute(_ASSET_TENANT_SQL, {"asset_id": asset_id}).fetchone()
        if row is None:
            raise NotFoundError(f"asset {asset_id} does not exist")
        return UUID(str(row[0]))

    def _state_of(self, asset_id: UUID, role: str) -> tuple[UUID, str]:
        row = self._conn.execute(_ASSET_STATE_SQL, {"asset_id": asset_id}).fetchone()
        if row is None:
            raise NotFoundError(f"{role} asset {asset_id} does not exist")
        return UUID(str(row[0])), str(row[1])

    def _insert_event(
        self,
        *,
        tenant_id: UUID,
        kind: str,
        survivor_id: UUID,
        merged_id: UUID,
        reverses_id: UUID | None,
        derivation: str,
        rationale: str | None,
        confidence: float | None,
        model_version: str | None,
    ) -> UUID:
        row = self._conn.execute(
            _INSERT_MERGE_EVENT_SQL,
            {
                "tenant_id": tenant_id,
                "kind": kind,
                "survivor_id": survivor_id,
                "merged_id": merged_id,
                "reverses_id": reverses_id,
                "derivation": derivation,
                "rationale": rationale,
                "confidence": confidence,
                "model_version": model_version,
            },
        ).fetchone()
        assert row is not None  # noqa: S101 — an INSERT … RETURNING always returns a row
        return UUID(str(row[0]))
