"""Postgres-backed `ScopeAuthority` — the engine's pre-flight check.

This is the control that keeps the platform from being attack infrastructure
(AGENTS.md §2.5). Everything here is written to fail closed:

* **Deny-by-default.** The query looks for a reason to say yes. No matching row — no
  authorization, an inactive one, an expired one, one belonging to another tenant — means
  `allowed=False`. There is no branch that grants access in the absence of evidence.
* **Every decision is audited, before it is returned.** The `audit_log` insert happens
  between deciding and answering. If the audit write fails, the exception propagates and
  the caller never receives an authorization: an undocumented scan does not happen.
* **Nothing is swallowed.** No `except` block turns a database failure into a decision.
  A check that could not be completed is not a check that passed.
* **The audit trail cannot be rolled back by the caller.** The connection must be in
  autocommit mode, so the record of a denial (or of an authorization about to be acted on)
  is durable the moment it is written, independent of whatever transaction the caller may
  abort afterwards.

The containment test itself is `cidr >>= target`, answered by the SP-GiST index from
migration `0001_expand`; `tests/integration/test_schema_invariants.py` proves the operator
behaves, and `tests/integration/test_scope_authority.py` proves this adapter does.
"""

from __future__ import annotations

import json
from typing import Any, Final
from uuid import UUID

import psycopg

from domain.errors import ScopeViolation
from domain.models import IPAddress, ScopeDecision

Connection = psycopg.Connection[tuple[Any, ...]]

#: The audited action name. Stable — the audit trail is queried by it.
SCOPE_ACTION: Final = "scope.authorize"

RESOURCE_TYPE: Final = "target"

#: Most specific match first: a /32 carve-out is the authorization an operator meant, and
#: it is the one worth recording against the decision.
_MATCH_SQL: Final = """
    select id, cidr::text
    from scope_authorization
    where tenant_id = %(tenant_id)s
      and active
      and (expires_at is null or expires_at > now())
      and cidr >>= %(target)s::inet
    order by masklen(cidr) desc
    limit 1
"""

_AUDIT_SQL: Final = """
    insert into audit_log (
        tenant_id, actor, actor_type, action, resource_type, resource_id,
        result, request_id, correlation_id, metadata
    ) values (
        %(tenant_id)s, %(actor)s, %(actor_type)s, %(action)s, %(resource_type)s, %(target)s,
        %(result)s, %(request_id)s, %(correlation_id)s, %(metadata)s::jsonb
    )
"""


class PostgresScopeAuthority:
    """`ScopeAuthority` over the `scope_authorization` table.

    One instance per unit of work: `actor`, `request_id` and `correlation_id` describe
    *who* is asking and under which operation, and are stamped onto every audit row so a
    decision can be tied back to the run that triggered it (AGENTS.md §8).
    """

    def __init__(
        self,
        conn: Connection,
        *,
        actor: str = "engine",
        actor_type: str = "service",
        request_id: str | None = None,
        correlation_id: str | None = None,
    ) -> None:
        if not conn.autocommit:
            raise ValueError(
                "PostgresScopeAuthority requires an autocommit connection: the audit "
                "record of a scope decision must not be rollback-able by the caller."
            )
        self._conn = conn
        self._actor = actor
        self._actor_type = actor_type
        self._request_id = request_id
        self._correlation_id = correlation_id

    def authorize(self, tenant_id: UUID, target: IPAddress) -> ScopeDecision:
        """Deny-by-default containment check against the tenant's active authorizations.

        Records the decision to `audit_log` before returning it. Any failure — of the
        lookup or of the audit write — propagates; it never degrades into `allowed=True`.
        """
        target_text = str(target)
        row = self._conn.execute(
            _MATCH_SQL, {"tenant_id": tenant_id, "target": target_text}
        ).fetchone()

        if row is None:
            decision = ScopeDecision(
                allowed=False,
                target=target_text,
                matched_authorization_id=None,
                reason=(
                    f"deny-by-default: no active authorization for tenant {tenant_id} "
                    f"contains {target_text}"
                ),
            )
            matched_cidr = None
        else:
            authorization_id = UUID(str(row[0]))
            matched_cidr = str(row[1])
            decision = ScopeDecision(
                allowed=True,
                target=target_text,
                matched_authorization_id=authorization_id,
                reason=(
                    f"target {target_text} is inside authorized range {matched_cidr} "
                    f"(authorization {authorization_id})"
                ),
            )

        self._audit(tenant_id, decision, matched_cidr)
        return decision

    def require_authorized(self, tenant_id: UUID, target: IPAddress) -> None:
        """Raise `ScopeViolation` unless the target is in scope.

        Call this at the point of emission so that forgetting a check fails closed rather
        than open: the exception is the default, the packet is the exception.
        """
        decision = self.authorize(tenant_id, target)
        if not decision.allowed:
            raise ScopeViolation(decision.reason)

    def _audit(self, tenant_id: UUID, decision: ScopeDecision, matched_cidr: str | None) -> None:
        """Write the decision to `audit_log`. Not best-effort: a failure here aborts the
        caller, because an unauditable decision must not be acted upon."""
        metadata = json.dumps(
            {
                "reason": decision.reason,
                "matched_cidr": matched_cidr,
                "matched_authorization_id": (
                    str(decision.matched_authorization_id)
                    if decision.matched_authorization_id is not None
                    else None
                ),
            },
            sort_keys=True,
        )
        self._conn.execute(
            _AUDIT_SQL,
            {
                "tenant_id": tenant_id,
                "actor": self._actor,
                "actor_type": self._actor_type,
                "action": SCOPE_ACTION,
                "resource_type": RESOURCE_TYPE,
                "target": decision.target,
                "result": "success" if decision.allowed else "denied",
                "request_id": self._request_id,
                "correlation_id": self._correlation_id,
                "metadata": metadata,
            },
        )
