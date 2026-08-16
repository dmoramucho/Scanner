"""The engine: orchestration over ports, with scope enforced before any packet is emitted.

`ScopeAuthority.require_authorized` is called here, at the point of emission, so a
forgotten check fails closed rather than open (AGENTS.md §2.5).

Empty at P1 by design: the scope pre-flight and the collector shell land in P2.
"""
