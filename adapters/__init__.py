"""Adapters: the only layer allowed to touch infrastructure.

Every adapter here structurally implements a `Protocol` from `domain.ports` — Postgres
for `ScopeAuthority`/`ObservationSink`/`AssetRepository`, the in-perimeter vault for
`SecretsPort`, RAG for `AdvisoryRetriever`, a local model for `InsightGenerator`.

Empty at P1 by design: implementations land in P2–P4 (ports.md §10).
"""
