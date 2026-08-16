"""The collector: passive discovery, read-only by construction.

Separable on purpose. It depends on `domain` for the shape of an observation and on
nothing else — no database, no network, no subprocess — so the outbound/mTLS boundary
(LATER) can be drawn around this package without changing what is inside it.
`tests/test_adapter_boundaries.py` enforces that, so the property does not decay.
"""
