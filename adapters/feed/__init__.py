"""Vulnerability feeds: where CVE knowledge comes from.

One adapter so far — the NVD API, cached locally. KEV and EPSS are the next two (P13).

Half A of M3 is deterministic by construction: nothing in this package imports a model or
an LLM client, and `tests/test_adapter_boundaries.py` fails if that ever changes. A CVE
match must trace back to a feed that said so, never to something that generated it
(m3-design §1, AGENTS.md §4.8).
"""
