"""The deterministic core: models, ports, errors.

Pure by construction — stdlib and pydantic only. No infrastructure SDK (DB driver,
cloud client, queue, LLM client) may be imported here (AGENTS.md §2.1); the boundary is
enforced by `tests/test_domain_boundary.py`.
"""
