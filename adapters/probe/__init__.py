"""Health probes — the circuit breaker's senses.

One adapter: a TCP connect to a port discovery already found open. It is deliberately the
lightest thing in the codebase, because a health check that could hurt the device it is
watching would defeat the mechanism it serves (m1-design §2, AGENTS.md §2.7).
"""
