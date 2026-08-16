"""Postgres adapters. The only place psycopg appears outside the tests.

Each class here structurally implements a `Protocol` from `domain.ports`; nothing in this
package is imported by `domain/`, and the dependency never points the other way.
"""
