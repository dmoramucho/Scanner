"""Authoritative-inventory sources: what the organization believes it owns.

One adapter so far — a CMDB CSV/Excel export. AD, MDM, EDR and API-based CMDBs are future
adapters behind the same `ManagedSource` port (m2-design §6).

Every row from these sources is untrusted input: a person edited the file, and a
spreadsheet cell is a program (AGENTS.md §2.9, ADR-0008).
"""
