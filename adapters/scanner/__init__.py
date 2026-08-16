"""Active-scanning adapters.

One member so far: the nmap orchestrator behind `domain.ports.ActiveScanner`. Everything
that knows what a scanner *flag* is lives in this package — the domain and the engine
speak only in `ScanProfile` (m1-design §2).
"""
