# Corporate Asset Scanner

Single-tenant, on-prem scanner for corporate networks: discovers, fingerprints, reconciles and
correlates assets (servers, IoT, IP cameras, VoIP, UPS), prioritises vulnerabilities by
real-world exploitability, and produces AI-assisted insight on top of deterministic facts.

The value is not in scanning — that is commoditised. It is in entity resolution, the
unmanaged-device (shadow-IT) diff, confidence-based noise reduction, and grounded AI insight.

**Start here:** [`AGENTS.md`](AGENTS.md) — the operating rules. Read it before writing code.

## Where things are

| Path | What it holds |
|---|---|
| [`docs/architecture/ports.md`](docs/architecture/ports.md) | The six port contracts, the error hierarchy, the `Secret` primitive |
| [`docs/data/asset-dossier-contract.md`](docs/data/asset-dossier-contract.md) | The redacted, typed object the LLM reasons over |
| [`docs/data/data-model.md`](docs/data/data-model.md) | The schema of record; applied by `0001_expand` |
| [`docs/adr/`](docs/adr/) | One ADR per material decision |
| [`docs/runbooks/`](docs/runbooks/) | Operator procedures — including the real-device scan validation |
| `domain/` | The deterministic core: models, ports, errors. **stdlib + pydantic only** |
| `adapters/postgres/` | `ScopeAuthority`, `ObservationSink`, `AssetRepository` over Postgres — the only place psycopg lives |
| `adapters/collector/` | Passive discovery (ARP / DHCP / mDNS). Read-only and store-free by construction |
| `adapters/scanner/` | Active scanning: the nmap orchestrator. The only place that knows what a scanner flag is |
| `adapters/inspector/` | Credentialed reads over SSH — read-only, allow-listed commands, credential-safe |
| `adapters/probe/` | The circuit breaker's health check: one TCP connect, no data, no root |
| `adapters/managed/` | Authoritative inventory: the CMDB CSV/Excel reader, untrusted-file-safe |
| `adapters/feed/` | Vulnerability feeds: NVD, CISA KEV, EPSS — rate-limited and cached. No model, ever |
| `engine/` | Orchestration; the scope gate runs before anything is recorded, and the scan-safety policy lives here |
| `config/` | Startup configuration — validated once, fail-fast |
| `migrations/` | Alembic revisions — hand-written raw SQL, no ORM ([how](migrations/README.md)) |
| `tests/` | Unit tests, the mechanically enforced `domain/` boundary, and `integration/` against a real Postgres |

## Architectural rule that shapes the layout

`domain/` may not import infrastructure — no DB driver, cloud SDK, queue, or LLM client
(AGENTS.md §2.1). Dependencies point inward: `adapters/` and `engine/` know the domain, never
the reverse. This is enforced by `tests/test_domain_boundary.py`, which parses every module
under `domain/` and rejects any import outside stdlib, `pydantic`, and `domain` itself. If a
domain module seems to need an infrastructure package, the abstraction is in the wrong layer —
move it, do not widen the allowlist.

## Getting started

Requires [uv](https://docs.astral.sh/uv/) and Docker.

```bash
cp .env.example .env        # then edit: nothing has a fallback in code
uv sync                     # create .venv, install pinned deps
docker compose up -d        # Postgres + MinIO + LocalStack

set -a; . ./.env; set +a    # alembic reads the DSN through config.load_config()
uv run alembic upgrade head # apply the store schema
```

Every port is published on `127.0.0.1` only. Postgres defaults to host port **5433** (5432 is
commonly taken by another local stack); change `POSTGRES_PORT` and `SCANNER_DATABASE_URL`
together if you want otherwise. LocalStack is pinned to the last license-free community
release — the 2026.x images refuse to start without an auth token.

Checks:

```bash
uv run ruff check .              # lint
uv run ruff format --check .
uv run mypy                      # strict; paths come from pyproject.toml
uv run pytest                    # everything
uv run pytest -m "not integration"  # unit only — no database needed
```

The integration tests run against the **real** compose Postgres: append-only triggers, the
SP-GiST containment index, and the partial unique index on strong anchors do not exist outside
it, so a mock or SQLite would prove nothing (ADR-0002). They provision their own
`<db>_test` database, apply the schema by running the actual migration, and roll back after
each test. With Docker stopped they skip with a message telling you what to start; set
`SCANNER_REQUIRE_INTEGRATION=1` to make that a failure instead (what CI should do).

Configuration is validated at startup by `config.load_config()`, which raises `ConfigError`
listing **every** missing variable. There are no silent defaults for credentials or endpoints;
the two optional variables (`SCANNER_REGION`, `SCANNER_LOG_LEVEL`) have documented, harmless
defaults. Secret-bearing values are wrapped in `domain.secret.Secret`, which redacts in `repr`
and `str` — `.reveal()` is the only path to the raw value, and greps as the list of places a
secret is actually used.

## Status

**M0–M3 complete (P1–P16).** A capture goes end to end: parsers turn an ARP
table, DHCP leases, or mDNS output into provenance-complete observations; the engine calls
`require_authorized` on every target *before* anything is recorded; the sink writes them
idempotently into the append-only spine; entity resolution collapses them into assets by stable
anchors. Three kinds of discovery feed one reconciled inventory: passive (ARP/DHCP/mDNS), active
(nmap under a gentle, breaker-protected profile), and credentialed (read-only SSH). The CMDB export is imported into
`managed_record` and reconciled against them, so the inventory now answers the question the
product exists for: **what does nobody manage?** All three
pass the same scope gate, write through the same append-only spine, and resolve through the same
entity resolution — so a camera seen three ways is one asset with three kinds of provenance.

What the system guarantees, each proven by tests:

- **Scope is a gate, not a filter.** Deny-by-default — no authorization, a revoked one, an
  expired one, or another tenant's one all deny. Every decision lands in `audit_log` before it
  is returned, and an out-of-scope target leaves no observation and no asset.
- **Evidence is immutable.** `observation`, `audit_log` and `asset_merge_event` refuse `UPDATE`
  and `DELETE` at the database. Re-ingesting a capture in the same run adds nothing; a later run
  is new evidence about the same assets.
- **Identity is deterministic.** A hard match comes only from `serial`, `cert_fingerprint` or
  `mac`. Hostnames and IPs are attached but never identify — they rotate. A strong anchor never
  changes owner: a conflict raises rather than silently re-pointing evidence.
- **Merges are reversible.** The event and the status change commit together, a reversal is a
  new event rather than an edit, and an LLM-proposed merge without a rationale is rejected by
  both the adapter and a `CHECK` constraint.
- **Fragile devices get the gentle profile.** The `GENTLE` scan profile means no `-A`, no
  `--version-all`, `--version-intensity 0`, SYN not connect, a `-T2` ceiling, a scan delay,
  capped rate and parallelism, and a curated IoT port set rather than all 65535 — asserted flag
  by flag, so loosening it fails the build (AGENTS.md §2.7). A device that nothing positively
  identifies as robust is treated as fragile, the same fail-safe direction as deny-by-default.
- **A device that stops answering stops being scanned.** Health checks bracket every scan; a
  device that was up before and silent after trips the circuit breaker, which backs off, records
  the trip as an observation rather than a counter, and moves on. One casualty never aborts the
  run — three in a row does (ADR-0004). The check itself is the lightest touch in the system: a
  single TCP connect to a port discovery already found open, no data sent, no root, and it raises
  rather than assuming health when it has no port to check (ADR-0007).
- **Nothing goes near a shell.** The nmap invocation is an argument list, and the target is
  validated as a real IP address before any command exists. nmap's XML is parsed as untrusted
  input, with external entities and entity expansion refused (ADR-0003).
- **A failure is never an empty success.** A missing binary, non-zero exit, timeout, or
  unparseable output raises a specific domain error; "host is down" is a distinct, explicit
  result.
- **A feed failure is never an empty answer.** NVD returning "no CVEs for this CPE" is a
  finding and is cached as one; NVD timing out, rate-limiting, or returning a proxy error page
  raises instead. Collapsing the two would make a component read as clean when nobody had
  checked it — a false negative the system would have created (ADR-0010).
- **A CVE never matches a version it does not affect.** NVD's ranges are re-checked locally
  against each component's version, with exact boundary semantics (`versionStartIncluding` is
  closed, `versionEndExcluding` is open) and numeric ordering — a lexical compare would put
  2.4.6 after 2.4.57. A comparison that cannot be decided keeps the finding but never calls it
  confirmed (ADR-0012).
- **`confidence_state` is derived, never guessed.** `package_manager` or `vendor_api` →
  `confirmed`; `banner` → `probable`, because a distribution that backported the fix serves the
  old version string forever. `verified_exploitable` is never produced by correlation — it
  belongs to a later `check` step that actually demonstrates exploitability.
- **A KEV lookup never quietly says "not exploited".** `False` means CISA published a catalog we
  hold and this CVE is not in it; a catalog we could not fetch raises. The same rule as above,
  applied where it costs the most — silently de-prioritising an actively-exploited vulnerability
  is the worst thing this system could do (ADR-0011). EPSS carries it one step softer: `None`
  means FIRST has not scored the CVE, never that we could not ask.
- **CVE knowledge only ever comes from a feed.** Nothing in `adapters/feed/` imports a model
  client, asserted by `tests/test_adapter_boundaries.py`: an LLM's CVE knowledge is stale and
  hallucinated CVE ids are its most characteristic failure (AGENTS.md §4.8).
- **What the model will read is quoted, not recalled.** The `AdvisoryRetriever` is the only
  channel by which CVE knowledge reaches insight generation: it quotes NVD's description and the
  fix patch behind the CVE, attributes each piece to the source it came from, and derives
  `fix_touched_summary` from the diff's own subject line and changed paths — or leaves it empty.
  No advisory text raises rather than returning grounding that is an empty string (ADR-0013).
- **A secret cannot reach the model.** The dossier the LLM reasons over is an allowlist
  projection of the contract's §4 fields — a key nobody named is dropped, a `config` observation
  contributes only derived flags and never the file, and a value *shaped* like a credential is
  dropped even under a permitted key. The assembled dossier is then swept, and a dossier still
  holding something secret-shaped is refused rather than stripped: if we do not know how it got
  through, we do not know what else did (ADR-0014).
- **The AI cannot fabricate, and cannot bury.** An insight that cites nothing is rejected before
  persistence — and "cites something" is checked, not taken on trust: every citation must resolve
  to the supplied advisory or to a path that exists in the dossier, and a quote must actually
  appear in the text it quotes. A rationale naming any CVE other than the match's is refused as
  recall. A KEV-listed finding cannot be de-prioritised by any recommendation. Three database
  CHECKs (`insight_must_be_grounded`, `insight_kev_not_hidden`, `derivation = 'llm_generated'`)
  restate all of it one layer down.
- **What the model saw is kept, immutably.** The `TriageDossier` snapshot is written *before* the
  model is called and carries the append-only trigger, so a refused or failed generation still
  leaves the evidence behind — and every insight can be replayed against exactly the input that
  produced it.
- **The model runs inside the perimeter.** The client refuses any endpoint that is not loopback,
  private or explicitly internal, at construction. No model SDK was added: the wire format is
  OpenAI-compatible, so Ollama, llama.cpp, vLLM and LM Studio all work and CI needs none of them.
- **Hostile advisory text is defanged at the boundary, before it is cached.** A CVE description
  is written by people — sometimes the people whose software the CVE is about — and it ends up
  inside a prompt. Chat-template tokens, envelope tags, invisible and bidi characters, and
  instruction-shaped spans are neutralised with a *visible* marker on the way in, so no ordering
  or configuration can route raw advisory text into a model. Fetching is restricted to https
  patch URLs on an allowlist of code hosts, because dereferencing a CVE's references from inside
  a corporate network is a server-side request forgery primitive (ADR-0013).
- **The shadow-IT number never overclaims.** A CMDB record matches an asset by the same anchor
  priority the ER uses (`serial › mac › hostname`); anything unresolved — two devices with one
  name, strong anchors that disagree, a name that only matches once punctuation is deleted, an
  asset with nothing comparable to look up — becomes *ambiguous*, resolves to `unknown`, and can
  never be counted as shadow IT. Asserted as an invariant, not as a case (ADR-0009).
- **A spreadsheet cell is a program, and is treated as one.** Every cell of a CMDB export is
  defanged on import (`=`, `+`, `-`, `@`, tab, CR), so no value can become a live formula in a
  report built on this data later; identity fields must additionally validate, so a formula
  never survives as an anchor the diff would match on. Column names are the operator's
  configuration, and a mapped column missing from the file is a hard error rather than a
  silently empty field (ADR-0008).
- **No row is ever silently dropped.** Blank, unidentifiable, duplicate, oversized — each is
  refused with a reason and a row number, and `rows_read == imported + skipped` is asserted. A
  lost row would read as shadow IT in the diff, which is the one false accusation this product
  cannot afford.
- **Ground truth outranks inference.** A credentialed read projects `version_source=
  'package_manager'` components over the banner-inferred ones for that asset; the superseded rows
  are retired, never deleted, so what we believed on an earlier date is still answerable
  (ADR-0006).
- **Credentials reach the wire and nothing else.** The SSH inspector resolves its credential
  through `SecretsPort`, holds a redacting `Secret`, and calls `reveal()` on exactly one line —
  a test greps the package and fails if it appears anywhere else. No log record, exception,
  traceback, or observation payload carries it, on success or on any failure path.
- **An inspector cannot write to a device.** Five constant commands, allow-listed by verb *and*
  arguments (`dpkg -l` is permitted, `dpkg --install` is not), with a canary test that fails if
  the list grows at all. Unknown SSH host keys are rejected; ambient keys and agents are
  disabled, so only the vault's credential can ever authenticate.
- **Adapters stay in their lane.** The collector imports no socket, subprocess, or database
  driver; the scanner imports no database driver and never `shell=True`; the inspector touches
  no store (`tests/test_adapter_boundaries.py`).

**One thing fixtures cannot prove, and it is owed:**
[`docs/runbooks/validate-gentle-scan.md`](docs/runbooks/validate-gentle-scan.md) is the procedure
for pointing a `GENTLE` scan at one real device, under real authorisation, and confirming it
survives. Until someone runs it, "we do not break embedded devices" is a well-tested design
intention rather than an observed fact. The runbook also names the gaps it runs into — chiefly that there is
still no CLI, so the procedure runs from a short script.

**Two things fixtures cannot prove, both owed:**
[`validate-gentle-scan.md`](docs/runbooks/validate-gentle-scan.md) — point a `GENTLE` scan at one
real device and confirm it survives; and
[`validate-cmdb-diff.md`](docs/runbooks/validate-cmdb-diff.md) — run the diff against the real
CMDB and check the shadow-IT list is genuinely unregistered devices rather than matching
failures. The second also measures the **ambiguous rate**, which is the evidence for whether M3's
LLM proposer is warranted at all — measured, not assumed (AGENTS.md §4.11).

**M3 is deliberately split in two** (m3-design §1). Half A is deterministic — CPE→CVE from NVD,
enriched with KEV and EPSS — and no model runs anywhere in it. Half B adds grounded, cited,
advisory AI insight *on top of* matches Half A already made, and only after Half A is verified.
The separation is a safety barrier, not organisation: it is what makes it structurally impossible
for a model to decide that a vulnerability exists.

**Half A is done.** The store now answers *what is vulnerable, how confident we are in the
version, whether it is actively exploited, and how likely exploitation is* — entirely
deterministically, with no model having run. That was the precondition: m3-design §1 makes the
split a safety barrier rather than an ordering preference, because code where an LLM might
"decide" whether a vulnerability exists is exactly where it would inject a false negative into a
security system.

**M3 is complete, and so is the platform's first full answer.** A capture becomes an asset;
an asset becomes an inventory; the inventory answers *what does nobody manage*; correlation
answers *what is vulnerable*; and the insight path answers *what does it actually mean* — with a
local model that reasons only over a redacted dossier and an advisory somebody actually published,
and that cannot fabricate a vulnerability, leak a secret, or hide an exploited finding. It
recommends; a human accepts. Nothing closes itself.

**Half B started with its grounding channel, not its model.** The `AdvisoryRetriever`
fetches the *real* advisory text and the fix patch behind a CVE, quotes them with their sources
attached, and derives what the fix touched from the diff itself — so every claim an insight will
later make traces to a document a human can open (AGENTS.md §4.8). Two properties are asserted:
hostile advisory content is neutralised **before it is cached**, so no ordering or configuration
can route attacker-written text into a prompt (ADR-0013); and no advisory text raises rather than
returning empty grounding, so the generator will be able to refuse instead of recalling.

Deliberately still absent, and next when they are wanted (AGENTS.md §5): the `check` module and
`verified_exploitable` (proving exploitability rather than inferring it), LLM-proposed entity
matching for M2's ambiguous queue, a CLI and a UI, and vendor inspectors (VAPIX, ISAPI, BusyBox).
Both manual runbooks — `validate-gentle-scan.md` and `validate-cmdb-diff.md` — remain unrun
against real hardware, and running them is the last thing between this and a pilot. Deferred by
design: RLS, live packet capture, default-credential probing, and any form of exploitation
(never).
