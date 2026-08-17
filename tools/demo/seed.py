"""Plant the demo estate by running the pipeline, and report exactly what it did.

Run it:

    set -a; . ./.env; set +a
    uv run python -m tools.demo.seed

Five phases, in the order the real system would do them, because that order is the thing
being demonstrated:

1. **Authorize.** Write the scope authorizations. Nothing else can happen first — the gate is
   deny-by-default, so an estate seeded before its ranges are authorized is an empty estate.
2. **Sweep.** Parse the captures and run them through `PassiveSweep`: the gate refuses the
   out-of-scope address, the sink records what survives, and entity resolution joins the ARP
   sighting and the DHCP lease into one asset per device, on the MAC they share.
3. **Attach software.** The one step with no collector behind it. P1–P17 grow components from
   a credentialed scan, which needs a live host; the seeder writes them through the same
   `set_current_software` port that scan uses, so the rows are shaped by the repository rather
   than by hand-written SQL.
4. **Correlate.** `VulnerabilityCorrelator` derives every match, every CVSS band, every KEV
   flag and every priority. The seeder does not choose a single one of them.
5. **Triage.** `TriagePipeline` assembles and redacts each dossier, writes the snapshot, and
   asks the model. The KEV floor and the grounding check run for real against the scripted
   replies.

The report at the end is the point of the exercise: it says how many targets were denied, how
many findings were derived and how many insights were refused, so a run that quietly produced
nothing is visibly a run that produced nothing.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import timedelta
from uuid import UUID

import psycopg

from adapters.advisory.retriever import HttpAdvisoryRetriever
from adapters.collector.passive import Capture, PassiveCollector
from adapters.llm.generator import ContainedInsightGenerator
from adapters.postgres.advisory_cache import PostgresAdvisoryDocumentCache
from adapters.postgres.asset_repository import PostgresAssetRepository
from adapters.postgres.observation_sink import PostgresObservationSink
from adapters.postgres.scope_authority import PostgresScopeAuthority
from adapters.postgres.triage_store import PostgresDossierSource, PostgresTriageStore
from adapters.postgres.vulnerability_match_store import PostgresVulnerabilityMatchStore
from config.settings import AppConfig, load_config
from domain.models import AnchorObservation, SoftwareComponent
from engine.correlation import VulnerabilityCorrelator
from engine.dossier import DossierAssembler
from engine.segments import SubnetVlanMap
from engine.sweep import PassiveSweep
from engine.triage import TriageOutcome, TriagePipeline
from tools.demo import estate
from tools.demo.guard import SeedRefusedError, require_dev_environment
from tools.demo.sources import (
    ScriptedModelClient,
    StaticEpssSource,
    StaticKevSource,
    StaticVulnerabilityFeed,
)

CAPTURES_DIR = __file__.rsplit("/", 1)[0] + "/captures"


@dataclass(frozen=True, slots=True)
class SeedReport:
    """What the seeder planted, phase by phase. Printed, and returned for tests."""

    authorized_ranges: int = 0
    observations: int = 0
    denied_targets: tuple[str, ...] = ()
    assets: int = 0
    components: int = 0
    matches: int = 0
    kev_matches: int = 0
    insights: int = 0
    no_advisory: int = 0
    refused: int = 0
    ungrounded: int = 0
    failed: tuple[str, ...] = ()

    def render(self) -> str:
        denied = ", ".join(self.denied_targets) or "none"
        failed = ", ".join(self.failed) or "none"
        return "\n".join(
            (
                "demo estate seeded",
                f"  authorized ranges  {self.authorized_ranges}",
                f"  observations       {self.observations}",
                f"  denied by scope    {self.denied} ({denied})",
                f"  assets resolved    {self.assets}",
                f"  components         {self.components}",
                f"  findings derived   {self.matches} ({self.kev_matches} KEV)",
                f"  insights proposed  {self.insights}",
                f"  no advisory        {self.no_advisory}  (finding stands, model not asked)",
                f"  refused by rules   {self.refused}",
                f"  ungrounded         {self.ungrounded}",
                f"  model failures     {failed}",
            )
        )

    @property
    def denied(self) -> int:
        return len(self.denied_targets)


def seed(config: AppConfig) -> SeedReport:
    """Plant the estate. Assumes the guard has already run — `main` is what runs it.

    **Why this refuses a second run instead of being idempotent.** Most of the pipeline is
    already idempotent: entity resolution gets-or-creates, `set_current_software` replaces, and
    the correlator upserts, so assets, components and matches settle at the same counts however
    often you run it. Triage does not — `pending_matches` re-offers every match on every run
    (see the note in `_triage`), so a second run appends a second set of proposals to the review
    queue.

    The honest response is a refusal that says so, not a seeder that quietly papers over it by
    skipping triage. Starting over means rebuilding the schema — see `REBUILD_HINT`, and the
    note there on why an append-only store has no undo.
    """
    tenant = config.tenant_id
    if tenant is None:  # pragma: no cover — main checks this first, with a better message
        raise SeedRefusedError("SCANNER_TENANT_ID is required: the seeder plants into one tenant")

    dsn = config.database_url.reveal()

    # Fixed, not `uuid4()`. The observation dedup index is keyed on `run_id` among other
    # things, so a fresh id every run would make a re-sighting of identical content a new row.
    # For a demo estate that is noise; for a real sweep it is the correct behaviour, which is
    # why the constant lives here and not in the sink.
    run_id = estate.RUN_ID

    with (
        # Two connections, for one reason: the scope authority refuses a non-autocommit
        # connection, because an audit record of a scope decision that a caller can roll back
        # is not an audit record. Everything else runs in a transaction it can.
        psycopg.connect(dsn, autocommit=True) as audited,
        psycopg.connect(dsn) as work,
    ):
        _refuse_if_already_seeded(work, tenant)

        ranges = _authorize(work, tenant)
        work.commit()

        sweep_report = _sweep(audited, work, tenant, run_id)
        work.commit()

        components = _attach_software(work, tenant)
        work.commit()

        matches, kev = _correlate(work, tenant, run_id)
        work.commit()

        triage = _triage(work, tenant, config.vlan_map)
        work.commit()

    return SeedReport(
        authorized_ranges=ranges,
        observations=sweep_report.observations,
        denied_targets=sweep_report.denied_targets,
        assets=sweep_report.assets,
        components=components,
        matches=matches,
        kev_matches=kev,
        insights=triage.insights,
        no_advisory=triage.skipped_no_advisory,
        refused=triage.refused,
        ungrounded=triage.ungrounded,
        failed=triage.failed,
    )


# ------------------------------------------------------------------------ 0. re-runs


#: How to get a clean estate. There is no `--reset`, and that is not an omission: five of the
#: tables the seeder plants into — `observation`, `triage_snapshot`, `insight_review_event`,
#: `audit_log`, `asset_merge_event` — carry a trigger that refuses DELETE outright. Evidence
#: and audit history are append-only by design (ADR-0002), so "undo the seed" is not an
#: operation this schema has. Rebuilding the schema is the honest way to start over, and the
#: fact that a demo convenience cannot be added without breaking that guarantee is the
#: guarantee working.
REBUILD_HINT = "uv run alembic downgrade base && uv run alembic upgrade head"


def _refuse_if_already_seeded(conn: psycopg.Connection[tuple[object, ...]], tenant: UUID) -> None:
    """Stop before writing a second estate on top of the first."""
    row = conn.execute("select count(*) from asset where tenant_id = %s", (tenant,)).fetchone()
    if row is not None and int(str(row[0])) > 0:
        raise SeedRefusedError(
            f"tenant {tenant} already has {row[0]} asset(s), so this estate is already seeded. "
            f"Re-running would append a second set of AI proposals to the review queue, "
            f"because triage re-offers every match on every run.\n"
            f"There is no --reset: observations, triage snapshots and review events are "
            f"append-only and refuse DELETE. To start over, rebuild the schema:\n"
            f"    {REBUILD_HINT}"
        )


# --------------------------------------------------------------------------- 1. authorize


def _authorize(conn: psycopg.Connection[tuple[object, ...]], tenant: UUID) -> int:
    """Write the scope authorizations, idempotently.

    `written_auth_ref` is not nullable and is not filled with a placeholder: the demo
    authorization cites a demo document, and says as much. An authorization whose paper trail
    is `''` is the exact thing the column exists to make impossible.
    """
    written = 0
    for cidr in estate.AUTHORIZED_CIDRS:
        # `on conflict do nothing` would be a no-op here: there is no unique constraint on
        # (tenant_id, cidr), so a repeat insert conflicts with nothing and duplicates the row.
        # Checked explicitly rather than relying on a constraint the schema does not have.
        existing = conn.execute(
            "select 1 from scope_authorization where tenant_id = %s and cidr = %s::cidr",
            (tenant, cidr),
        ).fetchone()
        if existing is not None:
            continue

        result = conn.execute(
            """
            insert into scope_authorization
                (tenant_id, cidr, written_auth_ref, active, authorized_at, expires_at)
            values (%s, %s::cidr, %s, true, %s, %s)
            """,
            (
                tenant,
                cidr,
                estate.WRITTEN_AUTH_REF,
                estate.SEEDED_AT,
                estate.SEEDED_AT + timedelta(days=365),
            ),
        )
        written += result.rowcount if result.rowcount > 0 else 0
    return written


# ------------------------------------------------------------------------------- 2. sweep


def _sweep(
    audited: psycopg.Connection[tuple[object, ...]],
    work: psycopg.Connection[tuple[object, ...]],
    tenant: UUID,
    run_id: UUID,
) -> _SweepReport:
    """Parse both captures and run them through the real gate, sink and resolver."""
    collector = PassiveCollector()
    collection = collector.collect(
        tenant_id=tenant,
        run_id=run_id,
        captures=(
            Capture(kind="arp", text=_capture("arp_table.txt"), observed_at=estate.SEEDED_AT),
            Capture(kind="dhcp", text=_capture("dhcp_leases.txt"), observed_at=estate.SEEDED_AT),
        ),
        collected_at=estate.SEEDED_AT,
    )

    sweep = PassiveSweep(
        scope=PostgresScopeAuthority(audited, actor="demo-seeder"),
        sink=PostgresObservationSink(work),
        assets=PostgresAssetRepository(work),
    )
    outcome = sweep.run(tenant, collection.candidates)
    return _SweepReport(
        observations=outcome.observations,
        denied_targets=outcome.denied_targets,
        assets=outcome.assets,
    )


@dataclass(frozen=True, slots=True)
class _SweepReport:
    observations: int
    denied_targets: tuple[str, ...]
    assets: int


def _capture(name: str) -> str:
    with open(f"{CAPTURES_DIR}/{name}", encoding="utf-8") as handle:
        return handle.read()


# --------------------------------------------------------------------- 3. attach software


def _attach_software(conn: psycopg.Connection[tuple[object, ...]], tenant: UUID) -> int:
    """Attach the fixture software to the assets resolution actually produced.

    Assets are found by resolving the MAC anchor rather than by remembering an id from the
    sweep: if entity resolution merged two observations into one asset, this follows it there.
    A seeder that held its own idea of which asset is which would drift from the resolver the
    moment the resolver got smarter.

    The anchor is a MAC and not a hostname because `resolve()` matches on strong anchors only
    — a hostname deliberately resolves to nothing, since a name that can move between machines
    is not an identity.
    """
    repository = PostgresAssetRepository(conn)
    attached = 0

    for host in estate.SOFTWARE:
        resolution = repository.resolve(
            tenant, [AnchorObservation(kind="mac", value=host.mac, confidence=0.95)]
        )
        if resolution.asset_id is None:
            # Nothing resolved for this MAC. Loud, because it means the captures and the
            # software table disagree about what is on this network.
            raise SeedRefusedError(
                f"no asset resolved for {host.label} ({host.mac}): the captures and "
                f"estate.SOFTWARE disagree about what this estate contains"
            )

        repository.set_current_software(
            resolution.asset_id,
            [
                SoftwareComponent(
                    name=component.name,
                    version=component.version,
                    cpe=component.cpe,
                    version_source=component.version_source,
                    confidence=component.confidence,
                )
                for component in host.components
            ],
        )
        attached += len(host.components)

    return attached


# ------------------------------------------------------------------------- 4. correlate


def _correlate(
    conn: psycopg.Connection[tuple[object, ...]], tenant: UUID, run_id: UUID
) -> tuple[int, int]:
    """Derive the findings. Every priority band below is the correlator's, not the seeder's."""
    correlator = VulnerabilityCorrelator(
        feed=StaticVulnerabilityFeed(by_cpe=estate.CVES),
        kev=StaticKevSource(entries=estate.KEV),
        epss=StaticEpssSource(scores=estate.EPSS),
        store=PostgresVulnerabilityMatchStore(conn),
    )
    correlator.run(tenant, run_id=run_id)

    row = conn.execute(
        "select count(*), count(*) filter (where kev) from vulnerability_match "
        "where tenant_id = %s",
        (tenant,),
    ).fetchone()
    if row is None:  # pragma: no cover — count(*) always returns a row
        raise SeedRefusedError("the match count query returned nothing; the store is not sane")
    return int(str(row[0])), int(str(row[1]))


# ---------------------------------------------------------------------------- 5. triage


def _triage(
    conn: psycopg.Connection[tuple[object, ...]], tenant: UUID, vlan_map: SubnetVlanMap
) -> TriageOutcome:
    """Attach proposals. The generator here is the real one, in front of a scripted model.

    Note for anyone re-running this: `pending_matches` re-offers every match on every run,
    because `record_snapshot` writes a null `match_id` while the pending query joins on it.
    That is a bug in the store rather than in the seeder, and it is why `seed()` refuses a
    second run instead of quietly appending another round of proposals.
    """
    feed = StaticVulnerabilityFeed(by_cpe=estate.CVES)
    pipeline = TriagePipeline(
        assembler=DossierAssembler(PostgresDossierSource(conn), segments=vlan_map),
        # The real retriever, offline: no HTTP client and no fix-document fetch, so it grounds
        # entirely on the feed record. `client=None` is a supported configuration, not a
        # degraded one — see its docstring.
        retriever=HttpAdvisoryRetriever(
            feed, PostgresAdvisoryDocumentCache(conn), client=None, fetch_fix_documents=False
        ),
        generator=ContainedInsightGenerator(ScriptedModelClient(replies=estate.MODEL_REPLIES)),
        store=PostgresTriageStore(conn),
    )
    return pipeline.run(tenant)


# ------------------------------------------------------------------------------- entry


def main(argv: Sequence[str] | None = None) -> int:
    """Guard, seed, report. Returns a process exit code."""
    arguments = sys.argv[1:] if argv is None else list(argv)
    if arguments:
        print(f"error: unknown argument(s): {' '.join(arguments)}", file=sys.stderr)
        print("usage: python -m tools.demo.seed", file=sys.stderr)
        return 2

    try:
        require_dev_environment()
    except SeedRefusedError as refusal:
        print(f"error: {refusal}", file=sys.stderr)
        return 2

    config = load_config()
    if config.tenant_id is None:
        print(
            "error: SCANNER_TENANT_ID is required — the seeder plants into exactly one "
            "tenant, and the API reads exactly one. They must be the same.",
            file=sys.stderr,
        )
        return 2

    try:
        report = seed(config)
    except SeedRefusedError as refusal:
        print(f"error: {refusal}", file=sys.stderr)
        return 2

    print(report.render())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__: Sequence[str] = ["SeedReport", "main", "seed"]
