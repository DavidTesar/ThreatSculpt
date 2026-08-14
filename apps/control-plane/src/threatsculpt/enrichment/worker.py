"""Turning completed scans into findings.

This is the caller ``enrichment.service`` never had. Ingest marks a job
``enrichment_status = 'pending'`` in the same UPDATE that completes it (see
``scanning.ingest._finalise``); this worker claims those jobs and runs the
matcher over the ports they produced. Without it a customer could scan a network
perfectly and the dashboard would stay empty forever, because assets and ports
are inventory and *findings* are the product.

**Its own process, not the API's event loop.** ``reports.runner`` records the
measurement that settles this: renders that were mostly awaited database time,
at concurrency 60, made an unrelated ``POST`` on the same worker wait 37
seconds. Enrichment is heavier than a render and happens on every completed
scan rather than on request, so putting it behind an HTTP handler would make
scan ingest the thing that decides how fast logins are.

**Safe to run in several processes at once.** The claim is one UPDATE whose
subquery takes ``FOR UPDATE SKIP LOCKED``, the same shape and for the same
reason as the agent job claim in ``scanning.sql`` — two workers polling
together must not both take the same job. Everything after the claim is
idempotent anyway: findings upsert on ``(org_id, asset_id, port_id, cve_id)``.

**A crashed worker's job comes back.** The claim stamps a lease and increments
an attempt counter. A lapsed lease makes the job claimable again by the same
statement that claims fresh ones, and a job that has burned every attempt is
marked ``failed`` rather than re-handed to a fourth worker. The alternative is a
job stuck ``running`` behind a process that no longer exists — which is exactly
the stranded-forever failure this whole workstream is about.

**Why it walks orgs one at a time.** Same reason as ``scanning.sweeper``: the
application connects as a NOBYPASSRLS role, so a query with no
``threatsculpt.org_id`` set sees zero rows. It enumerates orgs — ``orgs`` is the
tenant root and is not itself tenant-scoped — and does one scoped pass per org
under ``OrgScope.for_system``, a use that scope's docstring names as legitimate.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import TextClause, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatsculpt.core.scoped_sql import execute_scoped
from threatsculpt.db.session import scoped_session
from threatsculpt.enrichment.service import generate_all_findings
from threatsculpt.models.org import Org, OrgStatus
from threatsculpt.models.scan import MAX_ENRICHMENT_ATTEMPTS, EnrichmentStatus, ScanJob
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope

logger = logging.getLogger(__name__)

#: How often a pass runs. Shorter than the sweeper's minute: this one is the
#: latency between a scan finishing and its findings appearing, which a customer
#: watching a scan they just started does notice.
DEFAULT_ENRICHMENT_INTERVAL = timedelta(seconds=30)

#: How long a claim holds a job. Generously longer than a pass over the largest
#: realistic estate, because the cost of it being too short is two workers
#: doing the same job — harmless, since every write is an upsert — while the
#: cost of it being too long is a dead worker's job waiting that long to move.
ENRICHMENT_LEASE = timedelta(minutes=15)

#: Jobs one org may have claimed in one pass. Bounds a pass so that an org with
#: a large backlog cannot starve every org behind it in the enumeration.
MAX_JOBS_PER_PASS = 10

#: The claim, deliberately shaped like ``scanning.sql.CLAIM_JOBS``: select this
#: org's due jobs, skip rows another transaction already holds, and stamp the
#: lease and the attempt counter in the same statement that changes the status.
#: A read followed by a write would let two workers claim the same job.
#:
#: Every timestamp in *this* statement comes from the database clock, including
#: the lease comparison, so a worker whose host clock has drifted cannot claim a
#: lease that has not actually expired.
#:
#: Run through ``core.scoped_sql.execute_scoped``, which refuses a session not
#: already bound to this org. That check plus the explicit ``org_id`` predicate
#: plus RLS are what stand in for the ORM guard, which does not inspect raw SQL.
#:
#: A plain string literal with bind parameters and no interpolation of any kind,
#: for the reason ``scanning.sql`` gives: an f-string here would be
#: indistinguishable, to a reader and to a linter, from the shape that builds
#: SQL out of a request value.
CLAIM_ENRICHMENT_JOBS: TextClause = text(
    """
    UPDATE scan_jobs
       SET enrichment_status = 'running',
           enrichment_lease_expires_at = now() + make_interval(secs => :lease_seconds),
           enrichment_attempts = enrichment_attempts + 1,
           updated_at = now()
     WHERE id IN (
       SELECT id
         FROM scan_jobs
        WHERE org_id = :org_id
          AND enrichment_attempts < :max_attempts
          AND (
                enrichment_status = 'pending'
             OR (enrichment_status = 'running' AND enrichment_lease_expires_at < now())
          )
        ORDER BY created_at
        LIMIT :capacity
        FOR UPDATE SKIP LOCKED
     )
    RETURNING id
    """
)


@dataclass(frozen=True, slots=True)
class EnrichmentOutcome:
    """Counts from one pass. Frozen; passes combine with ``merge``."""

    jobs_enriched: int = 0
    jobs_failed: int = 0
    findings_written: int = 0

    def merge(self, other: EnrichmentOutcome) -> EnrichmentOutcome:
        return EnrichmentOutcome(
            jobs_enriched=self.jobs_enriched + other.jobs_enriched,
            jobs_failed=self.jobs_failed + other.jobs_failed,
            findings_written=self.findings_written + other.findings_written,
        )


async def enrich_org(
    session_factory: async_sessionmaker[AsyncSession],
    org_id: UUID,
    *,
    capacity: int = MAX_JOBS_PER_PASS,
    now: datetime | None = None,
) -> EnrichmentOutcome:
    """One org's due enrichment jobs, each in its own transaction.

    The claim commits before any matching happens. That ordering is what makes
    the lease worth having: a worker that dies during the match leaves a claimed
    job with a lease that lapses, rather than an unclaimed job it was silently
    in the middle of.
    """
    scope = OrgScope.for_system(org_id)
    moment = now or datetime.now(tz=UTC)
    async with scoped_session(session_factory, scope) as session:
        abandoned = await _abandon_exhausted(session, scope, moment)
        claimed = await _claim(session, scope, capacity)

    outcome = EnrichmentOutcome(jobs_failed=abandoned)
    for job_id in claimed:
        outcome = outcome.merge(await _enrich_claimed_job(session_factory, scope, job_id))
    return outcome


async def _abandon_exhausted(session: AsyncSession, scope: OrgScope, now: datetime) -> int:
    """Fail jobs whose lease lapsed with no attempts left.

    Terminal case first, exactly as ``scanning.sweeper.sweep_org`` orders its
    two updates: the predicates are disjoint on ``enrichment_attempts``, so this
    and the claim below cannot both take the same row.

    ``now`` is the pass's own moment rather than the database's ``now()``, again
    as the sweeper does — and not merely for symmetry. A SQL-side function in
    this predicate cannot be evaluated in Python, so SQLAlchemy falls back to
    synchronising the session by *fetching* the affected rows, which is an
    unscoped ORM SELECT that the tenancy guard refuses outright.

    Nothing is written to ``scan_jobs.error``. That column describes the *scan*,
    which succeeded; overwriting it here would report a completed scan as a
    failed one. The permanent record of this is the log line and the status.
    """
    repository = ScopedRepository(session, scope, ScanJob)
    abandoned = await repository.update_where(
        {
            "enrichment_status": EnrichmentStatus.FAILED.value,
            "enrichment_lease_expires_at": None,
        },
        ScanJob.enrichment_status == EnrichmentStatus.RUNNING.value,
        ScanJob.enrichment_lease_expires_at.is_not(None),
        ScanJob.enrichment_lease_expires_at < now,
        ScanJob.enrichment_attempts >= MAX_ENRICHMENT_ATTEMPTS,
    )
    if abandoned:
        logger.error(
            "enrichment abandoned jobs after exhausting every attempt",
            extra={"org_id": str(scope.org_id), "jobs": abandoned},
        )
    return abandoned


async def _claim(session: AsyncSession, scope: OrgScope, capacity: int) -> tuple[UUID, ...]:
    """Take up to ``capacity`` due jobs for this org, leasing each."""
    if not 1 <= capacity <= MAX_JOBS_PER_PASS:
        raise ValueError(f"capacity must be between 1 and {MAX_JOBS_PER_PASS}, got {capacity}")
    result = await execute_scoped(
        session,
        scope,
        CLAIM_ENRICHMENT_JOBS,
        {
            "org_id": scope.org_id,
            "lease_seconds": ENRICHMENT_LEASE.total_seconds(),
            "max_attempts": MAX_ENRICHMENT_ATTEMPTS,
            "capacity": capacity,
        },
    )
    return tuple(row.id for row in result.all())


async def _enrich_claimed_job(
    session_factory: async_sessionmaker[AsyncSession], scope: OrgScope, job_id: UUID
) -> EnrichmentOutcome:
    """Match one job's ports and release the claim.

    A failure here is logged and swallowed on purpose: the transaction rolls
    back, the lease stays until it lapses, and the job is retried by a later
    pass. One job that cannot be enriched must not stop the jobs behind it —
    and must not take the process down, which would strand every other org too.
    """
    try:
        async with scoped_session(session_factory, scope) as session:
            report = await generate_all_findings(session, scope, scan_job_id=job_id)
            await _release(session, scope, job_id, EnrichmentStatus.COMPLETE)
    except Exception:
        logger.exception(
            "enrichment failed for one job",
            extra={"org_id": str(scope.org_id), "scan_job_id": str(job_id)},
        )
        return EnrichmentOutcome()

    logger.info(
        "enrichment complete for job",
        extra={
            "org_id": str(scope.org_id),
            "scan_job_id": str(job_id),
            "ports_examined": report.ports_examined,
            "pages": report.pages,
            "findings_written": report.findings_written,
        },
    )
    return EnrichmentOutcome(jobs_enriched=1, findings_written=report.findings_written)


async def _release(
    session: AsyncSession, scope: OrgScope, job_id: UUID, status: EnrichmentStatus
) -> None:
    repository = ScopedRepository(session, scope, ScanJob)
    await repository.update_where(
        {"enrichment_status": status.value, "enrichment_lease_expires_at": None},
        ScanJob.id == job_id,
    )


async def enrich_once(session_factory: async_sessionmaker[AsyncSession]) -> EnrichmentOutcome:
    """One pass over every active org.

    A failure in one org is logged and the pass continues: one tenant's broken
    data must not stop every other tenant's scans from producing findings.
    """
    total = EnrichmentOutcome()
    for org_id in await _active_org_ids(session_factory):
        try:
            total = total.merge(await enrich_org(session_factory, org_id))
        except Exception:
            logger.exception("enrichment pass failed for one org", extra={"org_id": str(org_id)})

    if total.jobs_enriched or total.jobs_failed:
        logger.info(
            "enrichment pass complete",
            extra={
                "jobs_enriched": total.jobs_enriched,
                "jobs_failed": total.jobs_failed,
                "findings_written": total.findings_written,
            },
        )
    return total


async def _active_org_ids(session_factory: async_sessionmaker[AsyncSession]) -> list[UUID]:
    """Org ids to enrich. ``orgs`` is the tenant root, so this is a plain read.

    Deliberately not shared with ``scanning.sweeper``'s identical read: the two
    workers are separate deployables, and a shared helper would mean an
    enrichment change could break lease recovery. Eight lines is the cheaper
    coupling to avoid.
    """
    async with session_factory() as session:
        result = await session.execute(
            select(Org.id)
            .where(Org.status == OrgStatus.ACTIVE.value)
            .order_by(Org.created_at.asc())
        )
        return list(result.scalars().all())


async def run_forever(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    interval: timedelta = DEFAULT_ENRICHMENT_INTERVAL,
) -> None:
    """Enrich on a fixed interval until cancelled.

    Work first, then sleep — a worker that has just started should not wait an
    interval before touching a backlog that is already there.
    """
    seconds = interval.total_seconds()
    while True:
        try:
            await enrich_once(session_factory)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("enrichment pass failed")
        await asyncio.sleep(seconds)
