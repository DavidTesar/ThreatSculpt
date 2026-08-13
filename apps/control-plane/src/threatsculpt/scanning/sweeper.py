"""Lease recovery.

An agent that dies mid-scan leaves a job ``claimed`` with a lease nobody will
ever renew. Without this, that job is lost: it is not queued, so no agent will
take it, and it is not finished, so nothing reports it. The sweeper is what makes
the lease in docs/AGENT-PROTOCOL.md §3 mean anything.

**Safe to run in several processes at once.** Each pass is two ordinary UPDATEs
whose WHERE clause is also their precondition. Under PostgreSQL's READ COMMITTED
the second transaction re-evaluates that clause after the first commits, so it
matches zero rows rather than acting twice. No advisory lock, no leader election,
no "is another sweeper running" flag to get stuck.

**Why it walks orgs one at a time.** The application connects as a NOBYPASSRLS
role, so a query with no ``threatsculpt.org_id`` set sees zero rows — by design.
A cross-org sweep would therefore have to disable the isolation this service is
built around. Instead it enumerates orgs (``orgs`` is the tenant root and is not
itself tenant-scoped) and does one scoped pass per org, using
``OrgScope.for_system`` — a use the scope's own docstring names as legitimate.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatsculpt.db.session import scoped_session
from threatsculpt.models.org import Org, OrgStatus
from threatsculpt.models.scan import MAX_JOB_ATTEMPTS, ScanJob, ScanStatus
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope

logger = logging.getLogger(__name__)

DEFAULT_SWEEP_INTERVAL = timedelta(seconds=60)

LEASE_EXPIRED_ERROR = (
    f"The agent stopped reporting and the lease expired after {MAX_JOB_ATTEMPTS} attempts."
)

_LEASED_STATUSES = (ScanStatus.CLAIMED.value, ScanStatus.RUNNING.value)


@dataclass(frozen=True, slots=True)
class SweepOutcome:
    """Counts from one pass. Frozen; passes combine with ``merge`` rather than
    accumulating into a mutable tally."""

    requeued: int = 0
    failed: int = 0

    def merge(self, other: SweepOutcome) -> SweepOutcome:
        return SweepOutcome(
            requeued=self.requeued + other.requeued, failed=self.failed + other.failed
        )


async def sweep_org(session: AsyncSession, scope: OrgScope, now: datetime) -> SweepOutcome:
    """One org's expired leases: exhausted jobs fail, the rest go back to the queue."""
    repository = ScopedRepository(session, scope, ScanJob)
    expired = (
        ScanJob.status.in_(_LEASED_STATUSES),
        ScanJob.lease_expires_at.is_not(None),
        ScanJob.lease_expires_at < now,
    )

    # Terminal case first. The two predicates are disjoint on ``attempts``, so
    # order is not load-bearing for correctness — only for readability.
    failed = await repository.update_where(
        {
            "status": ScanStatus.FAILED.value,
            "agent_id": None,
            "lease_expires_at": None,
            "finished_at": now,
            "error": LEASE_EXPIRED_ERROR,
        },
        *expired,
        ScanJob.attempts >= MAX_JOB_ATTEMPTS,
    )
    requeued = await repository.update_where(
        {
            "status": ScanStatus.QUEUED.value,
            "agent_id": None,
            "lease_expires_at": None,
            "progress_percent": None,
        },
        *expired,
        ScanJob.attempts < MAX_JOB_ATTEMPTS,
    )
    return SweepOutcome(requeued=requeued, failed=failed)


async def sweep_once(
    session_factory: async_sessionmaker[AsyncSession], *, now: datetime | None = None
) -> SweepOutcome:
    """One pass over every active org.

    A failure in one org is logged and the sweep continues: one tenant's broken
    data must not stop every other tenant's jobs from recovering.
    """
    moment = now or datetime.now(tz=UTC)
    total = SweepOutcome()

    for org_id in await _active_org_ids(session_factory):
        scope = OrgScope.for_system(org_id)
        try:
            async with scoped_session(session_factory, scope) as session:
                total = total.merge(await sweep_org(session, scope, moment))
        except Exception:
            logger.exception("lease sweep failed for one org", extra={"org_id": str(org_id)})

    if total.requeued or total.failed:
        logger.info(
            "lease sweep recovered jobs",
            extra={"requeued": total.requeued, "failed": total.failed},
        )
    return total


async def _active_org_ids(session_factory: async_sessionmaker[AsyncSession]) -> list[UUID]:
    """Org ids to sweep. ``orgs`` is the tenant root, so this is a plain read."""
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
    interval: timedelta = DEFAULT_SWEEP_INTERVAL,
) -> None:
    """Sweep on a fixed interval until cancelled.

    Deployed as its own process (see ``python -m threatsculpt.scanning.sweeper``)
    rather than inside a web worker: several API replicas each running their own
    timer would be harmless but pointless, and a sweep that only happens while
    HTTP traffic is being served is a sweep that stops exactly when an outage
    makes it matter most.
    """
    seconds = interval.total_seconds()
    while True:
        try:
            await sweep_once(session_factory)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("lease sweep pass failed")
        await asyncio.sleep(seconds)
