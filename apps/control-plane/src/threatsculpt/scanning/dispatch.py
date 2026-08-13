"""Claiming work, reporting progress, and refusing a job.

The claim is the only place in the codebase where correctness depends on
database locking rather than on application logic. docs/AGENT-PROTOCOL.md §3
specifies ``FOR UPDATE SKIP LOCKED`` for a reason: two agents in one org polling
at the same instant must never come away with the same job, and no amount of
"check then update" in Python achieves that.

Every other function here begins with ``claimed_job``, which is the ownership
gate: a job belongs to the agent that holds an unexpired lease on it, and to
nobody else. An agent from another org never gets past ``ScopedRepository``; an
agent from the *same* org that did not claim the job is refused here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.core.scoped_sql import execute_scoped
from threatsculpt.models.scan import MAX_JOB_ATTEMPTS, ScanJob, ScanStatus
from threatsculpt.scanning.errors import JobNotClaimableError
from threatsculpt.scanning.schemas import ClaimedJob, JobRejectRequest, JobStatusUpdate
from threatsculpt.scanning.sql import CLAIM_JOBS
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope

#: How long a claim is good for. Long enough for a ``-p-`` scan of a /24, short
#: enough that a dead agent's work returns to the queue the same day.
LEASE_DURATION = timedelta(minutes=30)

#: Statuses from which an agent may still act on a job it holds.
ACTIVE_STATUSES: frozenset[str] = frozenset({ScanStatus.CLAIMED.value, ScanStatus.RUNNING.value})

#: Statuses an agent may report through ``/status``. ``completed`` is absent on
#: purpose: a job becomes completed by submitting results, so there is no way to
#: mark a scan done without the data it produced.
REPORTABLE_STATUSES: frozenset[str] = frozenset({ScanStatus.RUNNING.value, ScanStatus.FAILED.value})


@dataclass(frozen=True, slots=True)
class ClaimOutcome:
    """What one poll produced. Frozen — a claim result is a fact, not a buffer."""

    jobs: tuple[ClaimedJob, ...]

    @property
    def count(self) -> int:
        return len(self.jobs)


async def claim_jobs(
    session: AsyncSession, scope: OrgScope, agent_id: UUID, capacity: int
) -> ClaimOutcome:
    """Atomically take up to ``capacity`` queued jobs for this org.

    The lease and the attempt counter are set by the same UPDATE that changes the
    status, so a job cannot end up claimed without a lease or retried without
    being counted.
    """
    result = await execute_scoped(
        session,
        scope,
        CLAIM_JOBS,
        {
            "agent_id": agent_id,
            "org_id": scope.org_id,
            "lease_seconds": int(LEASE_DURATION.total_seconds()),
            "max_attempts": MAX_JOB_ATTEMPTS,
            "capacity": capacity,
        },
    )
    claimed = tuple(
        ClaimedJob(
            job_id=row.id,
            target=str(row.target),
            profile=row.profile,
            lease_expires_at=row.lease_expires_at,
        )
        for row in result.all()
    )
    return ClaimOutcome(jobs=claimed)


async def claimed_job(
    session: AsyncSession,
    scope: OrgScope,
    agent_id: UUID,
    job_id: UUID,
    *,
    now: datetime | None = None,
) -> ScanJob:
    """The job this agent currently holds, or 409.

    Three ways to fail, all answered identically because the agent's reaction is
    the same for each (§6: drop it and re-poll): the job is not this org's, it is
    not this agent's, or the lease has expired.
    """
    moment = now or datetime.now(tz=UTC)
    repository = ScopedRepository(session, scope, ScanJob)
    job = await repository.get(job_id)
    if job is None or job.agent_id != agent_id:
        raise JobNotClaimableError()
    if job.status not in ACTIVE_STATUSES:
        raise JobNotClaimableError(f"This job is in status '{job.status}'.")
    if job.lease_expires_at is None or job.lease_expires_at <= moment:
        raise JobNotClaimableError("The lease on this job has expired.")
    return job


async def report_status(
    session: AsyncSession,
    scope: OrgScope,
    agent_id: UUID,
    job_id: UUID,
    payload: JobStatusUpdate,
) -> ScanJob:
    """Record progress, or a failure the agent detected while running."""
    if payload.status.value not in REPORTABLE_STATUSES:
        raise JobNotClaimableError(
            f"Status '{payload.status.value}' is not reportable; submit results to complete a job."
        )

    job = await claimed_job(session, scope, agent_id, job_id)
    repository = ScopedRepository(session, scope, ScanJob)
    now = datetime.now(tz=UTC)

    changes: dict[str, object] = {"status": payload.status.value}
    if payload.progress_percent is not None:
        changes["progress_percent"] = payload.progress_percent

    if payload.status is ScanStatus.RUNNING:
        # Renew the lease on every heartbeat of progress: an agent that is
        # demonstrably alive should not lose work it is halfway through.
        changes["lease_expires_at"] = now + LEASE_DURATION
        if job.started_at is None:
            changes["started_at"] = now
    else:
        changes["finished_at"] = now
        changes["lease_expires_at"] = None
        changes["error"] = payload.detail or "The agent reported the scan as failed."

    return await repository.update(job, changes)


async def reject_job(
    session: AsyncSession,
    scope: OrgScope,
    agent_id: UUID,
    job_id: UUID,
    payload: JobRejectRequest,
) -> ScanJob:
    """§4: the agent refused the target against its own local allowlist.

    A refusal is not a failure of the scan, it is the agent doing its job. The
    reason is kept verbatim so an operator can see *why* a target their control
    plane accepted was rejected by the machine that would have scanned it — the
    two allowlists disagreeing is exactly the signal worth investigating.

    Requeue or fail is decided by the attempt count already spent on the claim:
    another agent with a wider local allowlist may succeed, but not forever.
    """
    job = await claimed_job(session, scope, agent_id, job_id)
    repository = ScopedRepository(session, scope, ScanJob)
    reason = f"{payload.reason}: {payload.detail}" if payload.detail else payload.reason

    if job.attempts >= MAX_JOB_ATTEMPTS:
        return await repository.update(
            job,
            {
                "status": ScanStatus.FAILED.value,
                "agent_id": None,
                "lease_expires_at": None,
                "finished_at": datetime.now(tz=UTC),
                "error": reason,
            },
        )

    return await repository.update(
        job,
        {
            "status": ScanStatus.QUEUED.value,
            "agent_id": None,
            "lease_expires_at": None,
            "progress_percent": None,
            "error": reason,
        },
    )
