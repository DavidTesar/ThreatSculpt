"""Withdrawing scan authorisation, and making it stick.

docs/SECURITY.md: *the ``authorized`` flag on a network is not a formality — it
is the record that you asserted you had permission.* An assertion that can be
made but not un-made is not a record of anything. Until this module existed,
``PATCH /networks/{id} {"authorized": false}`` and ``DELETE /networks/{id}`` both
changed the row and nothing else: the scan jobs already queued against that range
kept their place in the queue and the next agent poll was still handed the
target, profile and all.

That is the one failure in this service with a legal consequence rather than a
technical one. It needs no attacker — it fires for the operator who is trying to
stop a scan — and the product's answer to them was to keep sending packets.

Two mechanisms, deliberately overlapping:

* ``scanning.sql.CLAIM_JOBS`` re-asks the containment question inside the claim
  itself, so a queued job whose authorisation is gone cannot be dispatched even
  if this module never ran (a crashed request, a row changed by hand, a future
  code path that edits ``networks`` without calling here).
* ``revalidate_open_jobs`` runs on the write that changed the authorisation and
  closes out the jobs the claim predicate cannot reach — the ones an agent is
  already holding a lease on.

**Re-validate, do not blanket-cancel.** A job is only stopped when *no* remaining
authorized network covers its target. An org that has both ``10.0.0.0/8`` and
``10.0.4.0/24`` authorized and then removes the ``/24`` has not withdrawn
permission for ``10.0.4.0/24``; the ``/8`` still covers it and the scan is still
authorised. Cancelling it would be a bug of the mirror-image kind.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.audit.writer import record_audit
from threatsculpt.core.scoped_sql import execute_scoped
from threatsculpt.models.audit import AuditAction
from threatsculpt.scanning.sql import CANCEL_JOBS_LOSING_AUTHORIZATION
from threatsculpt.tenancy.scope import OrgScope

logger = logging.getLogger(__name__)

#: Written to ``scan_jobs.error`` and shown in the dashboard. Phrased for the
#: operator reading it later: it says what happened and why, not "cancelled".
WITHDRAWN_REASON = (
    "Cancelled: no authorized network covers this target any more. "
    "Scan authorisation for the range was withdrawn while the job was open."
)


@dataclass(frozen=True, slots=True)
class WithdrawnJob:
    """One job stopped by a withdrawal, and what it was doing at the time."""

    job_id: UUID
    target: str
    previous_status: str

    @property
    def was_leased(self) -> bool:
        """True when an agent was holding this job, not merely queued for it."""
        return self.previous_status in ("claimed", "running")


@dataclass(frozen=True, slots=True)
class RevalidationOutcome:
    """The result of one pass. Frozen — a cancellation set is a fact."""

    cancelled: tuple[WithdrawnJob, ...] = ()

    @property
    def count(self) -> int:
        return len(self.cancelled)

    @property
    def leased_count(self) -> int:
        return sum(1 for job in self.cancelled if job.was_leased)


async def revalidate_open_jobs(
    session: AsyncSession,
    scope: OrgScope,
    *,
    ip: str | None = None,
    now: datetime | None = None,
) -> RevalidationOutcome:
    """Cancel every open job this org no longer has an authorized network for.

    Call after **any** write to ``networks``. Passing an unchanged row through
    costs one indexed UPDATE that matches nothing, which is far cheaper than
    having to reason about which edits can and cannot remove coverage.

    A job an agent already holds is cancelled like any other. That releases the
    lease, so the agent is refused with 409 on its next call and drops the work
    (docs/AGENT-PROTOCOL.md §6). It is not a clean stop — an nmap process already
    running on the agent host keeps running until it finishes or the agent kills
    it — and the control plane has no channel to do better, because the agent
    never listens on a port (§ transport). What it does guarantee is that the
    scan produces no stored result and no further lease renewal. The heartbeat
    allowlist narrows on the same write and is the other half of the signal, but
    it is advisory by §4 and cannot be relied on alone.
    """
    moment = now or datetime.now(tz=UTC)
    result = await execute_scoped(
        session,
        scope,
        CANCEL_JOBS_LOSING_AUTHORIZATION,
        {"org_id": scope.org_id, "reason": WITHDRAWN_REASON},
    )
    cancelled = tuple(
        WithdrawnJob(
            job_id=row.id,
            target=str(row.target),
            previous_status=row.previous_status,
        )
        for row in result.all()
    )
    if not cancelled:
        return RevalidationOutcome()

    outcome = RevalidationOutcome(cancelled=cancelled)
    await _audit(session, scope, outcome, ip=ip, now=moment)
    logger.info(
        "cancelled scan jobs whose authorisation was withdrawn",
        extra={
            "org_id": str(scope.org_id),
            "cancelled": outcome.count,
            "leased": outcome.leased_count,
        },
    )
    return outcome


async def _audit(
    session: AsyncSession,
    scope: OrgScope,
    outcome: RevalidationOutcome,
    *,
    ip: str | None,
    now: datetime,
) -> None:
    """One row per stopped job.

    Per job rather than one summary row: an incident asks "was 10.0.4.0/24 still
    being scanned at 14:02, and who stopped it", and a summary row with a count
    answers neither half.
    """
    for job in outcome.cancelled:
        await record_audit(
            session,
            scope,
            AuditAction.SCAN_JOB_AUTHORIZATION_WITHDRAWN,
            target_type="scan_job",
            target_id=job.job_id,
            metadata={
                "target": job.target,
                "previous_status": job.previous_status,
                "was_leased_to_an_agent": job.was_leased,
                "withdrawn_at": now.isoformat(),
            },
            ip=ip,
        )
