"""Scan job creation and lifecycle from the dashboard side.

The rule this module exists to enforce: **a scan job is an instruction to send
packets at a network, so the target must be inside a CIDR the org registered and
explicitly marked authorized.** docs/ARCHITECTURE.md calls that non-negotiable,
and v1's defect was passing an unvalidated user string into a subprocess.

Containment is decided by PostgreSQL's ``cidr >>= cidr`` operator rather than in
Python: the column is a native ``cidr``, the operator is indexable, and the check
stays correct for an org with any number of networks without either an unbounded
fetch or a truncated one.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import cast, literal
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from threatsculpt.core.errors import ConflictError
from threatsculpt.core.pagination import Page, PaginationParams
from threatsculpt.db.types import CIDR
from threatsculpt.models.inventory import Network
from threatsculpt.models.scan import ScanJob, ScanStatus
from threatsculpt.scanning.errors import NetworkNotAuthorizedError
from threatsculpt.scanning.persistence import reloaded
from threatsculpt.scanning.schemas import ScanJobCreate
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope

#: Statuses a job can still be cancelled from. A finished job stays finished.
CANCELLABLE_STATUSES: frozenset[str] = frozenset(
    {ScanStatus.QUEUED.value, ScanStatus.CLAIMED.value, ScanStatus.RUNNING.value}
)


def _contains_target(target: str) -> ColumnElement[bool]:
    """``networks.cidr >>= <target>`` as a criterion for the scoped repository."""
    return Network.cidr.bool_op(">>=")(cast(literal(target), CIDR))


async def find_authorizing_network(
    session: AsyncSession, scope: OrgScope, target: str, network_id: UUID | None
) -> Network:
    """The registered, authorized network that permits scanning ``target``.

    Raises ``NetworkNotAuthorizedError`` rather than returning ``None`` so a
    caller cannot proceed by ignoring a falsy value.
    """
    repository = ScopedRepository(session, scope, Network)

    if network_id is not None:
        # An explicitly named network still has to actually cover the target;
        # naming one is not a way to opt out of the containment check.
        network = await repository.get_or_404(network_id)
        if not network.authorized:
            raise NetworkNotAuthorizedError(
                "The named network is not marked authorized for scanning."
            )
        covered = await repository.find_one(Network.id == network_id, _contains_target(target))
        if covered is None:
            raise NetworkNotAuthorizedError(
                "The target is not inside the named network.", field="target"
            )
        return covered

    match = (
        repository.select(Network.authorized.is_(True), _contains_target(target))
        .order_by(Network.created_at.asc())
        .limit(1)
    )
    found = (await session.execute(match)).scalar_one_or_none()
    if found is None:
        raise NetworkNotAuthorizedError(
            "The target is not inside any registered, authorized network.", field="target"
        )
    return found


async def create_scan_job(
    session: AsyncSession,
    scope: OrgScope,
    payload: ScanJobCreate,
    *,
    requested_by_user_id: UUID | None,
) -> ScanJob:
    """Queue a scan. Refuses unless an authorized network covers the target."""
    network = await find_authorizing_network(session, scope, payload.target, payload.network_id)
    repository = ScopedRepository(session, scope, ScanJob)
    return await repository.create(
        network_id=network.id,
        target=payload.target,
        profile=payload.profile.value,
        status=ScanStatus.QUEUED.value,
        requested_by_user_id=requested_by_user_id,
    )


async def list_scan_jobs(
    session: AsyncSession,
    scope: OrgScope,
    pagination: PaginationParams,
    *,
    status: str | None = None,
) -> Page[ScanJob]:
    repository = ScopedRepository(session, scope, ScanJob)
    criteria = [ScanJob.status == status] if status else []
    return await repository.list(pagination, *criteria, order_by=[ScanJob.created_at.desc()])


async def get_scan_job(session: AsyncSession, scope: OrgScope, job_id: UUID) -> ScanJob:
    repository = ScopedRepository(session, scope, ScanJob)
    return await repository.get_or_404(job_id)


async def cancel_scan_job(session: AsyncSession, scope: OrgScope, job_id: UUID) -> ScanJob:
    """Cancel a job that has not finished.

    Cancelling releases the lease, so an agent still holding it gets a 409 on its
    next call and drops the work — the agent is told by being refused, which
    needs no push channel.
    """
    repository = ScopedRepository(session, scope, ScanJob)
    job = await repository.get_or_404(job_id)
    if job.status not in CANCELLABLE_STATUSES:
        raise ConflictError(f"A job in status '{job.status}' cannot be cancelled.")
    cancelled = await repository.update(
        job,
        {
            "status": ScanStatus.CANCELLED.value,
            "agent_id": None,
            "lease_expires_at": None,
            "finished_at": datetime.now(tz=UTC),
        },
    )
    return await reloaded(repository, cancelled)
