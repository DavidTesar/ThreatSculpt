"""Admission control and retention for report requests.

``POST /reports`` used to do exactly one thing: insert a row and spawn an
``asyncio.Task``. Nothing counted how many were already running, nothing noticed
that sixty requests were the same request, and nothing ever removed a stored
artifact.

That was measured on an empty org, where it looks harmless. On a tenant with
30,000 findings it is not: **one** render takes 4.1 s, because every render
redoes the whole executive aggregation, and sixty of them queued on the request
event loop made the sixtieth ``POST`` take **37 s to be accepted** — the renders
starve the request handlers they share a loop with, so the damage lands on every
tenant served by that worker, not only the one that asked. One analyst-role
account inside the documented 100/min limit is enough.

Three controls, each aimed at a different part of that:

* ``coalesce`` — sixty identical requests become one render. This is the common
  case (a dashboard that retries, a user clicking twice) and the cheapest to fix.
  Only *queued* work is coalesced onto: a render already in progress will finish
  with data from when it started, and quietly handing somebody that as the answer
  to a request they made later is the kind of staleness nobody debugs.
* ``assert_capacity`` — a hard ceiling on how much work one org may have
  outstanding. Refused with 429 and a ``Retry-After``, which is what
  docs/AGENT-PROTOCOL.md §6 and docs/API.md already train clients to handle.
* ``purge_expired`` — reports do not live forever. Run opportunistically on the
  request path rather than from a timer: it is one indexed DELETE scoped to the
  org that is already being written to, so it needs no new process and cannot
  drift out of sync with a deployment.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.core.errors import RateLimitedError
from threatsculpt.core.pagination import PaginationParams
from threatsculpt.models.report import Report, ReportStatus
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope

logger = logging.getLogger(__name__)

#: Renders one org may have outstanding at once. Three rather than one so a
#: genuinely different report (another scope, another type) is not blocked behind
#: somebody else's, and small enough that a burst cannot own a worker.
MAX_PENDING_REPORTS_PER_ORG = 3

#: Told to the client on a 429. A render of a large estate takes seconds, not
#: minutes, so this is short enough to be worth honouring.
RETRY_AFTER_SECONDS = 30

#: How long a generated artifact is kept. Long enough to cover a reporting cycle
#: and a download link that somebody forwarded; short enough that a stored HTML
#: snapshot of a customer's whole risk posture is not held indefinitely, which
#: matters because ``reports.content`` is the most sensitive column in the schema.
REPORT_RETENTION_DAYS = 30

#: Newest kept per org regardless of age, so a tenant that requests reports all
#: day cannot accumulate without bound inside the retention window.
MAX_STORED_REPORTS_PER_ORG = 100

#: Statuses that represent work not yet finished.
PENDING_STATUSES: tuple[str, ...] = (ReportStatus.QUEUED.value, ReportStatus.GENERATING.value)


async def coalesce(
    session: AsyncSession,
    scope: OrgScope,
    *,
    type_: str,
    format_: str,
    report_scope: dict[str, Any],
) -> Report | None:
    """An identical request already queued for this org, if there is one.

    Identity is the whole of what determines the output: type, format and the
    requested scope. Two requests that differ in any of those are two reports.
    """
    repository = ScopedRepository(session, scope, Report)
    return await _newest(
        session,
        repository,
        Report.status == ReportStatus.QUEUED.value,
        Report.type == type_,
        Report.format == format_,
        Report.scope == report_scope,
    )


async def assert_capacity(session: AsyncSession, scope: OrgScope) -> None:
    """Refuse a request that would exceed this org's outstanding-render ceiling.

    Called after ``coalesce``, so a client repeating one request is never the
    thing that trips it.
    """
    repository = ScopedRepository(session, scope, Report)
    pending = await repository.count(Report.status.in_(PENDING_STATUSES))
    if pending < MAX_PENDING_REPORTS_PER_ORG:
        return
    logger.info(
        "report request refused: org at its concurrent-render ceiling",
        extra={"org_id": str(scope.org_id), "pending": pending},
    )
    raise RateLimitedError(
        f"This organisation already has {pending} reports generating. "
        "Wait for one to finish, or poll the report you already requested.",
        retry_after_seconds=RETRY_AFTER_SECONDS,
    )


async def purge_expired(
    session: AsyncSession, scope: OrgScope, *, now: datetime | None = None
) -> int:
    """Drop this org's reports past the retention window or beyond the count cap.

    Returns the number removed. Never raises on a normal miss — a request that
    happens to be the one carrying the purge must not fail because there was
    nothing to purge.
    """
    moment = now or datetime.now(tz=UTC)
    repository = ScopedRepository(session, scope, Report)

    cutoff = moment - timedelta(days=REPORT_RETENTION_DAYS)
    removed = await repository.delete_where(Report.created_at < cutoff)

    # Keep the newest N. The ids are fetched and then excluded by value rather
    # than expressed as a subquery: an ORM DELETE whose criteria cannot be
    # evaluated in Python falls back to a separate fetch pass, and that pass is
    # a statement the tenancy guard has no scope stamped on.
    newest = await repository.list(
        PaginationParams(per_page=MAX_STORED_REPORTS_PER_ORG),
        order_by=[Report.created_at.desc()],
    )
    if newest.total > MAX_STORED_REPORTS_PER_ORG:
        removed += await repository.delete_where(
            Report.id.not_in([report.id for report in newest.items])
        )

    if removed:
        logger.info(
            "purged stored reports", extra={"org_id": str(scope.org_id), "removed": removed}
        )
    return removed


async def _newest(
    session: AsyncSession, repository: ScopedRepository[Report], *criteria: Any
) -> Report | None:
    """The most recent row matching ``criteria``.

    ``find_one`` is not usable here: two identical requests may already have
    raced past ``coalesce`` before either committed, and refusing with a conflict
    because there are two is worse than picking the newer one.
    """
    statement = repository.select(*criteria).order_by(Report.created_at.desc()).limit(1)
    return (await session.execute(statement)).scalar_one_or_none()
