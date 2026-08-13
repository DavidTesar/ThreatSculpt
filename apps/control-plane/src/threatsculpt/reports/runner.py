"""Background report generation.

``POST /reports`` returns 202 and the work happens on the event loop afterwards,
so a report over a large estate cannot make an HTTP request slow. FastAPI's
``BackgroundTasks`` would not achieve that: it runs *after* the response is
written but still inside the request's task, which keeps a worker occupied for
the whole render.

The generator opens its own session with ``OrgScope.for_system`` — one of the
narrow, documented uses that scope exists for. It is still pinned to exactly one
org, so a report can only ever be built from the requesting tenant's data.

Tasks are held in a registry rather than fire-and-forgotten: an ``asyncio.Task``
with no strong reference can be garbage-collected mid-flight, which would show
up as reports that stay ``generating`` forever under load.

**They are also held behind a semaphore.** "Not on the request's task" is not the
same as "not on the request's event loop": a render takes 4.1 s of mostly
awaited database time on a tenant with 30,000 findings, and sixty of them
scheduled at once made an unrelated ``POST`` on the same worker wait 37 seconds.
The scheduling was never the expensive part — the *concurrency* was. Admission
control lives in ``reports.intake``; this is the second half, bounding how many
of the admitted renders run at any moment so a worker keeps serving requests
while it works through them.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any, Final
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatsculpt.core.pagination import PaginationParams
from threatsculpt.dashboard.executive import executive_dashboard
from threatsculpt.db.session import scoped_session
from threatsculpt.findings.queries import FindingFilters, list_findings
from threatsculpt.models.finding import FindingStatus
from threatsculpt.models.report import Report, ReportStatus
from threatsculpt.reports.renderer import (
    CONTENT_TYPE,
    MAX_FINDINGS_IN_REPORT,
    render_executive_summary,
)
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope

logger = logging.getLogger(__name__)

TASKS_ATTR: Final = "report_tasks"
SEMAPHORE_ATTR: Final = "report_semaphore"

#: Renders running at once on one worker, across every tenant. Two, because the
#: work is database-bound and the pool is small (10+5): more concurrent renders
#: buy no throughput and cost the connections the HTTP routes need.
MAX_CONCURRENT_RENDERS: Final = 2

#: Truncated before logging; the column never receives it.
MAX_ERROR_LENGTH: Final = 2000

#: What a client is told when a render fails. Never the exception text.
GENERIC_FAILURE_MESSAGE: Final = "Report generation failed. Try requesting it again."


def render_permit(app_state: Any) -> asyncio.Semaphore:
    """The worker's render permit, created on first use.

    Held on ``app.state`` rather than as a module global so it belongs to the
    application that owns the loop it will be awaited on — a module-level
    semaphore outlives the loop a test created it under.
    """
    existing = getattr(app_state, SEMAPHORE_ATTR, None)
    if isinstance(existing, asyncio.Semaphore):
        return existing
    created = asyncio.Semaphore(MAX_CONCURRENT_RENDERS)
    setattr(app_state, SEMAPHORE_ATTR, created)
    return created


def schedule(
    app_state: Any, session_factory: async_sessionmaker[AsyncSession], org_id: UUID, report_id: UUID
) -> asyncio.Task[None]:
    """Queue generation on the event loop and return the task."""
    registry: set[asyncio.Task[None]] = getattr(app_state, TASKS_ATTR, None) or set()
    setattr(app_state, TASKS_ATTR, registry)

    task = asyncio.create_task(
        _generate_when_permitted(render_permit(app_state), session_factory, org_id, report_id)
    )
    registry.add(task)
    task.add_done_callback(registry.discard)
    return task


async def _generate_when_permitted(
    permit: asyncio.Semaphore,
    session_factory: async_sessionmaker[AsyncSession],
    org_id: UUID,
    report_id: UUID,
) -> None:
    """Wait for a render slot, then generate.

    The row stays ``queued`` while waiting, which is exactly what a poller should
    see: the request was accepted and the work has not started.
    """
    async with permit:
        await generate(session_factory, org_id, report_id)


async def drain(app_state: Any) -> None:
    """Await every in-flight report. For shutdown and for deterministic tests."""
    registry: set[asyncio.Task[None]] = getattr(app_state, TASKS_ATTR, None) or set()
    if registry:
        await asyncio.gather(*tuple(registry), return_exceptions=True)


async def generate(
    session_factory: async_sessionmaker[AsyncSession], org_id: UUID, report_id: UUID
) -> None:
    """Render a report and store it, recording failure on the row rather than losing it."""
    scope = OrgScope.for_system(org_id)
    try:
        await _transition(session_factory, scope, report_id, ReportStatus.GENERATING)
        async with scoped_session(session_factory, scope) as session:
            repository = ScopedRepository(session, scope, Report)
            report = await repository.get(report_id)
            if report is None:
                logger.warning("report vanished before generation", extra={"id": str(report_id)})
                return
            html = await _render(session, scope, report)
            await repository.update(
                report,
                {
                    "status": ReportStatus.READY.value,
                    "content": html,
                    "content_type": CONTENT_TYPE,
                    "byte_size": len(html.encode("utf-8")),
                    "generated_at": datetime.now(UTC),
                    "error": None,
                },
            )
    except Exception as exc:  # a failed render must not take down the event loop
        logger.exception("report generation failed", extra={"report_id": str(report_id)})
        await _fail(session_factory, scope, report_id, str(exc))


async def _render(session: AsyncSession, scope: OrgScope, report: Report) -> str:
    from threatsculpt.models.org import Org

    dashboard = await executive_dashboard(session, scope)
    page = await list_findings(
        session,
        scope,
        FindingFilters(status=FindingStatus.OPEN.value),
        PaginationParams(page=1, per_page=MAX_FINDINGS_IN_REPORT),
    )
    org = await session.get(Org, scope.org_id)
    return render_executive_summary(
        org_name=org.name if org else "Organisation",
        dashboard=dashboard,
        findings=page.items,
    )


async def _transition(
    session_factory: async_sessionmaker[AsyncSession],
    scope: OrgScope,
    report_id: UUID,
    status: ReportStatus,
) -> None:
    async with scoped_session(session_factory, scope) as session:
        repository = ScopedRepository(session, scope, Report)
        report = await repository.get(report_id)
        if report is not None:
            await repository.update(report, {"status": status.value})


async def _fail(
    session_factory: async_sessionmaker[AsyncSession],
    scope: OrgScope,
    report_id: UUID,
    message: str,
) -> None:
    """Record the failure so a poller learns about it instead of waiting forever.

    The stored message is deliberately generic. ``error`` is served straight back
    to the client by ``GET /reports/{id}``, and a psycopg exception string
    carries table names, column names and often a literal from the failing row —
    exactly what ``api.handlers`` refuses to serialise everywhere else. The real
    message is in the log line above, correlated by report id.
    """
    logger.error(
        "report failed", extra={"report_id": str(report_id), "detail": message[:MAX_ERROR_LENGTH]}
    )
    try:
        async with scoped_session(session_factory, scope) as session:
            repository = ScopedRepository(session, scope, Report)
            report = await repository.get(report_id)
            if report is not None:
                await repository.update(
                    report,
                    {"status": ReportStatus.FAILED.value, "error": GENERIC_FAILURE_MESSAGE},
                )
    except Exception:
        logger.exception("could not record report failure", extra={"report_id": str(report_id)})
