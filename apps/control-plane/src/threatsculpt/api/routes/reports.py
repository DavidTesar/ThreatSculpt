"""``/reports`` — request, poll, download.

``POST`` returns 202 immediately and hands the render to the event loop, so no
request thread is ever occupied by report generation. ``GET`` polls.
``GET /download`` serves the artifact against a short-lived signed URL, which is
the only way a browser following a plain link can authenticate itself.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Query, Request, Response

from threatsculpt.api.dependencies import (
    RequireAnalyst,
    RequireViewer,
    SessionDep,
    get_settings_dep,
)
from threatsculpt.api.limits import enforce_general_rate_limit
from threatsculpt.api.middleware import client_ip
from threatsculpt.audit.writer import record_audit, try_record_audit
from threatsculpt.config import Settings
from threatsculpt.core.envelope import Envelope, ok
from threatsculpt.core.errors import NotFoundError, SemanticValidationError
from threatsculpt.core.pagination import PaginationParams, pagination_params
from threatsculpt.models.audit import AuditAction
from threatsculpt.models.report import Report, ReportFormat, ReportStatus
from threatsculpt.reports import runner
from threatsculpt.reports.schemas import (
    ReportCreate,
    ReportCreated,
    ReportDownloadLink,
    ReportOut,
)
from threatsculpt.reports.signing import DOWNLOAD_TTL_SECONDS, sign_download, verify_download
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope

router = APIRouter(prefix="/reports", tags=["reports"])

ReportId = Annotated[UUID, Path(description="Report id within your organisation")]
PaginationDep = Annotated[PaginationParams, Depends(pagination_params)]

SUPPORTED_FORMATS = tuple(item.value for item in ReportFormat)


@router.post(
    "",
    status_code=HTTPStatus.ACCEPTED,
    response_model=Envelope[ReportCreated],
    summary="Request a report",
    dependencies=[Depends(enforce_general_rate_limit)],
)
async def request_report(
    request: Request,
    principal: RequireAnalyst,
    session: SessionDep,
    payload: ReportCreate,
) -> Envelope[ReportCreated]:
    """202 and a report id. The render happens on the event loop, not here."""
    if payload.format not in SUPPORTED_FORMATS:
        raise SemanticValidationError(
            f"Only {', '.join(SUPPORTED_FORMATS)} reports are supported. "
            "PDF export is not implemented yet.",
            field="format",
            code="unsupported_report_format",
        )

    repository = ScopedRepository(session, principal.scope, Report)
    report = await repository.create(
        type=payload.type.value,
        format=payload.format,
        status=ReportStatus.QUEUED.value,
        scope=payload.scope.model_dump(mode="json"),
        requested_by_user_id=principal.user.id,
    )
    await record_audit(
        session,
        principal.scope,
        AuditAction.REPORT_REQUESTED,
        target_type="report",
        target_id=report.id,
        metadata={"type": payload.type.value, "format": payload.format},
        ip=client_ip(request),
    )

    # Committed before the worker starts: the background session is a different
    # transaction and would not see an uncommitted row.
    report_id = report.id
    await session.commit()
    runner.schedule(
        request.app.state, request.app.state.session_factory, principal.scope.org_id, report_id
    )
    return ok(ReportCreated(report_id=report_id, status=ReportStatus.QUEUED))


@router.get(
    "",
    response_model=Envelope[list[ReportOut]],
    summary="List reports",
    dependencies=[Depends(enforce_general_rate_limit)],
)
async def list_reports(
    principal: RequireViewer, session: SessionDep, pagination: PaginationDep
) -> Envelope[list[ReportOut]]:
    repository = ScopedRepository(session, principal.scope, Report)
    page = await repository.list(pagination, order_by=[Report.created_at.desc()])
    return ok([ReportOut.model_validate(item) for item in page.items], meta=page.meta)


@router.get(
    "/{report_id}",
    response_model=Envelope[ReportOut],
    summary="Poll a report",
    dependencies=[Depends(enforce_general_rate_limit)],
)
async def get_report(
    principal: RequireViewer, session: SessionDep, report_id: ReportId
) -> Envelope[ReportOut]:
    repository = ScopedRepository(session, principal.scope, Report)
    return ok(ReportOut.model_validate(await repository.get_or_404(report_id)))


@router.get(
    "/{report_id}/link",
    response_model=Envelope[ReportDownloadLink],
    summary="Mint a short-lived signed download URL",
    dependencies=[Depends(enforce_general_rate_limit)],
)
async def download_link(
    request: Request,
    principal: RequireViewer,
    session: SessionDep,
    report_id: ReportId,
    settings: Annotated[Settings, Depends(get_settings_dep)],
) -> Envelope[ReportDownloadLink]:
    """Minting requires a normal authenticated session; the URL itself does not."""
    repository = ScopedRepository(session, principal.scope, Report)
    report = await repository.get_or_404(report_id)
    if not report.is_ready:
        raise SemanticValidationError(
            f"This report is '{report.status}' and has nothing to download yet.",
            field="status",
            code="report_not_ready",
        )

    token = sign_download(settings.jwt_secret.get_secret_value(), report_id, principal.scope.org_id)
    path = request.url_for("download_report", report_id=str(report_id))
    return ok(
        ReportDownloadLink(
            url=f"{path}?token={token}",
            expires_at=datetime.now(UTC) + timedelta(seconds=DOWNLOAD_TTL_SECONDS),
        )
    )


@router.get(
    "/{report_id}/download",
    name="download_report",
    summary="Download a report via a signed URL",
    response_class=Response,
)
async def download_report(
    request: Request,
    session: SessionDep,
    report_id: ReportId,
    settings: Annotated[Settings, Depends(get_settings_dep)],
    token: Annotated[str, Query(description="Signed download token")],
) -> Response:
    """No bearer token: the signature is the credential, and it names the org.

    The org comes out of the *signature*, never out of the request, so this is
    still the rule docs/API.md sets — the tenant is never a client-supplied
    parameter. A tampered ``report_id`` is scoped to the signed org and 404s.
    """
    grant = verify_download(settings.jwt_secret.get_secret_value(), token)
    if grant.report_id != report_id:
        raise NotFoundError()

    from threatsculpt.db.session import bind_scope

    scope = OrgScope.for_system(grant.org_id)
    await bind_scope(session, scope)

    repository = ScopedRepository(session, scope, Report)
    report = await repository.get_or_404(report_id)
    if not report.is_ready or report.content is None:
        raise NotFoundError()

    await try_record_audit(
        session,
        scope,
        AuditAction.REPORT_DOWNLOADED,
        target_type="report",
        target_id=report_id,
        ip=client_ip(request),
    )
    return Response(
        content=report.content,
        media_type=report.content_type or "text/html; charset=utf-8",
        headers={
            "Content-Disposition": f'attachment; filename="threatsculpt-report-{report_id}.html"',
            # A signed URL is a capability; caches must not keep the artifact.
            "Cache-Control": "no-store",
        },
    )
