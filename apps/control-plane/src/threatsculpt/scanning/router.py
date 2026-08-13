"""``/scans`` — the dashboard side of the scan lifecycle.

Lives in the scanning package rather than under ``api/routes`` because the rule
it enforces is a scanning rule: a target must be inside a registered, authorized
network. Keeping the route next to ``jobs.find_authorizing_network`` makes it
hard to add a second creation path that forgets the check.

Roles follow docs/API.md: viewers read, analysts create and cancel.
"""

from __future__ import annotations

from http import HTTPStatus
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Query, Request

from threatsculpt.api.dependencies import RequireAnalyst, RequireViewer, SessionDep
from threatsculpt.api.limits import enforce_general_rate_limit
from threatsculpt.api.middleware import client_ip
from threatsculpt.audit.writer import record_audit
from threatsculpt.core.envelope import Envelope, ok
from threatsculpt.core.pagination import PaginationParams, pagination_params
from threatsculpt.models.audit import AuditAction
from threatsculpt.models.scan import ScanStatus
from threatsculpt.scanning import jobs
from threatsculpt.scanning.schemas import ScanJobCreate, ScanJobOut

router = APIRouter(
    prefix="/scans",
    tags=["scans"],
    dependencies=[Depends(enforce_general_rate_limit)],
)

ScanId = Annotated[UUID, Path(description="Scan job id within your organisation")]
PaginationDep = Annotated[PaginationParams, Depends(pagination_params)]
StatusFilter = Annotated[ScanStatus | None, Query(description="Filter by job status")]


@router.get("", response_model=Envelope[list[ScanJobOut]], summary="List scan jobs")
async def list_scans(
    principal: RequireViewer,
    session: SessionDep,
    pagination: PaginationDep,
    status: StatusFilter = None,
) -> Envelope[list[ScanJobOut]]:
    page = await jobs.list_scan_jobs(
        session, principal.scope, pagination, status=status.value if status else None
    )
    return ok([ScanJobOut.model_validate(item) for item in page.items], meta=page.meta)


@router.post(
    "",
    status_code=HTTPStatus.CREATED,
    response_model=Envelope[ScanJobOut],
    summary="Queue a scan",
)
async def create_scan(
    request: Request,
    principal: RequireAnalyst,
    session: SessionDep,
    payload: ScanJobCreate,
) -> Envelope[ScanJobOut]:
    """Refused with ``network_not_authorized`` unless an authorized network
    covers the target. This is the control plane's half of the two-sided check in
    docs/ARCHITECTURE.md; the agent re-checks against its own local allowlist."""
    job = await jobs.create_scan_job(
        session, principal.scope, payload, requested_by_user_id=principal.user.id
    )
    await record_audit(
        session,
        principal.scope,
        AuditAction.SCAN_JOB_CREATED,
        target_type="scan_job",
        target_id=job.id,
        metadata={"target": payload.target, "profile": payload.profile.value},
        ip=client_ip(request),
    )
    return ok(ScanJobOut.model_validate(job))


@router.get("/{scan_id}", response_model=Envelope[ScanJobOut], summary="Fetch a scan job")
async def get_scan(
    principal: RequireViewer, session: SessionDep, scan_id: ScanId
) -> Envelope[ScanJobOut]:
    return ok(ScanJobOut.model_validate(await jobs.get_scan_job(session, principal.scope, scan_id)))


@router.post(
    "/{scan_id}/cancel",
    response_model=Envelope[ScanJobOut],
    summary="Cancel a scan job that has not finished",
)
async def cancel_scan(
    request: Request, principal: RequireAnalyst, session: SessionDep, scan_id: ScanId
) -> Envelope[ScanJobOut]:
    job = await jobs.cancel_scan_job(session, principal.scope, scan_id)
    await record_audit(
        session,
        principal.scope,
        AuditAction.SCAN_JOB_CANCELLED,
        target_type="scan_job",
        target_id=scan_id,
        metadata={"target": job.target},
        ip=client_ip(request),
    )
    return ok(ScanJobOut.model_validate(job))
