"""``/findings`` — the triage queue, ordered by business risk.

Read is ``viewer``; the status transition is ``analyst``, per docs/API.md. Every
transition is audited with both the old and the new status, because "who
accepted the risk on this, and when" is the question an auditor asks first.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Query, Request

from threatsculpt.api.dependencies import RequireAnalyst, RequireViewer, SessionDep
from threatsculpt.api.limits import enforce_general_rate_limit
from threatsculpt.api.middleware import client_ip
from threatsculpt.audit.writer import record_audit
from threatsculpt.core.envelope import Envelope, ok
from threatsculpt.core.errors import ValidationError
from threatsculpt.core.pagination import PaginationParams, pagination_params
from threatsculpt.findings.queries import FindingFilters, get_finding, list_findings
from threatsculpt.findings.schemas import FindingDetail, FindingOut, FindingStatusUpdate
from threatsculpt.findings.transitions import changes_for, validate_transition
from threatsculpt.models.audit import AuditAction
from threatsculpt.models.finding import Finding, FindingStatus, MatchConfidence
from threatsculpt.tenancy.repository import ScopedRepository

router = APIRouter(
    prefix="/findings",
    tags=["findings"],
    dependencies=[Depends(enforce_general_rate_limit)],
)

FindingId = Annotated[UUID, Path(description="Finding id within your organisation")]
PaginationDep = Annotated[PaginationParams, Depends(pagination_params)]

#: Severity bands the CVE mirror stores. Constrained here so an unknown value is
#: a 400 rather than a silently empty result page.
SEVERITIES = ("critical", "high", "medium", "low", "none")


def finding_filters(
    status: Annotated[FindingStatus | None, Query(description="Triage status")] = None,
    severity: Annotated[str | None, Query(description="CVE severity band")] = None,
    service_id: Annotated[
        UUID | None, Query(description="Business service the asset supports")
    ] = None,
    asset_id: Annotated[UUID | None, Query(description="Restrict to one asset")] = None,
    kev_only: Annotated[bool, Query(description="Only CISA KEV-listed CVEs")] = False,
    min_confidence: Annotated[
        MatchConfidence | None, Query(description="Minimum CPE match confidence")
    ] = None,
) -> FindingFilters:
    """Validate filters at the boundary; the query layer receives only clean values."""
    if severity is not None and severity not in SEVERITIES:
        raise ValidationError(
            f"severity must be one of: {', '.join(SEVERITIES)}.", field="severity"
        )
    return FindingFilters(
        status=status.value if status else None,
        severity=severity,
        service_id=service_id,
        asset_id=asset_id,
        kev_only=kev_only,
        min_confidence=min_confidence.value if min_confidence else None,
    )


FiltersDep = Annotated[FindingFilters, Depends(finding_filters)]


@router.get("", response_model=Envelope[list[FindingOut]], summary="List findings")
async def list_all(
    principal: RequireViewer,
    session: SessionDep,
    pagination: PaginationDep,
    filters: FiltersDep,
) -> Envelope[list[FindingOut]]:
    """Sorted by ``business_risk_score`` descending. That ordering is the product."""
    page = await list_findings(session, principal.scope, filters, pagination)
    return ok(list(page.items), meta=page.meta)


@router.get(
    "/{finding_id}",
    response_model=Envelope[FindingDetail],
    summary="Fetch a finding and the explanation of its score",
)
async def get_one(
    principal: RequireViewer, session: SessionDep, finding_id: FindingId
) -> Envelope[FindingDetail]:
    return ok(await get_finding(session, principal.scope, finding_id))


@router.patch(
    "/{finding_id}",
    response_model=Envelope[FindingDetail],
    summary="Change a finding's triage status",
)
async def update_status(
    request: Request,
    principal: RequireAnalyst,
    session: SessionDep,
    finding_id: FindingId,
    payload: FindingStatusUpdate,
) -> Envelope[FindingDetail]:
    """Status transitions only. The score is computed and is not patchable."""
    repository = ScopedRepository(session, principal.scope, Finding)
    finding = await repository.get_or_404(finding_id)

    previous = finding.status
    validate_transition(previous, payload.status.value)
    await repository.update(finding, changes_for(payload.status.value))

    await record_audit(
        session,
        principal.scope,
        AuditAction.FINDING_STATUS_CHANGED,
        target_type="finding",
        target_id=finding_id,
        metadata={
            "from": previous,
            "to": payload.status.value,
            "cve_id": finding.cve_id,
            "note": payload.note,
        },
        ip=client_ip(request),
    )
    return ok(await get_finding(session, principal.scope, finding_id))
