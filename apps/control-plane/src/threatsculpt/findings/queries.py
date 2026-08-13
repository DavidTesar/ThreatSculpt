"""Reading findings: one joined, bounded, indexed query per request.

The listing joins ``findings -> vulnerabilities -> assets`` in SQL rather than
loading findings and then fetching each CVE and asset. That would be an N+1 on
the busiest read in the product, and it would be invisible in a test with three
rows and fatal in a tenant with thirty thousand.

The ``service_id`` filter is an ``EXISTS`` subquery rather than a join to
``asset_services``: an asset can support several services, and a join would
return the same finding once per matching service, silently inflating both the
page and the total.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import ColumnElement, Select, and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.core.errors import NotFoundError
from threatsculpt.core.pagination import Page, PaginationParams
from threatsculpt.core.scoped_sql import execute_scoped
from threatsculpt.findings.schemas import (
    AssetSummary,
    CveSummary,
    FindingDetail,
    FindingOut,
    MatchSummary,
)
from threatsculpt.models.finding import Finding, MatchConfidence, Vulnerability
from threatsculpt.models.inventory import Asset, AssetService
from threatsculpt.tenancy.scope import OrgScope

#: Weakest-first, so ``min_confidence=medium`` means "medium or better".
_CONFIDENCE_ORDER: dict[str, int] = {
    MatchConfidence.LOW.value: 0,
    MatchConfidence.MEDIUM.value: 1,
    MatchConfidence.HIGH.value: 2,
}


@dataclass(frozen=True, slots=True)
class FindingFilters:
    """Query-string filters, already validated at the route boundary."""

    status: str | None = None
    severity: str | None = None
    service_id: UUID | None = None
    asset_id: UUID | None = None
    kev_only: bool = False
    min_confidence: str | None = None


def _base_select(scope: OrgScope) -> Select[Any]:
    return (
        select(
            Finding.id,
            Finding.status,
            Finding.business_risk_score,
            Finding.score_factors,
            Finding.port_id,
            Finding.scan_job_id,
            Finding.match_confidence,
            Finding.match_method,
            Finding.match_rationale,
            Finding.first_seen_at,
            Finding.last_seen_at,
            Finding.resolved_at,
            Asset.id.label("asset_id"),
            Asset.ip.label("asset_ip"),
            Asset.hostname.label("asset_hostname"),
            Asset.exposure.label("asset_exposure"),
            Vulnerability.cve_id,
            Vulnerability.description,
            Vulnerability.severity,
            Vulnerability.cvss_base,
            Vulnerability.kev_listed,
            Vulnerability.kev_due_date,
            Vulnerability.exploit_maturity,
        )
        .select_from(Finding)
        .join(Vulnerability, Vulnerability.cve_id == Finding.cve_id)
        .join(Asset, and_(Asset.id == Finding.asset_id, Asset.org_id == scope.org_id))
        .where(Finding.org_id == scope.org_id)
    )


def _predicates(scope: OrgScope, filters: FindingFilters) -> list[ColumnElement[bool]]:
    clauses: list[ColumnElement[bool]] = []
    if filters.status is not None:
        clauses.append(Finding.status == filters.status)
    if filters.severity is not None:
        clauses.append(Vulnerability.severity == filters.severity)
    if filters.asset_id is not None:
        clauses.append(Finding.asset_id == filters.asset_id)
    if filters.kev_only:
        clauses.append(Vulnerability.kev_listed.is_(True))
    if filters.min_confidence is not None:
        clauses.append(Finding.match_confidence.in_(_at_least(filters.min_confidence)))
    if filters.service_id is not None:
        clauses.append(_supports_service(scope, filters.service_id))
    return clauses


def _at_least(confidence: str) -> tuple[str, ...]:
    floor = _CONFIDENCE_ORDER.get(confidence, 0)
    return tuple(name for name, rank in _CONFIDENCE_ORDER.items() if rank >= floor)


def _supports_service(scope: OrgScope, service_id: UUID) -> ColumnElement[bool]:
    return (
        select(AssetService.id)
        .where(
            AssetService.org_id == scope.org_id,
            AssetService.asset_id == Finding.asset_id,
            AssetService.business_service_id == service_id,
        )
        .exists()
    )


async def list_findings(
    session: AsyncSession,
    scope: OrgScope,
    filters: FindingFilters,
    pagination: PaginationParams,
) -> Page[FindingOut]:
    """Highest business risk first — the default the whole product argues for."""
    clauses = _predicates(scope, filters)
    statement = (
        _base_select(scope)
        .where(*clauses)
        # `id` breaks ties so paging is stable when scores collide, which they
        # do constantly: identical software on identical hosts scores identically.
        .order_by(Finding.business_risk_score.desc(), Finding.id.asc())
        .limit(pagination.limit)
        .offset(pagination.offset)
    )
    rows = (await execute_scoped(session, scope, statement)).all()
    total = await count_findings(session, scope, filters)
    return Page(items=tuple(_to_summary(row) for row in rows), total=total, params=pagination)


async def count_findings(session: AsyncSession, scope: OrgScope, filters: FindingFilters) -> int:
    statement = (
        select(func.count())
        .select_from(Finding)
        .join(Vulnerability, Vulnerability.cve_id == Finding.cve_id)
        .where(Finding.org_id == scope.org_id, *_predicates(scope, filters))
    )
    return int((await execute_scoped(session, scope, statement)).scalar_one())


async def get_finding(session: AsyncSession, scope: OrgScope, finding_id: UUID) -> FindingDetail:
    """A finding plus the explanation of its score. 404 for another org's id."""
    statement = _base_select(scope).where(Finding.id == finding_id)
    row = (await execute_scoped(session, scope, statement)).first()
    if row is None:
        raise NotFoundError()
    return _to_detail(row)


def _to_summary(row: Any) -> FindingOut:
    return FindingOut(
        id=row.id,
        status=row.status,
        business_risk_score=row.business_risk_score,
        asset=AssetSummary(
            id=row.asset_id,
            ip=row.asset_ip,
            hostname=row.asset_hostname,
            exposure=row.asset_exposure,
        ),
        cve=CveSummary(
            cve_id=row.cve_id,
            severity=row.severity,
            cvss_base=row.cvss_base,
            kev_listed=row.kev_listed,
            kev_due_date=row.kev_due_date,
            exploit_maturity=row.exploit_maturity,
        ),
        match=MatchSummary(
            confidence=row.match_confidence,
            method=row.match_method,
            rationale=row.match_rationale,
        ),
        port_id=row.port_id,
        scan_job_id=row.scan_job_id,
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
        resolved_at=row.resolved_at,
    )


def _to_detail(row: Any) -> FindingDetail:
    factors = row.score_factors or {}
    affected = factors.get("services_affected")
    return FindingDetail(
        **_to_summary(row).model_dump(),
        description=row.description,
        score_factors=factors,
        services_affected=list(affected) if isinstance(affected, list) else [],
    )
