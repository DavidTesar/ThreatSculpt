"""Reading assets with their risk roll-up and service mapping.

Two joins and two correlated aggregates, all in one statement. The obvious
alternative — list assets, then per asset fetch findings and services — is an
N+1 that turns a 50-row page into 101 round trips.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import ColumnElement, Select, Text, and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.assets.schemas import AssetOut, ServiceLink
from threatsculpt.core.errors import NotFoundError
from threatsculpt.core.pagination import Page, PaginationParams
from threatsculpt.core.scoped_sql import execute_scoped
from threatsculpt.models.finding import RESOLVED_STATUSES, Finding
from threatsculpt.models.inventory import Asset, AssetService, BusinessService
from threatsculpt.tenancy.scope import OrgScope

#: LIKE metacharacters an operator almost certainly meant literally.
_LIKE_ESCAPE = "\\"


@dataclass(frozen=True, slots=True)
class AssetFilters:
    network_id: UUID | None = None
    exposure: str | None = None
    service_id: UUID | None = None
    q: str | None = None


def _open_findings_count(scope: OrgScope) -> Any:
    return (
        select(func.count())
        .select_from(Finding)
        .where(
            Finding.org_id == scope.org_id,
            Finding.asset_id == Asset.id,
            Finding.status.not_in(tuple(RESOLVED_STATUSES)),
        )
        .correlate(Asset)
        .scalar_subquery()
    )


def _worst_score(scope: OrgScope) -> Any:
    return (
        select(func.max(Finding.business_risk_score))
        .where(
            Finding.org_id == scope.org_id,
            Finding.asset_id == Asset.id,
            Finding.status.not_in(tuple(RESOLVED_STATUSES)),
        )
        .correlate(Asset)
        .scalar_subquery()
    )


def _base_select(scope: OrgScope) -> Select[Any]:
    return (
        select(
            Asset.id,
            Asset.ip,
            Asset.hostname,
            Asset.mac,
            Asset.os_family,
            Asset.os_version,
            Asset.exposure,
            Asset.network_id,
            Asset.first_seen_at,
            Asset.last_seen_at,
            _open_findings_count(scope).label("open_findings"),
            _worst_score(scope).label("worst_finding_score"),
        )
        .select_from(Asset)
        .where(Asset.org_id == scope.org_id)
    )


def _predicates(scope: OrgScope, filters: AssetFilters) -> list[ColumnElement[bool]]:
    clauses: list[ColumnElement[bool]] = []
    if filters.network_id is not None:
        clauses.append(Asset.network_id == filters.network_id)
    if filters.exposure is not None:
        clauses.append(Asset.exposure == filters.exposure)
    if filters.service_id is not None:
        clauses.append(
            select(AssetService.id)
            .where(
                AssetService.org_id == scope.org_id,
                AssetService.asset_id == Asset.id,
                AssetService.business_service_id == filters.service_id,
            )
            .exists()
        )
    if filters.q:
        pattern = f"%{_escape_like(filters.q)}%"
        clauses.append(
            Asset.hostname.ilike(pattern, escape=_LIKE_ESCAPE)
            | Asset.ip.cast(Text).ilike(pattern, escape=_LIKE_ESCAPE)
        )
    return clauses


def _escape_like(value: str) -> str:
    """Treat the operator's ``%`` and ``_`` as characters, not wildcards.

    Unescaped, a search for ``%`` matches every asset in the org — a confusing
    result that reads like a broken filter.
    """
    escaped = value.replace(_LIKE_ESCAPE, _LIKE_ESCAPE * 2)
    return escaped.replace("%", f"{_LIKE_ESCAPE}%").replace("_", f"{_LIKE_ESCAPE}_")


async def list_assets(
    session: AsyncSession, scope: OrgScope, filters: AssetFilters, pagination: PaginationParams
) -> Page[AssetOut]:
    clauses = _predicates(scope, filters)
    statement = (
        _base_select(scope)
        .where(*clauses)
        .order_by(Asset.ip.asc(), Asset.id.asc())
        .limit(pagination.limit)
        .offset(pagination.offset)
    )
    rows = (await execute_scoped(session, scope, statement)).all()
    services = await load_services(session, scope, tuple(row.id for row in rows))
    total = int(
        (
            await execute_scoped(
                session,
                scope,
                select(func.count())
                .select_from(Asset)
                .where(Asset.org_id == scope.org_id, *clauses),
            )
        ).scalar_one()
    )
    items = tuple(_to_out(row, services.get(row.id, ())) for row in rows)
    return Page(items=items, total=total, params=pagination)


async def get_asset(session: AsyncSession, scope: OrgScope, asset_id: UUID) -> AssetOut:
    statement = _base_select(scope).where(Asset.id == asset_id)
    row = (await execute_scoped(session, scope, statement)).first()
    if row is None:
        raise NotFoundError()
    services = await load_services(session, scope, (asset_id,))
    return _to_out(row, services.get(asset_id, ()))


async def load_services(
    session: AsyncSession, scope: OrgScope, asset_ids: tuple[UUID, ...]
) -> dict[UUID, tuple[ServiceLink, ...]]:
    """Service links for a page of assets, in one query rather than one per asset."""
    if not asset_ids:
        return {}
    statement = (
        select(
            AssetService.asset_id,
            BusinessService.id,
            BusinessService.name,
            BusinessService.criticality,
        )
        .select_from(AssetService)
        .join(
            BusinessService,
            and_(
                BusinessService.id == AssetService.business_service_id,
                BusinessService.org_id == scope.org_id,
            ),
        )
        .where(AssetService.org_id == scope.org_id, AssetService.asset_id.in_(asset_ids))
        .order_by(BusinessService.name.asc())
    )
    rows = (await execute_scoped(session, scope, statement)).all()
    grouped: dict[UUID, list[ServiceLink]] = {}
    for asset_id, service_id, name, criticality in rows:
        grouped.setdefault(asset_id, []).append(
            ServiceLink(id=service_id, name=name, criticality=criticality)
        )
    return {key: tuple(value) for key, value in grouped.items()}


def _to_out(row: Any, services: tuple[ServiceLink, ...]) -> AssetOut:
    return AssetOut(
        id=row.id,
        ip=row.ip,
        hostname=row.hostname,
        mac=row.mac,
        os_family=row.os_family,
        os_version=row.os_version,
        exposure=row.exposure,
        network_id=row.network_id,
        open_findings=int(row.open_findings or 0),
        worst_finding_score=row.worst_finding_score,
        services=list(services),
        first_seen_at=row.first_seen_at,
        last_seen_at=row.last_seen_at,
    )
