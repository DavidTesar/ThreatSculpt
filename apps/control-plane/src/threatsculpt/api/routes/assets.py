"""``/assets`` — inventory, and the asset → business service mapping.

The mapping endpoint is the one that turns "CVE-2021-44228 on 10.0.4.12" into
"Payment processing is exposed", so both it and an exposure change re-score the
asset's findings immediately. Leaving the score stale until the next scan would
mean the dashboard disagrees with the inventory the operator is looking at.
"""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.api.dependencies import RequireAnalyst, RequireViewer, SessionDep
from threatsculpt.api.limits import enforce_general_rate_limit
from threatsculpt.api.middleware import client_ip
from threatsculpt.assets.queries import AssetFilters, get_asset, list_assets
from threatsculpt.assets.schemas import AssetOut, AssetServicesUpdate, AssetUpdate
from threatsculpt.audit.writer import record_audit
from threatsculpt.core.envelope import Envelope, ok
from threatsculpt.core.errors import SemanticValidationError
from threatsculpt.core.pagination import PaginationParams, pagination_params
from threatsculpt.enrichment.scoring_service import rescore_findings
from threatsculpt.models.audit import AuditAction
from threatsculpt.models.inventory import Asset, AssetService, BusinessService, Exposure, Network
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope

router = APIRouter(
    prefix="/assets",
    tags=["assets"],
    dependencies=[Depends(enforce_general_rate_limit)],
)

AssetId = Annotated[UUID, Path(description="Asset id within your organisation")]
PaginationDep = Annotated[PaginationParams, Depends(pagination_params)]

#: Bounded so a search term cannot become an unindexed scan of a huge text column.
MAX_SEARCH_LENGTH = 128


def asset_filters(
    network_id: Annotated[UUID | None, Query(description="Registered network")] = None,
    exposure: Annotated[Exposure | None, Query(description="Network exposure tier")] = None,
    service_id: Annotated[UUID | None, Query(description="Business service supported")] = None,
    q: Annotated[
        str | None, Query(max_length=MAX_SEARCH_LENGTH, description="Hostname or IP substring")
    ] = None,
) -> AssetFilters:
    return AssetFilters(
        network_id=network_id,
        exposure=exposure.value if exposure else None,
        service_id=service_id,
        q=q,
    )


FiltersDep = Annotated[AssetFilters, Depends(asset_filters)]


@router.get("", response_model=Envelope[list[AssetOut]], summary="List assets")
async def list_all(
    principal: RequireViewer,
    session: SessionDep,
    pagination: PaginationDep,
    filters: FiltersDep,
) -> Envelope[list[AssetOut]]:
    page = await list_assets(session, principal.scope, filters, pagination)
    return ok(list(page.items), meta=page.meta)


@router.get("/{asset_id}", response_model=Envelope[AssetOut], summary="Fetch an asset")
async def get_one(
    principal: RequireViewer, session: SessionDep, asset_id: AssetId
) -> Envelope[AssetOut]:
    return ok(await get_asset(session, principal.scope, asset_id))


@router.patch("/{asset_id}", response_model=Envelope[AssetOut], summary="Correct asset details")
async def update_one(
    request: Request,
    principal: RequireAnalyst,
    session: SessionDep,
    asset_id: AssetId,
    payload: AssetUpdate,
) -> Envelope[AssetOut]:
    repository = ScopedRepository(session, principal.scope, Asset)
    asset = await repository.get_or_404(asset_id)
    changes = payload.changes()

    if "network_id" in changes and changes["network_id"] is not None:
        await _assert_network_exists(session, principal.scope, changes["network_id"])

    exposure_changed = "exposure" in changes and changes["exposure"] != asset.exposure
    if changes:
        await repository.update(asset, changes)
    if exposure_changed:
        # Exposure is a scoring multiplier; a stale score here is a wrong number
        # on the executive dashboard within seconds of the edit.
        await rescore_findings(session, principal.scope, asset_ids=[asset_id])

    await record_audit(
        session,
        principal.scope,
        AuditAction.ASSET_UPDATED,
        target_type="asset",
        target_id=asset_id,
        metadata={"fields": sorted(changes), "rescored": exposure_changed},
        ip=client_ip(request),
    )
    return ok(await get_asset(session, principal.scope, asset_id))


@router.put(
    "/{asset_id}/services",
    response_model=Envelope[AssetOut],
    summary="Map an asset to business services",
)
async def set_services(
    request: Request,
    principal: RequireAnalyst,
    session: SessionDep,
    asset_id: AssetId,
    payload: AssetServicesUpdate,
) -> Envelope[AssetOut]:
    """Replaces the mapping wholesale, then re-scores the asset's findings."""
    scope = principal.scope
    assets = ScopedRepository(session, scope, Asset)
    await assets.get_or_404(asset_id)

    requested = tuple(dict.fromkeys(payload.service_ids))
    await _assert_services_exist(session, scope, requested)

    links = ScopedRepository(session, scope, AssetService)
    await links.delete_where(AssetService.asset_id == asset_id)
    for service_id in requested:
        await links.create(asset_id=asset_id, business_service_id=service_id)

    updated = await rescore_findings(session, scope, asset_ids=[asset_id])
    await record_audit(
        session,
        scope,
        AuditAction.ASSET_SERVICES_UPDATED,
        target_type="asset",
        target_id=asset_id,
        metadata={"service_ids": [str(item) for item in requested], "findings_rescored": updated},
        ip=client_ip(request),
    )
    return ok(await get_asset(session, scope, asset_id))


async def _assert_network_exists(
    session: AsyncSession, scope: OrgScope, network_id: object
) -> None:
    repository = ScopedRepository(session, scope, Network)
    if not await repository.exists(Network.id == network_id):
        raise SemanticValidationError(
            "That network does not exist in your organisation.",
            field="network_id",
            code="network_not_found",
        )


async def _assert_services_exist(
    session: AsyncSession, scope: OrgScope, service_ids: tuple[UUID, ...]
) -> None:
    """Reject the whole request if any id is unknown.

    Scoped, so an id belonging to another org is simply unknown here — the
    mapping cannot be used to probe for the existence of another tenant's rows.
    """
    if not service_ids:
        return
    repository = ScopedRepository(session, scope, BusinessService)
    found = await repository.count(BusinessService.id.in_(service_ids))
    if found != len(service_ids):
        raise SemanticValidationError(
            "One or more business services do not exist in your organisation.",
            field="service_ids",
            code="business_service_not_found",
        )
