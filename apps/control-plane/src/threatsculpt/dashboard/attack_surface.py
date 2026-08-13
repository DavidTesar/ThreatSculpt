"""``GET /dashboard/attack-surface`` — the graph payload, hard-capped.

Nodes are assets, business services, and the four exposure zones. Edges are
``supports`` (asset → business service) and ``exposes`` (exposure zone → asset).

The cap is the point of this module. An org with 40,000 assets would otherwise
be handed a graph payload no browser can lay out and no network can deliver
quickly — docs/API.md calls this out as how the v1 dashboard would have died on
its first real customer. So the query is ``ORDER BY risk DESC LIMIT n``: when it
truncates, it keeps the assets that matter and says so via ``aggregated``,
rather than returning an arbitrary 500 and pretending that is the estate.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any, Final
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.core.scoped_sql import execute_scoped
from threatsculpt.dashboard.schemas import AttackSurface, GraphEdge, GraphNode
from threatsculpt.models.finding import RESOLVED_STATUSES, Finding
from threatsculpt.models.inventory import Asset, AssetService, BusinessService
from threatsculpt.tenancy.scope import OrgScope

#: docs/API.md: "Capped at 500 nodes with an ``aggregated`` flag".
MAX_NODES: Final = 500

NODE_ASSET: Final = "asset"
NODE_SERVICE: Final = "business_service"
NODE_EXPOSURE: Final = "exposure"
NODE_AGGREGATE: Final = "aggregated_assets"

EDGE_SUPPORTS: Final = "supports"
EDGE_EXPOSES: Final = "exposes"

_OPEN = Finding.status.not_in(tuple(RESOLVED_STATUSES))


async def attack_surface(
    session: AsyncSession, scope: OrgScope, *, node_cap: int = MAX_NODES
) -> AttackSurface:
    services = await _services(session, scope)
    # Services and exposure zones are few and always shown; assets get whatever
    # budget is left, so the cap is a cap on the response, not just on assets.
    asset_budget = max(node_cap - len(services) - len(_exposure_zones()), 1)
    assets = await _assets(session, scope, asset_budget)
    total_assets = await _asset_count(session, scope)

    shown = {row.id for row in assets}
    links = await _service_links(session, scope, tuple(shown))

    nodes = [*_exposure_zones(), *_service_nodes(services), *_asset_nodes(assets)]
    edges = [*_exposure_edges(assets), *_support_edges(links, shown)]

    omitted = total_assets - len(assets)
    if omitted > 0:
        nodes.append(_aggregate_node(omitted))

    return AttackSurface(
        nodes=nodes,
        edges=edges,
        aggregated=omitted > 0,
        node_cap=node_cap,
        total_assets=total_assets,
    )


async def _assets(session: AsyncSession, scope: OrgScope, budget: int) -> list[Any]:
    """Riskiest assets first, so a truncated graph is still the useful half."""
    risk = func.coalesce(func.max(Finding.business_risk_score), 0).label("weight")
    statement = (
        select(Asset.id, Asset.ip, Asset.hostname, Asset.exposure, risk)
        .select_from(Asset)
        .outerjoin(
            Finding,
            (Finding.asset_id == Asset.id) & (Finding.org_id == scope.org_id) & _OPEN,
        )
        .where(Asset.org_id == scope.org_id)
        .group_by(Asset.id)
        .order_by(risk.desc(), Asset.ip.asc())
        .limit(budget)
    )
    return list((await execute_scoped(session, scope, statement)).all())


async def _asset_count(session: AsyncSession, scope: OrgScope) -> int:
    statement = select(func.count()).select_from(Asset).where(Asset.org_id == scope.org_id)
    return int((await execute_scoped(session, scope, statement)).scalar_one())


async def _services(session: AsyncSession, scope: OrgScope) -> list[Any]:
    risk = func.coalesce(func.max(Finding.business_risk_score), 0).label("weight")
    statement = (
        select(BusinessService.id, BusinessService.name, BusinessService.criticality, risk)
        .select_from(BusinessService)
        .outerjoin(
            AssetService,
            (AssetService.business_service_id == BusinessService.id)
            & (AssetService.org_id == scope.org_id),
        )
        .outerjoin(
            Finding,
            (Finding.asset_id == AssetService.asset_id) & (Finding.org_id == scope.org_id) & _OPEN,
        )
        .where(BusinessService.org_id == scope.org_id)
        .group_by(BusinessService.id)
        .order_by(risk.desc(), BusinessService.name.asc())
        .limit(MAX_NODES)
    )
    return list((await execute_scoped(session, scope, statement)).all())


async def _service_links(
    session: AsyncSession, scope: OrgScope, asset_ids: tuple[UUID, ...]
) -> list[Any]:
    if not asset_ids:
        return []
    statement = select(AssetService.asset_id, AssetService.business_service_id).where(
        AssetService.org_id == scope.org_id, AssetService.asset_id.in_(asset_ids)
    )
    return list((await execute_scoped(session, scope, statement)).all())


def _exposure_zones() -> list[GraphNode]:
    return [
        GraphNode(id=f"{NODE_EXPOSURE}:{value}", type=NODE_EXPOSURE, label=value, exposure=value)
        for value in ("internet", "dmz", "internal", "isolated")
    ]


def _service_nodes(rows: list[Any]) -> list[GraphNode]:
    return [
        GraphNode(
            id=f"{NODE_SERVICE}:{row.id}",
            type=NODE_SERVICE,
            label=row.name,
            weight=Decimal(str(row.weight)),
            criticality=row.criticality,
        )
        for row in rows
    ]


def _asset_nodes(rows: list[Any]) -> list[GraphNode]:
    return [
        GraphNode(
            id=f"{NODE_ASSET}:{row.id}",
            type=NODE_ASSET,
            label=row.hostname or row.ip,
            weight=Decimal(str(row.weight)),
            exposure=row.exposure,
        )
        for row in rows
    ]


def _exposure_edges(rows: list[Any]) -> list[GraphEdge]:
    return [
        GraphEdge(
            source=f"{NODE_EXPOSURE}:{row.exposure}",
            target=f"{NODE_ASSET}:{row.id}",
            type=EDGE_EXPOSES,
        )
        for row in rows
    ]


def _support_edges(links: list[Any], shown: set[UUID]) -> list[GraphEdge]:
    return [
        GraphEdge(
            source=f"{NODE_ASSET}:{asset_id}",
            target=f"{NODE_SERVICE}:{service_id}",
            type=EDGE_SUPPORTS,
        )
        for asset_id, service_id in links
        if asset_id in shown
    ]


def _aggregate_node(omitted: int) -> GraphNode:
    """One placeholder for everything the cap excluded.

    Present so the graph never implies the estate is smaller than it is — a
    silently truncated graph is a lie about attack surface.
    """
    return GraphNode(
        id=NODE_AGGREGATE,
        type=NODE_AGGREGATE,
        label=f"{omitted} lower-risk assets not shown",
        represents=omitted,
    )
