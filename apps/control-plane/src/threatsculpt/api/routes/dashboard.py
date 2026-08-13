"""``/dashboard`` — the two views that make this a product rather than a scanner."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from threatsculpt.api.dependencies import RequireViewer, SessionDep
from threatsculpt.api.limits import enforce_general_rate_limit
from threatsculpt.core.envelope import Envelope, ok
from threatsculpt.dashboard.attack_surface import MAX_NODES, attack_surface
from threatsculpt.dashboard.executive import executive_dashboard
from threatsculpt.dashboard.schemas import AttackSurface, ExecutiveDashboard

router = APIRouter(
    prefix="/dashboard",
    tags=["dashboard"],
    dependencies=[Depends(enforce_general_rate_limit)],
)


@router.get(
    "/executive",
    response_model=Envelope[ExecutiveDashboard],
    summary="Business-impact summary for a non-technical audience",
)
async def executive(principal: RequireViewer, session: SessionDep) -> Envelope[ExecutiveDashboard]:
    """Services at risk are ordered by business impact, not by CVSS."""
    return ok(await executive_dashboard(session, principal.scope))


@router.get(
    "/attack-surface",
    response_model=Envelope[AttackSurface],
    summary="Asset and business-service graph, capped",
)
async def surface(
    principal: RequireViewer,
    session: SessionDep,
    node_cap: Annotated[
        int,
        Query(ge=10, le=MAX_NODES, description="Maximum nodes to return"),
    ] = MAX_NODES,
) -> Envelope[AttackSurface]:
    return ok(await attack_surface(session, principal.scope, node_cap=node_cap))
