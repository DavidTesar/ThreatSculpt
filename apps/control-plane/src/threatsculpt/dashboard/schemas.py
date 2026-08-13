"""Dashboard response models — the exact payloads in docs/API.md."""

from __future__ import annotations

from decimal import Decimal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RiskPosture(StrictModel):
    score: int
    trend_30d: int
    band: str


class ServiceAtRisk(StrictModel):
    service_id: UUID
    name: str
    criticality: str
    revenue_at_risk: Decimal | None = None
    open_findings: int
    worst_finding_score: Decimal
    assets_affected: int


class ExposureSummary(StrictModel):
    internet: int = 0
    dmz: int = 0
    internal: int = 0
    isolated: int = 0


class RemediationProgress(StrictModel):
    opened_30d: int = 0
    resolved_30d: int = 0


class ExecutiveDashboard(StrictModel):
    risk_posture: RiskPosture
    services_at_risk: list[ServiceAtRisk] = Field(default_factory=list)
    exposure_summary: ExposureSummary
    kev_findings: int = 0
    remediation_progress: RemediationProgress


class GraphNode(StrictModel):
    id: str
    type: str
    label: str
    #: ``business_risk_score`` for assets; aggregated impact for services.
    weight: Decimal = Decimal("0")
    exposure: str | None = None
    criticality: str | None = None
    #: Set on a placeholder node standing in for assets the cap excluded.
    represents: int | None = None


class GraphEdge(StrictModel):
    source: str
    target: str
    type: str


class AttackSurface(StrictModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    #: True when the org exceeded the node cap and the graph was rolled up.
    aggregated: bool = False
    node_cap: int = 0
    total_assets: int = 0
