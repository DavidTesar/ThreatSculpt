"""``GET /dashboard/executive`` — five aggregates, five round trips, no loops.

This is the most-hit endpoint in the product, so every number here is computed
by the database. Pulling findings into Python to count them would make response
time a function of how many vulnerabilities a customer has, which is exactly
backwards: the customers with the most findings are the ones who most need the
page to load.

Every statement is ``WHERE org_id = :scope`` plus one indexed predicate, and
migration 0005 adds the composite indexes that back them.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Final

from sqlalchemy import Select, case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.core.scoped_sql import execute_scoped
from threatsculpt.dashboard.schemas import (
    ExecutiveDashboard,
    ExposureSummary,
    RemediationProgress,
    RiskPosture,
    ServiceAtRisk,
)
from threatsculpt.models.finding import RESOLVED_STATUSES, Finding, Vulnerability
from threatsculpt.models.inventory import Asset, AssetService, BusinessService
from threatsculpt.scoring import CRITICALITY_RANK
from threatsculpt.scoring.constants import CRITICALITY_UNMAPPED
from threatsculpt.scoring.engine import posture_band
from threatsculpt.tenancy.scope import OrgScope

#: The posture headline averages the worst N open findings rather than every
#: finding. A mean over everything is dominated by the long tail of low-severity
#: noise, so an org could fix nothing and watch its posture "improve" simply by
#: discovering more trivia.
POSTURE_SAMPLE_SIZE: Final = 10

#: docs/API.md's trend and remediation windows.
TREND_WINDOW_DAYS: Final = 30

#: Bounded, like every other collection in this API.
MAX_SERVICES_AT_RISK: Final = 20

_OPEN = Finding.status.not_in(tuple(RESOLVED_STATUSES))


def _criticality_rank() -> Any:
    """SQL CASE built from the scoring package's rank table.

    Defined once, in Python, so the dashboard's ordering cannot drift away from
    the ladder the scores themselves were computed against.
    """
    return case(
        dict(CRITICALITY_RANK),
        value=BusinessService.criticality,
        else_=CRITICALITY_RANK[CRITICALITY_UNMAPPED],
    )


async def executive_dashboard(session: AsyncSession, scope: OrgScope) -> ExecutiveDashboard:
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=TREND_WINDOW_DAYS)

    current = await _posture_score(session, scope)
    previous = await _posture_score(session, scope, as_of=cutoff)
    return ExecutiveDashboard(
        risk_posture=RiskPosture(
            score=int(current),
            trend_30d=int(current) - int(previous),
            band=posture_band(current),
        ),
        services_at_risk=await services_at_risk(session, scope),
        exposure_summary=await exposure_summary(session, scope),
        kev_findings=await kev_finding_count(session, scope),
        remediation_progress=await remediation_progress(session, scope, cutoff),
    )


async def _posture_score(
    session: AsyncSession, scope: OrgScope, *, as_of: datetime | None = None
) -> Decimal:
    """Mean of the org's worst open findings, 0-100.

    ``as_of`` reconstructs the population that was open at a past moment —
    findings first seen before the cutoff and not resolved until after it. It
    uses *today's* scores for those findings, because the schema keeps one score
    per finding rather than a score history. So the trend answers "how much of
    the risk we were carrying has gone away", not "what would the dashboard have
    printed a month ago". That is the more useful question, but it is a
    different one, and it is worth knowing which is being answered.
    """
    statement: Select[Any] = (
        select(Finding.business_risk_score)
        .where(Finding.org_id == scope.org_id)
        .order_by(Finding.business_risk_score.desc())
        .limit(POSTURE_SAMPLE_SIZE)
    )
    if as_of is None:
        statement = statement.where(_OPEN)
    else:
        statement = statement.where(
            Finding.first_seen_at <= as_of,
            (Finding.resolved_at.is_(None)) | (Finding.resolved_at > as_of),
        )

    worst = statement.subquery("worst")
    result = await execute_scoped(
        session, scope, select(func.avg(worst.c.business_risk_score)).select_from(worst)
    )
    average = result.scalar_one_or_none()
    if average is None:
        return Decimal("0")
    return Decimal(average).quantize(Decimal("1"), rounding=ROUND_HALF_UP)


async def services_at_risk(session: AsyncSession, scope: OrgScope) -> list[ServiceAtRisk]:
    """Business services with open findings, ordered by business impact.

    The ordering is lexicographic, and deliberately so:

    1. **Criticality tier, descending.** Of every input the product has, this is
       the only one that is a business statement rather than a technical
       measurement — the customer told us that payment processing matters more
       than the wiki. An executive view leads with that, so a ``critical``
       service is never listed below a ``low`` one.
    2. **Worst open finding score, descending.** Within a tier, the technical
       severity decides. That score already folds in exploit maturity, exposure
       and criticality, so it is not CVSS either.
    3. **Revenue at risk, descending.** When two services are equally critical
       and equally broken, the one carrying more money goes first.

    An earlier version multiplied criticality by the worst score into a single
    "impact" number. That was wrong twice over: criticality is *already* a factor
    inside ``business_risk_score``, so it counted the same input twice, and the
    product still let an internet-facing low-criticality service outrank an
    isolated critical one — the exact inversion this endpoint exists to prevent.

    Both sort keys are returned in the payload, so the order is checkable by the
    reader rather than something they have to trust.
    """
    rows = (await execute_scoped(session, scope, _services_statement(scope))).all()
    return [
        ServiceAtRisk(
            service_id=row.id,
            name=row.name,
            criticality=row.criticality,
            revenue_at_risk=row.revenue_at_risk,
            open_findings=int(row.open_findings),
            worst_finding_score=row.worst_finding_score,
            assets_affected=int(row.assets_affected),
        )
        for row in rows
    ]


def _services_statement(scope: OrgScope) -> Select[Any]:
    """One GROUP BY over ``business_services -> asset_services -> findings``."""
    return (
        select(
            BusinessService.id,
            BusinessService.name,
            BusinessService.criticality,
            BusinessService.revenue_at_risk,
            func.count(Finding.id).label("open_findings"),
            func.max(Finding.business_risk_score).label("worst_finding_score"),
            func.count(func.distinct(Finding.asset_id)).label("assets_affected"),
        )
        .select_from(BusinessService)
        .join(
            AssetService,
            (AssetService.business_service_id == BusinessService.id)
            & (AssetService.org_id == scope.org_id),
        )
        .join(
            Finding,
            (Finding.asset_id == AssetService.asset_id) & (Finding.org_id == scope.org_id) & _OPEN,
        )
        .where(BusinessService.org_id == scope.org_id)
        .group_by(BusinessService.id)
        .order_by(
            _criticality_rank().desc(),
            func.max(Finding.business_risk_score).desc(),
            BusinessService.revenue_at_risk.desc().nullslast(),
            BusinessService.name.asc(),
        )
        .limit(MAX_SERVICES_AT_RISK)
    )


async def exposure_summary(session: AsyncSession, scope: OrgScope) -> ExposureSummary:
    statement = (
        select(Asset.exposure, func.count())
        .where(Asset.org_id == scope.org_id)
        .group_by(Asset.exposure)
    )
    rows = (await execute_scoped(session, scope, statement)).all()
    counts = {exposure: int(count) for exposure, count in rows}
    return ExposureSummary(
        internet=counts.get("internet", 0),
        dmz=counts.get("dmz", 0),
        internal=counts.get("internal", 0),
        isolated=counts.get("isolated", 0),
    )


async def kev_finding_count(session: AsyncSession, scope: OrgScope) -> int:
    statement = (
        select(func.count())
        .select_from(Finding)
        .join(Vulnerability, Vulnerability.cve_id == Finding.cve_id)
        .where(Finding.org_id == scope.org_id, _OPEN, Vulnerability.kev_listed.is_(True))
    )
    return int((await execute_scoped(session, scope, statement)).scalar_one())


async def remediation_progress(
    session: AsyncSession, scope: OrgScope, cutoff: datetime
) -> RemediationProgress:
    """Opened and resolved in the window, from one scan of the findings table."""
    statement = select(
        func.count().filter(Finding.first_seen_at >= cutoff).label("opened"),
        func.count().filter(Finding.resolved_at >= cutoff).label("resolved"),
    ).where(Finding.org_id == scope.org_id)
    row = (await execute_scoped(session, scope, statement)).one()
    return RemediationProgress(opened_30d=int(row.opened), resolved_30d=int(row.resolved))
