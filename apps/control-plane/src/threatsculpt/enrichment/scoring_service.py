"""Loading scoring inputs from the database and writing scores back.

The split is deliberate: ``threatsculpt.scoring`` does arithmetic and knows
nothing about SQLAlchemy; this module does I/O and knows nothing about
multipliers. Re-scoring is therefore a pure re-run of the same function over the
same rows, which is what makes it safe to invoke repeatedly.

Why re-scoring exists at all: three things move a score without a rescan.
The CVE mirror learns a CVE is now KEV-listed; an operator corrects an asset's
exposure; an operator maps an asset to a business service. All three change the
answer for findings discovered weeks ago, and asking a customer to re-scan their
estate to see that is asking them to do work the server can do itself.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Final, cast
from uuid import UUID

from sqlalchemy import Table, bindparam, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.core.scoped_sql import execute_scoped
from threatsculpt.db.types import JSONB
from threatsculpt.models.finding import Finding, Vulnerability
from threatsculpt.models.inventory import Asset, AssetService, BusinessService
from threatsculpt.scoring import RiskScore, ScoreInputs, ServiceCriticality, score
from threatsculpt.tenancy.scope import OrgScope

logger = logging.getLogger(__name__)

#: Findings re-scored per round trip. Bounds both the statement size and the
#: number of rows held in memory during a full-org re-score.
RESCORE_BATCH_SIZE: Final = 500


@dataclass(frozen=True, slots=True)
class AssetContext:
    """The asset-side scoring inputs, resolved once per asset."""

    asset_id: UUID
    exposure: str
    services: tuple[ServiceCriticality, ...] = ()


async def load_asset_contexts(
    session: AsyncSession, scope: OrgScope, asset_ids: Sequence[UUID] | None = None
) -> dict[UUID, AssetContext]:
    """Exposure and business services for every asset, in one query.

    One LEFT JOIN rather than a query per asset: the alternative is an N+1 that
    scales with the size of the customer's estate, on the path that runs after
    every scan.
    """
    statement = (
        select(Asset.id, Asset.exposure, BusinessService.name, BusinessService.criticality)
        .select_from(Asset)
        .outerjoin(
            AssetService,
            (AssetService.asset_id == Asset.id) & (AssetService.org_id == scope.org_id),
        )
        .outerjoin(
            BusinessService,
            (BusinessService.id == AssetService.business_service_id)
            & (BusinessService.org_id == scope.org_id),
        )
        .where(Asset.org_id == scope.org_id)
    )
    if asset_ids is not None:
        if not asset_ids:
            return {}
        statement = statement.where(Asset.id.in_(tuple(asset_ids)))

    rows = (await execute_scoped(session, scope, statement)).all()
    return _fold_contexts(rows)


def _fold_contexts(rows: Sequence[Any]) -> dict[UUID, AssetContext]:
    """Collapse the joined rows into one context per asset. Never mutates a context."""
    exposures: dict[UUID, str] = {}
    services: dict[UUID, list[ServiceCriticality]] = {}
    for asset_id, exposure, service_name, criticality in rows:
        exposures[asset_id] = exposure
        bucket = services.setdefault(asset_id, [])
        if service_name is not None and criticality is not None:
            bucket.append(ServiceCriticality(name=service_name, criticality=criticality))
    return {
        asset_id: AssetContext(
            asset_id=asset_id, exposure=exposure, services=tuple(services.get(asset_id, ()))
        )
        for asset_id, exposure in exposures.items()
    }


def score_for(
    *,
    cvss_base: Decimal | None,
    exploit_maturity: str,
    kev_listed: bool,
    context: AssetContext | None,
) -> RiskScore:
    """Score one finding. ``context`` is ``None`` for an asset we cannot resolve."""
    return score(
        ScoreInputs(
            cvss_base=cvss_base,
            exploit_maturity=exploit_maturity,
            kev_listed=kev_listed,
            exposure=context.exposure if context else "internal",
            services=context.services if context else (),
        )
    )


async def rescore_findings(
    session: AsyncSession,
    scope: OrgScope,
    *,
    asset_ids: Sequence[UUID] | None = None,
    cve_ids: Sequence[str] | None = None,
) -> int:
    """Recompute scores for existing findings. Returns the number updated.

    Idempotent by construction: it reads the current inputs and writes the
    current answer, so running it twice changes nothing the second time.
    """
    contexts = await load_asset_contexts(session, scope, asset_ids)
    rows = await _load_rescore_rows(session, scope, asset_ids, cve_ids)
    if not rows:
        return 0

    updates = [_rescore_row(row, contexts.get(row.asset_id)) for row in rows]
    for batch in _batched(updates):
        await execute_scoped(session, scope, _rescore_statement(scope), batch)
    logger.info("findings rescored", extra={"org_id": str(scope.org_id), "count": len(updates)})
    return len(updates)


def _rescore_row(row: Any, context: AssetContext | None) -> dict[str, Any]:
    result = score_for(
        cvss_base=row.cvss_base,
        exploit_maturity=row.exploit_maturity,
        kev_listed=row.kev_listed,
        context=context,
    )
    return {
        "target_id": row.id,
        "new_score": result.score,
        "new_factors": result.score_factors(),
    }


async def _load_rescore_rows(
    session: AsyncSession,
    scope: OrgScope,
    asset_ids: Sequence[UUID] | None,
    cve_ids: Sequence[str] | None,
) -> Sequence[Any]:
    statement = (
        select(
            Finding.id,
            Finding.asset_id,
            Vulnerability.cvss_base,
            Vulnerability.exploit_maturity,
            Vulnerability.kev_listed,
        )
        .select_from(Finding)
        .join(Vulnerability, Vulnerability.cve_id == Finding.cve_id)
        .where(Finding.org_id == scope.org_id)
    )
    if asset_ids is not None:
        if not asset_ids:
            return ()
        statement = statement.where(Finding.asset_id.in_(tuple(asset_ids)))
    if cve_ids is not None:
        if not cve_ids:
            return ()
        statement = statement.where(Finding.cve_id.in_(tuple(cve_ids)))
    return (await execute_scoped(session, scope, statement)).all()


def _rescore_statement(scope: OrgScope) -> Any:
    """Parameterised UPDATE, run once per batch as an executemany.

    The org predicate is a literal from the scope rather than a bind parameter:
    a per-row org id would be a value the batch could get wrong.

    Targets the Core table rather than the mapped class: an ORM-entity UPDATE
    with a parameter list is interpreted as "bulk update by primary key", which
    refuses the extra ``org_id`` predicate this must carry. The tenancy guard
    inspects Core statements just as it inspects ORM ones, so nothing is given
    up by dropping to the table — the guard test in the suite covers exactly
    this shape.
    """
    table = cast(Table, Finding.__table__)
    return (
        update(table)
        .where(table.c.org_id == scope.org_id, table.c.id == bindparam("target_id"))
        .values(
            business_risk_score=bindparam("new_score"),
            score_factors=bindparam("new_factors", type_=JSONB),
        )
    )


def _batched(rows: Sequence[dict[str, Any]]) -> list[Sequence[dict[str, Any]]]:
    return [
        rows[index : index + RESCORE_BATCH_SIZE]
        for index in range(0, len(rows), RESCORE_BATCH_SIZE)
    ]
