"""Liveness and readiness.

Both are unauthenticated and neither reveals anything: liveness says the process
is up, readiness says the database answers. No version strings, no hostnames, no
migration revision — those are useful to an attacker fingerprinting the service
and useless to a load balancer.
"""

from __future__ import annotations

import logging
from http import HTTPStatus

from fastapi import APIRouter, Request, Response
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from threatsculpt.api.schemas import HealthOut, ReadinessOut
from threatsculpt.core.envelope import Envelope, ok

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])

_PING = text("SELECT 1")


@router.get("/health", response_model=Envelope[HealthOut], summary="Liveness")
async def health(request: Request) -> Envelope[HealthOut]:
    settings = request.app.state.settings
    return ok(HealthOut(status="ok", environment=settings.environment))


@router.get("/ready", response_model=Envelope[ReadinessOut], summary="Readiness")
async def ready(request: Request, response: Response) -> Envelope[ReadinessOut]:
    """503 when the database is unreachable, so a rolling deploy waits."""
    factory = request.app.state.session_factory
    try:
        async with factory() as session:
            await session.execute(_PING)
    except SQLAlchemyError as exc:
        logger.error("readiness probe failed", exc_info=exc, extra={"event": "not_ready"})
        response.status_code = HTTPStatus.SERVICE_UNAVAILABLE
        return ok(ReadinessOut(status="degraded", database="unavailable"))
    return ok(ReadinessOut(status="ok", database="ok"))
