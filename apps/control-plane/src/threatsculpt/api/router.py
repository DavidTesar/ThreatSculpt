"""Aggregates the v1 API surface.

Two audiences share the prefix and share nothing else: ``/agent/*`` is the
machine protocol in docs/AGENT-PROTOCOL.md, authenticated by an agent API key,
and everything else is the dashboard API in docs/API.md, authenticated by a user
JWT. Neither credential works on the other's routes — see
``api.dependencies.current_user`` and ``current_agent``.
"""

from __future__ import annotations

from fastapi import APIRouter

from threatsculpt.api.routes import (
    agent_admin,
    agent_protocol,
    assets,
    business_services,
    dashboard,
    findings,
    networks,
    reports,
    users,
)
from threatsculpt.auth.router import router as auth_router
from threatsculpt.scanning.router import router as scans_router

api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(users.router)
api_router.include_router(networks.router)
api_router.include_router(business_services.router)
api_router.include_router(assets.router)
api_router.include_router(findings.router)
api_router.include_router(dashboard.router)
api_router.include_router(reports.router)
api_router.include_router(scans_router)
api_router.include_router(agent_admin.router)
api_router.include_router(agent_protocol.router)
