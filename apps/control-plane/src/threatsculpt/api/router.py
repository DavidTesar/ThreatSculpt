"""Aggregates the v1 API surface.

Agent routes (``/agent/*``, docs/AGENT-PROTOCOL.md) are intentionally absent —
the ``current_agent`` dependency and key verification they build on live in
``api.dependencies``, but the endpoints belong to another workstream.
"""

from __future__ import annotations

from fastapi import APIRouter

from threatsculpt.api.routes import business_services, networks
from threatsculpt.auth.router import router as auth_router

api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(networks.router)
api_router.include_router(business_services.router)
