"""Application factory."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from threatsculpt.api.handlers import register_exception_handlers
from threatsculpt.api.limits import AUTH_LIMITER_ATTR, GENERAL_LIMITER_ATTR
from threatsculpt.api.middleware import RequestContextMiddleware
from threatsculpt.api.router import api_router
from threatsculpt.api.routes import health
from threatsculpt.auth.delivery import assert_email_delivery_is_usable, build_email_sender
from threatsculpt.config import Settings, get_settings
from threatsculpt.db.engine import build_engine, build_session_factory
from threatsculpt.db.privileges import assert_database_role_is_unprivileged
from threatsculpt.observability.context import REQUEST_ID_HEADER
from threatsculpt.observability.logging import configure_logging
from threatsculpt.security.ratelimit import SlidingWindowLimiter
from threatsculpt.security.tokens import JwtCodec

logger = logging.getLogger(__name__)

TITLE = "ThreatSculpt Control Plane"
VERSION = "2.0.0"
DESCRIPTION = (
    "Multi-tenant control plane. The organisation is always derived from the "
    "authenticated principal; no endpoint accepts a tenant identifier."
)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build a fully wired application.

    Takes settings rather than reading them so tests can construct an app
    against a throwaway database without touching the process environment.
    """
    resolved = settings or get_settings()
    configure_logging(level=resolved.log_level, as_json=resolved.log_json)

    app = FastAPI(
        title=TITLE,
        version=VERSION,
        description=DESCRIPTION,
        docs_url=None if resolved.is_production else "/docs",
        redoc_url=None,
        openapi_url=None if resolved.is_production else "/openapi.json",
        lifespan=_lifespan,
    )

    app.state.settings = resolved
    app.state.jwt_codec = JwtCodec(
        secret=resolved.jwt_secret.get_secret_value(),
        algorithm=resolved.jwt_algorithm,
        ttl=timedelta(minutes=resolved.access_token_ttl_minutes),
    )
    setattr(app.state, AUTH_LIMITER_ATTR, SlidingWindowLimiter())
    setattr(app.state, GENERAL_LIMITER_ATTR, SlidingWindowLimiter())
    # Before anything is served: prove the service can actually onboard a user.
    # Verification is enforced, so a deployment that cannot deliver a message
    # cannot verify anybody, and every login against it fails for a reason no
    # operator would connect to this setting. Same posture as the database-role
    # check below — refuse to start rather than start broken.
    assert_email_delivery_is_usable(
        resolved.email_delivery, allow_undeliverable=resolved.allow_undeliverable_email
    )
    app.state.email_sender = build_email_sender(resolved.email_delivery)

    _install_middleware(app, resolved)
    register_exception_handlers(app)

    app.include_router(health.router)
    app.include_router(api_router, prefix=resolved.api_prefix)
    return app


def _install_middleware(app: FastAPI, settings: Settings) -> None:
    """CORS comes from configuration and is never ``*``.

    Credentials are cookies here, so a wildcard origin would either be rejected
    by the browser or, worse, work — letting any site drive the API as the
    logged-in user. ``Settings`` rejects ``*`` outright; this only lists what was
    configured.
    """
    app.add_middleware(RequestContextMiddleware)
    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(settings.cors_origins),
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type", REQUEST_ID_HEADER],
            expose_headers=[REQUEST_ID_HEADER],
            max_age=600,
        )


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    engine = build_engine(settings)

    # Before anything is served: prove the database role cannot bypass RLS.
    # Checked here rather than lazily because the whole point is to fail at
    # deploy time, loudly, instead of serving traffic with one isolation layer
    # silently missing. On failure the engine is disposed and the error
    # propagates, so the process exits non-zero.
    try:
        await assert_database_role_is_unprivileged(
            engine, allow_superuser=settings.allow_superuser_db
        )
    except Exception:
        await engine.dispose()
        raise

    app.state.engine = engine
    app.state.session_factory = build_session_factory(engine)
    logger.info("control plane started", extra={"environment": settings.environment})
    try:
        yield
    finally:
        await engine.dispose()
        logger.info("control plane stopped")
