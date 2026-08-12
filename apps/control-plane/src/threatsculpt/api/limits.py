"""Rate-limit dependencies.

``10/min`` per IP on auth endpoints and ``100/min`` per user elsewhere, per
docs/API.md. The limiters live on ``app.state`` so tests can reset them and so
each app instance has its own.
"""

from __future__ import annotations

from fastapi import Request

from threatsculpt.api.middleware import client_ip
from threatsculpt.core.errors import RateLimitedError
from threatsculpt.security.ratelimit import SlidingWindowLimiter

AUTH_LIMITER_ATTR = "auth_limiter"
GENERAL_LIMITER_ATTR = "general_limiter"
UNKNOWN_CLIENT_KEY = "unknown"


def _limiter(request: Request, attribute: str) -> SlidingWindowLimiter:
    limiter: SlidingWindowLimiter = getattr(request.app.state, attribute)
    return limiter


async def enforce_auth_rate_limit(request: Request) -> None:
    """Per-IP limit on the auth endpoints. Applied before any credential work."""
    settings = request.app.state.settings
    key = f"auth:{client_ip(request) or UNKNOWN_CLIENT_KEY}:{request.url.path}"
    decision = _limiter(request, AUTH_LIMITER_ATTR).check(key, settings.auth_rate_limit_per_minute)
    if not decision.allowed:
        raise RateLimitedError(
            "Too many authentication attempts. Try again shortly.",
            retry_after_seconds=decision.retry_after_seconds,
        )


async def enforce_general_rate_limit(request: Request) -> None:
    """Per-principal limit on everything else.

    Falls back to the client IP before authentication has resolved a principal,
    so an unauthenticated flood is still bounded.
    """
    settings = request.app.state.settings
    actor = getattr(request.state, "actor_id", None) or client_ip(request) or UNKNOWN_CLIENT_KEY
    decision = _limiter(request, GENERAL_LIMITER_ATTR).check(
        f"general:{actor}", settings.general_rate_limit_per_minute
    )
    if not decision.allowed:
        raise RateLimitedError(retry_after_seconds=decision.retry_after_seconds)
