"""Rate-limit dependencies.

docs/API.md: ``10/min`` on auth endpoints per IP, ``100/min`` general per user.
The second half of that sentence is the hard part. A router-level dependency is
resolved *before* the route's own dependencies, so anything attached to a router
runs before ``current_user`` has authenticated anybody — there is no principal to
key on yet, and falling back to the client IP quietly turns "per user" into "per
source address". Everyone behind one office NAT or VPN egress then shares a
single bucket, and an unauthenticated flood from that address consumes the
allowance of every real user behind it.

So the per-principal charge happens where the principal first exists, in
``api.dependencies.current_user`` / ``current_agent``, and unauthenticated
traffic gets its own smaller bucket that authenticated users never draw from.
``enforce_general_rate_limit`` stays on the routers as the pre-authentication
guard for callers who present no credential at all.

The limiters live on ``app.state`` so tests can reset them and so each app
instance has its own.
"""

from __future__ import annotations

from fastapi import Request

from threatsculpt.api.middleware import client_ip
from threatsculpt.core.errors import RateLimitedError
from threatsculpt.security.ratelimit import SlidingWindowLimiter

AUTH_LIMITER_ATTR = "auth_limiter"
GENERAL_LIMITER_ATTR = "general_limiter"
UNKNOWN_CLIENT_KEY = "unknown"

#: Marks the request as already charged to the anonymous bucket, so a caller who
#: passes through both the router guard and a failed authentication is counted
#: once rather than twice.
_ANONYMOUS_CHARGED_ATTR = "anonymous_rate_limit_charged"

_ANONYMOUS_MESSAGE = "Too many unauthenticated requests. Try again shortly."


def _limiter(request: Request, attribute: str) -> SlidingWindowLimiter:
    limiter: SlidingWindowLimiter = getattr(request.app.state, attribute)
    return limiter


def _check(request: Request, attribute: str, key: str, limit: int, message: str | None) -> None:
    decision = _limiter(request, attribute).check(key, limit)
    if not decision.allowed:
        raise RateLimitedError(message, retry_after_seconds=decision.retry_after_seconds)


async def enforce_auth_rate_limit(request: Request) -> None:
    """Per-IP limit on the auth endpoints. Applied before any credential work."""
    settings = request.app.state.settings
    key = f"auth:{client_ip(request) or UNKNOWN_CLIENT_KEY}:{request.url.path}"
    _check(
        request,
        AUTH_LIMITER_ATTR,
        key,
        settings.auth_rate_limit_per_minute,
        "Too many authentication attempts. Try again shortly.",
    )


async def enforce_general_rate_limit(request: Request) -> None:
    """Bound callers who present no credential at all.

    Requests that *do* carry an ``Authorization`` header are charged to the
    principal behind it once authentication resolves, or to the anonymous bucket
    if that credential turns out to be worthless.
    """
    if request.headers.get("authorization"):
        return
    charge_anonymous(request)


def charge_anonymous(request: Request) -> None:
    """Count one unauthenticated request against its source address.

    Its own bucket and its own key namespace: an unauthenticated flood must not
    be able to spend an authenticated user's allowance.
    """
    if getattr(request.state, _ANONYMOUS_CHARGED_ATTR, False):
        return
    setattr(request.state, _ANONYMOUS_CHARGED_ATTR, True)
    settings = request.app.state.settings
    key = f"anon:{client_ip(request) or UNKNOWN_CLIENT_KEY}"
    _check(
        request,
        GENERAL_LIMITER_ATTR,
        key,
        settings.anonymous_rate_limit_per_minute,
        _ANONYMOUS_MESSAGE,
    )


def charge_principal(request: Request, actor_key: str) -> None:
    """Count one request against an authenticated principal's own bucket.

    ``actor_key`` is namespaced by principal type (``user:``/``agent:``) so a
    user and an agent can never collide, and neither can collide with the
    anonymous keys above.
    """
    settings = request.app.state.settings
    _check(
        request,
        GENERAL_LIMITER_ATTR,
        f"general:{actor_key}",
        settings.general_rate_limit_per_minute,
        None,
    )
