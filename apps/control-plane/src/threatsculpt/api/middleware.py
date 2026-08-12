"""Request-scoped middleware: correlation id, access log, client-IP resolution."""

from __future__ import annotations

import logging
import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from threatsculpt.observability.context import (
    REQUEST_ID_HEADER,
    bind_request_id,
    new_request_id,
    reset_request_id,
)

logger = logging.getLogger("threatsculpt.access")

MILLISECONDS = 1000


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assigns a request id, echoes it, and emits one structured access line.

    An inbound ``X-Request-ID`` is accepted for tracing continuity but bounded
    in length and stripped of anything but hex/dash, so a caller cannot inject
    newlines or arbitrary text into the log stream.
    """

    MAX_INBOUND_ID_LENGTH = 64

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request_id = self._resolve_request_id(request)
        token = bind_request_id(request_id)
        request.state.request_id = request_id
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            self._log(request, status=500, started=started)
            raise
        finally:
            reset_request_id(token)
        response.headers[REQUEST_ID_HEADER] = request_id
        self._log(request, status=response.status_code, started=started)
        return response

    @classmethod
    def _resolve_request_id(cls, request: Request) -> str:
        inbound = request.headers.get(REQUEST_ID_HEADER, "")
        cleaned = "".join(c for c in inbound if c.isalnum() or c == "-")
        if cleaned and len(cleaned) <= cls.MAX_INBOUND_ID_LENGTH:
            return cleaned
        return new_request_id()

    @staticmethod
    def _log(request: Request, *, status: int, started: float) -> None:
        logger.info(
            "request",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status": status,
                "duration_ms": round((time.perf_counter() - started) * MILLISECONDS, 2),
                "org_id": getattr(request.state, "org_id", None),
                "client_ip": client_ip(request),
            },
        )


def client_ip(request: Request) -> str | None:
    """The caller's IP, honouring ``X-Forwarded-For`` only as far as configured.

    ``trusted_proxy_count`` says how many proxies we actually run behind. Taking
    the leftmost XFF entry unconditionally would let any caller spoof their IP
    and walk straight past the per-IP auth rate limit.
    """
    settings = getattr(request.app.state, "settings", None)
    trusted = getattr(settings, "trusted_proxy_count", 0) or 0
    if trusted > 0:
        forwarded = request.headers.get("x-forwarded-for", "")
        hops = [part.strip() for part in forwarded.split(",") if part.strip()]
        if len(hops) >= trusted:
            return hops[-trusted]
    return request.client.host if request.client else None
