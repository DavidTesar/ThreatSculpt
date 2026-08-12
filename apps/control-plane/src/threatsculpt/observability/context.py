"""Per-request correlation context.

A contextvar rather than a request attribute so that log records emitted deep in
the call stack (repositories, the audit writer) can carry the request id without
threading it through every signature.
"""

from __future__ import annotations

from contextvars import ContextVar, Token
from uuid import uuid4

REQUEST_ID_HEADER = "X-Request-ID"

_request_id: ContextVar[str | None] = ContextVar("threatsculpt_request_id", default=None)


def new_request_id() -> str:
    return uuid4().hex


def bind_request_id(request_id: str) -> Token[str | None]:
    return _request_id.set(request_id)


def reset_request_id(token: Token[str | None]) -> None:
    _request_id.reset(token)


def current_request_id() -> str | None:
    return _request_id.get()
