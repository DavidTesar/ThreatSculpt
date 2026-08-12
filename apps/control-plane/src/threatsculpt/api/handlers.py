"""Global exception handlers.

Nothing that reaches a client is derived from an exception's text. A
``ProgrammingError`` from psycopg carries table names, column names and often
the offending literal; a stack trace carries file paths and library versions.
Both are logged, neither is serialised.
"""

from __future__ import annotations

import logging
from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from threatsculpt.core.envelope import error_payload
from threatsculpt.core.errors import AppError, RateLimitedError, TenancyViolationError

logger = logging.getLogger(__name__)

GENERIC_INTERNAL_MESSAGE = "An unexpected error occurred."

_STATUS_CODES: dict[int, str] = {
    HTTPStatus.BAD_REQUEST: "validation_error",
    HTTPStatus.UNAUTHORIZED: "unauthenticated",
    HTTPStatus.FORBIDDEN: "forbidden",
    HTTPStatus.NOT_FOUND: "not_found",
    HTTPStatus.METHOD_NOT_ALLOWED: "method_not_allowed",
    HTTPStatus.CONFLICT: "conflict",
    HTTPStatus.UNPROCESSABLE_ENTITY: "unprocessable",
    HTTPStatus.TOO_MANY_REQUESTS: "rate_limited",
}


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(TenancyViolationError, _handle_tenancy_violation)
    app.add_exception_handler(AppError, _handle_app_error)
    app.add_exception_handler(RequestValidationError, _handle_request_validation)
    app.add_exception_handler(StarletteHTTPException, _handle_http_exception)
    app.add_exception_handler(SQLAlchemyError, _handle_database_error)
    app.add_exception_handler(Exception, _handle_unexpected)


async def _handle_tenancy_violation(request: Request, exc: Exception) -> JSONResponse:
    """A tenant table was reached unscoped. Loud in logs, generic on the wire."""
    logger.critical(
        "tenancy violation blocked",
        exc_info=exc,
        extra={"path": request.url.path, "event": "tenancy_violation"},
    )
    return _internal_error_response()


async def _handle_app_error(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, AppError)
    if exc.status_code >= HTTPStatus.INTERNAL_SERVER_ERROR:
        logger.error("application error", exc_info=exc, extra={"path": request.url.path})
        return _internal_error_response()

    logger.info(
        "request rejected",
        extra={"path": request.url.path, "code": exc.code, "status": exc.status_code},
    )
    headers: dict[str, str] = {}
    if isinstance(exc, RateLimitedError):
        headers["Retry-After"] = str(exc.retry_after_seconds)
    return JSONResponse(
        status_code=exc.status_code,
        content=error_payload(exc.code, exc.message, exc.field),
        headers=headers or None,
    )


async def _handle_request_validation(request: Request, exc: Exception) -> JSONResponse:
    """Pydantic rejections become 400 with the first offending field named.

    The field path is echoed; the submitted value is not, because for
    ``/auth/login`` that value is a password.
    """
    assert isinstance(exc, RequestValidationError)
    first = exc.errors()[0] if exc.errors() else None
    field = _field_path(first) if first else None
    message = (
        str(first.get("msg", "Invalid value.")) if first else "The request payload is invalid."
    )
    return JSONResponse(
        status_code=HTTPStatus.BAD_REQUEST,
        content=error_payload("validation_error", message, field),
    )


def _field_path(error: dict[str, object]) -> str | None:
    location = error.get("loc")
    if not isinstance(location, (list, tuple)):
        return None
    parts = [str(part) for part in location if part not in ("body", "query", "path")]
    return ".".join(parts) or None


async def _handle_http_exception(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)
    code = _STATUS_CODES.get(exc.status_code, "error")
    detail = exc.detail if isinstance(exc.detail, str) else "Request could not be completed."
    if exc.status_code >= HTTPStatus.INTERNAL_SERVER_ERROR:
        logger.error("http error", exc_info=exc, extra={"path": request.url.path})
        return _internal_error_response()
    return JSONResponse(
        status_code=exc.status_code,
        content=error_payload(code, detail),
        headers=getattr(exc, "headers", None),
    )


async def _handle_database_error(request: Request, exc: Exception) -> JSONResponse:
    """Database messages never leave the process."""
    logger.error(
        "database error", exc_info=exc, extra={"path": request.url.path, "event": "db_error"}
    )
    return _internal_error_response()


async def _handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("unhandled exception", extra={"path": request.url.path})
    return _internal_error_response()


def _internal_error_response() -> JSONResponse:
    return JSONResponse(
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        content=error_payload("internal_error", GENERIC_INTERNAL_MESSAGE),
    )
