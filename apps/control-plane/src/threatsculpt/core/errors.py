"""Application error hierarchy.

Every error that reaches a client is one of these: a stable machine-readable
``code``, a message written for a human operator, and an optional ``field``.
Nothing else is ever serialised — no exception text, no driver message, no
stack trace. Unhandled exceptions become a generic ``internal_error``.
"""

from __future__ import annotations

from http import HTTPStatus


class AppError(Exception):
    """Base class for errors that are safe to render to a caller."""

    status_code: int = HTTPStatus.INTERNAL_SERVER_ERROR
    code: str = "internal_error"
    default_message: str = "An unexpected error occurred."

    def __init__(
        self,
        message: str | None = None,
        *,
        field: str | None = None,
        code: str | None = None,
    ) -> None:
        self.message = message or self.default_message
        self.field = field
        if code is not None:
            self.code = code
        super().__init__(self.message)


class AuthenticationError(AppError):
    status_code = HTTPStatus.UNAUTHORIZED
    code = "unauthenticated"
    default_message = "Authentication is required."


class InvalidCredentialsError(AuthenticationError):
    code = "invalid_credentials"
    default_message = "Invalid email or password."


class PermissionDeniedError(AppError):
    status_code = HTTPStatus.FORBIDDEN
    code = "forbidden"
    default_message = "You do not have permission to perform this action."


class NotFoundError(AppError):
    """Also used for cross-tenant access.

    ``docs/API.md``: a cross-tenant access attempt returns 404, never 403 — a 403
    would confirm the resource exists, which is an information leak.
    """

    status_code = HTTPStatus.NOT_FOUND
    code = "not_found"
    default_message = "Resource not found."


class ConflictError(AppError):
    status_code = HTTPStatus.CONFLICT
    code = "conflict"
    default_message = "The request conflicts with the current state."


class ValidationError(AppError):
    status_code = HTTPStatus.BAD_REQUEST
    code = "validation_error"
    default_message = "The request payload is invalid."


class SemanticValidationError(AppError):
    """Syntactically valid, semantically rejected — 422 per docs/API.md."""

    status_code = HTTPStatus.UNPROCESSABLE_ENTITY
    code = "unprocessable"
    default_message = "The request could not be processed."


class RateLimitedError(AppError):
    status_code = HTTPStatus.TOO_MANY_REQUESTS
    code = "rate_limited"
    default_message = "Too many requests. Try again shortly."

    def __init__(self, message: str | None = None, *, retry_after_seconds: int = 60) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class TenancyViolationError(AppError):
    """A tenant table was reached without an ``OrgScope``.

    This is a programming error, not a client error. It is never rendered as
    itself: the handler converts it to a generic 500 and logs it at CRITICAL,
    because a code path that can query tenant data unscoped is the exact defect
    class this service is built to prevent.
    """

    status_code = HTTPStatus.INTERNAL_SERVER_ERROR
    code = "internal_error"
    default_message = "An unexpected error occurred."
