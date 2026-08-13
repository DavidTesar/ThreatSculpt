"""Errors specific to the scan lifecycle.

Each carries the stable ``code`` docs/API.md promises callers, so the agent and
the dashboard can branch on the code rather than on message text.
"""

from __future__ import annotations

from http import HTTPStatus

from threatsculpt.core.errors import AppError


class NetworkNotAuthorizedError(AppError):
    """The scan target is not inside a registered, authorized network.

    422 rather than 403: the request is well-formed and the caller is permitted
    to create scans, the *target* is what the service refuses.
    """

    status_code = HTTPStatus.UNPROCESSABLE_ENTITY
    code = "network_not_authorized"
    default_message = "Scans require the network to be marked authorized."

    def __init__(self, message: str | None = None, *, field: str | None = "network_id") -> None:
        super().__init__(message, field=field)


class JobNotClaimableError(AppError):
    """The job is not this agent's to act on any more.

    docs/AGENT-PROTOCOL.md §6: 409 means the lease expired or the job was
    reassigned, and the agent should drop it and re-poll.
    """

    status_code = HTTPStatus.CONFLICT
    code = "job_not_claimable"
    default_message = "This job is no longer claimable."


class PayloadTooLargeError(AppError):
    """The submitted result batch exceeded the cap in docs/AGENT-PROTOCOL.md §5."""

    status_code = HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    code = "payload_too_large"
    default_message = "Result payloads are capped; submit the scan in smaller batches."
