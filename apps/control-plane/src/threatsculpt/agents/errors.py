"""Errors raised while enrolling an agent."""

from __future__ import annotations

from threatsculpt.core.errors import AuthenticationError


class EnrollmentTokenInvalidError(AuthenticationError):
    """Unknown, expired, or already-used enrollment token.

    One error for all three so a caller cannot use the response to learn whether
    a token it guessed ever existed. The agent's reaction is identical in every
    case: it has no valid credential and must be re-issued one by an operator.
    """

    code = "enrollment_token_invalid"
    default_message = "The enrollment token is invalid, expired, or already used."
