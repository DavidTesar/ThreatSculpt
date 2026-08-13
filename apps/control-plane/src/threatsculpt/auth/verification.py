"""Proving control of an email address.

The state machine is three states and two transitions:

    unverified ──verify(token)──> verified
        │
        └──token expires──> unverified, and no longer verifiable

An unverified account is inert. It is excluded from the login candidate set (so
it can neither authenticate nor absorb another account's failed attempts), and
it does not occupy one of the address's slots (so claiming an address somebody
else owns takes nothing away from them). That is what makes registration safe to
leave open: an unproved claim buys the claimant nothing at all.

Token handling matches every other credential in this service — a random opaque
value with a namespace prefix, stored only as its SHA-256, shown once, and
compared by hash lookup rather than by anything a caller supplies.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.auth.delivery import EmailSender, VerificationMessage
from threatsculpt.core.errors import AuthenticationError, ConflictError
from threatsculpt.models.user import User
from threatsculpt.security.tokens import generate_opaque_token, hash_token
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope

logger = logging.getLogger(__name__)

VERIFICATION_TOKEN_PREFIX = "tsv_"  # noqa: S105 - a namespace prefix, not a credential


class VerificationTokenInvalidError(AuthenticationError):
    """Unknown, already used, or expired. One error for all three.

    Distinguishing them would tell a caller holding a guessed value whether they
    had guessed a real token, which is the only thing they could learn here.
    """

    code = "verification_token_invalid"
    default_message = "This verification link is invalid or has expired."


@dataclass(frozen=True, slots=True)
class IssuedVerification:
    """The plaintext token plus when it stops working. Plaintext exists only here."""

    token: str
    expires_at: datetime


def issue_token(ttl_hours: int) -> IssuedVerification:
    """Mint a verification token. Pure — the caller decides where it is stored."""
    return IssuedVerification(
        token=generate_opaque_token(VERIFICATION_TOKEN_PREFIX),
        expires_at=datetime.now(tz=UTC) + timedelta(hours=ttl_hours),
    )


def pending_columns(issued: IssuedVerification) -> dict[str, object]:
    """The row state for "claimed, not proved"."""
    return {
        "email_verified_at": None,
        "verification_token_hash": hash_token(issued.token),
        "verification_expires_at": issued.expires_at,
    }


def verified_columns() -> dict[str, object]:
    """The row state for "proved". The spent token is dropped, not kept."""
    return {
        "email_verified_at": datetime.now(tz=UTC),
        "verification_token_hash": None,
        "verification_expires_at": None,
    }


def is_expired(user: User, *, now: datetime | None = None) -> bool:
    moment = now or datetime.now(tz=UTC)
    return user.verification_expires_at is None or user.verification_expires_at <= moment


def dispatch(sender: EmailSender, *, email: str, org_slug: str, issued: IssuedVerification) -> None:
    """Hand the message to delivery. Never fails the caller.

    A sign-up that failed because a mail provider was down would convert
    somebody else's outage into a broken registration, and the account is
    entirely valid unverified — it just cannot be logged into yet.
    """
    try:
        sender.send_verification(
            VerificationMessage(email=email, token=issued.token, org_slug=org_slug)
        )
    except Exception:
        logger.exception(
            "verification message could not be handed to delivery",
            extra={"event": "verification_dispatch_failed", "org_slug": org_slug},
        )


async def mark_verified(session: AsyncSession, scope: OrgScope, user: User) -> User:
    """Complete the transition. Idempotent for an already-verified account."""
    if user.is_verified:
        raise ConflictError("This address has already been verified.", field="token")
    repository = ScopedRepository(session, scope, User)
    return await repository.update(user, verified_columns())


async def replace_token(
    session: AsyncSession, scope: OrgScope, user: User, ttl_hours: int
) -> IssuedVerification:
    """Issue a fresh token for an unverified account, invalidating the old one.

    Replacing rather than adding: one outstanding token per account means a
    token that leaked stops working as soon as another is requested, and it
    keeps the lookup key unique.
    """
    if user.is_verified:
        raise ConflictError("This address has already been verified.", field="email")
    issued = issue_token(ttl_hours)
    repository = ScopedRepository(session, scope, User)
    await repository.update(user, pending_columns(issued))
    return issued
