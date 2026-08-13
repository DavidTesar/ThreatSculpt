"""Account-level state, and the backstop on how many accounts an address holds.

``users`` is unique on ``(org_id, email)``, so one address may legitimately hold
an account in several orgs — normal for the MSSP and consultancy market. Login
therefore verifies the presented password against every account matching the
address, and ``credentials.find_login_candidates`` bounds that set so a single
address cannot force an unbounded number of Argon2 verifications in one request.

What makes that bound safe is that **only verified accounts are counted at all**.
An account whose address has never been proved is not a login candidate and does
not occupy a slot, so a stranger registering somebody else's address takes
nothing from them: not a slot, not a place in the candidate window, and not the
ability to absorb failed attempts on their behalf. See ``auth.verification``.

The cap below is a backstop against a genuine pile-up of *proved* accounts on one
address, not the control that stops squatting. An earlier revision had it the
other way round — counting unverified claims — and that turned a lockout attack
into a denial of onboarding: ten unauthenticated registrations against a
prospect's address and its real owner met a 409 they had not caused, could not
explain, and had no way to clear.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.core.errors import ConflictError
from threatsculpt.models.user import User
from threatsculpt.tenancy import credentials
from threatsculpt.tenancy.credentials import MAX_LOGIN_CANDIDATES


def is_locked(user: User) -> bool:
    """True while a failed-attempt lockout is still in force.

    One definition, shared by the login path and by the operator tooling that
    has to clear it — a second copy that disagreed would let an account look
    unlocked to an admin while still refusing its owner.
    """
    return user.locked_until is not None and user.locked_until > datetime.now(tz=UTC)


async def count_verified_accounts(session: AsyncSession, email: str) -> int:
    """Verified accounts holding ``email``, across all orgs, capped at the window.

    A credential lookup, so it runs unscoped by design — see
    ``tenancy.credentials``. The count saturates at ``MAX_LOGIN_CANDIDATES``,
    which is all a capacity check needs to know.
    """
    return len(await credentials.find_login_candidates(session, email))


async def assert_email_has_capacity(session: AsyncSession, email: str) -> None:
    """Refuse to *verify* another account for ``email`` once the window is full.

    Called when a claim is being turned into a real account, never when one is
    merely being made: registration must stay open, because refusing it is how
    an attacker denies somebody else a sign-up. Reaching this limit takes
    ``MAX_LOGIN_CANDIDATES`` separate proofs of control of the same mailbox, so
    the party who hits it is the party who owns the address.
    """
    if await count_verified_accounts(session, email) >= MAX_LOGIN_CANDIDATES:
        raise ConflictError(
            "That email address has already been verified for the maximum number of organisations.",
            field="email",
        )
