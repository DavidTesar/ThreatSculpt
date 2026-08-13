"""The one place that reads a tenant table without an ``OrgScope``.

Authentication is a bootstrap problem: to know which org a caller belongs to,
something has to find the caller first, and the row that identifies them lives
in a tenant table. Rather than leaving RLS permissive when the GUC is unset —
which would make every unscoped bug a silent cross-tenant read — the exception
is made explicit and narrow:

* exactly five functions, all in this module;
* SELECT only, enforced by the guard (see ``_assert_credential_lookup_is_a_select``);
* the predicate is always equality on a SHA-256 hash or an email, never a
  caller-controlled ``org_id``;
* the matching RLS policies are ``FOR SELECT`` only and require the
  ``threatsculpt.authn`` GUC, which is set here and nowhere else.

Every caller must immediately bind an ``OrgScope`` from the row it found. The
returned object is a credential match, not an authorisation.
"""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import Select, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.models.agent import Agent, AgentStatus
from threatsculpt.models.token import RefreshToken
from threatsculpt.models.user import User, UserStatus
from threatsculpt.tenancy.guard import CREDENTIAL_LOOKUP_OPTION

AUTHN_GUC = "threatsculpt.authn"

#: Bound so a single email shared across many orgs cannot be used to force an
#: unbounded number of Argon2 verifications in one request.
#:
#: The same number caps how many active accounts may hold one address — see
#: ``auth.accounts``. Enforcing it at account creation is what stops this
#: ``LIMIT`` from silently dropping a legitimate account past the window.
MAX_LOGIN_CANDIDATES = 10

_ENABLE_AUTHN_SQL = text("SELECT set_config(:guc, 'on', true)")
_DISABLE_AUTHN_SQL = text("SELECT set_config(:guc, '', true)")


async def _enable_authn_window(session: AsyncSession) -> None:
    await session.execute(_ENABLE_AUTHN_SQL, {"guc": AUTHN_GUC})


async def _disable_authn_window(session: AsyncSession) -> None:
    await session.execute(_DISABLE_AUTHN_SQL, {"guc": AUTHN_GUC})


def _as_credential_lookup[StatementT: Select](statement: StatementT) -> StatementT:
    return statement.execution_options(**{CREDENTIAL_LOOKUP_OPTION: True})


async def find_login_candidates(
    session: AsyncSession, email: str, *, org_slug: str | None = None
) -> Sequence[User]:
    """Active, **verified** users matching ``email``, optionally narrowed to one org.

    Returns a sequence because ``users`` is unique on ``(org_id, email)``, not on
    ``email`` — the same address can legitimately exist in two customers. The
    caller verifies the password against each candidate, so an extra candidate
    grants nothing without the password.

    The verification predicate is load-bearing rather than cosmetic. Registration
    is open, so anyone can create a row claiming any address; if such a row were a
    candidate, a stranger's unproved claim would sit in the same candidate set as
    the address's real owner, absorbing failed attempts and reaching lockout on
    an account nobody involved controls. An unproved claim is not a credential
    and does not appear here.
    """
    from threatsculpt.models.org import Org  # local import: avoids a cycle at module load

    statement = (
        select(User)
        .where(
            User.email == email,
            User.status == UserStatus.ACTIVE.value,
            User.email_verified_at.is_not(None),
        )
        .order_by(User.created_at)
        .limit(MAX_LOGIN_CANDIDATES)
    )
    if org_slug is not None:
        statement = statement.join(Org, Org.id == User.org_id).where(Org.slug == org_slug)

    await _enable_authn_window(session)
    try:
        result = await session.execute(_as_credential_lookup(statement))
        return result.scalars().all()
    finally:
        await _disable_authn_window(session)


async def find_user_by_id(session: AsyncSession, user_id: object) -> User | None:
    """Resolve a user by primary key, for the JWT path.

    The token already carries a signed ``org``; the caller binds the scope from
    the token and re-checks that this row's ``org_id`` agrees, so a token whose
    ``org`` claim disagrees with the database matches nothing.
    """
    statement = select(User).where(User.id == user_id).limit(1)
    await _enable_authn_window(session)
    try:
        result = await session.execute(_as_credential_lookup(statement))
        return result.scalar_one_or_none()
    finally:
        await _disable_authn_window(session)


async def find_refresh_token_by_hash(session: AsyncSession, token_hash: str) -> RefreshToken | None:
    """Resolve a refresh token row from the SHA-256 of the presented cookie.

    A refresh token is an opaque random value carrying no org, so the row has to
    be found before a scope can exist. ``token_hash`` is UNIQUE, so this matches
    at most one row, and the caller derives its scope from that row — never from
    anything the caller supplied.
    """
    statement = select(RefreshToken).where(RefreshToken.token_hash == token_hash).limit(1)
    await _enable_authn_window(session)
    try:
        result = await session.execute(_as_credential_lookup(statement))
        return result.scalar_one_or_none()
    finally:
        await _disable_authn_window(session)


async def find_user_by_verification_hash(session: AsyncSession, token_hash: str) -> User | None:
    """Resolve the account a verification token belongs to.

    Same bootstrap problem as a refresh token: the value is opaque and carries no
    org, so the row has to be found before a scope can exist. The column is
    UNIQUE where non-NULL, so this matches at most one row, and the caller
    derives its scope from that row. Expiry is checked by the caller against the
    row it gets back, not here, so that an expired token and an unknown one take
    the same path.
    """
    statement = (
        select(User)
        .where(User.verification_token_hash == token_hash, User.status == UserStatus.ACTIVE.value)
        .limit(1)
    )
    await _enable_authn_window(session)
    try:
        result = await session.execute(_as_credential_lookup(statement))
        return result.scalar_one_or_none()
    finally:
        await _disable_authn_window(session)


async def find_agent_by_key_hash(session: AsyncSession, api_key_hash: str) -> Agent | None:
    """Resolve an agent from the SHA-256 of its presented API key.

    ``api_key_hash`` is UNIQUE, so this is a single-row index lookup. Revoked
    agents are excluded here rather than at the caller, so a revoked key cannot
    authenticate by way of a caller forgetting the status check.
    """
    statement = (
        select(Agent)
        .where(Agent.api_key_hash == api_key_hash, Agent.status == AgentStatus.ACTIVE.value)
        .limit(1)
    )
    await _enable_authn_window(session)
    try:
        result = await session.execute(_as_credential_lookup(statement))
        return result.scalar_one_or_none()
    finally:
        await _disable_authn_window(session)
