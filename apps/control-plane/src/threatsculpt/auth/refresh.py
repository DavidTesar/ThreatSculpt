"""Refresh-token issue, rotation, and family revocation.

Rotation means every use of a refresh token mints a new one and marks the old
one spent. That turns theft into something detectable: if the attacker uses the
stolen token the real user's next refresh presents a spent token, and if the
user goes first the attacker's does. Either way a spent token is presented, and
that revokes the whole family — logging everyone out, which is the correct
outcome when a credential is known to have leaked.

Family membership is the chain linked by ``replaced_by``. It is walked with a
single recursive CTE in both directions, with the SQL-standard ``CYCLE`` clause
guarding against a chain that loops.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.models.token import RefreshToken
from threatsculpt.security.tokens import generate_opaque_token, hash_token
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope

logger = logging.getLogger(__name__)

REFRESH_TOKEN_PREFIX = "tsr_"  # noqa: S105 - a namespace prefix, not a credential

#: Both directions of the chain in one pass: a row is family if it is the parent
#: of a member (``r.id = f.replaced_by``) or its child (``r.replaced_by = f.id``).
_FAMILY_SQL = text(
    """
    WITH RECURSIVE family(id, replaced_by) AS (
        SELECT id, replaced_by FROM refresh_tokens
         WHERE id = :seed AND org_id = :org_id
        UNION ALL
        SELECT r.id, r.replaced_by
          FROM refresh_tokens r
          JOIN family f ON (r.id = f.replaced_by OR r.replaced_by = f.id)
         WHERE r.org_id = :org_id
    ) CYCLE id SET is_cycle USING path
    SELECT DISTINCT id FROM family
    """
)


class IssuedRefreshToken:
    """The plaintext token plus its persisted row. Plaintext exists only here."""

    __slots__ = ("record", "token")

    def __init__(self, token: str, record: RefreshToken) -> None:
        self.token = token
        self.record = record


async def issue(
    session: AsyncSession,
    scope: OrgScope,
    *,
    user_id: UUID,
    ttl_days: int,
    user_agent: str | None,
    ip: str | None,
) -> IssuedRefreshToken:
    """Mint a new refresh token and store only its SHA-256."""
    token = generate_opaque_token(REFRESH_TOKEN_PREFIX)
    repository = ScopedRepository(session, scope, RefreshToken)
    record = await repository.create(
        user_id=user_id,
        token_hash=hash_token(token),
        expires_at=datetime.now(tz=UTC) + timedelta(days=ttl_days),
        user_agent=(user_agent or None),
        ip=ip,
    )
    return IssuedRefreshToken(token=token, record=record)


async def find_by_token(session: AsyncSession, scope: OrgScope, token: str) -> RefreshToken | None:
    repository = ScopedRepository(session, scope, RefreshToken)
    return await repository.find_one(RefreshToken.token_hash == hash_token(token))


async def rotate(
    session: AsyncSession,
    scope: OrgScope,
    current: RefreshToken,
    *,
    ttl_days: int,
    user_agent: str | None,
    ip: str | None,
) -> IssuedRefreshToken:
    """Replace ``current`` with a fresh token and link the two."""
    issued = await issue(
        session,
        scope,
        user_id=current.user_id,
        ttl_days=ttl_days,
        user_agent=user_agent,
        ip=ip,
    )
    repository = ScopedRepository(session, scope, RefreshToken)
    await repository.update(
        current, {"replaced_by": issued.record.id, "revoked_at": datetime.now(tz=UTC)}
    )
    return issued


async def revoke_family(session: AsyncSession, scope: OrgScope, seed_id: UUID) -> int:
    """Revoke every token in ``seed_id``'s chain. Returns the number revoked."""
    ids = await family_ids(session, scope, seed_id)
    if not ids:
        return 0
    repository = ScopedRepository(session, scope, RefreshToken)
    return await repository.update_where(
        {"revoked_at": datetime.now(tz=UTC)},
        RefreshToken.id.in_(ids),
        RefreshToken.revoked_at.is_(None),
    )


async def family_ids(session: AsyncSession, scope: OrgScope, seed_id: UUID) -> list[UUID]:
    """Ids of every token linked to ``seed_id``, in either direction.

    The ``org_id`` predicate appears in both the anchor and the recursive term,
    so the walk cannot leave the scope's org even if a row somehow pointed
    across one.
    """
    result = await session.execute(_FAMILY_SQL, {"seed": seed_id, "org_id": scope.org_id})
    return [row[0] for row in result.all()]


async def revoke_all_for_user(session: AsyncSession, scope: OrgScope, user_id: UUID) -> int:
    """Revoke every live token for a user — used by logout-everywhere paths."""
    repository = ScopedRepository(session, scope, RefreshToken)
    return await repository.update_where(
        {"revoked_at": datetime.now(tz=UTC)},
        RefreshToken.user_id == user_id,
        RefreshToken.revoked_at.is_(None),
    )
