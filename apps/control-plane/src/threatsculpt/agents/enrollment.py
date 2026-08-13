"""Trading a one-time enrollment token for a permanent API key.

The single-use guarantee is the whole point of this module, and it is enforced by
one conditional UPDATE:

    UPDATE enrollment_tokens SET used_at = now()
     WHERE token_hash = :hash AND used_at IS NULL AND expires_at > now()
    RETURNING id, org_id

docs/AGENT-PROTOCOL.md §1 spells out why it must be this and not a SELECT
followed by an UPDATE: two agents starting with the same token would both read
``used_at IS NULL`` and both enrol. Here the row lock serialises them, the loser
re-evaluates the WHERE clause against the committed row, and matches nothing.
Migration 0004 repeats the same conditions in the RLS policy, so the rule holds
even if this statement were ever rewritten carelessly.

The key itself is generated here, returned to the caller exactly once, and stored
only as a SHA-256 digest plus an 8-character display prefix. There is no code
path that can retrieve it again, which is what makes "shown once" true rather
than merely stated.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.agents.errors import EnrollmentTokenInvalidError
from threatsculpt.models.agent import Agent, AgentStatus
from threatsculpt.models.token import EnrollmentToken
from threatsculpt.security.tokens import (
    AGENT_KEY_PREFIX,
    ENROLLMENT_TOKEN_PREFIX,
    generate_opaque_token,
    hash_token,
    key_prefix_of,
)
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope

logger = logging.getLogger(__name__)

#: docs/DATA-MODEL.md — enrollment tokens expire in one hour.
ENROLLMENT_TOKEN_TTL = timedelta(hours=1)

#: Set only by ``consume_enrollment_token``, only around the statement below.
#: Migration 0004 documents the policies it unlocks.
ENROLL_GUC = "threatsculpt.enroll"

_ENABLE_ENROLL_SQL = text("SELECT set_config(:guc, 'on', true)")
_DISABLE_ENROLL_SQL = text("SELECT set_config(:guc, '', true)")

#: The conditional consume. Raw SQL because it runs before any ``OrgScope``
#: exists — the row is what *tells* us which org the caller belongs to.
_CONSUME_SQL = text(
    """
    UPDATE enrollment_tokens
       SET used_at = now(),
           updated_at = now()
     WHERE token_hash = :token_hash
       AND used_at IS NULL
       AND expires_at > now()
    RETURNING id, org_id
    """
)


@dataclass(frozen=True, slots=True)
class ConsumedToken:
    """The enrollment token that was just spent, and the org it belonged to."""

    token_id: UUID
    org_id: UUID


@dataclass(frozen=True, slots=True)
class IssuedEnrollmentToken:
    """A freshly minted token. ``plaintext`` is never persisted anywhere."""

    token_id: UUID
    plaintext: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class EnrolledAgent:
    """A new agent and its API key. The key exists in this object and nowhere else."""

    agent: Agent
    api_key: str


async def issue_enrollment_token(
    session: AsyncSession, scope: OrgScope, *, created_by_user_id: UUID | None
) -> IssuedEnrollmentToken:
    """Mint a token for an operator to configure on an agent host."""
    plaintext = generate_opaque_token(ENROLLMENT_TOKEN_PREFIX)
    expires_at = datetime.now(tz=UTC) + ENROLLMENT_TOKEN_TTL
    repository = ScopedRepository(session, scope, EnrollmentToken)
    row = await repository.create(
        token_hash=hash_token(plaintext),
        expires_at=expires_at,
        created_by_user_id=created_by_user_id,
    )
    return IssuedEnrollmentToken(token_id=row.id, plaintext=plaintext, expires_at=expires_at)


async def consume_enrollment_token(session: AsyncSession, presented: str) -> ConsumedToken:
    """Spend the token, or refuse. Exactly one caller can win for a given token."""
    await session.execute(_ENABLE_ENROLL_SQL, {"guc": ENROLL_GUC})
    try:
        result = await session.execute(_CONSUME_SQL, {"token_hash": hash_token(presented)})
        row = result.one_or_none()
    finally:
        # Closed even on failure: the window must not stay open for whatever the
        # request does next.
        await session.execute(_DISABLE_ENROLL_SQL, {"guc": ENROLL_GUC})

    if row is None:
        raise EnrollmentTokenInvalidError()
    return ConsumedToken(token_id=row.id, org_id=row.org_id)


async def enroll_agent(
    session: AsyncSession,
    scope: OrgScope,
    consumed: ConsumedToken,
    *,
    name: str,
    version: str | None,
    allowlist: tuple[str, ...],
) -> EnrolledAgent:
    """Create the agent row for a token that has already been spent.

    Takes the ``ConsumedToken`` rather than the token string so this cannot be
    called on a token nobody consumed — the type is the proof that step happened.
    """
    api_key = generate_opaque_token(AGENT_KEY_PREFIX)
    agents = ScopedRepository(session, scope, Agent)
    agent = await agents.create(
        name=name,
        api_key_hash=hash_token(api_key),
        key_prefix=key_prefix_of(api_key),
        status=AgentStatus.ACTIVE.value,
        version=version,
        allowlist=list(allowlist),
    )

    tokens = ScopedRepository(session, scope, EnrollmentToken)
    await tokens.update_where(
        {"used_by_agent_id": agent.id}, EnrollmentToken.id == consumed.token_id
    )
    logger.info(
        "agent enrolled",
        extra={
            "org_id": str(scope.org_id),
            "agent_id": str(agent.id),
            # The display prefix, never the key.
            "key_prefix": agent.key_prefix,
        },
    )
    return EnrolledAgent(agent=agent, api_key=api_key)
