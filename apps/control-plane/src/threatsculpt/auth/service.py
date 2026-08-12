"""Auth use cases: register, login, refresh, logout.

Everything that decides *whether* a credential is good lives here; the router
handles HTTP shape only.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatsculpt.audit.writer import record_audit
from threatsculpt.auth import refresh as refresh_tokens
from threatsculpt.auth.schemas import LoginRequest, RegisterRequest
from threatsculpt.config import Settings
from threatsculpt.core.errors import (
    AuthenticationError,
    ConflictError,
    InvalidCredentialsError,
)
from threatsculpt.db.session import bind_scope, scoped_session
from threatsculpt.models.audit import AuditAction
from threatsculpt.models.org import Org, OrgPlan, OrgStatus
from threatsculpt.models.token import RefreshToken
from threatsculpt.models.user import Role, User, UserStatus
from threatsculpt.security import passwords
from threatsculpt.security.tokens import JwtCodec, hash_token
from threatsculpt.tenancy import credentials
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RequestFacts:
    """The bits of the HTTP request the auth flows legitimately need."""

    user_agent: str | None
    ip: str | None


@dataclass(frozen=True, slots=True)
class AuthOutcome:
    """A successful authentication: the principal plus both fresh credentials."""

    user: User
    org: Org
    access_token: str
    access_expires_at: datetime
    refresh_token: str
    scope: OrgScope


async def register(
    session: AsyncSession,
    settings: Settings,
    codec: JwtCodec,
    payload: RegisterRequest,
    facts: RequestFacts,
) -> AuthOutcome:
    """Create an org and its first ``owner`` user, then log them in."""
    org = Org(
        name=payload.org_name,
        slug=payload.org_slug,
        plan=OrgPlan.TRIAL.value,
        status=OrgStatus.ACTIVE.value,
    )
    session.add(org)
    try:
        await session.flush()
    except IntegrityError as exc:
        raise ConflictError("That organisation slug is already taken.", field="org_slug") from exc

    # The org now exists but has no user yet, so there is no principal to derive
    # a scope from. This is the one legitimate use of a system scope.
    scope = OrgScope.for_system(org.id)
    await bind_scope(session, scope)

    users = ScopedRepository(session, scope, User)
    user = await users.create(
        email=str(payload.email),
        password_hash=passwords.hash_password(payload.password),
        full_name=payload.full_name,
        role=Role.OWNER.value,
        status=UserStatus.ACTIVE.value,
    )

    outcome = await _complete_login(session, settings, codec, user, org, facts)
    await record_audit(
        session,
        outcome.scope,
        AuditAction.AUTH_REGISTER,
        target_type="org",
        target_id=org.id,
        metadata={"org_slug": org.slug, "email": user.email},
        ip=facts.ip,
    )
    return outcome


async def login(
    session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    codec: JwtCodec,
    payload: LoginRequest,
    facts: RequestFacts,
) -> AuthOutcome:
    """Verify a password and issue both tokens.

    Unknown email and wrong password produce the same exception, the same status
    code, and the same body. The unknown-email branch still spends one Argon2
    verification so the two paths cost the same wall-clock time.

    ``session_factory`` is needed because a rejected login still has to *record*
    something: the request transaction is rolled back when the error propagates,
    which would take the attempt counter and the audit row with it. Failure
    bookkeeping therefore commits in its own transaction.
    """
    candidates = await credentials.find_login_candidates(
        session, str(payload.email), org_slug=payload.org_slug
    )
    if not candidates:
        passwords.burn_dummy_verification()
        raise InvalidCredentialsError()

    for candidate in candidates:
        scope = OrgScope.for_user(candidate)
        await bind_scope(session, scope)
        if _is_locked(candidate):
            continue
        if passwords.verify_password(payload.password, candidate.password_hash):
            org = await _load_org(session, candidate)
            if org is None or org.status != OrgStatus.ACTIVE.value:
                raise AuthenticationError("This organisation is not active.")
            await _clear_failures(session, scope, candidate)
            outcome = await _complete_login(session, settings, codec, candidate, org, facts)
            await record_audit(
                session,
                scope,
                AuditAction.AUTH_LOGIN,
                target_type="user",
                target_id=candidate.id,
                ip=facts.ip,
            )
            return outcome
        await _record_failure(session_factory, scope, candidate.id, settings, facts)

    raise InvalidCredentialsError()


async def rotate_refresh(
    session: AsyncSession,
    settings: Settings,
    codec: JwtCodec,
    presented_token: str,
    scope_hint: OrgScope | None,
    facts: RequestFacts,
) -> AuthOutcome:
    """Exchange a refresh token for a new pair, or revoke the family on reuse."""
    record, scope = await _resolve_refresh_token(session, presented_token, scope_hint)
    if record is None or scope is None:
        raise AuthenticationError("Refresh token is invalid or expired.")

    if record.is_spent:
        revoked = await refresh_tokens.revoke_family(session, scope, record.id)
        await record_audit(
            session,
            scope,
            AuditAction.AUTH_REFRESH_REUSE_DETECTED,
            target_type="user",
            target_id=record.user_id,
            metadata={"tokens_revoked": revoked},
            ip=facts.ip,
        )
        logger.warning(
            "refresh token reuse detected; family revoked",
            extra={"org_id": str(scope.org_id), "tokens_revoked": revoked},
        )
        raise AuthenticationError("Refresh token is invalid or expired.")

    if record.expires_at <= datetime.now(tz=UTC):
        raise AuthenticationError("Refresh token is invalid or expired.")

    users = ScopedRepository(session, scope, User)
    user = await users.get(record.user_id)
    if user is None or not user.is_active:
        raise AuthenticationError("Refresh token is invalid or expired.")

    org = await _load_org(session, user)
    if org is None or org.status != OrgStatus.ACTIVE.value:
        raise AuthenticationError("This organisation is not active.")

    rotated = await refresh_tokens.rotate(
        session,
        scope,
        record,
        ttl_days=settings.refresh_token_ttl_days,
        user_agent=facts.user_agent,
        ip=facts.ip,
    )
    access_token, expires_at = codec.encode(user_id=user.id, org_id=user.org_id, role=user.role)
    await record_audit(
        session, scope, AuditAction.AUTH_REFRESH, target_type="user", target_id=user.id, ip=facts.ip
    )
    return AuthOutcome(
        user=user,
        org=org,
        access_token=access_token,
        access_expires_at=expires_at,
        refresh_token=rotated.token,
        scope=scope,
    )


async def logout(
    session: AsyncSession,
    presented_token: str | None,
    scope_hint: OrgScope | None,
    facts: RequestFacts,
) -> bool:
    """Revoke the presented token's whole family. Idempotent and always 200."""
    if not presented_token:
        return False
    record, scope = await _resolve_refresh_token(session, presented_token, scope_hint)
    if record is None or scope is None:
        return False
    revoked = await refresh_tokens.revoke_family(session, scope, record.id)
    await record_audit(
        session,
        scope,
        AuditAction.AUTH_LOGOUT,
        target_type="user",
        target_id=record.user_id,
        metadata={"tokens_revoked": revoked},
        ip=facts.ip,
    )
    return revoked > 0


async def _complete_login(
    session: AsyncSession,
    settings: Settings,
    codec: JwtCodec,
    user: User,
    org: Org,
    facts: RequestFacts,
) -> AuthOutcome:
    scope = OrgScope.for_user(user)
    await bind_scope(session, scope)
    users = ScopedRepository(session, scope, User)
    await users.update(user, {"last_login_at": datetime.now(tz=UTC)})

    issued = await refresh_tokens.issue(
        session,
        scope,
        user_id=user.id,
        ttl_days=settings.refresh_token_ttl_days,
        user_agent=facts.user_agent,
        ip=facts.ip,
    )
    access_token, expires_at = codec.encode(user_id=user.id, org_id=user.org_id, role=user.role)
    return AuthOutcome(
        user=user,
        org=org,
        access_token=access_token,
        access_expires_at=expires_at,
        refresh_token=issued.token,
        scope=scope,
    )


async def _resolve_refresh_token(
    session: AsyncSession, presented: str, scope_hint: OrgScope | None
) -> tuple[RefreshToken | None, OrgScope | None]:
    """Find the token row and the scope it belongs to.

    A refresh token is an opaque random value with no org in it, so the row must
    be located before a scope exists. When the caller also sent a valid access
    token the scope is already known and the lookup stays inside it; otherwise
    the row is found by its unique hash and the scope is derived from the row —
    never from anything the caller said.
    """
    if scope_hint is not None:
        record = await refresh_tokens.find_by_token(session, scope_hint, presented)
        return (record, scope_hint) if record is not None else (None, None)

    record = await credentials.find_refresh_token_by_hash(session, hash_token(presented))
    if record is None:
        return None, None
    scope = OrgScope.for_system(record.org_id)
    await bind_scope(session, scope)
    return record, scope


async def _load_org(session: AsyncSession, user: User) -> Org | None:
    return await session.get(Org, user.org_id)


def _is_locked(user: User) -> bool:
    return user.locked_until is not None and user.locked_until > datetime.now(tz=UTC)


async def _record_failure(
    session_factory: async_sessionmaker[AsyncSession],
    scope: OrgScope,
    user_id: UUID,
    settings: Settings,
    facts: RequestFacts,
) -> None:
    """Count a failed attempt and lock the account once the threshold is hit.

    Runs in its own committed transaction: the caller is about to raise, and a
    lockout counter that a rolled-back request silently discards would let an
    attacker guess forever.

    A locked account still returns the same generic error, so lockout state is
    not observable to an attacker probing for valid addresses.
    """
    async with scoped_session(session_factory, scope) as bookkeeping:
        users = ScopedRepository(bookkeeping, scope, User)
        user = await users.get(user_id)
        if user is None:  # deleted between the lookup and now
            return
        attempts = (user.failed_login_count or 0) + 1
        changes: dict[str, object] = {"failed_login_count": attempts}
        if attempts >= settings.max_failed_logins:
            changes["locked_until"] = datetime.now(tz=UTC) + timedelta(
                minutes=settings.login_lockout_minutes
            )
            changes["failed_login_count"] = 0
        await users.update(user, changes)
        await record_audit(
            bookkeeping,
            scope,
            AuditAction.AUTH_LOGIN_FAILED,
            target_type="user",
            target_id=user_id,
            metadata={"attempts": attempts, "locked": "locked_until" in changes},
            ip=facts.ip,
        )


async def _clear_failures(session: AsyncSession, scope: OrgScope, user: User) -> None:
    if not user.failed_login_count and user.locked_until is None:
        return
    users = ScopedRepository(session, scope, User)
    await users.update(user, {"failed_login_count": 0, "locked_until": None})
