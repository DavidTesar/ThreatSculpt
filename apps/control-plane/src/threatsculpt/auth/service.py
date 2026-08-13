"""Auth use cases: register, login, refresh, logout.

Everything that decides *whether* a credential is good lives here; the router
handles HTTP shape only.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatsculpt.audit.writer import record_audit
from threatsculpt.auth import accounts, verification
from threatsculpt.auth import refresh as refresh_tokens
from threatsculpt.auth.delivery import EmailSender
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
from threatsculpt.tenancy.credentials import MAX_LOGIN_CANDIDATES
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
    sender: EmailSender,
) -> AuthOutcome:
    """Create an org and its first ``owner`` user, then log them in.

    Registration is deliberately open: refusing it is how one party denies
    another a sign-up, which is what an earlier capacity check on unverified
    claims did. The address starts unproved instead, and an unproved address
    counts for nothing anywhere — see ``auth.accounts``.

    The registrant keeps the session this returns, because they are holding the
    browser that made the request. What they do not get until the address is
    proved is the ability to *log in* to it by password, which is the thing that
    would let a claim on somebody else's address matter.
    """
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

    issued = verification.issue_token(settings.email_verification_ttl_hours)
    users = ScopedRepository(session, scope, User)
    user = await users.create(
        email=str(payload.email),
        password_hash=passwords.hash_password(payload.password),
        full_name=payload.full_name,
        role=Role.OWNER.value,
        status=UserStatus.ACTIVE.value,
        **verification.pending_columns(issued),
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
    verification.dispatch(sender, email=user.email, org_slug=org.slug, issued=issued)
    return outcome


async def verify_email(
    session: AsyncSession,
    presented_token: str,
    facts: RequestFacts,
) -> User:
    """Turn a claim on an address into a proved account.

    Unknown, spent and expired tokens are one error: telling them apart is the
    only thing a caller holding a guessed value could learn. The capacity check
    lands here rather than at registration, because this is the moment a slot is
    actually taken.
    """
    user = await credentials.find_user_by_verification_hash(session, hash_token(presented_token))
    if user is None or verification.is_expired(user):
        raise verification.VerificationTokenInvalidError()

    scope = OrgScope.for_system(user.org_id)
    await bind_scope(session, scope)
    await accounts.assert_email_has_capacity(session, user.email)
    verified = await verification.mark_verified(session, scope, user)
    await record_audit(
        session,
        scope,
        AuditAction.AUTH_EMAIL_VERIFIED,
        target_type="user",
        target_id=verified.id,
        ip=facts.ip,
    )
    return verified


async def resend_verification(
    session: AsyncSession,
    settings: Settings,
    scope: OrgScope,
    user: User,
    org: Org,
    sender: EmailSender,
    facts: RequestFacts,
) -> None:
    """Re-issue the token for the caller's own unverified account.

    Scoped to the authenticated principal on purpose: an endpoint that resent to
    any address on request would be an open relay for anybody who wanted to
    aim this service's mail at a third party.
    """
    issued = await verification.replace_token(
        session, scope, user, settings.email_verification_ttl_hours
    )
    await record_audit(
        session,
        scope,
        AuditAction.AUTH_VERIFICATION_RESENT,
        target_type="user",
        target_id=user.id,
        ip=facts.ip,
    )
    verification.dispatch(sender, email=user.email, org_slug=org.slug, issued=issued)


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
    code, and the same body — and, per ``_verify_against_candidates``, the same
    fixed amount of Argon2 work, whatever state the account is in and however
    many accounts the address holds.

    One address may exist in several orgs (``users`` is unique on
    ``(org_id, email)``), so every candidate is verified against the row already
    in hand. **No candidate loop touches the database**: password verification
    and the lockout check are pure functions of rows already loaded, and the
    session's tenant scope is bound exactly once, for the winner. Binding per
    candidate is what used to turn a second candidate into a
    ``TenancyViolationError`` — a 500 on a correct password, an unauthenticated
    CRITICAL log, and an oracle for "this address exists in more than one org".

    ``session_factory`` is needed because a rejected login still has to *record*
    something: the request transaction is rolled back when the error propagates,
    which would take the attempt counter and the audit row with it. Failure
    bookkeeping therefore commits in its own transaction.
    """
    candidates = await credentials.find_login_candidates(
        session, str(payload.email), org_slug=payload.org_slug
    )
    attempt = _verify_against_candidates(payload.password, candidates)
    if attempt.matched is None and not candidates:
        raise InvalidCredentialsError()
    if attempt.matched is None:
        # Charged to the accounts the wrong password was actually presented
        # against, not to whichever row happened to sort first.
        for candidate in attempt.failed:
            await _record_failure(
                session_factory, OrgScope.for_user(candidate), candidate.id, settings, facts
            )
        for candidate in attempt.locked:
            await _record_attempt_while_locked(
                session_factory, OrgScope.for_user(candidate), candidate.id, facts
            )
        raise InvalidCredentialsError()
    matched = attempt.matched

    # The password was right for one of the candidates, so this is the account
    # holder rather than somebody guessing: the near-misses are not charged a
    # failure. Without that, one org's routine logins would lock out an
    # unrelated org that happens to share the address.
    scope = OrgScope.for_user(matched)
    await bind_scope(session, scope)

    org = await _load_org(session, matched)
    if org is None or org.status != OrgStatus.ACTIVE.value:
        raise AuthenticationError("This organisation is not active.")
    await _clear_failures(session, scope, matched)
    outcome = await _complete_login(session, settings, codec, matched, org, facts)
    await record_audit(
        session,
        scope,
        AuditAction.AUTH_LOGIN,
        target_type="user",
        target_id=matched.id,
        ip=facts.ip,
    )
    return outcome


@dataclass(frozen=True, slots=True)
class _LoginAttempt:
    """How one presented password fared against each candidate account."""

    matched: User | None
    failed: tuple[User, ...]
    locked: tuple[User, ...]


def _verify_against_candidates(password: str, candidates: Sequence[User]) -> _LoginAttempt:
    """Sort the candidates into matched, wrong-password, and locked-out.

    Pure: no database access, no scope binding.

    **Every login spends exactly ``MAX_LOGIN_CANDIDATES`` Argon2 verifications**,
    whatever the outcome and however many accounts the address actually has.
    One per candidate was not enough: the locked branch skipping its verification
    made a locked account answer in a fraction of the time of any other outcome,
    and one-per-candidate made the total linear in the number of orgs an address
    is verified in — which does not distinguish zero accounts from one, but for
    two or more counts them exactly. In the consultancy market this product sells
    into, that count reads as "how many of your tenants is this person a customer
    of", which is not a question an unauthenticated stopwatch should answer.

    The cost of a flat profile is that the padding is real work: every login pays
    the cap, not the candidate count. That is what bounds ``MAX_LOGIN_CANDIDATES``
    to a small number — see the note on it in ``tenancy.credentials``.
    """
    failed: list[User] = []
    locked: list[User] = []
    matched: User | None = None
    spent = 0

    for candidate in candidates[:MAX_LOGIN_CANDIDATES]:
        spent += 1  # exactly one verification per candidate, on every branch
        if accounts.is_locked(candidate):
            passwords.burn_dummy_verification()
            locked.append(candidate)
        elif matched is not None:
            # Already authenticated by an earlier candidate. The remaining rows
            # are neither tried nor charged a failure, but still cost their
            # verification so the total does not depend on which one matched.
            passwords.burn_dummy_verification()
        elif passwords.verify_password(password, candidate.password_hash):
            matched = candidate
        else:
            failed.append(candidate)

    for _ in range(MAX_LOGIN_CANDIDATES - spent):
        passwords.burn_dummy_verification()
    return _LoginAttempt(matched, tuple(failed), tuple(locked))


async def rotate_refresh(
    session: AsyncSession,
    session_factory: async_sessionmaker[AsyncSession],
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
        await _revoke_family_on_reuse(session_factory, scope, record.id, record.user_id, facts)
        raise AuthenticationError("Refresh token is invalid or expired.")

    if record.expires_at <= datetime.now(tz=UTC):
        raise AuthenticationError("Refresh token is invalid or expired.")

    users = ScopedRepository(session, scope, User)
    user = await users.get(record.user_id)
    if user is None or not user.is_active:
        raise AuthenticationError("Refresh token is invalid or expired.")
    if not user.is_verified:
        # The registration session is real but deliberately short-lived. A
        # session that renews itself for thirty days without the address ever
        # being proved is the durable half of an unverified claim, and the
        # holder can always clear it by verifying.
        raise verification.EmailNotVerifiedError()

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
        metadata={"revoked_count": revoked},
        ip=facts.ip,
    )
    return revoked > 0


async def _revoke_family_on_reuse(
    session_factory: async_sessionmaker[AsyncSession],
    scope: OrgScope,
    seed_id: UUID,
    user_id: UUID,
    facts: RequestFacts,
) -> int:
    """Kill the family and record the detection, then let the caller raise.

    Same reasoning as ``_record_failure``: the caller is about to raise
    ``AuthenticationError``, and ``api.dependencies.get_session`` rolls the
    request transaction back on any exception. Writing the revocation into that
    transaction meant the stolen token survived its own detection — the attacker
    kept a 30-day session and the ``auth.refresh_reuse_detected`` row the SOC
    watches for was discarded with it. Both writes therefore commit in their own
    transaction, before the raise.
    """
    async with scoped_session(session_factory, scope) as bookkeeping:
        revoked = await refresh_tokens.revoke_family(bookkeeping, scope, seed_id)
        await record_audit(
            bookkeeping,
            scope,
            AuditAction.AUTH_REFRESH_REUSE_DETECTED,
            target_type="user",
            target_id=user_id,
            metadata={"revoked_count": revoked},
            ip=facts.ip,
        )
    logger.warning(
        "refresh token reuse detected; family revoked",
        extra={"org_id": str(scope.org_id), "revoked_count": revoked},
    )
    return revoked


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


async def _record_attempt_while_locked(
    session_factory: async_sessionmaker[AsyncSession],
    scope: OrgScope,
    user_id: UUID,
    facts: RequestFacts,
) -> None:
    """Log an attempt against an already-locked account, without extending it.

    Two jobs. It is the signal a SOC wants — somebody is still guessing at an
    account that has already tripped its threshold — and it gives the locked
    branch the same one-transaction database cost as the wrong-password branch,
    so the response time no longer says which of the two happened. Deliberately
    does *not* touch ``locked_until``: a stranger who can extend a lockout for as
    long as they keep guessing has an indefinite denial of service.
    """
    async with scoped_session(session_factory, scope) as bookkeeping:
        await record_audit(
            bookkeeping,
            scope,
            AuditAction.AUTH_LOGIN_FAILED,
            target_type="user",
            target_id=user_id,
            metadata={"locked": True, "attempts": 0},
            ip=facts.ip,
        )


async def _clear_failures(session: AsyncSession, scope: OrgScope, user: User) -> None:
    if not user.failed_login_count and user.locked_until is None:
        return
    users = ScopedRepository(session, scope, User)
    await users.update(user, {"failed_login_count": 0, "locked_until": None})
