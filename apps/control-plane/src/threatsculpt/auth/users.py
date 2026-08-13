"""User-management use cases: invite, update, deactivate, change password.

The rules that are easy to get wrong live here rather than in the route, so a
second endpoint cannot reimplement them differently:

* **An org always keeps at least one active owner.** Demoting, disabling or
  deleting the last one is refused. Without it a single PATCH leaves an org with
  nobody who can administer it, and no self-service way back.
* **Nobody may act on a principal who outranks them, and nobody may promote
  themselves.** An admin who could set their own role to ``owner``, or reset an
  owner's password, has the owner role in everything but name.
* **Every credential change ends the target's sessions.** A password that has
  been changed because it leaked is not changed until the refresh tokens minted
  with it are dead.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.auth import accounts, verification
from threatsculpt.auth import refresh as refresh_tokens
from threatsculpt.auth.delivery import EmailSender
from threatsculpt.core.errors import (
    ConflictError,
    InvalidCredentialsError,
    PermissionDeniedError,
)
from threatsculpt.models.user import ROLE_RANK, Role, User, UserStatus
from threatsculpt.security import passwords
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope

#: 22 URL-safe characters — comfortably past ``MIN_PASSWORD_LENGTH`` and far
#: past anything worth guessing.
_TEMPORARY_PASSWORD_BYTES = 16


@dataclass(frozen=True, slots=True)
class PasswordReset:
    """The plaintext temporary password plus what it cost the target."""

    user: User
    temporary_password: str
    sessions_revoked: int


def _repository(session: AsyncSession, scope: OrgScope) -> ScopedRepository[User]:
    return ScopedRepository(session, scope, User)


def assert_may_act_on(actor: User, target: User) -> None:
    """Refuse an administrative action against somebody who outranks the actor.

    Peers may administer each other — that is what an admin tier is for, and the
    alternative leaves a compromised admin account that no other admin can
    disable. What must not happen is an admin reaching *up*: resetting an
    owner's password would hand them the owner role in everything but name.
    """
    if actor.id == target.id:
        return
    if ROLE_RANK.get(actor.role, -1) < ROLE_RANK.get(target.role, -1):
        raise PermissionDeniedError("You cannot administer a user above your own role.")


def assert_may_grant(actor: User, role: str) -> None:
    """Refuse to hand out a role the actor does not itself hold."""
    if ROLE_RANK.get(actor.role, -1) < ROLE_RANK[role]:
        raise PermissionDeniedError("You cannot grant a role above your own.")


async def count_active_owners(session: AsyncSession, scope: OrgScope) -> int:
    return await _repository(session, scope).count(
        User.role == Role.OWNER.value, User.status == UserStatus.ACTIVE.value
    )


async def assert_not_last_owner(session: AsyncSession, scope: OrgScope, target: User) -> None:
    """An org that has lost its last active owner cannot be recovered in-product."""
    if target.role != Role.OWNER.value or target.status != UserStatus.ACTIVE.value:
        return
    if await count_active_owners(session, scope) <= 1:
        raise ConflictError(
            "This is the organisation's last owner; promote another owner first.",
            field="role",
        )


async def create_user(
    session: AsyncSession,
    scope: OrgScope,
    actor: User,
    org_slug: str,
    sender: EmailSender,
    ttl_hours: int,
    *,
    email: str,
    password: str,
    full_name: str | None,
    role: str,
) -> User:
    """Add a user to the actor's own org. The org is never a parameter.

    The new account starts unverified, exactly like a self-service registration.
    An administrator asserting that they own a colleague's address is still an
    assertion, and treating it as proof would put an unproved claim back into
    the login candidate set and back into the address's slot count — the same
    hole self-service registration had, reachable from any admin account.
    """
    assert_may_grant(actor, role)
    issued = verification.issue_token(ttl_hours)
    created = await _repository(session, scope).create(
        email=email,
        password_hash=passwords.hash_password(password),
        full_name=full_name,
        role=role,
        status=UserStatus.ACTIVE.value,
        **verification.pending_columns(issued),
    )
    verification.dispatch(sender, email=email, org_slug=org_slug, issued=issued)
    return created


async def update_user(
    session: AsyncSession,
    scope: OrgScope,
    actor: User,
    target: User,
    changes: dict[str, object],
) -> tuple[User, int]:
    """Apply ``changes`` to ``target``. Returns the user and sessions revoked."""
    assert_may_act_on(actor, target)

    new_role = changes.get("role")
    if isinstance(new_role, str) and new_role != target.role:
        if actor.id == target.id:
            raise PermissionDeniedError("You cannot change your own role.")
        assert_may_grant(actor, new_role)
        await assert_not_last_owner(session, scope, target)

    new_status = changes.get("status")
    is_being_disabled = new_status == UserStatus.DISABLED.value
    if is_being_disabled and target.status == UserStatus.ACTIVE.value:
        await assert_not_last_owner(session, scope, target)

    is_being_reactivated = (
        new_status == UserStatus.ACTIVE.value and target.status != UserStatus.ACTIVE.value
    )
    if is_being_reactivated and target.is_verified:
        # Reactivating a *proved* account is a create as far as the candidate
        # window is concerned: it puts the address back into the set login
        # searches. An unproved one goes back to counting for nothing.
        await accounts.assert_email_has_capacity(session, target.email)

    updated = await _repository(session, scope).update(target, dict(changes))
    revoked = 0
    if is_being_disabled:
        # A disabled user whose refresh token still rotates is not disabled.
        revoked = await refresh_tokens.revoke_all_for_user(session, scope, target.id)
    return updated, revoked


async def deactivate_user(
    session: AsyncSession, scope: OrgScope, actor: User, target: User
) -> tuple[User, int]:
    """Soft-delete: the row stays for the audit trail, the access does not.

    Deleting the row outright would orphan every audit entry that names it,
    which is the opposite of what an append-only trail is for.
    """
    if actor.id == target.id:
        raise ConflictError("You cannot deactivate your own account.")
    assert_may_act_on(actor, target)
    await assert_not_last_owner(session, scope, target)

    updated = await _repository(session, scope).update(
        target, {"status": UserStatus.DISABLED.value, "locked_until": None}
    )
    revoked = await refresh_tokens.revoke_all_for_user(session, scope, target.id)
    return updated, revoked


async def change_own_password(
    session: AsyncSession,
    scope: OrgScope,
    user: User,
    *,
    current_password: str,
    new_password: str,
) -> int:
    """Rotate the caller's own password. Returns the sessions revoked."""
    if not passwords.verify_password(current_password, user.password_hash):
        raise InvalidCredentialsError(
            "Your current password is incorrect.", field="current_password"
        )
    if passwords.verify_password(new_password, user.password_hash):
        raise ConflictError(
            "The new password must differ from the current one.", field="new_password"
        )

    await _repository(session, scope).update(
        user,
        {
            "password_hash": passwords.hash_password(new_password),
            "failed_login_count": 0,
            "locked_until": None,
        },
    )
    return await refresh_tokens.revoke_all_for_user(session, scope, user.id)


async def reset_password(
    session: AsyncSession, scope: OrgScope, actor: User, target: User
) -> PasswordReset:
    """Issue a one-time password for an account the operator has to recover.

    This is the lever an operator needs when an account is locked out — by its
    own holder or by a stranger spraying guesses at a known address — so it also
    clears the lockout state it is being used to escape.
    """
    if actor.id == target.id:
        # Self-service reset without proving the current password would make a
        # stolen access token enough to take the account over permanently.
        raise ConflictError("Change your own password through the password-change endpoint.")
    assert_may_act_on(actor, target)
    temporary = secrets.token_urlsafe(_TEMPORARY_PASSWORD_BYTES)
    await _repository(session, scope).update(
        target,
        {
            "password_hash": passwords.hash_password(temporary),
            "failed_login_count": 0,
            "locked_until": None,
        },
    )
    revoked = await refresh_tokens.revoke_all_for_user(session, scope, target.id)
    return PasswordReset(user=target, temporary_password=temporary, sessions_revoked=revoked)


async def unlock_user(session: AsyncSession, scope: OrgScope, actor: User, target: User) -> User:
    """Clear a lockout without touching the password."""
    assert_may_act_on(actor, target)
    return await _repository(session, scope).update(
        target, {"failed_login_count": 0, "locked_until": None}
    )


async def get_or_404(session: AsyncSession, scope: OrgScope, user_id: UUID) -> User:
    """A user in another org is a 404, never a 403 (docs/API.md)."""
    return await _repository(session, scope).get_or_404(user_id)
