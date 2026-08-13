"""``/users`` — the org's own user directory.

docs/API.md: ``GET/POST /users`` and ``PATCH/DELETE /users/{id}``, admin, and
"cannot remove the last owner". Two endpoints beyond that table exist because
the table's promise is unusable without them: an operator with no way to reset a
password cannot recover a colleague who is locked out, and a user with no way to
change their own password cannot respond to their own credential leaking.

Every route here is a credential-bearing administrative action, so every one of
them writes an audit row, and the decisions all live in ``auth.users`` rather
than being re-derived per endpoint.
"""

from __future__ import annotations

from http import HTTPStatus
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Request

from threatsculpt.api.dependencies import CurrentUser, RequireAdmin, SessionDep, SettingsDep
from threatsculpt.api.limits import enforce_general_rate_limit
from threatsculpt.api.middleware import client_ip
from threatsculpt.audit.writer import record_audit
from threatsculpt.auth import accounts
from threatsculpt.auth import users as user_service
from threatsculpt.auth.schemas import (
    PasswordChangeRequest,
    PasswordResetResponse,
    UserAdminSummary,
    UserCreate,
    UserUpdate,
)
from threatsculpt.core.envelope import Envelope, ok
from threatsculpt.core.pagination import PaginationParams, pagination_params
from threatsculpt.models.audit import AuditAction
from threatsculpt.models.org import Org
from threatsculpt.models.user import User
from threatsculpt.tenancy.repository import ScopedRepository

router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(enforce_general_rate_limit)],
)

UserId = Annotated[UUID, Path(description="User id within your organisation")]
PaginationDep = Annotated[PaginationParams, Depends(pagination_params)]


def _summary(user: User) -> UserAdminSummary:
    return UserAdminSummary(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        status=user.status,
        last_login_at=user.last_login_at,
        locked=accounts.is_locked(user),
        verified=user.is_verified,
    )


def _applied(payload: UserUpdate) -> dict[str, object]:
    """Sent fields only, with the two that are not nullable dropped when null.

    ``full_name`` may legitimately be cleared; ``role`` and ``status`` are NOT
    NULL columns, so an explicit ``null`` there is "leave it alone", not "unset".
    """
    return {
        field: value
        for field, value in payload.changes().items()
        if value is not None or field == "full_name"
    }


@router.get("", response_model=Envelope[list[UserAdminSummary]], summary="List users in your org")
async def list_users(
    principal: RequireAdmin,
    session: SessionDep,
    pagination: PaginationDep,
) -> Envelope[list[UserAdminSummary]]:
    repository = ScopedRepository(session, principal.scope, User)
    page = await repository.list(pagination, order_by=[User.email.asc()])
    return ok([_summary(item) for item in page.items], meta=page.meta)


@router.post(
    "",
    status_code=HTTPStatus.CREATED,
    response_model=Envelope[UserAdminSummary],
    summary="Add a user to your org",
)
async def create_user(
    request: Request,
    principal: RequireAdmin,
    session: SessionDep,
    settings: SettingsDep,
    payload: UserCreate,
) -> Envelope[UserAdminSummary]:
    """The new account starts unverified — an admin's word is not proof either."""
    org = await session.get(Org, principal.scope.org_id)
    assert org is not None  # the principal could not have authenticated otherwise
    created = await user_service.create_user(
        session,
        principal.scope,
        principal.user,
        org.slug,
        request.app.state.email_sender,
        settings.email_verification_ttl_hours,
        email=str(payload.email),
        password=payload.password,
        full_name=payload.full_name,
        role=payload.role,
    )
    await record_audit(
        session,
        principal.scope,
        AuditAction.USER_CREATED,
        target_type="user",
        target_id=created.id,
        metadata={"role": created.role},
        ip=client_ip(request),
    )
    return ok(_summary(created))


@router.patch("/{user_id}", response_model=Envelope[UserAdminSummary], summary="Update a user")
async def update_user(
    request: Request,
    principal: RequireAdmin,
    session: SessionDep,
    user_id: UserId,
    payload: UserUpdate,
) -> Envelope[UserAdminSummary]:
    target = await user_service.get_or_404(session, principal.scope, user_id)
    changes = _applied(payload)
    updated, revoked = await user_service.update_user(
        session, principal.scope, principal.user, target, changes
    )
    await record_audit(
        session,
        principal.scope,
        AuditAction.USER_UPDATED,
        target_type="user",
        target_id=user_id,
        metadata={"fields": sorted(changes), "revoked_count": revoked},
        ip=client_ip(request),
    )
    return ok(_summary(updated))


@router.delete(
    "/{user_id}",
    status_code=HTTPStatus.OK,
    response_model=Envelope[UserAdminSummary],
    summary="Deactivate a user",
)
async def deactivate_user(
    request: Request,
    principal: RequireAdmin,
    session: SessionDep,
    user_id: UserId,
) -> Envelope[UserAdminSummary]:
    """Deactivation, not deletion — the audit trail must keep naming this user."""
    target = await user_service.get_or_404(session, principal.scope, user_id)
    updated, revoked = await user_service.deactivate_user(
        session, principal.scope, principal.user, target
    )
    await record_audit(
        session,
        principal.scope,
        AuditAction.USER_DEACTIVATED,
        target_type="user",
        target_id=user_id,
        metadata={"revoked_count": revoked},
        ip=client_ip(request),
    )
    return ok(_summary(updated))


@router.post(
    "/me/password",
    response_model=Envelope[UserAdminSummary],
    summary="Change your own password",
)
async def change_own_password(
    request: Request,
    principal: CurrentUser,
    session: SessionDep,
    payload: PasswordChangeRequest,
) -> Envelope[UserAdminSummary]:
    """Any role. Requires the current password and ends every existing session."""
    revoked = await user_service.change_own_password(
        session,
        principal.scope,
        principal.user,
        current_password=payload.current_password,
        new_password=payload.new_password,
    )
    await record_audit(
        session,
        principal.scope,
        AuditAction.USER_PASSWORD_CHANGED,
        target_type="user",
        target_id=principal.user.id,
        metadata={"revoked_count": revoked},
        ip=client_ip(request),
    )
    return ok(_summary(principal.user))


@router.post(
    "/{user_id}/unlock",
    response_model=Envelope[UserAdminSummary],
    summary="Clear a failed-login lockout",
)
async def unlock_user(
    request: Request,
    principal: RequireAdmin,
    session: SessionDep,
    user_id: UserId,
) -> Envelope[UserAdminSummary]:
    """The cheaper half of the recovery lever, for a lockout somebody else caused.

    A lockout any stranger who knows the address can trigger has to be
    clearable without also invalidating the password the account holder still
    knows perfectly well.
    """
    target = await user_service.get_or_404(session, principal.scope, user_id)
    updated = await user_service.unlock_user(session, principal.scope, principal.user, target)
    await record_audit(
        session,
        principal.scope,
        AuditAction.USER_UPDATED,
        target_type="user",
        target_id=user_id,
        metadata={"action": "unlock"},
        ip=client_ip(request),
    )
    return ok(_summary(updated))


@router.post(
    "/{user_id}/password-reset",
    response_model=Envelope[PasswordResetResponse],
    summary="Issue a temporary password for a user",
)
async def reset_password(
    request: Request,
    principal: RequireAdmin,
    session: SessionDep,
    user_id: UserId,
) -> Envelope[PasswordResetResponse]:
    """The operator's recovery lever: also clears any failed-login lockout.

    The temporary password is in this response and nowhere else — it is never
    logged, never stored in plaintext, and not recoverable if lost.
    """
    target = await user_service.get_or_404(session, principal.scope, user_id)
    reset = await user_service.reset_password(session, principal.scope, principal.user, target)
    await record_audit(
        session,
        principal.scope,
        AuditAction.USER_PASSWORD_RESET,
        target_type="user",
        target_id=user_id,
        metadata={"revoked_count": reset.sessions_revoked},
        ip=client_ip(request),
    )
    return ok(
        PasswordResetResponse(
            user_id=reset.user.id,
            temporary_password=reset.temporary_password,
            sessions_revoked=reset.sessions_revoked,
        )
    )
