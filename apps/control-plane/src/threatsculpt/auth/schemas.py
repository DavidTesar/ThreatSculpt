"""Request and response models for the auth endpoints.

Note what is absent from every request model here and everywhere else: there is
no ``org_id``, ``orgId``, ``tenant`` or ``userID`` field. ``extra="forbid"``
means sending one is a 400 rather than a silently ignored field.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from threatsculpt.models.user import Role
from threatsculpt.security.passwords import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH

SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MAX_SLUG_LENGTH = 63

Password = Annotated[str, Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)]

#: Validated at the boundary against the ladder itself, so an unknown role name
#: is a 400 rather than a row the role check silently ranks below ``viewer``.
RoleName = Annotated[str, Field(pattern=f"^({'|'.join(role.value for role in Role)})$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class RegisterRequest(StrictModel):
    """Creates an org and its first ``owner`` user. Trial plan."""

    org_name: Annotated[str, Field(min_length=1, max_length=200)]
    org_slug: Annotated[str, Field(min_length=3, max_length=MAX_SLUG_LENGTH)]
    email: EmailStr
    password: Password
    full_name: Annotated[str | None, Field(max_length=200)] = None

    @field_validator("org_slug")
    @classmethod
    def _validate_slug(cls, value: str) -> str:
        lowered = value.lower()
        if not SLUG_PATTERN.match(lowered):
            raise ValueError("org_slug must be lowercase alphanumeric words separated by hyphens")
        return lowered


class LoginRequest(StrictModel):
    """``org_slug`` is optional and *only* disambiguates.

    An address may legitimately exist in two customers, since ``users`` is
    unique on ``(org_id, email)``. Supplying the slug narrows the candidate set;
    omitting it still works, because the password is verified against each
    candidate. It grants nothing on its own — it is not a tenant selector in the
    sense docs/API.md forbids, which is a caller naming *whose data to return*.
    """

    email: EmailStr
    password: Annotated[str, Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)]
    org_slug: Annotated[str | None, Field(max_length=MAX_SLUG_LENGTH)] = None


class TokenResponse(StrictModel):
    """The refresh token is deliberately absent — it goes out as a cookie only."""

    access_token: str
    token_type: str = "bearer"  # noqa: S105 - a scheme name, not a credential
    expires_at: datetime


class OrgSummary(StrictModel):
    id: UUID
    name: str
    slug: str
    plan: str
    status: str


class UserSummary(StrictModel):
    id: UUID
    email: str
    full_name: str | None
    role: str
    status: str
    last_login_at: datetime | None


class UserAdminSummary(UserSummary):
    """What an administrator needs that the user themselves does not.

    ``locked`` is derived rather than stored: an operator looking at the user
    directory has to be able to see *why* a colleague cannot log in, or the
    unlock lever below is one they never know to pull.
    """

    locked: bool
    #: Whether control of the address was ever proved. An unverified colleague
    #: cannot log in, which is otherwise indistinguishable from a wrong password.
    verified: bool


class MeResponse(StrictModel):
    user: UserSummary
    org: OrgSummary


class RegisterResponse(StrictModel):
    user: UserSummary
    org: OrgSummary
    access_token: str
    expires_at: datetime


class LogoutResponse(StrictModel):
    revoked: bool


class VerifyEmailRequest(StrictModel):
    """The token from the verification message. No address, no org.

    Naming the account would let a caller aim a guessed token at a chosen
    victim; the token identifies the account by itself or it is worthless.
    """

    token: Annotated[str, Field(min_length=8, max_length=128)]


class VerificationStateResponse(StrictModel):
    """Whether the address is proved, and when the outstanding claim lapses."""

    email: str
    verified: bool
    verification_expires_at: datetime | None


class UserCreate(StrictModel):
    """An administrator adding a colleague to their own org.

    There is no ``org_id``: the org comes from the caller's principal, like
    everywhere else. ``role`` is bounded by the caller's own role at the service
    layer — an admin cannot mint an owner.
    """

    email: EmailStr
    password: Password
    full_name: Annotated[str | None, Field(max_length=200)] = None
    role: RoleName = Role.VIEWER.value


class UserUpdate(StrictModel):
    """Partial update. Only the fields actually sent are applied."""

    full_name: Annotated[str | None, Field(max_length=200)] = None
    role: RoleName | None = None
    status: Annotated[str | None, Field(pattern="^(active|disabled)$")] = None

    def changes(self) -> dict[str, object]:
        return self.model_dump(exclude_unset=True, exclude_none=False)


class PasswordChangeRequest(StrictModel):
    """A user changing their own password. The current one is required.

    Requiring it is what stops a stolen access token from becoming a permanent
    account takeover in one request.
    """

    current_password: Annotated[str, Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)]
    new_password: Password


class PasswordResetResponse(StrictModel):
    """An admin-issued temporary password, shown exactly once.

    Same handling as every other credential this service mints: the plaintext
    exists in this response and nowhere else, and the holder is expected to
    change it immediately.
    """

    user_id: UUID
    temporary_password: str
    sessions_revoked: int
