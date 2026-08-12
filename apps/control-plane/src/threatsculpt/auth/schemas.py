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

from threatsculpt.security.passwords import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH

SLUG_PATTERN = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MAX_SLUG_LENGTH = 63

Password = Annotated[str, Field(min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)]


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
