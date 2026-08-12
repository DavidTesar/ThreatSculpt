"""Users and the role ladder."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from sqlalchemy import CheckConstraint, Index, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from threatsculpt.db.base import TenantModel
from threatsculpt.db.types import CITEXT


class Role(StrEnum):
    """``owner`` > ``admin`` > ``analyst`` > ``viewer`` (docs/ARCHITECTURE.md)."""

    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


#: Higher number outranks lower. Comparison lives here so no route re-derives it.
ROLE_RANK: dict[str, int] = {
    Role.VIEWER.value: 0,
    Role.ANALYST.value: 1,
    Role.ADMIN.value: 2,
    Role.OWNER.value: 3,
}


def outranks_or_equals(actual: str, required: str) -> bool:
    return ROLE_RANK.get(actual, -1) >= ROLE_RANK[required]


class UserStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"


class User(TenantModel):
    __tablename__ = "users"
    __table_args__ = (
        UniqueConstraint("org_id", "email", name="uq_users_org_id_email"),
        CheckConstraint("role IN ('owner','admin','analyst','viewer')", name="users_role_valid"),
        CheckConstraint("status IN ('active','disabled')", name="users_status_valid"),
        Index("ix_users_email", "email"),
    )

    email: Mapped[str] = mapped_column(CITEXT(), nullable=False)
    #: Argon2id only. Never bcrypt, never plaintext (docs/DATA-MODEL.md).
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(200))
    role: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default=UserStatus.ACTIVE.value)
    last_login_at: Mapped[datetime | None] = mapped_column()
    failed_login_count: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")
    locked_until: Mapped[datetime | None] = mapped_column()

    @property
    def is_active(self) -> bool:
        return self.status == UserStatus.ACTIVE

    def has_role(self, required: str) -> bool:
        return outranks_or_equals(self.role, required)
