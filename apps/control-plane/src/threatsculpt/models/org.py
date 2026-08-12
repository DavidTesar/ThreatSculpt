"""The tenant root. Not itself tenant-scoped — it *is* the tenant."""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import CheckConstraint, String
from sqlalchemy.orm import Mapped, mapped_column

from threatsculpt.db.base import Base, TimestampMixin, UuidPkMixin
from threatsculpt.db.types import CITEXT


class OrgPlan(StrEnum):
    TRIAL = "trial"
    STANDARD = "standard"
    ENTERPRISE = "enterprise"


class OrgStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"


class Org(UuidPkMixin, TimestampMixin, Base):
    __tablename__ = "orgs"
    __table_args__ = (
        CheckConstraint("plan IN ('trial','standard','enterprise')", name="orgs_plan_valid"),
        CheckConstraint("status IN ('active','suspended')", name="orgs_status_valid"),
    )

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(CITEXT(), nullable=False, unique=True)
    plan: Mapped[str] = mapped_column(String(32), nullable=False, default=OrgPlan.TRIAL.value)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default=OrgStatus.ACTIVE.value)

    @property
    def is_active(self) -> bool:
        return self.status == OrgStatus.ACTIVE
