"""Scan agents — the second principal type."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from sqlalchemy import CheckConstraint, String, text
from sqlalchemy.orm import Mapped, mapped_column

from threatsculpt.db.base import TenantModel
from threatsculpt.db.types import cidr_array


class AgentStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"


class Agent(TenantModel):
    __tablename__ = "agents"
    __table_args__ = (
        CheckConstraint("status IN ('active','revoked')", name="agents_status_valid"),
    )

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    #: SHA-256 of the key. The key itself is shown exactly once, at enrollment.
    api_key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    #: First 8 characters, for display and support. Not a secret.
    key_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=AgentStatus.ACTIVE.value
    )
    version: Mapped[str | None] = mapped_column(String(64))
    #: What this agent is permitted to scan, as native CIDRs.
    allowlist: Mapped[list[str]] = mapped_column(
        cidr_array(), nullable=False, server_default=text("'{}'::cidr[]")
    )
    last_seen_at: Mapped[datetime | None] = mapped_column()

    @property
    def is_active(self) -> bool:
        return self.status == AgentStatus.ACTIVE
