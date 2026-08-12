"""Refresh tokens and agent enrollment tokens.

Both store a SHA-256 ``token_hash`` and never the token itself. A database dump
therefore yields nothing a caller can present.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from threatsculpt.db.base import TenantModel
from threatsculpt.db.types import Inet, PgUUID


class RefreshToken(TenantModel):
    """One link in a rotation chain.

    Presenting a token that already has ``replaced_by`` set, or that is revoked,
    means the token was captured and replayed: the whole family is revoked. That
    is the detection signal described in docs/DATA-MODEL.md.
    """

    __tablename__ = "refresh_tokens"
    __table_args__ = (
        Index("ix_refresh_tokens_user_id", "user_id"),
        Index("ix_refresh_tokens_expires_at", "expires_at"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column()
    replaced_by: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("refresh_tokens.id", ondelete="SET NULL")
    )
    user_agent: Mapped[str | None] = mapped_column(String(400))
    ip: Mapped[str | None] = mapped_column(Inet)

    @property
    def is_spent(self) -> bool:
        return self.revoked_at is not None or self.replaced_by is not None


class EnrollmentToken(TenantModel):
    """One-time token an agent trades for an API key. Expires in 1 hour."""

    __tablename__ = "enrollment_tokens"
    __table_args__ = (Index("ix_enrollment_tokens_expires_at", "expires_at"),)

    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    expires_at: Mapped[datetime] = mapped_column(nullable=False)
    used_at: Mapped[datetime | None] = mapped_column()
    used_by_agent_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL")
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
