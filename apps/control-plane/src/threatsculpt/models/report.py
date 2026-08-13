"""Generated reports.

The artifact lives in the row rather than on a local disk: the control plane is
horizontally scaled, so a file written by the instance that generated the report
is not there when the poll for it lands on a different one. Reports are small
HTML documents, and keeping them in the tenant table means they inherit RLS
instead of needing a second isolation story for object storage.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, Text, text
from sqlalchemy.orm import Mapped, mapped_column

from threatsculpt.db.base import TenantModel
from threatsculpt.db.types import JSONB, PgUUID


class ReportType(StrEnum):
    EXECUTIVE_SUMMARY = "executive_summary"


class ReportFormat(StrEnum):
    HTML = "html"


class ReportStatus(StrEnum):
    QUEUED = "queued"
    GENERATING = "generating"
    READY = "ready"
    FAILED = "failed"


#: Terminal states — a poller can stop here.
TERMINAL_REPORT_STATUSES: frozenset[str] = frozenset(
    {ReportStatus.READY.value, ReportStatus.FAILED.value}
)


class Report(TenantModel):
    __tablename__ = "reports"
    __table_args__ = (
        CheckConstraint("type IN ('executive_summary')", name="reports_type_valid"),
        CheckConstraint("format IN ('html')", name="reports_format_valid"),
        CheckConstraint(
            "status IN ('queued','generating','ready','failed')", name="reports_status_valid"
        ),
        CheckConstraint("byte_size IS NULL OR byte_size >= 0", name="reports_byte_size_valid"),
        Index("ix_reports_org_id_created_at", "org_id", "created_at"),
    )

    type: Mapped[str] = mapped_column(String(64), nullable=False)
    format: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=ReportStatus.QUEUED.value, server_default="queued"
    )
    #: The requested scope, echoed back so a stale report is self-describing.
    scope: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'")
    )
    content: Mapped[str | None] = mapped_column(Text())
    content_type: Mapped[str | None] = mapped_column(String(128))
    byte_size: Mapped[int | None] = mapped_column()
    error: Mapped[str | None] = mapped_column(String(2000))
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    generated_at: Mapped[datetime | None] = mapped_column()

    @property
    def is_ready(self) -> bool:
        return self.status == ReportStatus.READY.value and self.content is not None
