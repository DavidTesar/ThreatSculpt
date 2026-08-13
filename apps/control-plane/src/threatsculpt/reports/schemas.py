"""Request and response models for ``/reports``."""

from __future__ import annotations

from datetime import date, datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from threatsculpt.models.report import ReportStatus, ReportType


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class ReportScope(StrictModel):
    """What the report should cover. Empty means the whole org."""

    service_ids: list[UUID] = Field(default_factory=list, max_length=100)
    since: date | None = None


class ReportCreate(StrictModel):
    type: ReportType = ReportType.EXECUTIVE_SUMMARY
    #: Free-form so an unsupported value produces a specific, actionable error
    #: rather than pydantic's generic enum rejection. ``pdf`` is the value the
    #: API doc's example sends, and it is the one worth explaining.
    format: Annotated[str, Field(max_length=16)] = "html"
    scope: ReportScope = Field(default_factory=ReportScope)


class ReportOut(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, from_attributes=True)

    id: UUID
    type: str
    format: str
    status: ReportStatus
    byte_size: int | None = None
    error: str | None = None
    created_at: datetime
    generated_at: datetime | None = None


class ReportCreated(StrictModel):
    """202 body. Named ``report_id`` to match docs/API.md exactly."""

    report_id: UUID
    status: ReportStatus


class ReportDownloadLink(StrictModel):
    url: str
    expires_at: datetime
