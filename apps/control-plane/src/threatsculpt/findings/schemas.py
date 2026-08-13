"""Request and response models for ``/findings``.

Same discipline as ``api.schemas``: ``extra="forbid"``, frozen, and no field
anywhere that names a tenant.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from threatsculpt.models.finding import FindingStatus, MatchConfidence


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class CveSummary(StrictModel):
    cve_id: str
    severity: str | None = None
    cvss_base: Decimal | None = None
    kev_listed: bool = False
    kev_due_date: Any | None = None
    exploit_maturity: str = "none"


class AssetSummary(StrictModel):
    id: UUID
    ip: str
    hostname: str | None = None
    exposure: str


class MatchSummary(StrictModel):
    """How the CVE was attached to this service, and how sure we were.

    Surfaced on every finding rather than only on request: an operator deciding
    whether to page someone at 2am needs to know the difference between "your
    version is inside the affected range" and "we guessed from a banner".
    """

    confidence: MatchConfidence
    method: str | None = None
    rationale: str | None = None


class FindingOut(StrictModel):
    id: UUID
    status: FindingStatus
    business_risk_score: Decimal
    asset: AssetSummary
    cve: CveSummary
    match: MatchSummary
    port_id: UUID | None = None
    scan_job_id: UUID | None = None
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    resolved_at: datetime | None = None


class FindingDetail(FindingOut):
    """Adds the score explanation and the CVE text.

    ``score_factors`` is the reason this endpoint exists in this shape. A list
    row can carry a number; a detail view has to be able to defend it.
    """

    description: str | None = None
    score_factors: dict[str, Any] = Field(default_factory=dict)
    services_affected: list[str] = Field(default_factory=list)


class FindingStatusUpdate(StrictModel):
    """Status transitions only — no other field is patchable.

    Letting a caller PATCH ``business_risk_score`` would make the score an
    opinion rather than a computation, and the whole product rests on it being
    a computation.
    """

    status: FindingStatus
    note: Annotated[str | None, Field(max_length=1000)] = None
