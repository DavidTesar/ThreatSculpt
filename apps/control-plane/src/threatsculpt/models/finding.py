"""Global CVE reference data and the tenant-scoped findings that cite it."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any

from sqlalchemy import CheckConstraint, ForeignKey, Index, Numeric, String, UniqueConstraint, text
from sqlalchemy.orm import Mapped, mapped_column

from threatsculpt.db.base import Base, TenantModel, TimestampMixin
from threatsculpt.db.types import JSONB, PgUUID, text_array


class ExploitMaturity(StrEnum):
    WEAPONIZED = "weaponized"
    POC = "poc"
    NONE = "none"


class FindingStatus(StrEnum):
    OPEN = "open"
    ACCEPTED_RISK = "accepted_risk"
    REMEDIATED = "remediated"
    FALSE_POSITIVE = "false_positive"


class Vulnerability(TimestampMixin, Base):
    """Global CVE reference data. **Not tenant-scoped** — no ``org_id``.

    Deliberately outside the tenancy guard: it holds no customer data, and one
    NVD/KEV sync serves every tenant.
    """

    __tablename__ = "vulnerabilities"
    __table_args__ = (
        CheckConstraint(
            "exploit_maturity IN ('weaponized','poc','none')",
            name="vulnerabilities_exploit_maturity_valid",
        ),
        Index("ix_vulnerabilities_kev_listed", "kev_listed"),
        Index("ix_vulnerabilities_cpes", "cpes", postgresql_using="gin"),
    )

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    description: Mapped[str | None] = mapped_column(String())
    cvss_base: Mapped[Decimal | None] = mapped_column(Numeric(3, 1))
    cvss_vector: Mapped[str | None] = mapped_column(String(255))
    severity: Mapped[str | None] = mapped_column(String(32))
    cpes: Mapped[list[str]] = mapped_column(
        text_array(), nullable=False, server_default=text("'{}'::text[]")
    )
    kev_listed: Mapped[bool] = mapped_column(nullable=False, default=False, server_default="false")
    kev_due_date: Mapped[date | None] = mapped_column()
    exploit_maturity: Mapped[str] = mapped_column(
        String(32), nullable=False, default=ExploitMaturity.NONE.value, server_default="none"
    )
    published_at: Mapped[datetime | None] = mapped_column()
    last_synced_at: Mapped[datetime | None] = mapped_column()


class Finding(TenantModel):
    """A vulnerability observed on a specific asset. What the dashboard renders."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint(
            "org_id",
            "asset_id",
            "port_id",
            "cve_id",
            name="uq_findings_org_id_asset_id_port_id_cve_id",
        ),
        CheckConstraint(
            "status IN ('open','accepted_risk','remediated','false_positive')",
            name="findings_status_valid",
        ),
        CheckConstraint("business_risk_score >= 0", name="findings_score_non_negative"),
        Index("ix_findings_org_id_status", "org_id", "status"),
        Index("ix_findings_org_id_business_risk_score", "org_id", "business_risk_score"),
        Index("ix_findings_asset_id", "asset_id"),
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    port_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("ports.id", ondelete="CASCADE")
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="SET NULL")
    )
    cve_id: Mapped[str] = mapped_column(
        String(32), ForeignKey("vulnerabilities.cve_id", ondelete="RESTRICT"), nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=FindingStatus.OPEN.value, server_default="open"
    )
    business_risk_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False)
    #: The inputs to the score, so the UI can explain the number.
    score_factors: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'")
    )
    first_seen_at: Mapped[datetime | None] = mapped_column()
    last_seen_at: Mapped[datetime | None] = mapped_column()
    resolved_at: Mapped[datetime | None] = mapped_column()
