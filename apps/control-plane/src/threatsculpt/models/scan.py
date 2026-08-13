"""Scan jobs, per-host results, and ports."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import CheckConstraint, ForeignKey, Index, String, text
from sqlalchemy.orm import Mapped, mapped_column

from threatsculpt.db.base import TenantModel
from threatsculpt.db.types import JSONB, Cidr, PgUUID, text_array

MAX_JOB_ATTEMPTS = 3


class ScanProfile(StrEnum):
    """Named profiles only. The API never accepts raw nmap flags."""

    DISCOVERY = "discovery"
    SERVICE = "service"
    VULNERABILITY = "vulnerability"


class ScanStatus(StrEnum):
    QUEUED = "queued"
    CLAIMED = "claimed"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanJob(TenantModel):
    __tablename__ = "scan_jobs"
    __table_args__ = (
        CheckConstraint(
            "profile IN ('discovery','service','vulnerability')", name="scan_jobs_profile_valid"
        ),
        CheckConstraint(
            "status IN ('queued','claimed','running','completed','failed','cancelled')",
            name="scan_jobs_status_valid",
        ),
        CheckConstraint(
            f"attempts >= 0 AND attempts <= {MAX_JOB_ATTEMPTS}", name="scan_jobs_attempts_bounded"
        ),
        CheckConstraint(
            "progress_percent IS NULL OR (progress_percent >= 0 AND progress_percent <= 100)",
            name="scan_jobs_progress_in_range",
        ),
        Index("ix_scan_jobs_org_id_status", "org_id", "status"),
        # Partial index backing the claim query in docs/AGENT-PROTOCOL.md §3.
        Index(
            "ix_scan_jobs_queued",
            "org_id",
            "created_at",
            postgresql_where=text("status = 'queued'"),
        ),
    )

    network_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("networks.id", ondelete="SET NULL")
    )
    #: Must be contained by a registered, authorized network CIDR.
    target: Mapped[str] = mapped_column(Cidr, nullable=False)
    profile: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=ScanStatus.QUEUED.value, server_default="queued"
    )
    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agents.id", ondelete="SET NULL")
    )
    lease_expires_at: Mapped[datetime | None] = mapped_column()
    attempts: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")
    #: Self-reported by the agent while the scan runs (docs/AGENT-PROTOCOL.md §5).
    progress_percent: Mapped[int | None] = mapped_column()
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    started_at: Mapped[datetime | None] = mapped_column()
    finished_at: Mapped[datetime | None] = mapped_column()
    error: Mapped[str | None] = mapped_column(String(2000))


class ScanResult(TenantModel):
    """One row per (job, asset)."""

    __tablename__ = "scan_results"
    __table_args__ = (
        # Ingest is idempotent on (job, asset): a retried batch must not double-insert.
        Index(
            "uq_scan_results_scan_job_id_asset_id",
            "scan_job_id",
            "asset_id",
            unique=True,
        ),
    )

    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    state: Mapped[str | None] = mapped_column(String(32))
    raw: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'"))


class Port(TenantModel):
    """A port belongs to one scan_result, which belongs to exactly one asset.

    v1 accumulated ports into a shared list, so host #2 inherited host #1's
    ports; the foreign key here is what makes that impossible.
    """

    __tablename__ = "ports"
    __table_args__ = (
        Index("ix_ports_scan_result_id", "scan_result_id"),
        Index("ix_ports_org_id_asset_id", "org_id", "asset_id"),
        CheckConstraint("port > 0 AND port <= 65535", name="ports_port_in_range"),
    )

    scan_result_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_results.id", ondelete="CASCADE"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    port: Mapped[int] = mapped_column(nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    state: Mapped[str | None] = mapped_column(String(32))
    service: Mapped[str | None] = mapped_column(String(128))
    product: Mapped[str | None] = mapped_column(String(255))
    version: Mapped[str | None] = mapped_column(String(128))
    cpe: Mapped[list[str]] = mapped_column(
        text_array(), nullable=False, server_default=text("'{}'::text[]")
    )
