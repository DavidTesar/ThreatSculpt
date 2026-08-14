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

#: Enrichment passes a job may be given before it is abandoned as failed. The
#: same number as ``MAX_JOB_ATTEMPTS`` and for the same reason: a worker that
#: dies mid-pass must get the job back, and a job that kills every worker that
#: touches it must stop being handed out.
MAX_ENRICHMENT_ATTEMPTS = 3


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


class EnrichmentStatus(StrEnum):
    """Where a completed job is in the enrichment queue.

    ``NULL`` — not this enum — is the fourth state and the default: a job that
    has not completed is not a candidate at all. Making "not queued" a real
    value would mean every queued job carried a row the claim query's partial
    index had to exclude.
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


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
        CheckConstraint(
            "enrichment_status IS NULL OR "
            "enrichment_status IN ('pending','running','complete','failed')",
            name="scan_jobs_enrichment_status_valid",
        ),
        CheckConstraint(
            f"enrichment_attempts >= 0 AND enrichment_attempts <= {MAX_ENRICHMENT_ATTEMPTS}",
            name="scan_jobs_enrichment_attempts_bounded",
        ),
        Index("ix_scan_jobs_org_id_status", "org_id", "status"),
        # Partial index backing the claim query in docs/AGENT-PROTOCOL.md §3.
        Index(
            "ix_scan_jobs_queued",
            "org_id",
            "created_at",
            postgresql_where=text("status = 'queued'"),
        ),
        # Partial index backing the enrichment claim. It covers both halves of
        # that query's predicate — work waiting and work whose lease lapsed —
        # because a lapsed lease is re-claimed by the same statement.
        Index(
            "ix_scan_jobs_enrichment_claimable",
            "org_id",
            "created_at",
            postgresql_where=text("enrichment_status IN ('pending','running')"),
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
    #: NULL until the job completes; set to ``pending`` by the same UPDATE that
    #: completes it, so a job cannot reach ``completed`` without being queued for
    #: enrichment. Two writes would leave a window in which a crash strands a
    #: finished scan with no findings, permanently and silently.
    enrichment_status: Mapped[str | None] = mapped_column(String(32))
    enrichment_attempts: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")
    #: Held by the worker that claimed the job. Once it lapses another worker
    #: may take the job back — the recovery path for a worker that died mid-pass.
    enrichment_lease_expires_at: Mapped[datetime | None] = mapped_column()


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
