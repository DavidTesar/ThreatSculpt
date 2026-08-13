"""Append-only audit log.

The application role holds INSERT and SELECT only; UPDATE and DELETE are
revoked in the migration. An audit trail the application can rewrite is not an
audit trail.
"""

from __future__ import annotations

import uuid
from enum import StrEnum
from typing import Any

from sqlalchemy import CheckConstraint, Index, String, text
from sqlalchemy.orm import Mapped, mapped_column

from threatsculpt.db.base import TenantModel
from threatsculpt.db.types import JSONB, Inet, PgUUID


class ActorType(StrEnum):
    USER = "user"
    AGENT = "agent"
    SYSTEM = "system"


class AuditAction(StrEnum):
    """Actions worth a permanent record. Extend as endpoints are added."""

    AUTH_REGISTER = "auth.register"
    AUTH_LOGIN = "auth.login"
    AUTH_LOGIN_FAILED = "auth.login_failed"
    AUTH_REFRESH = "auth.refresh"
    AUTH_REFRESH_REUSE_DETECTED = "auth.refresh_reuse_detected"
    AUTH_LOGOUT = "auth.logout"
    AGENT_AUTHENTICATED = "agent.authenticated"
    AGENT_ENROLLMENT_TOKEN_ISSUED = "agent.enrollment_token_issued"  # noqa: S105 - an action name
    AGENT_ENROLLED = "agent.enrolled"
    AGENT_ENROLLMENT_REJECTED = "agent.enrollment_rejected"
    AGENT_REVOKED = "agent.revoked"
    NETWORK_CREATED = "network.created"
    NETWORK_UPDATED = "network.updated"
    NETWORK_DELETED = "network.deleted"
    BUSINESS_SERVICE_CREATED = "business_service.created"
    BUSINESS_SERVICE_UPDATED = "business_service.updated"
    BUSINESS_SERVICE_DELETED = "business_service.deleted"
    SCAN_JOB_CREATED = "scan_job.created"
    SCAN_JOB_CLAIMED = "scan_job.claimed"
    SCAN_JOB_REJECTED = "scan_job.rejected"
    SCAN_JOB_CANCELLED = "scan_job.cancelled"
    SCAN_JOB_LEASE_EXPIRED = "scan_job.lease_expired"
    SCAN_RESULTS_INGESTED = "scan_result.ingested"
    #: A host the agent submitted that was outside the job's target or the org's
    #: registered networks. Security-relevant: it means a client sent data it was
    #: never asked to collect.
    SCAN_RESULT_HOST_REJECTED = "scan_result.host_rejected"
    FINDING_STATUS_CHANGED = "finding.status_changed"
    ASSET_UPDATED = "asset.updated"
    ASSET_SERVICES_UPDATED = "asset.services_updated"
    REPORT_REQUESTED = "report.requested"
    REPORT_GENERATED = "report.generated"
    REPORT_FAILED = "report.failed"
    REPORT_DOWNLOADED = "report.downloaded"
    TENANCY_VIOLATION = "security.tenancy_violation"


class AuditLog(TenantModel):
    __tablename__ = "audit_log"
    __table_args__ = (
        CheckConstraint(
            "actor_type IN ('user','agent','system')", name="audit_log_actor_type_valid"
        ),
        Index("ix_audit_log_org_id_created_at", "org_id", "created_at"),
        Index("ix_audit_log_org_id_action", "org_id", "action"),
    )

    actor_type: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True))
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(64))
    audit_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, server_default=text("'{}'")
    )
    ip: Mapped[str | None] = mapped_column(Inet)
