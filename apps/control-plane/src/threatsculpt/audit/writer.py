"""Append-only audit writer.

One function, so every audit row is shaped the same way and every one is scoped.
Metadata is scrubbed through the same redactor the logger uses — an audit row
that captured a password would be a durable secret leak, and audit rows are the
one thing the application cannot delete.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.models.audit import AuditAction, AuditLog
from threatsculpt.observability.logging import scrub
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope

logger = logging.getLogger(__name__)


async def record_audit(
    session: AsyncSession,
    scope: OrgScope,
    action: AuditAction,
    *,
    target_type: str | None = None,
    target_id: str | UUID | None = None,
    metadata: dict[str, Any] | None = None,
    ip: str | None = None,
) -> AuditLog:
    """Append one audit row. The scope supplies both ``org_id`` and the actor."""
    repository = ScopedRepository(session, scope, AuditLog)
    return await repository.create(
        actor_type=scope.actor_type.value,
        actor_id=scope.actor_id,
        action=action.value,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        audit_metadata=scrub(metadata or {}),
        ip=ip,
    )


async def try_record_audit(
    session: AsyncSession,
    scope: OrgScope,
    action: AuditAction,
    **kwargs: Any,
) -> None:
    """Audit on a best-effort basis, for paths where the audit must not fail the request.

    Used only where the primary action has already succeeded and rolling it back
    would be worse than losing one audit row. The failure is logged at ERROR
    rather than swallowed, so a broken audit path is visible in monitoring.
    """
    try:
        await record_audit(session, scope, action, **kwargs)
    except Exception:
        logger.exception(
            "failed to write audit row", extra={"action": action.value, "org_id": str(scope.org_id)}
        )
