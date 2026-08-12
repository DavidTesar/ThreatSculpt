"""Session lifecycle and scope binding.

``bind_scope`` is layer 3's activation point: it issues
``set_config('threatsculpt.org_id', <org>, true)`` — the transaction-local form
of ``SET LOCAL`` — so every RLS policy has a value to match against for the rest
of the transaction. It also records the scope on ``Session.info``, which is what
the guard checks.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatsculpt.core.errors import TenancyViolationError
from threatsculpt.tenancy.guard import SESSION_SCOPE_KEY, bound_scope
from threatsculpt.tenancy.scope import GUC_NAME, OrgScope

logger = logging.getLogger(__name__)

_SET_SCOPE_SQL = text("SELECT set_config(:guc, :value, true)")
_CLEAR_SCOPE_SQL = text("SELECT set_config(:guc, '', true)")


async def bind_scope(session: AsyncSession, scope: OrgScope) -> None:
    """Pin this session's transaction to ``scope``.

    Rebinding to a *different* org on the same session is refused: within one
    request there is exactly one principal, so a second org id means two
    principals got mixed, which is precisely the confusion that produces a
    cross-tenant read.
    """
    existing = bound_scope(session)
    if existing is not None:
        if existing.org_id != scope.org_id:
            raise TenancyViolationError(
                "attempted to rebind a session already scoped to a different org"
            )
        # Same org, better-identified actor: authentication binds the org from
        # the signed token first, then narrows to the concrete principal once
        # the row is loaded. The isolation predicate is unchanged either way.
        session.info[SESSION_SCOPE_KEY] = scope
        return

    session.info[SESSION_SCOPE_KEY] = scope
    await session.execute(_SET_SCOPE_SQL, {"guc": GUC_NAME, "value": scope.guc_value()})


async def clear_scope(session: AsyncSession) -> None:
    """Drop the scope. Used by the credential-lookup helper, which runs unscoped."""
    session.info.pop(SESSION_SCOPE_KEY, None)
    await session.execute(_CLEAR_SCOPE_SQL, {"guc": GUC_NAME})


@asynccontextmanager
async def scoped_session(
    session_factory: async_sessionmaker[AsyncSession], scope: OrgScope
) -> AsyncIterator[AsyncSession]:
    """Open a session already bound to ``scope``, committing on clean exit.

    For non-HTTP callers (the lease sweeper, enrichment jobs, tests). HTTP
    requests get their session from ``api.dependencies.get_session`` instead.
    """
    async with session_factory() as session:
        await bind_scope(session, scope)
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        else:
            await session.commit()
