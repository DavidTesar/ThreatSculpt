"""Running scoped statements that ``ScopedRepository`` cannot express.

``ScopedRepository`` covers CRUD on one mapped model, which is the right shape
for a resource endpoint and the wrong shape for two things this service needs:

* aggregate queries — the executive dashboard has to be ``GROUP BY`` in SQL, not
  a Python loop over every finding in the org;
* multi-table joins and ``INSERT ... ON CONFLICT`` upserts.

Rewriting those as repository calls would mean pulling rows into Python to count
them, which is the N+1 the dashboard cannot afford. So they are built as Core
statements and run through here.

This is a narrower thing than it looks. It does **not** loosen tenancy:

1. ``execute`` refuses unless the session is already bound to the same scope.
2. Every statement still carries the guard's execution option, so the ORM guard
   in ``tenancy.guard`` is satisfied honestly rather than bypassed.
3. Callers still write the ``org_id`` predicate themselves, and RLS is still
   underneath — a statement that forgot its predicate returns nothing rather
   than another tenant's rows, because the policy is evaluated in the database.

The cross-tenant tests exercise the endpoints built on this, not just the
repository, precisely because an aggregate is an easy place to leak a count.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from sqlalchemy import Executable
from sqlalchemy.engine import Result
from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.core.errors import TenancyViolationError
from threatsculpt.tenancy.guard import SCOPED_OPTION, bound_scope
from threatsculpt.tenancy.scope import OrgScope


def scoped(statement: Executable, scope: OrgScope) -> Executable:
    """Stamp ``statement`` with the execution option the ORM guard requires."""
    return statement.execution_options(**{SCOPED_OPTION: scope.org_id})


async def execute_scoped(
    session: AsyncSession,
    scope: OrgScope,
    statement: Executable,
    params: Sequence[Mapping[str, Any]] | Mapping[str, Any] | None = None,
) -> Result[Any]:
    """Run a Core statement under ``scope``, refusing a mismatched session.

    ``params`` may be a list of dicts, which becomes one executemany round trip
    — the shape a re-score of thousands of historical findings needs.
    """
    session_scope = bound_scope(session)
    if session_scope is None or session_scope.org_id != scope.org_id:
        raise TenancyViolationError(
            "scoped statement does not match the scope bound to the session"
        )
    prepared = scoped(statement, scope)
    if params is None:
        return await session.execute(prepared)
    return await session.execute(prepared, params)
