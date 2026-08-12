"""Layer 2 of tenancy enforcement: an ORM-level guard.

The schema (``org_id NOT NULL``) is layer 1 and RLS is layer 3. This module is
the part that turns "we always remember to filter by org" into something the
process refuses to do wrong.

How it works: every ORM statement is intercepted before execution. If it touches
a table carrying ``org_id`` and does *not* carry the scoped execution option
that ``ScopedRepository`` stamps on, execution raises ``TenancyViolationError``.

So this raises:

    await session.execute(select(Network))            # no scope -> refused

and this is the only shape that runs:

    repo = ScopedRepository(session, scope, Network)
    await repo.list(pagination)

The escape hatch for pre-authentication credential lookups is
``tenancy.credentials``; it is a named, audited exception rather than an
accidental one, and it is limited to SELECT-by-hash on two tables.
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

from sqlalchemy import Delete, Insert, Select, Update
from sqlalchemy.orm import ORMExecuteState, Session
from sqlalchemy.sql import ClauseElement
from sqlalchemy.sql.expression import Executable

from threatsculpt.core.errors import TenancyViolationError
from threatsculpt.db.base import tenant_table_names
from threatsculpt.tenancy.scope import GUC_NAME, OrgScope

logger = logging.getLogger(__name__)

#: Execution option stamped by the scoped repository; its value is the org UUID.
SCOPED_OPTION = "threatsculpt_org_id"

#: Execution option for the two pre-authentication credential lookups.
CREDENTIAL_LOOKUP_OPTION = "threatsculpt_credential_lookup"

#: Key under which the bound scope lives in ``Session.info``.
SESSION_SCOPE_KEY = "threatsculpt_scope"


def bound_scope(session: Session | Any) -> OrgScope | None:
    """The scope bound to this session, if any. Accepts sync or async sessions."""
    info = getattr(session, "info", None)
    if info is None:
        return None
    value = info.get(SESSION_SCOPE_KEY)
    return value if isinstance(value, OrgScope) else None


_GUARD_INSTALLED = False


def install_guard_globally() -> None:
    """Attach the guard to every ``Session``. Idempotent.

    Registered on the class rather than on one factory so that a session built
    somewhere unexpected — a script, a test helper, a future background worker —
    is guarded too. Opting out would require deleting this listener, which is a
    visible act rather than an omission.
    """
    global _GUARD_INSTALLED
    if _GUARD_INSTALLED:
        return

    from sqlalchemy import event

    event.listen(Session, "do_orm_execute", _on_orm_execute)
    event.listen(Session, "after_begin", _reapply_guc_on_new_transaction)
    _GUARD_INSTALLED = True


def _reapply_guc_on_new_transaction(session: Session, transaction: Any, connection: Any) -> None:
    """Re-issue ``SET LOCAL`` whenever a new transaction starts on a scoped session.

    ``set_config(..., is_local => true)`` dies with its transaction. After a
    rollback the session would otherwise keep its Python-side scope while the
    database lost the GUC — RLS would then deny everything (fail-closed, but
    confusingly). Re-applying keeps layer 2 and layer 3 in agreement.
    """
    scope = bound_scope(session)
    if scope is None:
        return
    connection.exec_driver_sql("SELECT set_config(%s, %s, true)", (GUC_NAME, scope.guc_value()))


def _on_orm_execute(state: ORMExecuteState) -> None:
    statement = state.statement
    touched = _tenant_tables_in(statement)
    if not touched:
        return

    options = state.execution_options
    if options.get(CREDENTIAL_LOOKUP_OPTION):
        _assert_credential_lookup_is_a_select(statement, touched)
        return

    declared = options.get(SCOPED_OPTION)
    if declared is None:
        raise TenancyViolationError(
            f"unscoped access to tenant table(s) {sorted(touched)}: statements touching "
            "customer data must go through ScopedRepository"
        )

    scope = bound_scope(state.session)
    if scope is None:
        raise TenancyViolationError(
            f"tenant table(s) {sorted(touched)} accessed on a session with no bound OrgScope"
        )
    if not scope.owns(_as_uuid(declared)):
        raise TenancyViolationError("statement scope does not match the scope bound to the session")


def _assert_credential_lookup_is_a_select(
    statement: Executable | ClauseElement, touched: frozenset[str]
) -> None:
    """The credential escape hatch may read, never write."""
    if not isinstance(statement, Select):
        raise TenancyViolationError(
            f"credential lookup may only SELECT; refused on {sorted(touched)}"
        )


def _as_uuid(value: object) -> UUID:
    if isinstance(value, UUID):
        return value
    if isinstance(value, str):
        return UUID(value)
    raise TenancyViolationError("scoped execution option must carry a UUID org id")


def _tenant_tables_in(statement: Executable | ClauseElement) -> frozenset[str]:
    """Names of tenant tables referenced by ``statement``."""
    registry = tenant_table_names()
    if not registry:
        return frozenset()

    candidates: set[str] = set()
    if isinstance(statement, Select):
        for from_clause in statement.get_final_froms():
            candidates.update(_table_names_of(from_clause))
        for column in statement.exported_columns:
            table = getattr(column, "table", None)
            if table is not None:
                candidates.update(_table_names_of(table))
    elif isinstance(statement, (Update, Delete, Insert)):
        candidates.update(_table_names_of(statement.table))
    else:
        return frozenset()

    return frozenset(candidates & registry)


def _table_names_of(element: object) -> set[str]:
    """Collect table names from a FROM element, descending into joins/aliases."""
    names: set[str] = set()
    name = getattr(element, "name", None)
    if isinstance(name, str):
        names.add(name)
    for attribute in ("left", "right", "element", "original"):
        child = getattr(element, attribute, None)
        if child is not None and child is not element:
            names |= _table_names_of(child)
    return names
