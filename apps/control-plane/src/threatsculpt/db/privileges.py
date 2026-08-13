"""Startup check: the application must not connect as a privileged role.

Row-Level Security is layer 3 of tenancy isolation, and PostgreSQL silently
ignores every policy for a role with ``SUPERUSER`` or ``BYPASSRLS``. There is no
error, no warning, and no log line — the application keeps serving traffic and
looks completely healthy while one of the three isolation layers has quietly
stopped existing.

That state is reachable by an ordinary operational mistake. Migration 0003 grants
privileges to the application role; an operator who migrates before creating that
role gets an application with no privileges at all, where every query fails with
``permission denied``. The fastest way to make those errors stop is to point the
application at the superuser DSN — which works instantly, and removes RLS.

Layer 2 does not cover the gap: the ORM guard inspects ORM statements, so raw
``text()`` SQL passes straight through it. With RLS bypassed, a raw query is
unfenced.

So this is checked once at startup and the process refuses to boot. A warning
would not do — a warning in a log nobody reads is exactly how this ships.
"""

from __future__ import annotations

import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

logger = logging.getLogger(__name__)

_ROLE_ATTRIBUTES_SQL = text(
    "SELECT current_user AS role_name, rolsuper, rolbypassrls "
    "FROM pg_roles WHERE rolname = current_user"
)

ESCAPE_HATCH_ENV_VAR = "TS_ALLOW_SUPERUSER_DB"


class InsecureDatabaseRoleError(RuntimeError):
    """The configured database role would bypass Row-Level Security."""


class DatabaseRolePrivileges:
    """What PostgreSQL reports about the role we are connected as."""

    __slots__ = ("bypasses_rls", "is_superuser", "role_name")

    def __init__(self, role_name: str, is_superuser: bool, bypasses_rls: bool) -> None:
        self.role_name = role_name
        self.is_superuser = is_superuser
        self.bypasses_rls = bypasses_rls

    @property
    def bypasses_row_level_security(self) -> bool:
        return self.is_superuser or self.bypasses_rls

    def reasons(self) -> list[str]:
        reasons = []
        if self.is_superuser:
            reasons.append("SUPERUSER")
        if self.bypasses_rls:
            reasons.append("BYPASSRLS")
        return reasons


async def read_role_privileges(engine: AsyncEngine) -> DatabaseRolePrivileges:
    """Ask the database what the connected role is allowed to do."""
    async with engine.connect() as connection:
        row = (await connection.execute(_ROLE_ATTRIBUTES_SQL)).one()
    return DatabaseRolePrivileges(
        role_name=str(row.role_name),
        is_superuser=bool(row.rolsuper),
        bypasses_rls=bool(row.rolbypassrls),
    )


def build_refusal_message(privileges: DatabaseRolePrivileges) -> str:
    """The error an operator will actually read, at the moment it matters."""
    attributes = " and ".join(privileges.reasons())
    return (
        f"Refusing to start: the database role {privileges.role_name!r} has "
        f"{attributes}, and PostgreSQL silently ignores every Row-Level Security "
        "policy for such a role. Tenancy isolation would be reduced without any "
        "error or log entry.\n\n"
        "Fix: create the unprivileged application role and point "
        "TS_DATABASE_URL at it —\n"
        "    psql -d <database> -v role_password=\"'<generated>'\" "
        "-f scripts/bootstrap_db.sql\n"
        "then re-run 'alembic upgrade head' so the role receives its grants.\n\n"
        f"To override for local development only, set {ESCAPE_HATCH_ENV_VAR}=1. "
        "Never set it in a deployed environment."
    )


async def assert_database_role_is_unprivileged(
    engine: AsyncEngine, *, allow_superuser: bool = False
) -> DatabaseRolePrivileges:
    """Refuse to boot on a role that bypasses RLS.

    Returns the privileges when the check passes so a caller can log them.
    Raises ``InsecureDatabaseRoleError`` when it does not.
    """
    privileges = await read_role_privileges(engine)

    if not privileges.bypasses_row_level_security:
        logger.info(
            "database role verified as unprivileged",
            extra={"db_role": privileges.role_name},
        )
        return privileges

    if allow_superuser:
        # Deliberate, greppable opt-out. Logged at CRITICAL every boot so that
        # an override left on by accident is visible rather than forgotten.
        logger.critical(
            "RLS BYPASSED: running as a privileged database role because "
            f"{ESCAPE_HATCH_ENV_VAR} is set. Tenancy isolation is reduced to the "
            "query layer. This must never be set in a deployed environment.",
            extra={
                "db_role": privileges.role_name,
                "role_attributes": privileges.reasons(),
                "event": "rls_bypass_permitted",
            },
        )
        return privileges

    raise InsecureDatabaseRoleError(build_refusal_message(privileges))
