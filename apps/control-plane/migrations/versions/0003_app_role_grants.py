"""Privileges for the application role, including append-only ``audit_log``.

The role name comes from ``-x app_role=`` or ``TS_DB_APP_ROLE``.

**If the role does not exist this migration fails.** It used to no-op silently,
which started a bad chain: the operator gets an application with zero privileges
where every query returns ``permission denied``, and the quickest way to make
that stop is to point the application at the superuser DSN — which works
instantly and silently disables Row-Level Security. Failing here keeps the
problem visible at the step that caused it, while it is still cheap to fix.

Create the role first::

    psql -d <database> -v role_password="'<generated>'" -f scripts/bootstrap_db.sql

To skip the grants deliberately — a developer running the schema against a local
superuser database, or a CI job that only checks migrations apply and roll back —
opt in explicitly::

    alembic -x allow_missing_role=1 upgrade head
    TS_ALLOW_MISSING_APP_ROLE=1 alembic upgrade head

Both forms are greppable, which a silent default was not.

``audit_log`` gets INSERT and SELECT only. UPDATE and DELETE are never granted,
so the application physically cannot rewrite its own audit trail — that is what
"append-only" has to mean to be worth anything.

Revision ID: 0003
Revises: 0002
"""

from __future__ import annotations

import os
import re
from collections.abc import Sequence

from alembic import context, op
from sqlalchemy import text

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APPEND_ONLY_TABLES: tuple[str, ...] = ("audit_log",)

READ_ONLY_TABLES: tuple[str, ...] = ("vulnerabilities",)

FULL_ACCESS_TABLES: tuple[str, ...] = (
    "orgs",
    "users",
    "refresh_tokens",
    "agents",
    "enrollment_tokens",
    "networks",
    "business_services",
    "assets",
    "asset_services",
    "scan_jobs",
    "scan_results",
    "ports",
    "findings",
)


#: A role name is interpolated into DDL, where bind parameters are not allowed.
#: Restricting it to an identifier-shaped string is what keeps that safe.
_ROLE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")


def app_role() -> str:
    """``-x app_role=`` beats ``TS_DB_APP_ROLE`` beats the default."""
    override = context.get_x_argument(as_dictionary=True).get("app_role")
    role = override or os.environ.get("TS_DB_APP_ROLE", "threatsculpt_app")
    if not _ROLE_NAME.match(role):
        raise ValueError(f"invalid database role name: {role!r}")
    return role


def _role_exists(role: str) -> bool:
    connection = op.get_bind()
    result = connection.execute(
        text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role}
    )
    return result.first() is not None


class MissingApplicationRoleError(RuntimeError):
    """The application role does not exist and no opt-out was given."""


def _allow_missing_role() -> bool:
    """Explicit opt-out, via ``-x allow_missing_role=1`` or the environment."""
    override = context.get_x_argument(as_dictionary=True).get("allow_missing_role", "")
    flag = override or os.environ.get("TS_ALLOW_MISSING_APP_ROLE", "")
    return flag.strip().lower() in {"1", "true", "yes", "on"}


def _refuse(role: str) -> None:
    raise MissingApplicationRoleError(
        f"Database role {role!r} does not exist, so no privileges can be granted "
        "and the application would start with none.\n\n"
        "Create it first:\n"
        "    psql -d <database> -v role_password=\"'<generated>'\" "
        "-f scripts/bootstrap_db.sql\n\n"
        "Or skip the grants deliberately (local schema checks, CI migration "
        "smoke tests) with:\n"
        "    alembic -x allow_missing_role=1 upgrade head\n"
        "    TS_ALLOW_MISSING_APP_ROLE=1 alembic upgrade head\n\n"
        "Do not work around a missing role by pointing the application at a "
        "superuser DSN: PostgreSQL ignores every Row-Level Security policy for "
        "a SUPERUSER or BYPASSRLS role, which removes tenancy isolation silently."
    )


def upgrade() -> None:
    role = app_role()
    if not _role_exists(role):
        if not _allow_missing_role():
            _refuse(role)
        print(f"[0003] role {role!r} does not exist; skipping grants (opted in)")
        return

    op.execute(f"GRANT USAGE ON SCHEMA public TO {role}")
    for table in FULL_ACCESS_TABLES:
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {role}")
    for table in READ_ONLY_TABLES:
        op.execute(f"GRANT SELECT ON {table} TO {role}")
    for table in APPEND_ONLY_TABLES:
        op.execute(f"GRANT SELECT, INSERT ON {table} TO {role}")
        op.execute(f"REVOKE UPDATE, DELETE, TRUNCATE ON {table} FROM {role}")


def downgrade() -> None:
    """Revoking privileges from a role that is already gone is a no-op.

    Unlike ``upgrade``, a missing role here is not a problem worth failing on:
    there is nothing to revoke and nothing downstream can be misled by it.
    """
    role = app_role()
    if not _role_exists(role):
        return

    for table in APPEND_ONLY_TABLES + READ_ONLY_TABLES + FULL_ACCESS_TABLES:
        op.execute(f"REVOKE ALL ON {table} FROM {role}")
    op.execute(f"REVOKE USAGE ON SCHEMA public FROM {role}")
