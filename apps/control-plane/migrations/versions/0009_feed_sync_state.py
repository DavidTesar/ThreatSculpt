"""Somewhere durable for the CVE mirror sync to record how far it got.

Before this revision the mirror could not be synced at all in production, and
the shape of the fix is what forces a new table. NVD 2.0 serves 2,000 results
per request against roughly 300,000 CVEs, so a cold sync is roughly 150 requests
under an API key and roughly 1,500 without one — an hour at best, ten at worst,
and the rate limit is per source address so it cannot be parallelised away.

A sync that long has to be resumable. Holding the resume point in memory means a
process restart at hour nine starts again at zero, and on a connection that
drops more often than that the mirror never completes even once. So the progress
of a run has to survive the run.

``last_modified_at`` is the watermark and only advances when a whole window has
been written; ``window_start``/``window_end``/``next_start_index`` are the
resume point of a run still in flight. Keeping them apart is what stops a crash
mid-window from letting the next run skip the remainder: the watermark still
points at the last thing that genuinely finished.

Not tenant-scoped, exactly like ``vulnerabilities`` — it describes the state of
a global mirror and holds no customer data, so no ``org_id`` and no RLS policy.

Revision ID: 0009
Revises: 0008
"""

from __future__ import annotations

import os
import re
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy import text
from sqlalchemy.dialects import postgresql

revision: str = "0009"
down_revision: str | None = "0008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE_NAME = "feed_sync_state"

#: Same identifier guard as migrations 0003 and 0005 — a role name is
#: interpolated into DDL, where bind parameters are not permitted.
_ROLE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")


def app_role() -> str:
    override = context.get_x_argument(as_dictionary=True).get("app_role")
    role = override or os.environ.get("TS_DB_APP_ROLE", "threatsculpt_app")
    if not _ROLE_NAME.match(role):
        raise ValueError(f"invalid database role name: {role!r}")
    return role


def _role_exists(role: str) -> bool:
    result = op.get_bind().execute(
        text("SELECT 1 FROM pg_roles WHERE rolname = :role"), {"role": role}
    )
    return result.first() is not None


def upgrade() -> None:
    op.create_table(
        TABLE_NAME,
        sa.Column("feed", sa.String(length=32), nullable=False),
        sa.Column("last_modified_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("window_start", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("window_end", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("next_start_index", sa.Integer(), server_default="0", nullable=False),
        sa.Column("last_completed_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            postgresql.TIMESTAMP(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "next_start_index >= 0", name=op.f("ck_feed_sync_state_index_non_negative")
        ),
        # A half-set window is a resume point that cannot be resumed from.
        sa.CheckConstraint(
            "(window_start IS NULL) = (window_end IS NULL)",
            name=op.f("ck_feed_sync_state_window_complete"),
        ),
        sa.PrimaryKeyConstraint("feed", name=op.f("pk_feed_sync_state")),
    )
    op.create_index(op.f("ix_feed_sync_state_created_at"), TABLE_NAME, ["created_at"])
    _grant()


def _grant() -> None:
    role = app_role()
    if not _role_exists(role):
        print(f"[0009] role {role!r} does not exist; skipping grants")
        return
    # No DELETE: a watermark row is upserted for the life of the deployment.
    # Dropping one silently converts the next incremental sync into a ten-hour
    # cold one, which is not something the application should be able to do.
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {TABLE_NAME} TO {role}")


def downgrade() -> None:
    op.drop_index(op.f("ix_feed_sync_state_created_at"), table_name=TABLE_NAME)
    op.drop_table(TABLE_NAME)
