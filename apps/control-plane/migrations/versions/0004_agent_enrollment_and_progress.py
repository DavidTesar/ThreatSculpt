"""Enrollment consumption policies and scan job progress.

Two additive changes, both required by docs/AGENT-PROTOCOL.md.

**1. ``scan_jobs.progress_percent``** — §5 has the agent post progress while a
scan runs. Without a column the number would be accepted and thrown away, which
is worse than not accepting it.

**2. RLS policies for enrollment.** ``POST /agent/enroll`` is unauthenticated by
construction: the caller holds a one-time token and nothing else, so no
``OrgScope`` can exist until the token row has been found. That row lives in
``enrollment_tokens``, which migration 0002 fenced behind
``org_id = current_setting('threatsculpt.org_id')``. An unscoped session sees
zero rows there — fail-closed, and also unable to enroll.

The fix is the same shape 0002 already uses for ``threatsculpt.authn``: a third
GUC, set by exactly one function
(``threatsculpt.agents.enrollment.consume_enrollment_token``) around exactly one
statement. Two policies rather than one ``FOR ALL`` so the grant stays as narrow
as the operation:

* SELECT — needed because the consuming UPDATE has a ``RETURNING`` clause, and
  PostgreSQL requires a SELECT policy for the returned row.
* UPDATE — its ``USING`` clause repeats the single-use and expiry conditions, so
  even a caller that reached this statement with the wrong ``WHERE`` could not
  consume a spent or expired token. The rule is enforced in the database, not
  only in the application.

Neither policy permits INSERT or DELETE: tokens are created by an authenticated
admin through the ordinary scoped path.

Revision ID: 0004
Revises: 0003
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ENROLL_GUC = "threatsculpt.enroll"
TABLE = "enrollment_tokens"

SELECT_POLICY = f"{TABLE}_enroll_select"
UPDATE_POLICY = f"{TABLE}_enroll_consume"

PROGRESS_CONSTRAINT = "scan_jobs_progress_in_range"

_ENROLL_PREDICATE = f"current_setting('{ENROLL_GUC}', true) = 'on'"


def upgrade() -> None:
    op.add_column("scan_jobs", sa.Column("progress_percent", sa.Integer(), nullable=True))
    op.create_check_constraint(
        PROGRESS_CONSTRAINT,
        "scan_jobs",
        "progress_percent IS NULL OR (progress_percent >= 0 AND progress_percent <= 100)",
    )

    op.execute(
        f"""
        CREATE POLICY {SELECT_POLICY} ON {TABLE}
            FOR SELECT
            USING ({_ENROLL_PREDICATE})
        """
    )
    op.execute(
        f"""
        CREATE POLICY {UPDATE_POLICY} ON {TABLE}
            FOR UPDATE
            USING ({_ENROLL_PREDICATE} AND used_at IS NULL AND expires_at > now())
            WITH CHECK ({_ENROLL_PREDICATE})
        """
    )


def downgrade() -> None:
    op.execute(f"DROP POLICY IF EXISTS {UPDATE_POLICY} ON {TABLE}")
    op.execute(f"DROP POLICY IF EXISTS {SELECT_POLICY} ON {TABLE}")
    # The short name, not the rendered one: alembic applies the metadata naming
    # convention on the way down exactly as it did on the way up.
    op.drop_constraint(PROGRESS_CONSTRAINT, "scan_jobs", type_="check")
    op.drop_column("scan_jobs", "progress_percent")
