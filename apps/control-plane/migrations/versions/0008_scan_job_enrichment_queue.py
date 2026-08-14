"""The enrichment queue, carried on ``scan_jobs``.

Until this revision a scan that finished produced assets and ports and nothing
else: ``enrichment.service.generate_findings`` had no caller anywhere in the
request path, so ``findings`` stayed empty in any running system and every
dashboard and report rendered zeros. These three columns are the queue that
connects the two halves.

**Columns rather than a table.** The queue is one-to-one with a scan job and
carries no state a job does not already have a place for. A separate table would
need its own tenant policy, its own grants and its own foreign key, all of which
``scan_jobs`` already has correctly — and, more importantly, it could not be
written by the same UPDATE that completes the job. That single-statement
property is the point: a job must not be able to reach ``completed`` without
being marked for enrichment, because two writes leave a window in which a crash
strands a finished scan with no findings, forever and silently.

``enrichment_status`` is nullable and NULL means *not a candidate*. A job that
has not completed has nothing to enrich, and a fourth enum value for that state
would put every queued job into the claim query's index for no benefit.

**Existing completed jobs are backfilled to ``pending``.** They are exactly the
rows the missing caller stranded, and leaving them NULL would upgrade a
deployment into the same empty dashboard it had before. The worker is bounded
and idempotent — a finding upsert refreshes rather than duplicates — so the
catch-up pass costs one enrichment run per historical job and produces the
findings those scans should have created when they ran.

Revision ID: 0008
Revises: 0007
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: Kept in step with ``models.scan.MAX_ENRICHMENT_ATTEMPTS``. Spelled out here
#: because a migration must not import application code that will keep moving.
_MAX_ENRICHMENT_ATTEMPTS = 3


def upgrade() -> None:
    op.add_column("scan_jobs", sa.Column("enrichment_status", sa.String(length=32), nullable=True))
    op.add_column(
        "scan_jobs",
        sa.Column("enrichment_attempts", sa.Integer(), nullable=False, server_default="0"),
    )
    op.add_column(
        "scan_jobs",
        sa.Column(
            "enrichment_lease_expires_at", postgresql.TIMESTAMP(timezone=True), nullable=True
        ),
    )

    op.create_check_constraint(
        "scan_jobs_enrichment_status_valid",
        "scan_jobs",
        "enrichment_status IS NULL OR "
        "enrichment_status IN ('pending','running','complete','failed')",
    )
    op.create_check_constraint(
        "scan_jobs_enrichment_attempts_bounded",
        "scan_jobs",
        f"enrichment_attempts >= 0 AND enrichment_attempts <= {_MAX_ENRICHMENT_ATTEMPTS}",
    )

    # Backs the claim query, which reads work waiting *and* work whose lease
    # lapsed in one statement, ordered by creation. Partial, so the index holds
    # only the jobs actually in the queue rather than every scan ever run.
    op.create_index(
        "ix_scan_jobs_enrichment_claimable",
        "scan_jobs",
        ["org_id", "created_at"],
        postgresql_where=sa.text("enrichment_status IN ('pending','running')"),
    )

    op.execute(
        "UPDATE scan_jobs SET enrichment_status = 'pending' "
        "WHERE status = 'completed' AND enrichment_status IS NULL"
    )


def downgrade() -> None:
    op.drop_index("ix_scan_jobs_enrichment_claimable", table_name="scan_jobs")
    op.drop_constraint("scan_jobs_enrichment_attempts_bounded", "scan_jobs", type_="check")
    op.drop_constraint("scan_jobs_enrichment_status_valid", "scan_jobs", type_="check")
    op.drop_column("scan_jobs", "enrichment_lease_expires_at")
    op.drop_column("scan_jobs", "enrichment_attempts")
    op.drop_column("scan_jobs", "enrichment_status")
