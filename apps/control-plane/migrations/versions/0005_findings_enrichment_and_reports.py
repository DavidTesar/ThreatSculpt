"""Match confidence on findings, CPE version ranges, reports, dashboard indexes.

Four additive changes, none of which alter an existing column:

1. ``findings.match_confidence`` / ``match_method`` / ``match_rationale`` — how
   sure the CPE matcher was, persisted rather than inferred. Existing rows
   default to ``high``, which is the honest default for rows that only a
   confident matcher could have produced.
2. ``vulnerability_cpe_matches`` — NVD's vulnerable-configuration rows with
   their version windows. ``vulnerabilities.cpes`` remains the GIN-indexed
   first-pass filter; this table is what makes "2.0 <= version < 2.15.0" a
   thing the matcher can actually evaluate.
3. ``reports`` — generated artifacts, tenant-scoped, with the RLS policy and
   ``FORCE`` that every other tenant table carries. A new tenant table without
   a policy is a tenant table with no isolation, so the policy lands in the
   same migration as the table rather than a later one.
4. Composite indexes for the executive dashboard. Every aggregate it runs is
   ``WHERE org_id = ?`` plus one more predicate; without these each one is a
   sequential scan over the org's whole finding history on the most-hit
   endpoint in the product.

Grants: the app role gains write access to ``vulnerabilities`` and
``vulnerability_cpe_matches``, which migration 0003 left read-only. The CVE
mirror sync runs in-process under the same role, and no HTTP route writes
either table — the only writer is ``threatsculpt.enrichment.sync``.

Revision ID: 0005
Revises: 0004
"""

from __future__ import annotations

import os
import re
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op
from sqlalchemy import text
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ORG_GUC = "threatsculpt.org_id"
_ORG_PREDICATE = f"org_id = NULLIF(current_setting('{ORG_GUC}', true), '')::uuid"

#: New tenant tables introduced by this revision.
NEW_TENANT_TABLES: tuple[str, ...] = ("reports",)

#: Tables the CVE mirror sync writes. Not tenant-scoped: one sync serves every
#: tenant, which is the whole reason enrichment is server-side.
GLOBAL_WRITABLE_TABLES: tuple[str, ...] = ("vulnerabilities", "vulnerability_cpe_matches")

#: Same identifier guard as migration 0003 — a role name is interpolated into
#: DDL, where bind parameters are not permitted.
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
    _create_cpe_match_table()
    _create_reports_table()
    _extend_findings()
    _enable_rls()
    _grant()


def _create_cpe_match_table() -> None:
    op.create_table(
        "vulnerability_cpe_matches",
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("cpe23", sa.String(length=512), nullable=False),
        sa.Column("vendor", sa.String(length=255), nullable=False),
        sa.Column("product", sa.String(length=255), nullable=False),
        sa.Column("version_start_including", sa.String(length=128), nullable=True),
        sa.Column("version_start_excluding", sa.String(length=128), nullable=True),
        sa.Column("version_end_including", sa.String(length=128), nullable=True),
        sa.Column("version_end_excluding", sa.String(length=128), nullable=True),
        sa.Column("vulnerable", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
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
        sa.ForeignKeyConstraint(
            ["cve_id"],
            ["vulnerabilities.cve_id"],
            name=op.f("fk_vulnerability_cpe_matches_cve_id"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_vulnerability_cpe_matches")),
    )
    op.create_index(
        op.f("ix_vulnerability_cpe_matches_created_at"),
        "vulnerability_cpe_matches",
        ["created_at"],
    )
    op.create_index("ix_vulnerability_cpe_matches_cve_id", "vulnerability_cpe_matches", ["cve_id"])
    op.create_index(
        "ix_vulnerability_cpe_matches_vendor_product",
        "vulnerability_cpe_matches",
        ["vendor", "product"],
    )
    # Re-syncing the mirror must update a criteria row, not append a second copy.
    op.create_index(
        "uq_vulnerability_cpe_matches_cve_id_cpe23",
        "vulnerability_cpe_matches",
        ["cve_id", "cpe23"],
        unique=True,
    )


def _create_reports_table() -> None:
    op.create_table(
        "reports",
        sa.Column("type", sa.String(length=64), nullable=False),
        sa.Column("format", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="queued", nullable=False),
        sa.Column(
            "scope",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("content_type", sa.String(length=128), nullable=True),
        sa.Column("byte_size", sa.Integer(), nullable=True),
        sa.Column("error", sa.String(length=2000), nullable=True),
        sa.Column("requested_by_user_id", sa.UUID(), nullable=True),
        sa.Column("generated_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("org_id", sa.UUID(), nullable=False),
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
        sa.CheckConstraint("format IN ('html')", name=op.f("ck_reports_reports_format_valid")),
        sa.CheckConstraint(
            "status IN ('queued','generating','ready','failed')",
            name=op.f("ck_reports_reports_status_valid"),
        ),
        sa.CheckConstraint(
            "type IN ('executive_summary')", name=op.f("ck_reports_reports_type_valid")
        ),
        sa.CheckConstraint(
            "byte_size IS NULL OR byte_size >= 0", name=op.f("ck_reports_reports_byte_size_valid")
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_reports_org_id"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_user_id"],
            ["users.id"],
            name=op.f("fk_reports_requested_by_user_id"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_reports")),
    )
    op.create_index(op.f("ix_reports_created_at"), "reports", ["created_at"])
    op.create_index(op.f("ix_reports_org_id"), "reports", ["org_id"])
    op.create_index("ix_reports_org_id_created_at", "reports", ["org_id", "created_at"])


def _extend_findings() -> None:
    op.add_column(
        "findings",
        sa.Column("match_confidence", sa.String(length=16), server_default="high", nullable=False),
    )
    op.add_column("findings", sa.Column("match_method", sa.String(length=64), nullable=True))
    op.add_column("findings", sa.Column("match_rationale", sa.String(length=1000), nullable=True))
    op.create_check_constraint(
        op.f("ck_findings_findings_match_confidence_valid"),
        "findings",
        "match_confidence IN ('high','medium','low')",
    )

    op.create_index("ix_findings_org_id_cve_id", "findings", ["org_id", "cve_id"])
    op.create_index("ix_findings_org_id_first_seen_at", "findings", ["org_id", "first_seen_at"])
    op.create_index("ix_findings_org_id_resolved_at", "findings", ["org_id", "resolved_at"])
    # The default `/findings` sort and the dashboard's worst-score aggregates
    # both read this index in order, so the score is stored descending.
    op.create_index(
        "ix_findings_org_id_status_score",
        "findings",
        ["org_id", "status", sa.literal_column("business_risk_score DESC")],
    )


def _enable_rls() -> None:
    for table in NEW_TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        # FORCE is what makes the policy bind for the table's owner too.
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY {table}_org_isolation ON {table}
                USING ({_ORG_PREDICATE})
                WITH CHECK ({_ORG_PREDICATE})
            """
        )


def _grant() -> None:
    role = app_role()
    if not _role_exists(role):
        print(f"[0005] role {role!r} does not exist; skipping grants")
        return
    for table in (*NEW_TENANT_TABLES, *GLOBAL_WRITABLE_TABLES):
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {role}")


def downgrade() -> None:
    role = app_role()
    if _role_exists(role):
        for table in (*NEW_TENANT_TABLES, *GLOBAL_WRITABLE_TABLES):
            op.execute(f"REVOKE ALL ON {table} FROM {role}")
        # 0003 left ``vulnerabilities`` readable; restore that rather than
        # leaving the application unable to read the CVE mirror at all.
        op.execute(f"GRANT SELECT ON vulnerabilities TO {role}")

    for table in NEW_TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {table}_org_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")

    op.drop_constraint(
        op.f("ck_findings_findings_match_confidence_valid"), "findings", type_="check"
    )
    op.drop_index("ix_findings_org_id_status_score", table_name="findings")
    op.drop_index("ix_findings_org_id_resolved_at", table_name="findings")
    op.drop_index("ix_findings_org_id_first_seen_at", table_name="findings")
    op.drop_index("ix_findings_org_id_cve_id", table_name="findings")
    op.drop_column("findings", "match_rationale")
    op.drop_column("findings", "match_method")
    op.drop_column("findings", "match_confidence")

    op.drop_index("ix_reports_org_id_created_at", table_name="reports")
    op.drop_index(op.f("ix_reports_org_id"), table_name="reports")
    op.drop_index(op.f("ix_reports_created_at"), table_name="reports")
    op.drop_table("reports")

    op.drop_index(
        "uq_vulnerability_cpe_matches_cve_id_cpe23", table_name="vulnerability_cpe_matches"
    )
    op.drop_index(
        "ix_vulnerability_cpe_matches_vendor_product", table_name="vulnerability_cpe_matches"
    )
    op.drop_index("ix_vulnerability_cpe_matches_cve_id", table_name="vulnerability_cpe_matches")
    op.drop_index(
        op.f("ix_vulnerability_cpe_matches_created_at"), table_name="vulnerability_cpe_matches"
    )
    op.drop_table("vulnerability_cpe_matches")
