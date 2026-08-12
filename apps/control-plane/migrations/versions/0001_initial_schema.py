"""Initial schema — every table in docs/DATA-MODEL.md.

Creates the ``citext`` and ``pgcrypto`` extensions first: ``citext`` backs the
case-insensitive ``orgs.slug`` and ``users.email`` columns, and ``pgcrypto``
provides ``gen_random_uuid()`` used as the default for every primary key.

Row-Level Security is deliberately *not* here — it lands in 0002, so that the
tenancy policies are one reviewable diff rather than lines buried in 400 lines
of table DDL.

Revision ID: 0001
Revises:
Create Date: 2026-08-12 17:28:17.484337
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

import threatsculpt.db.types

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS citext")
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    op.create_table(
        "orgs",
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("slug", threatsculpt.db.types.CITEXT(), nullable=False),
        sa.Column("plan", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
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
        sa.CheckConstraint(
            "plan IN ('trial','standard','enterprise')", name=op.f("ck_orgs_orgs_plan_valid")
        ),
        sa.CheckConstraint(
            "status IN ('active','suspended')", name=op.f("ck_orgs_orgs_status_valid")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_orgs")),
        sa.UniqueConstraint("slug", name=op.f("uq_orgs_slug")),
    )
    op.create_index(op.f("ix_orgs_created_at"), "orgs", ["created_at"], unique=False)
    op.create_table(
        "vulnerabilities",
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("cvss_base", sa.Numeric(precision=3, scale=1), nullable=True),
        sa.Column("cvss_vector", sa.String(length=255), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=True),
        sa.Column(
            "cpes",
            postgresql.ARRAY(sa.Text()),
            server_default=sa.text("'{}'::text[]"),
            nullable=False,
        ),
        sa.Column("kev_listed", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("kev_due_date", sa.Date(), nullable=True),
        sa.Column("exploit_maturity", sa.String(length=32), server_default="none", nullable=False),
        sa.Column("published_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_synced_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
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
            "exploit_maturity IN ('weaponized','poc','none')",
            name=op.f("ck_vulnerabilities_vulnerabilities_exploit_maturity_valid"),
        ),
        sa.PrimaryKeyConstraint("cve_id", name=op.f("pk_vulnerabilities")),
    )
    op.create_index(
        "ix_vulnerabilities_cpes", "vulnerabilities", ["cpes"], unique=False, postgresql_using="gin"
    )
    op.create_index(
        op.f("ix_vulnerabilities_created_at"), "vulnerabilities", ["created_at"], unique=False
    )
    op.create_index(
        "ix_vulnerabilities_kev_listed", "vulnerabilities", ["kev_listed"], unique=False
    )
    op.create_table(
        "agents",
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("api_key_hash", sa.String(length=64), nullable=False),
        sa.Column("key_prefix", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=True),
        sa.Column(
            "allowlist",
            postgresql.ARRAY(postgresql.CIDR()),
            server_default=sa.text("'{}'::cidr[]"),
            nullable=False,
        ),
        sa.Column("last_seen_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
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
        sa.CheckConstraint(
            "status IN ('active','revoked')", name=op.f("ck_agents_agents_status_valid")
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_agents_org_id"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_agents")),
        sa.UniqueConstraint("api_key_hash", name=op.f("uq_agents_api_key_hash")),
    )
    op.create_index(op.f("ix_agents_created_at"), "agents", ["created_at"], unique=False)
    op.create_index(op.f("ix_agents_org_id"), "agents", ["org_id"], unique=False)
    op.create_table(
        "audit_log",
        sa.Column("actor_type", sa.String(length=16), nullable=False),
        sa.Column("actor_id", sa.UUID(), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("target_type", sa.String(length=64), nullable=True),
        sa.Column("target_id", sa.String(length=64), nullable=True),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
        sa.Column("ip", postgresql.INET(), nullable=True),
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
        sa.CheckConstraint(
            "actor_type IN ('user','agent','system')",
            name=op.f("ck_audit_log_audit_log_actor_type_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_audit_log_org_id"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_log")),
    )
    op.create_index(op.f("ix_audit_log_created_at"), "audit_log", ["created_at"], unique=False)
    op.create_index(op.f("ix_audit_log_org_id"), "audit_log", ["org_id"], unique=False)
    op.create_index("ix_audit_log_org_id_action", "audit_log", ["org_id", "action"], unique=False)
    op.create_index(
        "ix_audit_log_org_id_created_at", "audit_log", ["org_id", "created_at"], unique=False
    )
    op.create_table(
        "business_services",
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("description", sa.String(length=2000), nullable=True),
        sa.Column("criticality", sa.String(length=32), nullable=False),
        sa.Column("revenue_at_risk", sa.Numeric(precision=14, scale=2), nullable=True),
        sa.Column("owner_name", sa.String(length=200), nullable=True),
        sa.Column("owner_email", sa.String(length=320), nullable=True),
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
        sa.CheckConstraint(
            "criticality IN ('critical','high','medium','low')",
            name=op.f("ck_business_services_business_services_criticality_valid"),
        ),
        sa.CheckConstraint(
            "revenue_at_risk IS NULL OR revenue_at_risk >= 0",
            name=op.f("ck_business_services_business_services_revenue_non_negative"),
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_business_services_org_id"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_business_services")),
    )
    op.create_index(
        op.f("ix_business_services_created_at"), "business_services", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_business_services_org_id"), "business_services", ["org_id"], unique=False
    )
    op.create_table(
        "networks",
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("cidr", postgresql.CIDR(), nullable=False),
        sa.Column("authorized", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("authorization_note", sa.String(length=1000), nullable=True),
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
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_networks_org_id"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_networks")),
        sa.UniqueConstraint("org_id", "cidr", name="uq_networks_org_id_cidr"),
    )
    op.create_index(op.f("ix_networks_created_at"), "networks", ["created_at"], unique=False)
    op.create_index(op.f("ix_networks_org_id"), "networks", ["org_id"], unique=False)
    op.create_table(
        "users",
        sa.Column("email", threatsculpt.db.types.CITEXT(), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=200), nullable=True),
        sa.Column("role", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("last_login_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("failed_login_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("locked_until", postgresql.TIMESTAMP(timezone=True), nullable=True),
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
        sa.CheckConstraint(
            "role IN ('owner','admin','analyst','viewer')", name=op.f("ck_users_users_role_valid")
        ),
        sa.CheckConstraint(
            "status IN ('active','disabled')", name=op.f("ck_users_users_status_valid")
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_users_org_id"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("org_id", "email", name="uq_users_org_id_email"),
    )
    op.create_index(op.f("ix_users_created_at"), "users", ["created_at"], unique=False)
    op.create_index("ix_users_email", "users", ["email"], unique=False)
    op.create_index(op.f("ix_users_org_id"), "users", ["org_id"], unique=False)
    op.create_table(
        "assets",
        sa.Column("network_id", sa.UUID(), nullable=True),
        sa.Column("ip", postgresql.INET(), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("mac", postgresql.MACADDR(), nullable=True),
        sa.Column("os_family", sa.String(length=64), nullable=True),
        sa.Column("os_version", sa.String(length=64), nullable=True),
        sa.Column("exposure", sa.String(length=32), server_default="internal", nullable=False),
        sa.Column("first_seen_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_seen_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
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
        sa.CheckConstraint(
            "exposure IN ('internet','dmz','internal','isolated')",
            name=op.f("ck_assets_assets_exposure_valid"),
        ),
        sa.ForeignKeyConstraint(
            ["network_id"], ["networks.id"], name=op.f("fk_assets_network_id"), ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_assets_org_id"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_assets")),
        sa.UniqueConstraint("org_id", "ip", name="uq_assets_org_id_ip"),
    )
    op.create_index(op.f("ix_assets_created_at"), "assets", ["created_at"], unique=False)
    op.create_index(op.f("ix_assets_org_id"), "assets", ["org_id"], unique=False)
    op.create_index("ix_assets_org_id_exposure", "assets", ["org_id", "exposure"], unique=False)
    op.create_table(
        "enrollment_tokens",
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", postgresql.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("used_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("used_by_agent_id", sa.UUID(), nullable=True),
        sa.Column("created_by_user_id", sa.UUID(), nullable=True),
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
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name=op.f("fk_enrollment_tokens_created_by_user_id"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_enrollment_tokens_org_id"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["used_by_agent_id"],
            ["agents.id"],
            name=op.f("fk_enrollment_tokens_used_by_agent_id"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_enrollment_tokens")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_enrollment_tokens_token_hash")),
    )
    op.create_index(
        op.f("ix_enrollment_tokens_created_at"), "enrollment_tokens", ["created_at"], unique=False
    )
    op.create_index(
        "ix_enrollment_tokens_expires_at", "enrollment_tokens", ["expires_at"], unique=False
    )
    op.create_index(
        op.f("ix_enrollment_tokens_org_id"), "enrollment_tokens", ["org_id"], unique=False
    )
    op.create_table(
        "refresh_tokens",
        sa.Column("user_id", sa.UUID(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", postgresql.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("revoked_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("replaced_by", sa.UUID(), nullable=True),
        sa.Column("user_agent", sa.String(length=400), nullable=True),
        sa.Column("ip", postgresql.INET(), nullable=True),
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
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_refresh_tokens_org_id"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["replaced_by"],
            ["refresh_tokens.id"],
            name=op.f("fk_refresh_tokens_replaced_by"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"], name=op.f("fk_refresh_tokens_user_id"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_refresh_tokens")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_refresh_tokens_token_hash")),
    )
    op.create_index(
        op.f("ix_refresh_tokens_created_at"), "refresh_tokens", ["created_at"], unique=False
    )
    op.create_index("ix_refresh_tokens_expires_at", "refresh_tokens", ["expires_at"], unique=False)
    op.create_index(op.f("ix_refresh_tokens_org_id"), "refresh_tokens", ["org_id"], unique=False)
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"], unique=False)
    op.create_table(
        "scan_jobs",
        sa.Column("network_id", sa.UUID(), nullable=True),
        sa.Column("target", postgresql.CIDR(), nullable=False),
        sa.Column("profile", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="queued", nullable=False),
        sa.Column("agent_id", sa.UUID(), nullable=True),
        sa.Column("lease_expires_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("requested_by_user_id", sa.UUID(), nullable=True),
        sa.Column("started_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("finished_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("error", sa.String(length=2000), nullable=True),
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
        sa.CheckConstraint(
            "profile IN ('discovery','service','vulnerability')",
            name=op.f("ck_scan_jobs_scan_jobs_profile_valid"),
        ),
        sa.CheckConstraint(
            "status IN ('queued','claimed','running','completed','failed','cancelled')",
            name=op.f("ck_scan_jobs_scan_jobs_status_valid"),
        ),
        sa.CheckConstraint(
            "attempts >= 0 AND attempts <= 3", name=op.f("ck_scan_jobs_scan_jobs_attempts_bounded")
        ),
        sa.ForeignKeyConstraint(
            ["agent_id"], ["agents.id"], name=op.f("fk_scan_jobs_agent_id"), ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["network_id"],
            ["networks.id"],
            name=op.f("fk_scan_jobs_network_id"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_scan_jobs_org_id"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["requested_by_user_id"],
            ["users.id"],
            name=op.f("fk_scan_jobs_requested_by_user_id"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_jobs")),
    )
    op.create_index(op.f("ix_scan_jobs_created_at"), "scan_jobs", ["created_at"], unique=False)
    op.create_index(op.f("ix_scan_jobs_org_id"), "scan_jobs", ["org_id"], unique=False)
    op.create_index("ix_scan_jobs_org_id_status", "scan_jobs", ["org_id", "status"], unique=False)
    op.create_index(
        "ix_scan_jobs_queued",
        "scan_jobs",
        ["org_id", "created_at"],
        unique=False,
        postgresql_where=sa.text("status = 'queued'"),
    )
    op.create_table(
        "asset_services",
        sa.Column("asset_id", sa.UUID(), nullable=False),
        sa.Column("business_service_id", sa.UUID(), nullable=False),
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
        sa.ForeignKeyConstraint(
            ["asset_id"], ["assets.id"], name=op.f("fk_asset_services_asset_id"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["business_service_id"],
            ["business_services.id"],
            name=op.f("fk_asset_services_business_service_id"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_asset_services_org_id"), ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_asset_services")),
        sa.UniqueConstraint(
            "asset_id", "business_service_id", name="uq_asset_services_asset_id_business_service_id"
        ),
    )
    op.create_index(
        "ix_asset_services_business_service_id",
        "asset_services",
        ["business_service_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_asset_services_created_at"), "asset_services", ["created_at"], unique=False
    )
    op.create_index(op.f("ix_asset_services_org_id"), "asset_services", ["org_id"], unique=False)
    op.create_table(
        "scan_results",
        sa.Column("scan_job_id", sa.UUID(), nullable=False),
        sa.Column("asset_id", sa.UUID(), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=True),
        sa.Column(
            "raw",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
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
        sa.ForeignKeyConstraint(
            ["asset_id"], ["assets.id"], name=op.f("fk_scan_results_asset_id"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_scan_results_org_id"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["scan_job_id"],
            ["scan_jobs.id"],
            name=op.f("fk_scan_results_scan_job_id"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_results")),
    )
    op.create_index(
        op.f("ix_scan_results_created_at"), "scan_results", ["created_at"], unique=False
    )
    op.create_index(op.f("ix_scan_results_org_id"), "scan_results", ["org_id"], unique=False)
    op.create_index(
        "uq_scan_results_scan_job_id_asset_id",
        "scan_results",
        ["scan_job_id", "asset_id"],
        unique=True,
    )
    op.create_table(
        "ports",
        sa.Column("scan_result_id", sa.UUID(), nullable=False),
        sa.Column("asset_id", sa.UUID(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=16), nullable=False),
        sa.Column("state", sa.String(length=32), nullable=True),
        sa.Column("service", sa.String(length=128), nullable=True),
        sa.Column("product", sa.String(length=255), nullable=True),
        sa.Column("version", sa.String(length=128), nullable=True),
        sa.Column(
            "cpe",
            postgresql.ARRAY(sa.Text()),
            server_default=sa.text("'{}'::text[]"),
            nullable=False,
        ),
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
        sa.CheckConstraint("port > 0 AND port <= 65535", name=op.f("ck_ports_ports_port_in_range")),
        sa.ForeignKeyConstraint(
            ["asset_id"], ["assets.id"], name=op.f("fk_ports_asset_id"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_ports_org_id"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["scan_result_id"],
            ["scan_results.id"],
            name=op.f("fk_ports_scan_result_id"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_ports")),
    )
    op.create_index(op.f("ix_ports_created_at"), "ports", ["created_at"], unique=False)
    op.create_index(op.f("ix_ports_org_id"), "ports", ["org_id"], unique=False)
    op.create_index("ix_ports_org_id_asset_id", "ports", ["org_id", "asset_id"], unique=False)
    op.create_index("ix_ports_scan_result_id", "ports", ["scan_result_id"], unique=False)
    op.create_table(
        "findings",
        sa.Column("asset_id", sa.UUID(), nullable=False),
        sa.Column("port_id", sa.UUID(), nullable=True),
        sa.Column("scan_job_id", sa.UUID(), nullable=True),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=32), server_default="open", nullable=False),
        sa.Column("business_risk_score", sa.Numeric(precision=5, scale=2), nullable=False),
        sa.Column(
            "score_factors",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'"),
            nullable=False,
        ),
        sa.Column("first_seen_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("last_seen_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("resolved_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
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
        sa.CheckConstraint(
            "status IN ('open','accepted_risk','remediated','false_positive')",
            name=op.f("ck_findings_findings_status_valid"),
        ),
        sa.CheckConstraint(
            "business_risk_score >= 0", name=op.f("ck_findings_findings_score_non_negative")
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"], ["assets.id"], name=op.f("fk_findings_asset_id"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["cve_id"],
            ["vulnerabilities.cve_id"],
            name=op.f("fk_findings_cve_id"),
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["org_id"], ["orgs.id"], name=op.f("fk_findings_org_id"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["port_id"], ["ports.id"], name=op.f("fk_findings_port_id"), ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["scan_job_id"],
            ["scan_jobs.id"],
            name=op.f("fk_findings_scan_job_id"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_findings")),
        sa.UniqueConstraint(
            "org_id",
            "asset_id",
            "port_id",
            "cve_id",
            name="uq_findings_org_id_asset_id_port_id_cve_id",
        ),
    )
    op.create_index("ix_findings_asset_id", "findings", ["asset_id"], unique=False)
    op.create_index(op.f("ix_findings_created_at"), "findings", ["created_at"], unique=False)
    op.create_index(op.f("ix_findings_org_id"), "findings", ["org_id"], unique=False)
    op.create_index(
        "ix_findings_org_id_business_risk_score",
        "findings",
        ["org_id", "business_risk_score"],
        unique=False,
    )
    op.create_index("ix_findings_org_id_status", "findings", ["org_id", "status"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_findings_org_id_status", table_name="findings")
    op.drop_index("ix_findings_org_id_business_risk_score", table_name="findings")
    op.drop_index(op.f("ix_findings_org_id"), table_name="findings")
    op.drop_index(op.f("ix_findings_created_at"), table_name="findings")
    op.drop_index("ix_findings_asset_id", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_ports_scan_result_id", table_name="ports")
    op.drop_index("ix_ports_org_id_asset_id", table_name="ports")
    op.drop_index(op.f("ix_ports_org_id"), table_name="ports")
    op.drop_index(op.f("ix_ports_created_at"), table_name="ports")
    op.drop_table("ports")
    op.drop_index("uq_scan_results_scan_job_id_asset_id", table_name="scan_results")
    op.drop_index(op.f("ix_scan_results_org_id"), table_name="scan_results")
    op.drop_index(op.f("ix_scan_results_created_at"), table_name="scan_results")
    op.drop_table("scan_results")
    op.drop_index(op.f("ix_asset_services_org_id"), table_name="asset_services")
    op.drop_index(op.f("ix_asset_services_created_at"), table_name="asset_services")
    op.drop_index("ix_asset_services_business_service_id", table_name="asset_services")
    op.drop_table("asset_services")
    op.drop_index(
        "ix_scan_jobs_queued", table_name="scan_jobs", postgresql_where=sa.text("status = 'queued'")
    )
    op.drop_index("ix_scan_jobs_org_id_status", table_name="scan_jobs")
    op.drop_index(op.f("ix_scan_jobs_org_id"), table_name="scan_jobs")
    op.drop_index(op.f("ix_scan_jobs_created_at"), table_name="scan_jobs")
    op.drop_table("scan_jobs")
    op.drop_index("ix_refresh_tokens_user_id", table_name="refresh_tokens")
    op.drop_index(op.f("ix_refresh_tokens_org_id"), table_name="refresh_tokens")
    op.drop_index("ix_refresh_tokens_expires_at", table_name="refresh_tokens")
    op.drop_index(op.f("ix_refresh_tokens_created_at"), table_name="refresh_tokens")
    op.drop_table("refresh_tokens")
    op.drop_index(op.f("ix_enrollment_tokens_org_id"), table_name="enrollment_tokens")
    op.drop_index("ix_enrollment_tokens_expires_at", table_name="enrollment_tokens")
    op.drop_index(op.f("ix_enrollment_tokens_created_at"), table_name="enrollment_tokens")
    op.drop_table("enrollment_tokens")
    op.drop_index("ix_assets_org_id_exposure", table_name="assets")
    op.drop_index(op.f("ix_assets_org_id"), table_name="assets")
    op.drop_index(op.f("ix_assets_created_at"), table_name="assets")
    op.drop_table("assets")
    op.drop_index(op.f("ix_users_org_id"), table_name="users")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_index(op.f("ix_users_created_at"), table_name="users")
    op.drop_table("users")
    op.drop_index(op.f("ix_networks_org_id"), table_name="networks")
    op.drop_index(op.f("ix_networks_created_at"), table_name="networks")
    op.drop_table("networks")
    op.drop_index(op.f("ix_business_services_org_id"), table_name="business_services")
    op.drop_index(op.f("ix_business_services_created_at"), table_name="business_services")
    op.drop_table("business_services")
    op.drop_index("ix_audit_log_org_id_created_at", table_name="audit_log")
    op.drop_index("ix_audit_log_org_id_action", table_name="audit_log")
    op.drop_index(op.f("ix_audit_log_org_id"), table_name="audit_log")
    op.drop_index(op.f("ix_audit_log_created_at"), table_name="audit_log")
    op.drop_table("audit_log")
    op.drop_index(op.f("ix_agents_org_id"), table_name="agents")
    op.drop_index(op.f("ix_agents_created_at"), table_name="agents")
    op.drop_table("agents")
    op.drop_index("ix_vulnerabilities_kev_listed", table_name="vulnerabilities")
    op.drop_index(op.f("ix_vulnerabilities_created_at"), table_name="vulnerabilities")
    op.drop_index("ix_vulnerabilities_cpes", table_name="vulnerabilities", postgresql_using="gin")
    op.drop_table("vulnerabilities")
    op.drop_index(op.f("ix_orgs_created_at"), table_name="orgs")
    op.drop_table("orgs")

    # Both extensions are dropped only if nothing else in the database still
    # uses them; RESTRICT (the default) is deliberate.
    op.execute("DROP EXTENSION IF EXISTS citext")
    op.execute("DROP EXTENSION IF EXISTS pgcrypto")
