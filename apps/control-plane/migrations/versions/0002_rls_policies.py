"""Row-Level Security — layer 3 of tenancy isolation.

Every tenant-scoped table gets ``ENABLE`` + ``FORCE ROW LEVEL SECURITY`` and one
policy keyed on ``current_setting('threatsculpt.org_id', true)::uuid``, which the
application sets per transaction from the authenticated principal.

Two details that matter:

* ``FORCE`` is what makes the policy apply to the table's *owner* as well. Without
  it, running the app as the owning role would bypass RLS entirely and this whole
  migration would be decoration.
* The GUC is read as ``NULLIF(current_setting(..., true), '')::uuid``. The
  ``NULLIF`` is load-bearing, not defensive noise: ``set_config(..., is_local =>
  true)`` restores the *value the GUC held at transaction start*, and for a
  custom GUC first set on that connection that value is the empty string rather
  than unset. On a pooled connection the next transaction would therefore
  evaluate ``''::uuid`` and every query would fail with
  ``invalid input syntax for type uuid``. With ``NULLIF`` the unscoped case
  yields NULL, ``org_id = NULL`` is NULL, which is not TRUE — so an unscoped
  session sees zero rows. The failure mode is "no data", never "everyone's data".

Superusers and roles with BYPASSRLS ignore all of this. The application must
connect as a plain, non-superuser role; ``.env.example`` says so and
``scripts/bootstrap_db.sql`` creates one.

Authentication is a bootstrap problem — resolving *which* org a caller belongs to
requires reading a row before any scope exists. Rather than leaving the main
policies permissive when the GUC is unset, three tables carry an extra
SELECT-only policy gated on ``threatsculpt.authn``, a second GUC set exclusively
by ``threatsculpt.tenancy.credentials``.

Revision ID: 0002
Revises: 0001
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ORG_GUC = "threatsculpt.org_id"
AUTHN_GUC = "threatsculpt.authn"

#: Kept as a literal list rather than derived from the models at runtime: a
#: migration must describe the schema as of this revision, not as of whatever
#: the code happens to declare when it is replayed.
TENANT_TABLES: tuple[str, ...] = (
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
    "audit_log",
)

#: Tables the pre-authentication credential lookup must read from.
AUTHN_LOOKUP_TABLES: tuple[str, ...] = ("users", "agents", "refresh_tokens")

_ORG_PREDICATE = f"org_id = NULLIF(current_setting('{ORG_GUC}', true), '')::uuid"
_AUTHN_PREDICATE = f"current_setting('{AUTHN_GUC}', true) = 'on'"


def _policy_name(table: str) -> str:
    return f"{table}_org_isolation"


def _authn_policy_name(table: str) -> str:
    return f"{table}_authn_lookup"


def upgrade() -> None:
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY {_policy_name(table)} ON {table}
                USING ({_ORG_PREDICATE})
                WITH CHECK ({_ORG_PREDICATE})
            """
        )

    for table in AUTHN_LOOKUP_TABLES:
        op.execute(
            f"""
            CREATE POLICY {_authn_policy_name(table)} ON {table}
                FOR SELECT
                USING ({_AUTHN_PREDICATE})
            """
        )


def downgrade() -> None:
    for table in reversed(AUTHN_LOOKUP_TABLES):
        op.execute(f"DROP POLICY IF EXISTS {_authn_policy_name(table)} ON {table}")

    for table in reversed(TENANT_TABLES):
        op.execute(f"DROP POLICY IF EXISTS {_policy_name(table)} ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
