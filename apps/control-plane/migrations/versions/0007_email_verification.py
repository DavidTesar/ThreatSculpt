"""Email verification, so an address has to be proved before it counts.

Registration let anybody claim any address. Two separate denial-of-service
findings came out of that single fact:

* an attacker who registered a victim's work address in other orgs put that
  victim's account into the shared login candidate set, where failed guesses were
  charged to it and could lock it out from a tenant the victim had never heard of;
* once a cap was placed on how many accounts one address may hold, the same
  registrations consumed the whole cap and stopped the address's real owner from
  ever signing up.

Both are the same root cause: an unproved claim on an address counted for
something. After this revision it counts for nothing. An account is created
unverified; unverified accounts are excluded from the login candidate set, cannot
authenticate by password, and do not consume a slot. Only proof of control turns
one into a real account.

Columns rather than a table: ``users`` already carries the org-isolation policy,
the ``FOR SELECT`` credential-lookup policy the unauthenticated verification
endpoint needs, and the application role's grants — all of which extend to new
columns automatically. A new tenant table would need every one of those
re-established correctly, which is a great deal more that can be got wrong for a
row that is one-to-one with a user and lives for a day.

Existing rows are backfilled as verified. They were created before there was
anything to prove, and locking every current account out of a live deployment
would be a migration doing considerably more than it was asked.

Revision ID: 0007
Revises: 0006
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0007"
down_revision: str | None = "0006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: SHA-256 hex. The plaintext is handed to the delivery interface once and is
#: never stored, exactly like refresh tokens and agent API keys.
_TOKEN_HASH_LENGTH = 64


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("email_verified_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("verification_token_hash", sa.String(length=_TOKEN_HASH_LENGTH), nullable=True),
    )
    op.add_column(
        "users",
        sa.Column("verification_expires_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
    )

    # Partial and unique: the hash is the sole lookup key for an unauthenticated
    # request, so it must match at most one row, and the many NULLs of verified
    # accounts must not collide with each other.
    op.create_index(
        "uq_users_verification_token_hash",
        "users",
        ["verification_token_hash"],
        unique=True,
        postgresql_where=sa.text("verification_token_hash IS NOT NULL"),
    )

    op.execute("UPDATE users SET email_verified_at = created_at WHERE email_verified_at IS NULL")


def downgrade() -> None:
    op.drop_index("uq_users_verification_token_hash", table_name="users")
    op.drop_column("users", "verification_expires_at")
    op.drop_column("users", "verification_token_hash")
    op.drop_column("users", "email_verified_at")
