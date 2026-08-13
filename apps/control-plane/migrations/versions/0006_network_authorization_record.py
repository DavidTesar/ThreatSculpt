"""Attribution for a scan authorization, so the flag becomes a record.

docs/SECURITY.md describes ``networks.authorized`` as *the record that you
asserted you had permission*. It was a boolean with a default and nothing else:
no author, no timestamp, nothing to show anyone afterwards. Two additive columns
turn it into something that can be produced when it is asked for.

* ``authorized_by_user_id`` — who made the assertion. ``ON DELETE SET NULL``
  rather than ``CASCADE``: the assertion outlives the account that made it, and
  losing the network row because somebody offboarded would be worse than losing
  the name.
* ``authorized_at`` — when. Distinct from ``updated_at``, which any later edit
  moves; this one is the moment permission was asserted.

Both are nullable, and existing rows keep NULL. Backfilling them with the
migration's own timestamp would be inventing a record, which is exactly the thing
this revision exists to stop. Rows that predate it read as "asserted before this
was tracked", which is true.

``authorization_note`` already existed and is unchanged; what changes is that
``scanning.authorization`` now requires it to be non-empty before a **public**
range may be marked authorized. Private ranges are untouched.

No index: these columns are read when a single network row is displayed and are
never a search key.

Revision ID: 0006
Revises: 0005
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("networks", sa.Column("authorized_by_user_id", sa.UUID(), nullable=True))
    op.add_column(
        "networks",
        sa.Column("authorized_at", postgresql.TIMESTAMP(timezone=True), nullable=True),
    )
    op.create_foreign_key(
        op.f("fk_networks_authorized_by_user_id"),
        "networks",
        "users",
        ["authorized_by_user_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(op.f("fk_networks_authorized_by_user_id"), "networks", type_="foreignkey")
    op.drop_column("networks", "authorized_at")
    op.drop_column("networks", "authorized_by_user_id")
