"""Where the last CVE mirror sync got to. **Not tenant-scoped.**

A cold NVD sync is roughly 150 requests under an API key and roughly 1,500
without one, spread over an hour or ten. Without somewhere durable to record
progress, a sync interrupted at hour nine restarts at zero, and on a connection
that drops more often than that it never completes at all.

Two independent facts live here, and conflating them is the mistake this table
is shaped to prevent:

``last_modified_at`` is the **watermark** — everything modified upstream before
this instant is mirrored. It only ever advances when a whole window has been
written, so a crash mid-window cannot make the next run skip the remainder.

``window_start`` / ``window_end`` / ``next_start_index`` are the **resume
point** of a run that is still in flight. They are non-null only between the
first page of a window and its last. A run that finds them set continues that
window instead of re-fetching it.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import CheckConstraint, String
from sqlalchemy.orm import Mapped, mapped_column

from threatsculpt.db.base import Base, TimestampMixin

#: Feed identifiers. One row per feed: the two feeds advance independently, and
#: KEV is a single small document with no paging of its own.
NVD_FEED = "nvd"
KEV_FEED = "kev"


class FeedSyncState(TimestampMixin, Base):
    """One row per upstream feed, holding its watermark and any resume point."""

    __tablename__ = "feed_sync_state"
    __table_args__ = (
        CheckConstraint("next_start_index >= 0", name="feed_sync_state_index_non_negative"),
        CheckConstraint(
            "(window_start IS NULL) = (window_end IS NULL)",
            name="feed_sync_state_window_complete",
        ),
    )

    feed: Mapped[str] = mapped_column(String(32), primary_key=True)
    #: Upstream ``lastModified`` high-water mark. NULL means nothing has ever
    #: completed, which is what makes the next run a cold sync.
    last_modified_at: Mapped[datetime | None] = mapped_column()
    window_start: Mapped[datetime | None] = mapped_column()
    window_end: Mapped[datetime | None] = mapped_column()
    #: NVD ``startIndex`` to resume the in-flight window at.
    next_start_index: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")
    #: When a run last finished cleanly. Operational signal only — staleness is
    #: judged from this, never resumption.
    last_completed_at: Mapped[datetime | None] = mapped_column()
