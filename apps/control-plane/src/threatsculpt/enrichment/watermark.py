"""Reading and advancing the mirror's sync watermark.

Kept apart from ``sync`` so the resumption rules can be read — and tested —
without a feed, a session full of CVE upserts, or an hour of patience.

The planner is a pure function of ``(state, now)``. Everything about "where does
this run start" is decided there and nowhere else, which is the only reason it
is possible to be confident that an interrupted sync resumes rather than
restarts.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.enrichment.feeds import SyncWindow, windows_between
from threatsculpt.models.feed_sync_state import FeedSyncState


@dataclass(frozen=True, slots=True)
class Watermark:
    """A ``feed_sync_state`` row, detached from the session that read it."""

    feed: str
    last_modified_at: datetime | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None
    next_start_index: int = 0
    last_completed_at: datetime | None = None

    @property
    def in_flight(self) -> SyncWindow | None:
        """The window a previous run was part-way through, if there was one."""
        if self.window_start is None or self.window_end is None:
            return None
        return SyncWindow(start=self.window_start, end=self.window_end)


@dataclass(frozen=True, slots=True)
class SyncLeg:
    """One window's worth of work, and the index to begin it at.

    ``window is None`` is the cold sync: no date filter, page through the whole
    catalogue. Every later run is windowed.
    """

    window: SyncWindow | None
    start_index: int = 0

    def completed_watermark(self, now: datetime) -> datetime:
        """Where the watermark stands once this leg is fully written."""
        return now if self.window is None else self.window.end


def plan_legs(state: Watermark | None, now: datetime) -> tuple[SyncLeg, ...]:
    """Decide what a run starting at ``now`` has to fetch.

    No watermark at all means a cold sync, resumed at whatever index the last
    attempt reached. Otherwise: finish any in-flight window first, then walk
    120-day windows up to ``now``.
    """
    if state is None or state.last_modified_at is None:
        return (SyncLeg(window=None, start_index=state.next_start_index if state else 0),)

    legs: list[SyncLeg] = []
    cursor = state.last_modified_at
    interrupted = state.in_flight
    if interrupted is not None:
        legs.append(SyncLeg(window=interrupted, start_index=state.next_start_index))
        cursor = interrupted.end
    legs.extend(SyncLeg(window=window) for window in windows_between(cursor, now))
    return tuple(legs)


async def load_watermark(session: AsyncSession, feed: str) -> Watermark | None:
    row = (
        await session.execute(select(FeedSyncState).where(FeedSyncState.feed == feed))
    ).scalar_one_or_none()
    if row is None:
        return None
    return Watermark(
        feed=row.feed,
        last_modified_at=row.last_modified_at,
        window_start=row.window_start,
        window_end=row.window_end,
        next_start_index=row.next_start_index,
        last_completed_at=row.last_completed_at,
    )


async def save_progress(
    session: AsyncSession, feed: str, window: SyncWindow | None, next_start_index: int
) -> None:
    """Record how far into ``window`` this run has got. Does not move the watermark."""
    await _upsert(
        session,
        feed,
        {
            "window_start": window.start if window else None,
            "window_end": window.end if window else None,
            "next_start_index": next_start_index,
        },
    )


async def complete_leg(
    session: AsyncSession, feed: str, watermark: datetime, *, completed_at: datetime
) -> None:
    """Advance the watermark and clear the resume point, in one statement."""
    await _upsert(
        session,
        feed,
        {
            "last_modified_at": watermark,
            "window_start": None,
            "window_end": None,
            "next_start_index": 0,
            "last_completed_at": completed_at,
        },
    )


async def _upsert(session: AsyncSession, feed: str, values: dict[str, object]) -> None:
    statement = pg_insert(FeedSyncState).values(feed=feed, **values)
    await session.execute(
        statement.on_conflict_do_update(
            index_elements=[FeedSyncState.feed],
            set_={column: statement.excluded[column] for column in values},
        )
    )
