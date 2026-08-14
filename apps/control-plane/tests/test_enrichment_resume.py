"""Resuming an interrupted mirror sync, against a real database.

A cold NVD sync is roughly 150 requests with an API key and roughly 1,500
without, and the rate limit is per source address so it cannot be parallelised
away. That is an hour at best and ten at worst. A sync that restarts from zero
every time the connection drops does not eventually finish — it never finishes.

So the property under test is not "a sync works". It is: **kill one halfway and
the next run continues rather than starting over**, and the mirror ends up with
every CVE exactly once either way.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatsculpt.enrichment.feeds import CvePage, SyncWindow
from threatsculpt.enrichment.sync import sync_mirror
from threatsculpt.enrichment.watermark import SyncLeg, Watermark, load_watermark, plan_legs
from threatsculpt.models.feed_sync_state import NVD_FEED
from threatsculpt.models.finding import Vulnerability

Factory = async_sessionmaker[AsyncSession]

T0 = datetime(2026, 1, 1, tzinfo=UTC)


class ScriptedFeed:
    """A feed that pages, records what it was asked for, and can drop dead.

    ``die_after_pages`` stands in for the connection loss that makes
    resumability matter — the sync is killed between one commit and the next.
    """

    def __init__(self, total: int, page_size: int = 2, die_after_pages: int | None = None) -> None:
        self.entries = [{"cve": {"id": f"CVE-2026-{index:05d}"}} for index in range(total)]
        self.page_size = page_size
        self.die_after_pages = die_after_pages
        self.start_indexes: list[int] = []
        self.windows: list[SyncWindow | None] = []
        self.kev_calls = 0

    async def fetch_kev(self) -> Sequence[Mapping[str, Any]]:
        self.kev_calls += 1
        return ()

    async def iter_cve_pages(
        self, *, window: SyncWindow | None = None, start_index: int = 0
    ) -> AsyncIterator[CvePage]:
        self.windows.append(window)
        self.start_indexes.append(start_index)
        index = start_index
        served = 0
        while True:
            if served == self.die_after_pages:
                raise ConnectionError("upstream went away mid-sync")
            batch = tuple(self.entries[index : index + self.page_size])
            page = CvePage(entries=batch, start_index=index, total_results=len(self.entries))
            yield page
            served += 1
            if page.is_last:
                return
            index = page.next_index


async def count_cves(session: AsyncSession) -> int:
    statement = select(func.count()).select_from(Vulnerability)
    return int((await session.execute(statement)).scalar_one())


# --- planning, without a database ------------------------------------------


def test_no_watermark_at_all_is_a_cold_sync() -> None:
    assert plan_legs(None, T0) == (SyncLeg(window=None, start_index=0),)


def test_a_cold_sync_resumes_at_the_index_it_reached() -> None:
    """``last_modified_at`` is still NULL: nothing has completed, so no window yet."""
    state = Watermark(feed=NVD_FEED, next_start_index=42000)
    assert plan_legs(state, T0) == (SyncLeg(window=None, start_index=42000),)


def test_an_interrupted_window_is_finished_before_any_new_one_is_started() -> None:
    interrupted = SyncWindow(start=T0, end=T0 + timedelta(days=10))
    state = Watermark(
        feed=NVD_FEED,
        last_modified_at=T0,
        window_start=interrupted.start,
        window_end=interrupted.end,
        next_start_index=4000,
    )
    legs = plan_legs(state, T0 + timedelta(days=20))

    assert legs[0] == SyncLeg(window=interrupted, start_index=4000)
    assert legs[1].start_index == 0
    assert legs[1].window is not None
    # The next window picks up exactly where the interrupted one ends. A gap
    # here is a slice of NVD that no run ever mirrors.
    assert legs[1].window.start == interrupted.end
    assert legs[-1].window is not None
    assert legs[-1].window.end == T0 + timedelta(days=20)


def test_a_long_outage_becomes_several_windows() -> None:
    state = Watermark(feed=NVD_FEED, last_modified_at=T0)
    legs = plan_legs(state, T0 + timedelta(days=400))
    assert len(legs) == 4  # NVD caps a window at 120 days
    assert all(leg.start_index == 0 for leg in legs)


def test_an_up_to_date_mirror_plans_no_work() -> None:
    state = Watermark(feed=NVD_FEED, last_modified_at=T0)
    assert plan_legs(state, T0) == ()


def test_a_cold_leg_takes_the_run_time_as_its_watermark() -> None:
    assert SyncLeg(window=None).completed_watermark(T0) == T0


def test_a_windowed_leg_takes_the_window_end() -> None:
    window = SyncWindow(start=T0, end=T0 + timedelta(days=5))
    assert SyncLeg(window=window).completed_watermark(T0 + timedelta(days=9)) == window.end


# --- resuming, against the database ----------------------------------------


async def test_a_clean_sync_records_a_watermark(session_factory: Factory) -> None:
    feed = ScriptedFeed(total=5)
    async with session_factory() as session:
        report = await sync_mirror(session, feed, now=T0)

    assert report.cves_upserted == 5
    async with session_factory() as session:
        assert await count_cves(session) == 5
        state = await load_watermark(session, NVD_FEED)

    assert state is not None
    assert state.last_modified_at == T0
    assert state.in_flight is None, "a finished run leaves no resume point"
    assert state.next_start_index == 0


async def test_a_sync_killed_midway_keeps_what_it_had_written(session_factory: Factory) -> None:
    feed = ScriptedFeed(total=10, page_size=2, die_after_pages=2)

    async with session_factory() as session:
        with pytest.raises(ConnectionError):
            await sync_mirror(session, feed, now=T0)

    async with session_factory() as session:
        assert await count_cves(session) == 4, "two pages of two, committed as they landed"
        state = await load_watermark(session, NVD_FEED)

    assert state is not None
    assert state.next_start_index == 4
    assert state.last_modified_at is None, "nothing completed, so the watermark must not move"


async def test_the_next_run_continues_instead_of_starting_over(
    session_factory: Factory,
) -> None:
    """The whole point: page 3 is fetched next, not page 1."""
    async with session_factory() as session:
        with pytest.raises(ConnectionError):
            await sync_mirror(
                session, ScriptedFeed(total=10, page_size=2, die_after_pages=2), now=T0
            )

    resumed = ScriptedFeed(total=10, page_size=2)
    async with session_factory() as session:
        report = await sync_mirror(session, resumed, now=T0)

    assert resumed.start_indexes == [4], "restarted at 0 — the sync is not resumable"
    assert report.cves_upserted == 6, "only the six it had not already written"
    async with session_factory() as session:
        assert await count_cves(session) == 10


async def test_resuming_leaves_no_duplicates(session_factory: Factory) -> None:
    async with session_factory() as session:
        with pytest.raises(ConnectionError):
            await sync_mirror(
                session, ScriptedFeed(total=6, page_size=2, die_after_pages=1), now=T0
            )
    async with session_factory() as session:
        await sync_mirror(session, ScriptedFeed(total=6, page_size=2), now=T0)
    async with session_factory() as session:
        assert await count_cves(session) == 6


async def test_the_second_run_is_incremental_not_another_full_mirror(
    session_factory: Factory,
) -> None:
    async with session_factory() as session:
        await sync_mirror(session, ScriptedFeed(total=4), now=T0)

    later = ScriptedFeed(total=4)
    async with session_factory() as session:
        await sync_mirror(session, later, now=T0 + timedelta(days=1))

    assert len(later.windows) == 1
    window = later.windows[0]
    assert window is not None, "a second run must be windowed, not another cold sync"
    assert window.start == T0
    assert window.end == T0 + timedelta(days=1)


async def test_an_up_to_date_mirror_fetches_no_cve_pages(session_factory: Factory) -> None:
    async with session_factory() as session:
        await sync_mirror(session, ScriptedFeed(total=4), now=T0)

    idle = ScriptedFeed(total=4)
    async with session_factory() as session:
        await sync_mirror(session, idle, now=T0)

    assert idle.start_indexes == []
    assert idle.kev_calls == 1, "KEV is small and always refreshed"


async def test_an_empty_feed_still_advances_the_watermark(session_factory: Factory) -> None:
    """Otherwise a quiet week leaves the mirror permanently planning a cold sync."""
    async with session_factory() as session:
        report = await sync_mirror(session, ScriptedFeed(total=0), now=T0)

    assert report.cves_upserted == 0
    async with session_factory() as session:
        state = await load_watermark(session, NVD_FEED)
    assert state is not None
    assert state.last_modified_at == T0
