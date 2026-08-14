"""Paging the NVD feed, and the windows an incremental sync is cut into.

The bug these tests exist to keep fixed: ``fetch_cves`` used to call NVD with no
parameters at all. NVD 2.0 caps a response at 2,000 results against roughly
300,000 CVEs, so that mirrored under one percent of the catalogue — and always
the same one percent, however often it ran.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta, timezone
from itertools import pairwise
from typing import Any

import pytest

from threatsculpt.enrichment.feeds import (
    MAX_PAGES_PER_WINDOW,
    NVD_CVE_API_URL,
    NVD_MAX_RESULTS_PER_PAGE,
    NVD_MAX_WINDOW_DAYS,
    CvePage,
    RemoteFeed,
    StaticFeed,
    SyncWindow,
    format_feed_timestamp,
    windows_between,
)


class PagedFetcher:
    """A fake NVD that honours ``startIndex`` and ``resultsPerPage``."""

    def __init__(self, total: int) -> None:
        self.entries = [{"cve": {"id": f"CVE-2024-{index:05d}"}} for index in range(total)]
        self.requests: list[Mapping[str, str]] = []

    async def get_json(self, url: str, params: Mapping[str, str] | None = None) -> Any:
        self.requests.append(dict(params or {}))
        start = int((params or {}).get("startIndex", 0))
        size = int((params or {}).get("resultsPerPage", NVD_MAX_RESULTS_PER_PAGE))
        window = self.entries[start : start + size]
        return {
            "totalResults": len(self.entries),
            "resultsPerPage": len(window),
            "startIndex": start,
            "vulnerabilities": window,
        }


async def collect(feed: RemoteFeed, **kwargs: Any) -> list[CvePage]:
    return [page async for page in feed.iter_cve_pages(**kwargs)]


# --- paging -----------------------------------------------------------------


async def test_every_page_is_walked_not_just_the_first() -> None:
    fetcher = PagedFetcher(total=5)
    pages = await collect(RemoteFeed(fetcher=fetcher, page_size=2))

    assert [request["startIndex"] for request in fetcher.requests] == ["0", "2", "4"]
    assert sum(len(page.entries) for page in pages) == 5
    assert pages[-1].is_last


async def test_the_page_size_asked_for_is_nvds_documented_maximum() -> None:
    """NVD's *default* is 20; leaving it unset is a 15,000-request cold sync."""
    fetcher = PagedFetcher(total=1)
    await collect(RemoteFeed(fetcher=fetcher))
    assert fetcher.requests[0]["resultsPerPage"] == str(NVD_MAX_RESULTS_PER_PAGE)


async def test_an_exactly_full_final_page_costs_no_extra_request() -> None:
    """``totalResults`` ends the walk, so a page that lands on the boundary stops."""
    fetcher = PagedFetcher(total=4)
    pages = await collect(RemoteFeed(fetcher=fetcher, page_size=2))

    assert [request["startIndex"] for request in fetcher.requests] == ["0", "2"]
    assert sum(len(page.entries) for page in pages) == 4
    assert pages[-1].is_last


async def test_paging_resumes_from_a_given_index() -> None:
    fetcher = PagedFetcher(total=5)
    pages = await collect(RemoteFeed(fetcher=fetcher, page_size=2), start_index=4)

    assert fetcher.requests[0]["startIndex"] == "4"
    assert sum(len(page.entries) for page in pages) == 1


async def test_a_feed_that_never_reaches_its_own_total_is_cut_off() -> None:
    """A liar for ``totalResults`` must not become an infinite loop."""

    class NeverEnding:
        def __init__(self) -> None:
            self.calls = 0

        async def get_json(self, url: str, params: Mapping[str, str] | None = None) -> Any:
            self.calls += 1
            return {"totalResults": 10**9, "vulnerabilities": [{"cve": {"id": "CVE-2024-0001"}}]}

    fetcher = NeverEnding()
    pages = await collect(RemoteFeed(fetcher=fetcher, page_size=1))
    assert len(pages) == MAX_PAGES_PER_WINDOW
    assert fetcher.calls == MAX_PAGES_PER_WINDOW


async def test_the_static_feed_pages_the_same_shape() -> None:
    feed = StaticFeed(cve_items=({"cve": {"id": "CVE-1"}}, {"cve": {"id": "CVE-2"}}))
    pages = [page async for page in feed.iter_cve_pages()]
    assert len(pages) == 1
    assert pages[0].total_results == 2
    assert pages[0].is_last


# --- the page record --------------------------------------------------------


def test_a_page_reports_where_the_next_one_starts() -> None:
    page = CvePage(entries=({"a": 1}, {"b": 2}), start_index=100, total_results=500)
    assert page.next_index == 102
    assert not page.is_last


def test_an_empty_page_ends_the_walk_whatever_the_total_claims() -> None:
    page = CvePage(entries=(), start_index=100, total_results=10**9)
    assert page.is_last


# --- windows ----------------------------------------------------------------


def test_a_short_gap_is_one_window() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    windows = windows_between(start, start + timedelta(days=3))
    assert windows == (SyncWindow(start=start, end=start + timedelta(days=3)),)


def test_a_long_gap_is_split_at_nvds_limit() -> None:
    """NVD rejects a range more than 120 days wide, so a year needs four calls."""
    start = datetime(2025, 1, 1, tzinfo=UTC)
    end = start + timedelta(days=365)
    windows = windows_between(start, end)

    assert len(windows) == 4
    assert all(
        window.end - window.start <= timedelta(days=NVD_MAX_WINDOW_DAYS) for window in windows
    )
    assert windows[0].start == start
    assert windows[-1].end == end
    # Contiguous: a gap between windows is a slice of NVD nobody ever mirrors.
    assert all(earlier.end == later.start for earlier, later in pairwise(windows))


def test_an_already_current_mirror_has_nothing_to_fetch() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    assert windows_between(now, now) == ()
    assert windows_between(now, now - timedelta(days=1)) == ()


def test_a_nonsensical_window_size_is_refused() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    with pytest.raises(ValueError, match="max_days"):
        windows_between(now, now + timedelta(days=1), max_days=0)


# --- what goes on the wire --------------------------------------------------


async def test_a_window_becomes_the_documented_query_parameters() -> None:
    fetcher = PagedFetcher(total=1)
    window = SyncWindow(
        start=datetime(2026, 1, 1, 12, 30, tzinfo=UTC), end=datetime(2026, 2, 1, tzinfo=UTC)
    )
    await collect(RemoteFeed(fetcher=fetcher), window=window)

    assert fetcher.requests[0]["lastModStartDate"] == "2026-01-01T12:30:00.000+00:00"
    assert fetcher.requests[0]["lastModEndDate"] == "2026-02-01T00:00:00.000+00:00"


async def test_a_cold_sync_sends_no_date_filter_at_all() -> None:
    fetcher = PagedFetcher(total=1)
    await collect(RemoteFeed(fetcher=fetcher))
    assert "lastModStartDate" not in fetcher.requests[0]


def test_a_non_utc_timestamp_is_converted_rather_than_relabelled() -> None:
    moment = datetime(2026, 1, 1, 12, 0, tzinfo=timezone(timedelta(hours=2)))
    assert format_feed_timestamp(moment) == "2026-01-01T10:00:00.000+00:00"


def test_a_naive_timestamp_is_read_as_utc() -> None:
    naive = datetime(2026, 1, 1, 12, 0)  # deliberately naive
    assert format_feed_timestamp(naive) == "2026-01-01T12:00:00.000+00:00"


def test_the_documented_url_is_the_one_that_is_paged() -> None:
    assert RemoteFeed(fetcher=PagedFetcher(0)).nvd_url == NVD_CVE_API_URL
