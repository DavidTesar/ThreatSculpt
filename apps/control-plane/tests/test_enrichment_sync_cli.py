"""The sync entry point's wiring.

The CLI is where settings become an HTTP client, and the one decision worth
testing here is which host the NVD API key is allowed to reach. Everything else
it does — open an engine, open a session, call ``sync_mirror`` — is covered by
the tests for those pieces.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import SecretStr

from threatsculpt.config import Settings
from threatsculpt.enrichment.feeds import KEV_CATALOG_URL, NVD_CVE_API_URL
from threatsculpt.enrichment.http import API_KEY_HEADER, NVD_ANONYMOUS_RATE, NVD_KEYED_RATE
from threatsculpt.enrichment.sync_cli import build_feed, build_fetcher, is_due
from threatsculpt.enrichment.watermark import Watermark
from threatsculpt.models.feed_sync_state import NVD_FEED

SECRET = "nvd-key-that-must-not-travel"


def settings_with(**overrides: object) -> Settings:
    return Settings(
        database_url="postgresql://user@localhost/db",
        jwt_secret="a-test-jwt-secret-long-enough-to-be-accepted",
        **overrides,  # type: ignore[arg-type]
    )


def test_the_key_is_scoped_to_the_host_the_feed_url_names() -> None:
    fetcher = build_fetcher(settings_with(nvd_api_key=SecretStr(SECRET)))
    assert fetcher._headers_for(NVD_CVE_API_URL) == {API_KEY_HEADER: SECRET}
    assert fetcher._headers_for(KEV_CATALOG_URL) == {}


def test_pointing_the_feed_at_a_mirror_moves_the_key_with_it() -> None:
    """An internal mirror is a deliberate configuration, not a leak."""
    fetcher = build_fetcher(
        settings_with(
            nvd_api_key=SecretStr(SECRET),
            nvd_cve_url="https://nvd-mirror.internal.example/rest/json/cves/2.0",
        )
    )
    assert fetcher._headers_for("https://nvd-mirror.internal.example/rest/json/cves/2.0") == {
        API_KEY_HEADER: SECRET
    }
    assert fetcher._headers_for(NVD_CVE_API_URL) == {}


def test_no_key_configured_sends_no_key_anywhere() -> None:
    fetcher = build_fetcher(settings_with())
    assert fetcher._headers_for(NVD_CVE_API_URL) == {}


@pytest.mark.parametrize(
    ("key", "expected"),
    [(None, NVD_ANONYMOUS_RATE), (SecretStr(SECRET), NVD_KEYED_RATE)],
)
def test_the_rate_budget_follows_the_key(key: SecretStr | None, expected: int) -> None:
    fetcher = build_fetcher(settings_with(nvd_api_key=key))
    assert fetcher._limiter._limit == expected


def test_the_feed_is_built_from_the_configured_urls_and_page_size() -> None:
    settings = settings_with(nvd_page_size=500)
    feed = build_feed(settings, build_fetcher(settings))

    assert feed.nvd_url == NVD_CVE_API_URL
    assert feed.kev_url == KEV_CATALOG_URL
    assert feed.page_size == 500


def test_a_page_size_above_nvds_maximum_is_refused_at_startup() -> None:
    with pytest.raises(ValueError, match="nvd_page_size"):
        settings_with(nvd_page_size=5000)


def test_the_api_key_is_not_printed_by_a_settings_dump() -> None:
    dumped = str(settings_with(nvd_api_key=SecretStr(SECRET)))
    assert SECRET not in dumped
    assert "nvd_api_key=SecretStr" in dumped


# --- the cadence, which is enforced here rather than left to the crontab -----

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)


def test_a_mirror_that_has_never_completed_is_always_due() -> None:
    """A failing cold sync must not talk itself out of retrying."""
    assert is_due(None, interval_hours=24, now=NOW)
    assert is_due(Watermark(feed=NVD_FEED, next_start_index=40_000), interval_hours=24, now=NOW)


def test_a_recent_run_is_not_due_so_an_hourly_cron_costs_nothing() -> None:
    recent = Watermark(feed=NVD_FEED, last_completed_at=NOW - timedelta(hours=1))
    assert not is_due(recent, interval_hours=24, now=NOW)


def test_a_stale_run_is_due() -> None:
    stale = Watermark(feed=NVD_FEED, last_completed_at=NOW - timedelta(hours=25))
    assert is_due(stale, interval_hours=24, now=NOW)


def test_the_boundary_counts_as_due() -> None:
    exact = Watermark(feed=NVD_FEED, last_completed_at=NOW - timedelta(hours=24))
    assert is_due(exact, interval_hours=24, now=NOW)
