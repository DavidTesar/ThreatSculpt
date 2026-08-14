"""Run a CVE mirror sync as its own process.

::

    python -m threatsculpt.enrichment.sync_cli

Shaped like ``threatsculpt.scanning``'s sweeper entry point: settings come from
the environment exactly as they do for the web application, so the sync connects
as the same NOBYPASSRLS role. It is deliberately a separate process rather than
a task inside the API — a run is hours long on a cold mirror and would otherwise
hold an API worker for the duration.

**Safe to interrupt, and safe to run on a schedule.** Progress is committed
after every page, so a killed run resumes where it stopped rather than starting
over, and exits are non-zero on failure so a scheduler notices.

``TS_CVE_SYNC_INTERVAL_HOURS`` is enforced here rather than left to whoever
writes the crontab: a run that finds the mirror synced more recently than that
exits without touching the network. So the cron entry can be as frequent as an
operator likes — hourly, to recover quickly from a failed run — without turning
into an hourly hammering of a public, rate-limited API. ``--force`` overrides it
for the operator who wants a sync *now*.

Not wired into ``enrichment/__main__.py``, which belongs to the enrichment
worker: the sync and the finding generator have different cadences, different
failure modes, and different reasons to be restarted.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sys
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from threatsculpt.config import Settings, get_settings
from threatsculpt.db.engine import build_engine, build_session_factory
from threatsculpt.enrichment.feeds import RemoteFeed
from threatsculpt.enrichment.http import FeedFetchError, HttpJsonFetcher
from threatsculpt.enrichment.sync import sync_mirror
from threatsculpt.enrichment.watermark import Watermark, load_watermark
from threatsculpt.models.feed_sync_state import NVD_FEED
from threatsculpt.observability.logging import configure_logging

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_FAILED = 1

FORCE_FLAG = "--force"


def build_fetcher(settings: Settings) -> HttpJsonFetcher:
    """An HTTP client that will only ever send the API key to NVD's own host."""
    return HttpJsonFetcher(
        api_key=settings.nvd_api_key,
        api_key_host=urlsplit(settings.nvd_cve_url).hostname,
        timeout_seconds=settings.feed_timeout_seconds,
        max_attempts=settings.feed_max_attempts,
    )


def build_feed(settings: Settings, fetcher: HttpJsonFetcher) -> RemoteFeed:
    return RemoteFeed(
        fetcher=fetcher,
        kev_url=settings.kev_catalog_url,
        nvd_url=settings.nvd_cve_url,
        page_size=settings.nvd_page_size,
    )


def is_due(watermark: Watermark | None, *, interval_hours: int, now: datetime) -> bool:
    """False only when a completed run is more recent than the configured cadence.

    A mirror that has never completed is always due, however recently something
    was attempted — otherwise a failing cold sync would talk itself out of ever
    retrying.
    """
    if watermark is None or watermark.last_completed_at is None:
        return True
    return now - watermark.last_completed_at >= timedelta(hours=interval_hours)


async def run_sync(settings: Settings, *, force: bool = False) -> int:
    engine = build_engine(settings)
    factory = build_session_factory(engine)
    try:
        if not force:
            async with factory() as session:
                watermark = await load_watermark(session, NVD_FEED)
            if not is_due(
                watermark,
                interval_hours=settings.cve_sync_interval_hours,
                now=datetime.now(UTC),
            ):
                logger.info(
                    "cve mirror is current; skipping",
                    extra={"interval_hours": settings.cve_sync_interval_hours},
                )
                return EXIT_OK

        async with build_fetcher(settings) as fetcher:
            feed = build_feed(settings, fetcher)
            async with factory() as session:
                report = await sync_mirror(session, feed)
    except FeedFetchError:
        # Only the feed's own give-up is caught. A database error is a different
        # problem and should surface as a crash rather than a tidy exit code.
        # `FeedFetchError` carries the URL and status and never the API key —
        # see `enrichment.http` — so the traceback is safe to log in full, and
        # whatever progress the run committed is already durable.
        logger.exception("cve mirror sync failed")
        return EXIT_FAILED
    finally:
        await engine.dispose()

    logger.info(
        "cve mirror sync complete",
        extra={
            "cves": report.cves_upserted,
            "cpe_matches": report.cpe_matches_upserted,
            "kev_flagged": report.kev_flagged,
            "skipped": len(report.skipped),
        },
    )
    return EXIT_OK


async def _main(argv: list[str]) -> int:
    settings = get_settings()
    configure_logging(level=settings.log_level, as_json=settings.log_json)
    force = FORCE_FLAG in argv
    logger.info(
        "cve mirror sync started",
        extra={
            "environment": settings.environment,
            # Whether a key is configured is operationally load-bearing — it is
            # the difference between a one-hour and a ten-hour cold sync — and
            # is not itself a secret. The key's value is never logged.
            "nvd_api_key_configured": settings.nvd_api_key is not None,
            "force": force,
        },
    )
    return await run_sync(settings, force=force)


if __name__ == "__main__":  # pragma: no cover - process entrypoint
    with contextlib.suppress(KeyboardInterrupt):
        sys.exit(asyncio.run(_main(sys.argv[1:])))
