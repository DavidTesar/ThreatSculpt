"""Run the enrichment worker as its own process: ``python -m threatsculpt.enrichment``.

Kept out of the API process on purpose — see ``worker.run_forever`` and the
measurement quoted in ``reports.runner``. Settings come from the environment
exactly as they do for the web application, so the worker connects as the same
NOBYPASSRLS role and is subject to the same row-level security.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from threatsculpt.config import get_settings
from threatsculpt.db.engine import build_engine, build_session_factory
from threatsculpt.enrichment.worker import run_forever
from threatsculpt.observability.logging import configure_logging

logger = logging.getLogger(__name__)


async def _main() -> None:
    settings = get_settings()
    configure_logging(level=settings.log_level, as_json=settings.log_json)
    engine = build_engine(settings)
    try:
        logger.info("enrichment worker started", extra={"environment": settings.environment})
        await run_forever(build_session_factory(engine))
    finally:
        await engine.dispose()
        logger.info("enrichment worker stopped")


if __name__ == "__main__":  # pragma: no cover - process entrypoint
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_main())
