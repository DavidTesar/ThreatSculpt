"""Run the lease sweeper as its own process: ``python -m threatsculpt.scanning``.

Kept out of the API process on purpose — see ``sweeper.run_forever``. Settings
come from the environment exactly as they do for the web application, so the
sweeper connects as the same NOBYPASSRLS role and is subject to the same
row-level security.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from threatsculpt.config import get_settings
from threatsculpt.db.engine import build_engine, build_session_factory
from threatsculpt.observability.logging import configure_logging
from threatsculpt.scanning.sweeper import run_forever

logger = logging.getLogger(__name__)


async def _main() -> None:
    settings = get_settings()
    configure_logging(level=settings.log_level, as_json=settings.log_json)
    engine = build_engine(settings)
    try:
        logger.info("lease sweeper started", extra={"environment": settings.environment})
        await run_forever(build_session_factory(engine))
    finally:
        await engine.dispose()
        logger.info("lease sweeper stopped")


if __name__ == "__main__":  # pragma: no cover - process entrypoint
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(_main())
