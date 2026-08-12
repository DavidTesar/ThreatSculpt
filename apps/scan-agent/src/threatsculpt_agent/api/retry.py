"""Retry helper for control-plane calls.

Retryable: transport failures, 5xx, and 429 (which uses the server's Retry-After when it
sent one, since the server knows better than our policy does).

Never retried: 401 (the key is dead — retrying it is pointless and looks like an attack),
409 (the job is gone), and other 4xx (the request itself is wrong; a retry sends the same
wrong request again).
"""

from __future__ import annotations

import asyncio
import logging
import random
from collections.abc import Awaitable, Callable

from ..errors import ApiError, RateLimitedError, ServerError, TransportError
from .backoff import BackoffPolicy

log = logging.getLogger(__name__)

RETRYABLE: tuple[type[ApiError], ...] = (TransportError, ServerError, RateLimitedError)

Sleeper = Callable[[float], Awaitable[None]]


async def retry_async[T](
    operation: Callable[[], Awaitable[T]],
    *,
    policy: BackoffPolicy,
    max_attempts: int = 5,
    description: str = "request",
    sleep: Sleeper | None = None,
    rng: random.Random | None = None,
) -> T:
    """Run ``operation`` until it succeeds or the attempt budget is exhausted.

    Returns the operation's value. Re-raises the last error once out of attempts, so a
    caller always learns why the call ultimately failed — nothing is swallowed.
    """
    if max_attempts < 1:
        raise ValueError("max_attempts must be >= 1")
    sleeper = sleep or asyncio.sleep
    last_error: ApiError | None = None

    for attempt in range(max_attempts):
        try:
            return await operation()
        except RETRYABLE as exc:
            last_error = exc
            if attempt == max_attempts - 1:
                break
            delay = _delay_for(exc, policy, attempt, rng)
            log.warning(
                "%s failed (attempt %d/%d): %s; retrying in %.1fs",
                description,
                attempt + 1,
                max_attempts,
                exc,
                delay,
            )
            await sleeper(delay)

    assert last_error is not None  # only reachable after a RETRYABLE was caught
    log.error("%s failed after %d attempts: %s", description, max_attempts, last_error)
    raise last_error


def _delay_for(
    exc: ApiError, policy: BackoffPolicy, attempt: int, rng: random.Random | None
) -> float:
    """Honour Retry-After on 429; otherwise use the jittered backoff curve."""
    if isinstance(exc, RateLimitedError) and exc.retry_after is not None:
        return max(0.0, min(exc.retry_after, policy.max_seconds))
    return policy.delay_for(attempt, rng)
