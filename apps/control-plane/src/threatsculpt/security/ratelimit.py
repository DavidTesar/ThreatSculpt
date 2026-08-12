"""In-process sliding-window rate limiter.

Hand-rolled rather than pulled in: the requirement is two fixed limits, and a
dependency-free limiter is deterministic to test. It is explicitly per-process —
behind more than one worker the effective limit multiplies by the worker count.
For production this should move to a shared counter (Redis ``INCR`` with
expiry); the interface here is the seam for that swap.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass

WINDOW_SECONDS = 60.0


@dataclass(frozen=True, slots=True)
class LimitDecision:
    allowed: bool
    retry_after_seconds: int


class SlidingWindowLimiter:
    """Bucketed request timestamps, trimmed on read. Thread-safe."""

    def __init__(self, *, window_seconds: float = WINDOW_SECONDS) -> None:
        self._window = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, *, now: float | None = None) -> LimitDecision:
        """Record an attempt against ``key`` and say whether it is permitted."""
        moment = time.monotonic() if now is None else now
        cutoff = moment - self._window
        with self._lock:
            bucket = self._events[key]
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= limit:
                retry_after = max(1, int(bucket[0] + self._window - moment) + 1)
                return LimitDecision(allowed=False, retry_after_seconds=retry_after)
            bucket.append(moment)
            return LimitDecision(allowed=True, retry_after_seconds=0)

    def reset(self, key: str | None = None) -> None:
        """Drop counters. Used between tests, and on successful login."""
        with self._lock:
            if key is None:
                self._events.clear()
            else:
                self._events.pop(key, None)

    def prune(self, *, now: float | None = None) -> None:
        """Drop empty buckets so the dict does not grow without bound."""
        moment = time.monotonic() if now is None else now
        cutoff = moment - self._window
        with self._lock:
            for key in [k for k, v in self._events.items() if not v or v[-1] <= cutoff]:
                del self._events[key]
