"""Exponential backoff with jitter.

Jitter is not decoration. A fleet of agents that all lose the control plane at the same
moment and retry on the same deterministic schedule will keep hitting it in lockstep as
it comes back up. Randomising each delay spreads the retry storm out.

The policy is a pure, frozen value and takes an injected ``random.Random``, so tests
assert exact delays instead of ranges.
"""

from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class BackoffPolicy:
    """Computes retry delays. ``attempt`` is 0-based: attempt 0 is the first retry."""

    base_seconds: float = 1.0
    max_seconds: float = 300.0
    multiplier: float = 2.0
    jitter_ratio: float = 0.5

    def __post_init__(self) -> None:
        if self.base_seconds <= 0:
            raise ValueError("base_seconds must be positive")
        if self.max_seconds < self.base_seconds:
            raise ValueError("max_seconds must be >= base_seconds")
        if self.multiplier <= 1:
            raise ValueError("multiplier must be > 1")
        if not 0.0 <= self.jitter_ratio <= 1.0:
            raise ValueError("jitter_ratio must be within [0, 1]")

    def ceiling_for(self, attempt: int) -> float:
        """The un-jittered delay for an attempt, capped at max_seconds."""
        if attempt < 0:
            raise ValueError("attempt must be >= 0")
        try:
            raw = self.base_seconds * (self.multiplier**attempt)
        except OverflowError:
            return self.max_seconds
        return min(raw, self.max_seconds)

    def delay_for(self, attempt: int, rng: random.Random | None = None) -> float:
        """Delay for ``attempt``, jittered downward within ``jitter_ratio`` of the ceiling."""
        ceiling = self.ceiling_for(attempt)
        if self.jitter_ratio == 0:
            return ceiling
        generator = rng or random.SystemRandom()
        low = ceiling * (1.0 - self.jitter_ratio)
        return generator.uniform(low, ceiling)

    def with_max(self, max_seconds: float) -> BackoffPolicy:
        """Return a new policy with a different cap. Never mutates the original."""
        return BackoffPolicy(
            base_seconds=self.base_seconds,
            max_seconds=max_seconds,
            multiplier=self.multiplier,
            jitter_ratio=self.jitter_ratio,
        )
