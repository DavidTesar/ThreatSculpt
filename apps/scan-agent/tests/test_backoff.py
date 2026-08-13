"""Exponential backoff with jitter, and the retry policy built on it."""

from __future__ import annotations

import random

import pytest
from conftest import RecordingSleeper

from threatsculpt_agent.api.backoff import BackoffPolicy
from threatsculpt_agent.api.retry import retry_async
from threatsculpt_agent.errors import (
    AuthRevokedError,
    ClientError,
    JobConflictError,
    RateLimitedError,
    ServerError,
    TransportError,
)

# --- the curve -----------------------------------------------------------------------


def test_delays_grow_exponentially() -> None:
    policy = BackoffPolicy(base_seconds=1.0, max_seconds=1000.0, multiplier=2.0)
    assert [policy.ceiling_for(n) for n in range(5)] == [1.0, 2.0, 4.0, 8.0, 16.0]


def test_delays_are_capped() -> None:
    policy = BackoffPolicy(base_seconds=1.0, max_seconds=10.0, multiplier=2.0)
    assert policy.ceiling_for(20) == 10.0
    assert policy.ceiling_for(10_000) == 10.0  # no OverflowError on a long outage


def test_jitter_stays_within_the_configured_band() -> None:
    policy = BackoffPolicy(base_seconds=8.0, max_seconds=100.0, jitter_ratio=0.5)
    rng = random.Random(1234)
    delays = [policy.delay_for(0, rng) for _ in range(200)]

    assert all(4.0 <= delay <= 8.0 for delay in delays)
    assert len(set(delays)) > 100  # actually randomised, not a constant


def test_jitter_spreads_a_fleet_out() -> None:
    """Two agents failing at the same instant must not retry in lockstep."""
    policy = BackoffPolicy(base_seconds=30.0, max_seconds=300.0, jitter_ratio=0.5)
    first = [policy.delay_for(2, random.Random(1)) for _ in range(50)]
    second = [policy.delay_for(2, random.Random(2)) for _ in range(50)]

    assert first != second


def test_zero_jitter_is_deterministic() -> None:
    policy = BackoffPolicy(base_seconds=2.0, max_seconds=100.0, jitter_ratio=0.0)
    assert policy.delay_for(3) == policy.delay_for(3) == 16.0


def test_policies_are_immutable_values() -> None:
    policy = BackoffPolicy(base_seconds=1.0, max_seconds=10.0)
    narrowed = policy.with_max(5.0)

    assert policy.max_seconds == 10.0  # unchanged
    assert narrowed.max_seconds == 5.0


@pytest.mark.parametrize(
    "kwargs",
    [
        {"base_seconds": 0},
        {"base_seconds": 10, "max_seconds": 1},
        {"multiplier": 1.0},
        {"jitter_ratio": 1.5},
    ],
)
def test_nonsensical_policies_are_refused(kwargs: dict[str, float]) -> None:
    with pytest.raises(ValueError):
        BackoffPolicy(**kwargs)


def test_negative_attempts_are_refused() -> None:
    with pytest.raises(ValueError):
        BackoffPolicy().ceiling_for(-1)


# --- retry_async ---------------------------------------------------------------------

POLICY = BackoffPolicy(base_seconds=1.0, max_seconds=100.0, multiplier=2.0, jitter_ratio=0.0)


async def test_a_successful_call_does_not_sleep() -> None:
    sleeper = RecordingSleeper()

    async def succeed() -> str:
        return "ok"

    assert await retry_async(succeed, policy=POLICY, sleep=sleeper) == "ok"
    assert sleeper.delays == []


async def test_retries_then_succeeds() -> None:
    sleeper = RecordingSleeper()
    attempts = 0

    async def flaky() -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise ServerError("503")
        return "ok"

    assert await retry_async(flaky, policy=POLICY, sleep=sleeper) == "ok"
    assert attempts == 3
    assert sleeper.delays == [1.0, 2.0]


async def test_the_attempt_budget_is_enforced_and_the_error_surfaces() -> None:
    sleeper = RecordingSleeper()
    attempts = 0

    async def always_fails() -> None:
        nonlocal attempts
        attempts += 1
        raise ServerError("500")

    with pytest.raises(ServerError):
        await retry_async(always_fails, policy=POLICY, max_attempts=5, sleep=sleeper)

    assert attempts == 5
    assert len(sleeper.delays) == 4  # no sleep after the final failure


@pytest.mark.parametrize("error", [TransportError("down"), ServerError("502")])
async def test_transport_and_server_errors_are_retried(error: Exception) -> None:
    sleeper = RecordingSleeper()
    attempts = 0

    async def failing() -> None:
        nonlocal attempts
        attempts += 1
        raise error

    with pytest.raises(type(error)):
        await retry_async(failing, policy=POLICY, max_attempts=2, sleep=sleeper)
    assert attempts == 2


@pytest.mark.parametrize(
    "error",
    [AuthRevokedError("401"), JobConflictError("409"), ClientError("400")],
)
async def test_non_retryable_errors_fail_immediately(error: Exception) -> None:
    sleeper = RecordingSleeper()
    attempts = 0

    async def failing() -> None:
        nonlocal attempts
        attempts += 1
        raise error

    with pytest.raises(type(error)):
        await retry_async(failing, policy=POLICY, max_attempts=5, sleep=sleeper)

    assert attempts == 1
    assert sleeper.delays == []


async def test_retry_after_overrides_the_backoff_curve() -> None:
    """The server knows when it will be ready; our curve is only a guess."""
    sleeper = RecordingSleeper()
    attempts = 0

    async def limited() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RateLimitedError("429", retry_after=42.0)
        return "ok"

    assert await retry_async(limited, policy=POLICY, sleep=sleeper) == "ok"
    assert sleeper.delays == [42.0]


async def test_retry_after_is_capped_by_the_policy() -> None:
    """A hostile or broken Retry-After must not park the agent for a week."""
    sleeper = RecordingSleeper()

    async def limited() -> None:
        raise RateLimitedError("429", retry_after=604800.0)

    with pytest.raises(RateLimitedError):
        await retry_async(limited, policy=POLICY, max_attempts=2, sleep=sleeper)
    assert sleeper.delays == [100.0]


async def test_a_429_without_retry_after_uses_the_curve() -> None:
    sleeper = RecordingSleeper()

    async def limited() -> None:
        raise RateLimitedError("429")

    with pytest.raises(RateLimitedError):
        await retry_async(limited, policy=POLICY, max_attempts=3, sleep=sleeper)
    assert sleeper.delays == [1.0, 2.0]


async def test_zero_attempts_is_a_programming_error() -> None:
    async def anything() -> None:
        return None

    with pytest.raises(ValueError):
        await retry_async(anything, policy=POLICY, max_attempts=0)
