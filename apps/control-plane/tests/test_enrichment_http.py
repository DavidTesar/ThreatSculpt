"""The feed HTTP client.

A cold NVD sync is hours of requests against a rate-limited public API, so the
interesting behaviour is entirely in the failure paths: what gets retried, what
does not, how long we wait, and where the API key is allowed to go. All of it is
driven through ``httpx.MockTransport``, which never opens a socket — and could
not, because ``conftest`` blocks them.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from threatsculpt.enrichment.http import (
    MAX_RETRY_AFTER_SECONDS,
    NVD_ANONYMOUS_RATE,
    NVD_KEYED_RATE,
    FeedFetchError,
    HttpJsonFetcher,
    RollingWindowLimiter,
    default_rate_limit,
)

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = SecretStr("nvd-key-never-logged")


class Recorder:
    """A sleeper that records what it was asked to wait for, and does not."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


def fetcher_over(
    handler: Any, *, sleeper: Recorder | None = None, **kwargs: Any
) -> HttpJsonFetcher:
    """A fetcher whose transport is a function, with the rate limiter out of the way."""
    return HttpJsonFetcher(
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False),
        sleeper=sleeper or Recorder(),
        rate_limit=1000,
        **kwargs,
    )


# --- the happy path ---------------------------------------------------------


async def test_a_successful_response_is_decoded() -> None:
    fetcher = fetcher_over(lambda request: httpx.Response(200, json={"totalResults": 3}))
    assert await fetcher.get_json(URL) == {"totalResults": 3}
    await fetcher.aclose()


async def test_params_reach_the_request() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json={})

    fetcher = fetcher_over(handler)
    await fetcher.get_json(URL, {"startIndex": "2000", "resultsPerPage": "2000"})
    await fetcher.aclose()

    assert "startIndex=2000" in seen[0]
    assert "resultsPerPage=2000" in seen[0]


async def test_the_fetcher_closes_its_client_on_exit() -> None:
    client = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    async with HttpJsonFetcher(client=client, rate_limit=1000):
        pass
    assert client.is_closed


# --- retry ------------------------------------------------------------------


@pytest.mark.parametrize("status", [403, 429, 500, 502, 503, 504])
async def test_transient_statuses_are_retried_and_can_recover(status: int) -> None:
    attempts: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(status)
        if len(attempts) < 3:
            return httpx.Response(status)
        return httpx.Response(200, json={"ok": True})

    fetcher = fetcher_over(handler)
    assert await fetcher.get_json(URL) == {"ok": True}
    assert len(attempts) == 3
    await fetcher.aclose()


async def test_a_transport_failure_is_retried() -> None:
    attempts: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        if len(attempts) < 2:
            raise httpx.ConnectError("connection reset", request=request)
        return httpx.Response(200, json={"ok": True})

    fetcher = fetcher_over(handler)
    assert await fetcher.get_json(URL) == {"ok": True}
    await fetcher.aclose()


async def test_html_served_with_a_200_is_retried_not_returned() -> None:
    """A feed outage routinely answers 200 with an error page."""
    attempts: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        if len(attempts) < 2:
            return httpx.Response(200, text="<html>503 Service Unavailable</html>")
        return httpx.Response(200, json={"ok": True})

    fetcher = fetcher_over(handler)
    assert await fetcher.get_json(URL) == {"ok": True}
    await fetcher.aclose()


async def test_a_permanent_failure_is_not_retried() -> None:
    attempts: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        return httpx.Response(404)

    fetcher = fetcher_over(handler, max_attempts=5)
    with pytest.raises(FeedFetchError, match="HTTP 404"):
        await fetcher.get_json(URL)
    assert attempts == [1], "a 404 will not become a 200 on the fourth try"
    await fetcher.aclose()


async def test_retries_are_bounded_and_the_url_survives_into_the_error() -> None:
    attempts: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        return httpx.Response(503)

    fetcher = fetcher_over(handler, max_attempts=3)
    with pytest.raises(FeedFetchError, match=URL):
        await fetcher.get_json(URL)
    assert len(attempts) == 3
    await fetcher.aclose()


async def test_backoff_grows_between_attempts() -> None:
    sleeper = Recorder()
    fetcher = fetcher_over(
        lambda request: httpx.Response(503),
        sleeper=sleeper,
        max_attempts=5,
        backoff_seconds=10.0,
    )
    with pytest.raises(FeedFetchError):
        await fetcher.get_json(URL)
    await fetcher.aclose()

    # Full jitter, so assert on the ceiling rather than the value: 0-10, 0-20,
    # 0-40, 0-80. The last wait before giving up is never taken.
    assert len(sleeper.delays) == 4
    assert sleeper.delays[0] <= 10.0
    assert sleeper.delays[3] <= 80.0


async def test_retry_after_is_honoured_and_capped() -> None:
    sleeper = Recorder()
    fetcher = fetcher_over(
        lambda request: httpx.Response(429, headers={"Retry-After": "99999"}),
        sleeper=sleeper,
        max_attempts=2,
    )
    with pytest.raises(FeedFetchError):
        await fetcher.get_json(URL)
    await fetcher.aclose()

    assert sleeper.delays == [MAX_RETRY_AFTER_SECONDS]


async def test_an_http_date_retry_after_falls_back_to_backoff() -> None:
    """Only the delay-seconds form is understood; a date is ignored, not guessed."""
    sleeper = Recorder()
    fetcher = fetcher_over(
        lambda request: httpx.Response(
            503, headers={"Retry-After": "Wed, 21 Oct 2099 07:28:00 GMT"}
        ),
        sleeper=sleeper,
        max_attempts=2,
        backoff_seconds=4.0,
    )
    with pytest.raises(FeedFetchError):
        await fetcher.get_json(URL)
    await fetcher.aclose()

    assert sleeper.delays[0] <= 4.0


# --- where the API key may go ----------------------------------------------


async def test_the_api_key_is_sent_to_the_configured_host() -> None:
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("apiKey"))
        return httpx.Response(200, json={})

    fetcher = fetcher_over(handler, api_key=API_KEY, api_key_host="services.nvd.nist.gov")
    await fetcher.get_json(URL)
    await fetcher.aclose()

    assert seen == [API_KEY.get_secret_value()]


async def test_the_api_key_is_withheld_from_every_other_host() -> None:
    """CISA gets no NVD credential, and neither does a mirror or a typo."""
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("apiKey"))
        return httpx.Response(200, json={})

    fetcher = fetcher_over(handler, api_key=API_KEY, api_key_host="services.nvd.nist.gov")
    await fetcher.get_json("https://www.cisa.gov/feeds/known_exploited_vulnerabilities.json")
    await fetcher.get_json("https://services.nvd.nist.gov.evil.test/rest/json/cves/2.0")
    await fetcher.aclose()

    assert seen == [None, None]


async def test_a_key_with_no_host_configured_is_never_sent() -> None:
    """The default is to withhold, so a misconfiguration loses a request, not a key."""
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("apiKey"))
        return httpx.Response(200, json={})

    fetcher = fetcher_over(handler, api_key=API_KEY, api_key_host=None)
    await fetcher.get_json(URL)
    await fetcher.aclose()

    assert seen == [None]


async def test_a_redirect_is_refused_rather_than_followed() -> None:
    """httpx replays custom headers across origins; the key would go with it."""
    fetcher = fetcher_over(
        lambda request: httpx.Response(302, headers={"Location": "https://elsewhere.test/"}),
        api_key=API_KEY,
        api_key_host="services.nvd.nist.gov",
    )
    with pytest.raises(FeedFetchError, match="HTTP 302"):
        await fetcher.get_json(URL)
    await fetcher.aclose()


async def test_the_api_key_never_appears_in_an_error_or_a_log_record(
    caplog: pytest.LogCaptureFixture,
) -> None:
    fetcher = fetcher_over(
        lambda request: httpx.Response(503, text=f"denied for {API_KEY.get_secret_value()}"),
        api_key=API_KEY,
        api_key_host="services.nvd.nist.gov",
        max_attempts=2,
    )
    with caplog.at_level(logging.WARNING), pytest.raises(FeedFetchError) as caught:
        await fetcher.get_json(URL)
    await fetcher.aclose()

    secret = API_KEY.get_secret_value()
    assert secret not in str(caught.value)
    assert secret not in caplog.text


# --- rate limiting ----------------------------------------------------------


def test_the_default_budget_follows_whether_a_key_is_configured() -> None:
    assert default_rate_limit(None) == NVD_ANONYMOUS_RATE
    assert default_rate_limit(API_KEY) == NVD_KEYED_RATE
    assert NVD_KEYED_RATE == NVD_ANONYMOUS_RATE * 10, "the ~10h vs ~1h cold sync"


async def test_the_limiter_holds_callers_back_once_the_window_is_full() -> None:
    limiter = RollingWindowLimiter(2, 0.2)
    started = time.monotonic()
    for _ in range(3):
        await limiter.acquire()
    assert time.monotonic() - started >= 0.2


async def test_the_limiter_lets_a_full_window_through_without_waiting() -> None:
    limiter = RollingWindowLimiter(5, 30.0)
    started = time.monotonic()
    await asyncio.gather(*(limiter.acquire() for _ in range(5)))
    assert time.monotonic() - started < 0.2


@pytest.mark.parametrize(("limit", "window"), [(0, 30.0), (1, 0.0), (1, -1.0)])
def test_a_nonsensical_limiter_is_refused_at_construction(limit: int, window: float) -> None:
    with pytest.raises(ValueError, match="must be"):
        RollingWindowLimiter(limit, window)


def test_zero_attempts_is_refused() -> None:
    with pytest.raises(ValueError, match="max_attempts"):
        HttpJsonFetcher(max_attempts=0)
