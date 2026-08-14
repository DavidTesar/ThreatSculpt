"""The HTTP client for the upstream feeds. **The only module in ``src/`` that imports httpx.**

Everything else in ``enrichment/`` takes a ``feeds.JsonFetcher``, so the sync
path stays testable without a network call. That used to be guaranteed by there
being no HTTP client in ``src/`` at all, which also made ``RemoteFeed``
un-constructible in production. The guarantee now lives in
``tests/test_enrichment_no_network.py``: nothing under ``enrichment/`` except
this module may import httpx, and the whole suite runs behind a socket block.

Three things this module owns that the feeds themselves must not care about:

**Rate limiting.** NVD publishes 5 requests per rolling 30 seconds for anonymous
callers and 50 with an API key, per source address. Exceeding it earns a 403 for
a while, not a 429, so there is no retry that recovers a sustained overrun — the
limiter has to keep us under it rather than react to it. The same numbers are
the difference between a ~10-hour and a ~1-hour cold sync.

**Retry.** Transport failures and 5xx are transient; a cold sync spans hours, so
a run that gives up on the first blip never finishes. ``Retry-After`` is honoured
when the server sends one, capped so a hostile or broken value cannot park the
sync for a day.

**Redirects are not followed.** The NVD API key travels in a custom ``apiKey``
header, and httpx only strips ``Authorization`` and ``Cookie`` when a redirect
crosses origins — a custom header would be replayed to whatever host the
redirect named. Failing loudly on a 3xx is the cheaper mistake: an operator sees
an error instead of a credential landing somewhere it was never meant to go.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections import deque
from collections.abc import Awaitable, Callable, Mapping
from types import TracebackType
from typing import Any, Final, Self
from urllib.parse import urlsplit

import httpx
from pydantic import SecretStr

logger = logging.getLogger(__name__)

#: NVD's documented request budget, per source address, over a rolling window.
NVD_ANONYMOUS_RATE: Final = 5
NVD_KEYED_RATE: Final = 50
NVD_RATE_WINDOW_SECONDS: Final = 30.0

DEFAULT_TIMEOUT_SECONDS: Final = 30.0
DEFAULT_MAX_ATTEMPTS: Final = 5
DEFAULT_BACKOFF_SECONDS: Final = 2.0
MAX_BACKOFF_SECONDS: Final = 60.0

#: A server may name any delay it likes; this is the longest we will believe.
MAX_RETRY_AFTER_SECONDS: Final = 120.0

#: 403 is in here because NVD answers a rate-limit overrun with one rather than
#: a 429. It is retried on the assumption that the limiter has already backed
#: off; a genuinely forbidden request simply exhausts its attempts.
RETRYABLE_STATUS: Final = frozenset({403, 408, 429, 500, 502, 503, 504})

API_KEY_HEADER: Final = "apiKey"

_Sleeper = Callable[[float], Awaitable[None]]


class FeedFetchError(RuntimeError):
    """A feed request could not be completed.

    Carries the URL and status only. Response bodies are deliberately left out:
    they are attacker-influenced text that would end up in logs verbatim.
    """


class RollingWindowLimiter:
    """At most ``limit`` acquisitions per ``window_seconds``, oldest-first.

    Holding the lock across the sleep serialises callers on purpose. Paging is
    sequential anyway, and a limiter that lets ten coroutines through the moment
    a slot frees is not a limiter.
    """

    def __init__(
        self, limit: int, window_seconds: float, *, sleeper: _Sleeper = asyncio.sleep
    ) -> None:
        if limit < 1:
            raise ValueError("limit must be at least 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self._limit = limit
        self._window = window_seconds
        self._sleeper = sleeper
        self._lock = asyncio.Lock()
        self._issued: deque[float] = deque()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                while self._issued and now - self._issued[0] >= self._window:
                    self._issued.popleft()
                if len(self._issued) < self._limit:
                    self._issued.append(now)
                    return
                await self._sleeper(self._window - (now - self._issued[0]))


class HttpJsonFetcher:
    """An httpx-backed ``feeds.JsonFetcher``.

    Use it as an async context manager so the connection pool is closed even
    when a sync is interrupted::

        async with HttpJsonFetcher(api_key=settings.nvd_api_key) as fetcher:
            report = await sync_mirror(session, RemoteFeed(fetcher=fetcher))
    """

    def __init__(
        self,
        *,
        api_key: SecretStr | None = None,
        api_key_host: str | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        backoff_seconds: float = DEFAULT_BACKOFF_SECONDS,
        rate_limit: int | None = None,
        rate_window_seconds: float = NVD_RATE_WINDOW_SECONDS,
        client: httpx.AsyncClient | None = None,
        sleeper: _Sleeper = asyncio.sleep,
    ) -> None:
        if max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        self._api_key = api_key
        #: The key is only ever attached to this host. Anything else — a
        #: mirror, a proxy, a typo in configuration — gets an unkeyed request.
        self._api_key_host = api_key_host
        self._max_attempts = max_attempts
        self._backoff = backoff_seconds
        self._sleeper = sleeper
        self._limiter = RollingWindowLimiter(
            rate_limit if rate_limit is not None else default_rate_limit(api_key),
            rate_window_seconds,
            sleeper=sleeper,
        )
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            headers={"Accept": "application/json", "User-Agent": "threatsculpt-control-plane/2.0"},
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def get_json(self, url: str, params: Mapping[str, str] | None = None) -> Any:
        """Fetch and decode one JSON document, retrying what is worth retrying."""
        last_error = ""
        for attempt in range(1, self._max_attempts + 1):
            await self._limiter.acquire()
            outcome = await self._attempt(url, params)
            if outcome.payload is not _MISSING:
                return outcome.payload
            last_error = outcome.error
            if not outcome.retryable or attempt == self._max_attempts:
                break
            delay = outcome.retry_after or self._backoff_for(attempt)
            logger.warning(
                "feed request failed, retrying",
                extra={"url": url, "attempt": attempt, "delay": round(delay, 2)},
            )
            await self._sleeper(delay)
        raise FeedFetchError(f"{url}: {last_error} (after {self._max_attempts} attempts)")

    async def _attempt(self, url: str, params: Mapping[str, str] | None) -> _Attempt:
        try:
            response = await self._client.get(url, params=params, headers=self._headers_for(url))
        except httpx.TransportError as exc:
            return _Attempt(error=f"transport error: {type(exc).__name__}", retryable=True)
        if response.is_success:
            return self._decode(response)
        return _Attempt(
            error=f"HTTP {response.status_code}",
            retryable=response.status_code in RETRYABLE_STATUS,
            retry_after=_retry_after(response.headers.get("Retry-After")),
        )

    def _decode(self, response: httpx.Response) -> _Attempt:
        try:
            return _Attempt(payload=response.json())
        except ValueError:
            # A feed outage routinely answers 200 with an HTML error page.
            return _Attempt(error="response body was not JSON", retryable=True)

    def _headers_for(self, url: str) -> dict[str, str]:
        """The key travels only to a host that was named. Default is to withhold.

        ``api_key_host`` is checked for truth rather than just compared, so a
        misconfiguration that leaves it unset cannot match a URL that happens to
        parse to no hostname and quietly send the credential.
        """
        if self._api_key is None or not self._api_key_host:
            return {}
        if urlsplit(url).hostname != self._api_key_host:
            return {}
        return {API_KEY_HEADER: self._api_key.get_secret_value()}

    def _backoff_for(self, attempt: int) -> float:
        """Exponential with full jitter, so a fleet does not retry in lockstep."""
        ceiling = min(self._backoff * (2 ** (attempt - 1)), MAX_BACKOFF_SECONDS)
        return random.uniform(0.0, ceiling)  # noqa: S311 - jitter, not a secret


class _Missing:
    """Sentinel: ``None`` is a legitimate JSON document, so it cannot mean failure."""


_MISSING: Final = _Missing()


class _Attempt:
    __slots__ = ("error", "payload", "retry_after", "retryable")

    def __init__(
        self,
        *,
        payload: Any = _MISSING,
        error: str = "",
        retryable: bool = False,
        retry_after: float | None = None,
    ) -> None:
        self.payload = payload
        self.error = error
        self.retryable = retryable
        self.retry_after = retry_after


def default_rate_limit(api_key: SecretStr | None) -> int:
    return NVD_KEYED_RATE if api_key is not None else NVD_ANONYMOUS_RATE


def _retry_after(value: str | None) -> float | None:
    """Only the delay-seconds form. An HTTP-date is ignored rather than guessed."""
    if value is None:
        return None
    try:
        seconds = float(value.strip())
    except ValueError:
        return None
    if seconds < 0:
        return None
    return min(seconds, MAX_RETRY_AFTER_SECONDS)
