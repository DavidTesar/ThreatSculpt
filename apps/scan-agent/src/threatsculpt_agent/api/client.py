"""Async HTTP client for the agent side of docs/AGENT-PROTOCOL.md.

Outbound HTTPS only; the agent never listens. The API key travels in an Authorization
header, is never logged, and is never placed in a URL (URLs end up in proxy logs).

Status handling follows §6 exactly: 401 -> AuthRevokedError (caller wipes the key and
exits), 409 -> JobConflictError (drop the job, re-poll), 429 -> RateLimitedError carrying
Retry-After, 5xx -> ServerError (retryable), other 4xx -> ClientError (not retryable).
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from .. import AGENT_VERSION
from ..errors import (
    ApiError,
    AuthRevokedError,
    ClientError,
    JobConflictError,
    RateLimitedError,
    ServerError,
    TransportError,
)
from ..models import (
    ClaimRequest,
    ClaimResponse,
    EnrollRequest,
    EnrollResponse,
    HeartbeatRequest,
    HeartbeatResponse,
    RejectRequest,
    ResultSubmission,
    StatusRequest,
    SubmissionAck,
)

log = logging.getLogger(__name__)

API_BASE_PATH = "/api/v1/agent"
USER_AGENT = f"threatsculpt-scan-agent/{AGENT_VERSION}"


class ControlPlaneClient:
    """One client per process. Immutable with respect to its API key.

    ``with_api_key`` returns a *new* client sharing the same connection pool rather than
    mutating this one, so an enrolled key can never be retro-fitted onto a request that
    was already built.
    """

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str | None = None,
        timeout: float = 30.0,
        verify: bool = True,
        http_client: httpx.AsyncClient | None = None,
        _owns_client: bool = True,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._owns_client = _owns_client if http_client is not None else True
        self._http = http_client or httpx.AsyncClient(
            timeout=timeout,
            verify=verify,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        )

    # -- lifecycle ---------------------------------------------------------------

    def with_api_key(self, api_key: str) -> ControlPlaneClient:
        return ControlPlaneClient(
            self._base_url,
            api_key=api_key,
            http_client=self._http,
            _owns_client=False,
        )

    @property
    def has_api_key(self) -> bool:
        return bool(self._api_key)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._http.aclose()

    async def __aenter__(self) -> ControlPlaneClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.aclose()

    # -- protocol endpoints ------------------------------------------------------

    async def enroll(self, request: EnrollRequest) -> EnrollResponse:
        payload = await self._post("/enroll", request, authenticated=False)
        return EnrollResponse.model_validate(payload)

    async def heartbeat(self, request: HeartbeatRequest) -> HeartbeatResponse:
        payload = await self._post("/heartbeat", request)
        response = HeartbeatResponse.model_validate(payload)
        if response.revoked:
            raise AuthRevokedError("control plane reported this agent as revoked")
        return response

    async def claim_jobs(self, capacity: int) -> ClaimResponse:
        payload = await self._post("/jobs/claim", ClaimRequest(capacity=capacity))
        return ClaimResponse.model_validate(payload)

    async def reject_job(self, job_id: str, request: RejectRequest) -> None:
        await self._post(f"/jobs/{job_id}/reject", request)

    async def update_status(self, job_id: str, request: StatusRequest) -> None:
        await self._post(f"/jobs/{job_id}/status", request)

    async def submit_results(self, job_id: str, submission: ResultSubmission) -> SubmissionAck:
        payload = await self._post(
            f"/jobs/{job_id}/results",
            submission,
            extra_headers={
                "Idempotency-Key": f"{job_id}:{submission.chunk_index}",
            },
        )
        return SubmissionAck.model_validate(payload) if payload else SubmissionAck()

    # -- transport ---------------------------------------------------------------

    async def _post(
        self,
        path: str,
        body: Any,
        *,
        authenticated: bool = True,
        extra_headers: Mapping[str, str] | None = None,
    ) -> Any:
        url = f"{self._base_url}{API_BASE_PATH}{path}"
        headers = dict(extra_headers or {})
        if authenticated:
            if not self._api_key:
                raise ApiError(f"POST {path} requires an API key but none is loaded")
            headers["Authorization"] = f"Bearer {self._api_key}"

        try:
            response = await self._http.post(
                url, json=body.model_dump(mode="json"), headers=headers
            )
        except httpx.HTTPError as exc:
            raise TransportError(f"POST {path} failed: {type(exc).__name__}: {exc}") from exc

        _raise_for_status(path, response)
        return _decode(path, response)


def _raise_for_status(path: str, response: httpx.Response) -> None:
    status = response.status_code
    if status < 400:
        return
    detail = _short_body(response)
    if status == 401:
        raise AuthRevokedError(f"POST {path} rejected the agent key (401): {detail}")
    if status == 409:
        raise JobConflictError(f"POST {path} conflict (409): {detail}")
    if status == 429:
        raise RateLimitedError(
            f"POST {path} rate limited (429): {detail}",
            retry_after=_retry_after_seconds(response.headers.get("Retry-After")),
        )
    if status >= 500:
        raise ServerError(f"POST {path} server error ({status}): {detail}")
    raise ClientError(f"POST {path} failed ({status}): {detail}")


def _decode(path: str, response: httpx.Response) -> Any:
    if response.status_code == 204 or not response.content:
        return None
    try:
        return response.json()
    except ValueError as exc:
        raise ApiError(f"POST {path} returned a non-JSON body: {exc}") from exc


def _short_body(response: httpx.Response, limit: int = 300) -> str:
    try:
        return response.text[:limit].replace("\n", " ")
    except (UnicodeDecodeError, httpx.ResponseNotRead):
        return "<unreadable body>"


def _retry_after_seconds(raw: str | None) -> float | None:
    """Retry-After is either delta-seconds or an HTTP-date. Support both."""
    if not raw:
        return None
    stripped = raw.strip()
    try:
        return max(0.0, float(stripped))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(stripped)
    except (TypeError, ValueError):
        log.warning("unparseable Retry-After header")
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0.0, (when - datetime.now(tz=UTC)).total_seconds())
