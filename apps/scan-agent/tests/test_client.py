"""Control-plane client: auth handling, status-code mapping, secret hygiene."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import httpx
import pytest
import respx
from conftest import API_PREFIX, BASE_URL

from threatsculpt_agent.api.client import ControlPlaneClient
from threatsculpt_agent.errors import (
    ApiError,
    AuthRevokedError,
    ClientError,
    JobConflictError,
    RateLimitedError,
    ServerError,
    TransportError,
)
from threatsculpt_agent.models import (
    ClaimedJob,
    HeartbeatRequest,
    HostObservation,
    RejectRequest,
    ResultSubmission,
    StatusRequest,
)

API_KEY = "tsa_secret_key_value"
HEARTBEAT = HeartbeatRequest(version="2.0.0", nmap_version="7.99")


@pytest.fixture
async def client() -> ControlPlaneClient:
    async with ControlPlaneClient(BASE_URL, api_key=API_KEY) as instance:
        yield instance


# --- auth ------------------------------------------------------------------------------


@respx.mock
async def test_the_api_key_travels_as_a_bearer_header(client: ControlPlaneClient) -> None:
    route = respx.post(f"{API_PREFIX}/heartbeat").mock(
        return_value=httpx.Response(200, json={"revoked": False})
    )
    await client.heartbeat(HEARTBEAT)

    assert route.calls.last.request.headers["Authorization"] == f"Bearer {API_KEY}"


@respx.mock
async def test_the_api_key_never_appears_in_a_url(client: ControlPlaneClient) -> None:
    """URLs end up in proxy logs and access logs; headers do not."""
    route = respx.post(f"{API_PREFIX}/heartbeat").mock(
        return_value=httpx.Response(200, json={"revoked": False})
    )
    await client.heartbeat(HEARTBEAT)

    request = route.calls.last.request
    assert API_KEY not in str(request.url)
    assert API_KEY not in request.content.decode()


@respx.mock
async def test_enrollment_is_the_only_unauthenticated_call() -> None:
    route = respx.post(f"{API_PREFIX}/enroll").mock(
        return_value=httpx.Response(
            201, json={"agent_id": "a", "api_key": "tsa_new", "org_id": "o"}
        )
    )
    async with ControlPlaneClient(BASE_URL) as anonymous:
        from threatsculpt_agent.models import EnrollRequest

        await anonymous.enroll(
            EnrollRequest(enrollment_token="tse_x", name="a", version="2.0.0", hostname="h")
        )

    assert "Authorization" not in route.calls.last.request.headers


async def test_an_authenticated_call_without_a_key_fails_loudly() -> None:
    async with ControlPlaneClient(BASE_URL) as anonymous:
        with pytest.raises(ApiError, match="requires an API key"):
            await anonymous.heartbeat(HEARTBEAT)


async def test_with_api_key_returns_a_new_client_and_leaves_the_original_alone() -> None:
    async with ControlPlaneClient(BASE_URL) as anonymous:
        authenticated = anonymous.with_api_key(API_KEY)

        assert authenticated is not anonymous
        assert authenticated.has_api_key
        assert not anonymous.has_api_key


# --- status-code mapping (protocol §6) --------------------------------------------------


@respx.mock
async def test_401_is_revocation(client: ControlPlaneClient) -> None:
    respx.post(f"{API_PREFIX}/heartbeat").mock(return_value=httpx.Response(401))
    with pytest.raises(AuthRevokedError):
        await client.heartbeat(HEARTBEAT)


@respx.mock
async def test_a_revoked_flag_is_revocation_even_with_a_200(client: ControlPlaneClient) -> None:
    respx.post(f"{API_PREFIX}/heartbeat").mock(
        return_value=httpx.Response(200, json={"revoked": True})
    )
    with pytest.raises(AuthRevokedError, match="revoked"):
        await client.heartbeat(HEARTBEAT)


@respx.mock
async def test_409_is_a_job_conflict(client: ControlPlaneClient) -> None:
    respx.post(f"{API_PREFIX}/jobs/job-1/status").mock(return_value=httpx.Response(409))
    with pytest.raises(JobConflictError):
        await client.update_status("job-1", StatusRequest(status="running", progress_percent=1))


@respx.mock
async def test_429_carries_retry_after_seconds(client: ControlPlaneClient) -> None:
    respx.post(f"{API_PREFIX}/jobs/claim").mock(
        return_value=httpx.Response(429, headers={"Retry-After": "17"})
    )
    with pytest.raises(RateLimitedError) as caught:
        await client.claim_jobs(1)

    assert caught.value.retry_after == 17.0


@respx.mock
async def test_429_accepts_an_http_date_retry_after(client: ControlPlaneClient) -> None:
    when = datetime.now(tz=UTC) + timedelta(seconds=60)
    respx.post(f"{API_PREFIX}/jobs/claim").mock(
        return_value=httpx.Response(429, headers={"Retry-After": format_datetime(when)})
    )
    with pytest.raises(RateLimitedError) as caught:
        await client.claim_jobs(1)

    assert caught.value.retry_after is not None
    assert 50 <= caught.value.retry_after <= 61


@respx.mock
async def test_an_unparseable_retry_after_is_not_fatal(client: ControlPlaneClient) -> None:
    respx.post(f"{API_PREFIX}/jobs/claim").mock(
        return_value=httpx.Response(429, headers={"Retry-After": "soon"})
    )
    with pytest.raises(RateLimitedError) as caught:
        await client.claim_jobs(1)

    assert caught.value.retry_after is None


@respx.mock
@pytest.mark.parametrize("status", [500, 502, 503])
async def test_5xx_is_retryable(client: ControlPlaneClient, status: int) -> None:
    respx.post(f"{API_PREFIX}/jobs/claim").mock(return_value=httpx.Response(status))
    with pytest.raises(ServerError):
        await client.claim_jobs(1)


@respx.mock
@pytest.mark.parametrize("status", [400, 403, 404, 422])
async def test_other_4xx_is_not_retryable(client: ControlPlaneClient, status: int) -> None:
    respx.post(f"{API_PREFIX}/jobs/claim").mock(return_value=httpx.Response(status))
    with pytest.raises(ClientError):
        await client.claim_jobs(1)


@respx.mock
async def test_a_network_failure_becomes_a_transport_error(client: ControlPlaneClient) -> None:
    respx.post(f"{API_PREFIX}/heartbeat").mock(side_effect=httpx.ConnectError("no route"))
    with pytest.raises(TransportError, match="ConnectError"):
        await client.heartbeat(HEARTBEAT)


@respx.mock
async def test_a_non_json_body_is_reported_clearly(client: ControlPlaneClient) -> None:
    respx.post(f"{API_PREFIX}/jobs/claim").mock(
        return_value=httpx.Response(200, text="<html>gateway</html>")
    )
    with pytest.raises(ApiError, match="non-JSON"):
        await client.claim_jobs(1)


# --- payload shapes --------------------------------------------------------------------


@respx.mock
async def test_claim_parses_jobs(client: ControlPlaneClient) -> None:
    route = respx.post(f"{API_PREFIX}/jobs/claim").mock(
        return_value=httpx.Response(
            200,
            json={
                "jobs": [
                    {
                        "job_id": "job-1",
                        "target": "10.0.4.0/24",
                        "profile": "service",
                        "lease_expires_at": "2026-08-12T18:00:00Z",
                    }
                ]
            },
        )
    )
    response = await client.claim_jobs(2)

    assert response.jobs[0] == ClaimedJob(
        job_id="job-1",
        target="10.0.4.0/24",
        profile="service",
        lease_expires_at=datetime(2026, 8, 12, 18, 0, tzinfo=UTC),
    )
    assert route.calls.last.request.read() == b'{"capacity":2}'


@respx.mock
async def test_heartbeat_distinguishes_an_absent_allowlist_from_an_empty_one(
    client: ControlPlaneClient,
) -> None:
    respx.post(f"{API_PREFIX}/heartbeat").mock(
        return_value=httpx.Response(200, json={"revoked": False})
    )
    assert (await client.heartbeat(HEARTBEAT)).allowlist is None

    respx.post(f"{API_PREFIX}/heartbeat").mock(
        return_value=httpx.Response(200, json={"allowlist": [], "revoked": False})
    )
    assert (await client.heartbeat(HEARTBEAT)).allowlist == ()


@respx.mock
async def test_unknown_response_fields_do_not_break_an_older_agent(
    client: ControlPlaneClient,
) -> None:
    respx.post(f"{API_PREFIX}/heartbeat").mock(
        return_value=httpx.Response(
            200, json={"revoked": False, "a_field_from_the_future": {"nested": 1}}
        )
    )
    assert (await client.heartbeat(HEARTBEAT)).revoked is False


@respx.mock
async def test_reject_sends_the_reason_and_detail(client: ControlPlaneClient) -> None:
    route = respx.post(f"{API_PREFIX}/jobs/job-1/reject").mock(return_value=httpx.Response(204))
    await client.reject_job(
        "job-1", RejectRequest(reason="target_not_in_local_allowlist", detail="8.8.8.8/32")
    )

    body = route.calls.last.request.read().decode()
    assert "target_not_in_local_allowlist" in body


@respx.mock
async def test_results_carry_an_idempotency_key(client: ControlPlaneClient) -> None:
    """A retried batch must not double-insert; the server keys on (job_id, host_ip)."""
    route = respx.post(f"{API_PREFIX}/jobs/job-1/results").mock(
        return_value=httpx.Response(202, json={"accepted": True, "hosts_ingested": 1})
    )
    moment = datetime.now(tz=UTC)
    submission = ResultSubmission(
        started_at=moment,
        finished_at=moment,
        nmap_version="7.99",
        hosts=(HostObservation(ip="10.0.4.12"),),
        chunk_index=3,
    )
    ack = await client.submit_results("job-1", submission)

    assert ack.accepted and ack.hosts_ingested == 1
    assert route.calls.last.request.headers["Idempotency-Key"] == "job-1:3"


@respx.mock
async def test_an_empty_202_body_is_accepted(client: ControlPlaneClient) -> None:
    respx.post(f"{API_PREFIX}/jobs/job-1/results").mock(return_value=httpx.Response(202))
    moment = datetime.now(tz=UTC)
    ack = await client.submit_results(
        "job-1",
        ResultSubmission(
            started_at=moment, finished_at=moment, nmap_version="7.99", hosts=()
        ),
    )
    assert ack.accepted
