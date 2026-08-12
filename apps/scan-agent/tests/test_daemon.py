"""The poll loop: heartbeat, claim, revocation, backoff, graceful shutdown."""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import pytest
import respx
from conftest import API_PREFIX, BASE_URL, make_settings

from threatsculpt_agent.api.client import ControlPlaneClient
from threatsculpt_agent.daemon import EXIT_OK, AgentDaemon, LoopState, _parse_server_allowlist
from threatsculpt_agent.keystore import KeyStore
from threatsculpt_agent.models import HeartbeatResponse
from threatsculpt_agent.nmap.runner import NmapRunResult

JOB = {"job_id": "job-1", "target": "10.0.4.0/24", "profile": "service"}


class StubRunner:
    """A controllable nmap. Can block forever or take a known moment, to test shutdown."""

    def __init__(self, stdout: bytes = b"", block: bool = False, delay: float = 0.0) -> None:
        self.stdout = stdout
        self.block = block
        self.delay = delay
        self.started = asyncio.Event()

    async def run(self, target: str, profile: str) -> NmapRunResult:
        self.started.set()
        if self.block:
            await asyncio.sleep(3600)
        if self.delay:
            await asyncio.sleep(self.delay)
        return NmapRunResult(("nmap",), 0, self.stdout, "", 0.1)


def build_daemon(
    tmp_path: Path, client: ControlPlaneClient, runner: StubRunner | None = None, **overrides
) -> AgentDaemon:  # type: ignore[no-untyped-def]
    keystore = KeyStore(tmp_path / "agent.key")
    keystore.write("tsa_test_key")
    daemon = AgentDaemon.build(make_settings(tmp_path, **overrides), client, keystore, "7.99")
    if runner is not None:
        daemon.executor = type(daemon.executor)(  # frozen dataclass -> build a new one
            settings=daemon.executor.settings,
            client=daemon.executor.client,
            runner=runner,  # type: ignore[arg-type]
            policy=daemon.executor.policy,
        )
    return daemon


@pytest.fixture
async def client() -> ControlPlaneClient:
    async with ControlPlaneClient(BASE_URL, api_key="tsa_test_key") as instance:
        yield instance


def _mock_endpoints(
    jobs: list[dict[str, str]] | None = None, **heartbeat: object
) -> dict[str, respx.Route]:
    """Register every agent endpoint and hand back the routes.

    Callers must use these handles rather than re-registering a route to inspect it:
    a second respx.post() for the same URL replaces the mock and silently changes the
    response the code under test sees.
    """
    return {
        "heartbeat": respx.post(f"{API_PREFIX}/heartbeat").mock(
            return_value=httpx.Response(200, json={"revoked": False, **heartbeat})
        ),
        "claim": respx.post(f"{API_PREFIX}/jobs/claim").mock(
            return_value=httpx.Response(200, json={"jobs": jobs or []})
        ),
        "status": respx.post(f"{API_PREFIX}/jobs/job-1/status").mock(
            return_value=httpx.Response(204)
        ),
        "reject": respx.post(f"{API_PREFIX}/jobs/job-1/reject").mock(
            return_value=httpx.Response(204)
        ),
        "results": respx.post(f"{API_PREFIX}/jobs/job-1/results").mock(
            return_value=httpx.Response(202, json={"accepted": True})
        ),
    }


# --- the loop ----------------------------------------------------------------------------


@respx.mock
async def test_a_cycle_heartbeats_then_claims(tmp_path: Path, client: ControlPlaneClient) -> None:
    routes = _mock_endpoints()

    assert await build_daemon(tmp_path, client).run(max_cycles=1) == EXIT_OK
    assert routes["heartbeat"].called and routes["claim"].called


@respx.mock
async def test_the_heartbeat_reports_versions(tmp_path: Path, client: ControlPlaneClient) -> None:
    routes = _mock_endpoints()

    await build_daemon(tmp_path, client).run(max_cycles=1)

    body = routes["heartbeat"].calls.last.request.read().decode()
    assert '"nmap_version":"7.99"' in body
    assert '"healthy":true' in body


@respx.mock
async def test_a_claimed_job_runs_to_completion(
    tmp_path: Path, client: ControlPlaneClient, service_xml: bytes
) -> None:
    routes = _mock_endpoints(jobs=[JOB])

    await build_daemon(tmp_path, client, StubRunner(stdout=service_xml)).run(max_cycles=1)

    assert routes["results"].called


@respx.mock
async def test_the_server_poll_interval_is_adopted(
    tmp_path: Path, client: ControlPlaneClient
) -> None:
    _mock_endpoints(poll_interval_seconds=77)
    daemon = build_daemon(tmp_path, client)

    await daemon.run(max_cycles=1)

    assert daemon._state.poll_interval_seconds == 77.0


@respx.mock
async def test_a_job_outside_the_local_allowlist_is_rejected_by_the_loop(
    tmp_path: Path, client: ControlPlaneClient
) -> None:
    routes = _mock_endpoints(jobs=[{**JOB, "target": "8.8.8.8/32"}], allowlist=["0.0.0.0/0"])
    runner = StubRunner()

    await build_daemon(tmp_path, client, runner).run(max_cycles=1)

    assert not runner.started.is_set()
    body = routes["reject"].calls.last.request.read().decode()
    assert "target_not_in_local_allowlist" in body


# --- revocation ---------------------------------------------------------------------------


@respx.mock
async def test_a_revoked_flag_wipes_the_key_and_exits_cleanly(
    tmp_path: Path, client: ControlPlaneClient
) -> None:
    respx.post(f"{API_PREFIX}/heartbeat").mock(
        return_value=httpx.Response(200, json={"revoked": True})
    )
    daemon = build_daemon(tmp_path, client)

    exit_code = await daemon.run(max_cycles=5)

    assert exit_code == EXIT_OK
    assert not daemon.keystore.exists()


@respx.mock
async def test_a_401_wipes_the_key_and_exits_cleanly(
    tmp_path: Path, client: ControlPlaneClient
) -> None:
    respx.post(f"{API_PREFIX}/heartbeat").mock(return_value=httpx.Response(401))
    daemon = build_daemon(tmp_path, client)

    assert await daemon.run(max_cycles=5) == EXIT_OK
    assert not daemon.keystore.exists()


@respx.mock
async def test_revocation_is_not_retried(tmp_path: Path, client: ControlPlaneClient) -> None:
    """Hammering an endpoint that just said 'you are revoked' looks like an attack."""
    heartbeat = respx.post(f"{API_PREFIX}/heartbeat").mock(return_value=httpx.Response(401))

    await build_daemon(tmp_path, client).run(max_cycles=5)

    assert heartbeat.call_count == 1


@respx.mock
async def test_revocation_mid_job_still_wipes_the_key(
    tmp_path: Path, client: ControlPlaneClient, service_xml: bytes
) -> None:
    _mock_endpoints(jobs=[JOB])
    respx.post(f"{API_PREFIX}/jobs/job-1/status").mock(return_value=httpx.Response(401))
    daemon = build_daemon(tmp_path, client, StubRunner(stdout=service_xml))

    assert await daemon.run(max_cycles=1) == EXIT_OK
    assert not daemon.keystore.exists()


# --- failure and backoff --------------------------------------------------------------------


@respx.mock
async def test_a_server_outage_backs_off_and_keeps_polling(
    tmp_path: Path, client: ControlPlaneClient
) -> None:
    heartbeat = respx.post(f"{API_PREFIX}/heartbeat").mock(return_value=httpx.Response(503))
    daemon = build_daemon(tmp_path, client)

    assert await daemon.run(max_cycles=2) == EXIT_OK
    assert daemon._state.consecutive_failures == 2
    assert heartbeat.call_count == 6  # 3 attempts per cycle, 2 cycles


@respx.mock
async def test_consecutive_failures_reset_after_a_good_cycle(
    tmp_path: Path, client: ControlPlaneClient
) -> None:
    respx.post(f"{API_PREFIX}/heartbeat").mock(
        side_effect=[httpx.Response(503)] * 3 + [httpx.Response(200, json={"revoked": False})]
    )
    respx.post(f"{API_PREFIX}/jobs/claim").mock(
        return_value=httpx.Response(200, json={"jobs": []})
    )
    daemon = build_daemon(tmp_path, client)

    await daemon.run(max_cycles=2)

    assert daemon._state.consecutive_failures == 0


@respx.mock
async def test_a_429_does_not_kill_the_loop(tmp_path: Path, client: ControlPlaneClient) -> None:
    respx.post(f"{API_PREFIX}/heartbeat").mock(
        return_value=httpx.Response(429, headers={"Retry-After": "0"})
    )
    assert await build_daemon(tmp_path, client).run(max_cycles=1) == EXIT_OK


def test_an_unparseable_server_allowlist_narrows_to_nothing() -> None:
    """Fail closed. A garbled allowlist must never be read as 'anything goes'."""
    assert _parse_server_allowlist(("not-a-cidr",)) == ()
    assert _parse_server_allowlist(None) is None


def test_loop_state_is_replaced_not_mutated() -> None:
    state = LoopState()
    updated = state.with_heartbeat(HeartbeatResponse(poll_interval_seconds=60), 30.0)

    assert state.poll_interval_seconds == 30.0
    assert updated.poll_interval_seconds == 60.0


# --- shutdown ---------------------------------------------------------------------------------


@respx.mock
async def test_shutdown_stops_the_loop(tmp_path: Path, client: ControlPlaneClient) -> None:
    _mock_endpoints()
    daemon = build_daemon(tmp_path, client, poll_interval_seconds=30)
    daemon.request_shutdown("SIGTERM")

    assert await daemon.run() == EXIT_OK


@respx.mock
async def test_shutdown_interrupts_a_long_poll_sleep(
    tmp_path: Path, client: ControlPlaneClient
) -> None:
    """A 300-second backoff must not make systemd wait 300 seconds to stop the unit."""
    _mock_endpoints()
    daemon = build_daemon(tmp_path, client, poll_interval_seconds=300)

    async def stop_soon() -> None:
        await asyncio.sleep(0.05)
        daemon.request_shutdown("SIGTERM")

    async with asyncio.timeout(5):
        await asyncio.gather(daemon.run(), stop_soon())


@respx.mock
async def test_a_pre_shutdown_start_claims_nothing(
    tmp_path: Path, client: ControlPlaneClient
) -> None:
    """Shutdown before the first cycle: exit without taking on work someone else can run."""
    routes = _mock_endpoints(jobs=[JOB])
    daemon = build_daemon(tmp_path, client, StubRunner())
    daemon.request_shutdown("SIGTERM")

    assert await daemon.run(max_cycles=1) == EXIT_OK
    assert not routes["claim"].called


@respx.mock
async def test_a_single_cycle_exits_without_waiting_out_the_poll_interval(
    tmp_path: Path, client: ControlPlaneClient
) -> None:
    """`--once` must return promptly, not idle for a full server-supplied interval."""
    _mock_endpoints(poll_interval_seconds=600)
    daemon = build_daemon(tmp_path, client)

    async with asyncio.timeout(5):
        assert await daemon.run(max_cycles=1) == EXIT_OK


@respx.mock
async def test_an_in_flight_job_is_allowed_to_finish(
    tmp_path: Path, client: ControlPlaneClient, service_xml: bytes
) -> None:
    """A scan already running when SIGTERM lands completes and submits its results."""
    routes = _mock_endpoints(jobs=[JOB])
    runner = StubRunner(stdout=service_xml, delay=0.2)
    daemon = build_daemon(tmp_path, client, runner, shutdown_grace_seconds=10)

    async def stop_once_scanning() -> None:
        await runner.started.wait()
        daemon.request_shutdown("SIGTERM")

    async with asyncio.timeout(10):
        await asyncio.gather(daemon.run(max_cycles=1), stop_once_scanning())

    assert routes["results"].called  # finished, not abandoned
    assert not routes["reject"].called


@respx.mock
async def test_a_hung_job_is_released_rather_than_abandoned(
    tmp_path: Path, client: ControlPlaneClient
) -> None:
    """The lease is handed back so the control plane can requeue now, not in 30 minutes."""
    routes = _mock_endpoints(jobs=[JOB])
    runner = StubRunner(block=True)
    daemon = build_daemon(tmp_path, client, runner, shutdown_grace_seconds=0.1)

    async def stop_once_scanning() -> None:
        await runner.started.wait()
        daemon.request_shutdown("SIGTERM")

    async with asyncio.timeout(10):
        await asyncio.gather(daemon.run(max_cycles=1), stop_once_scanning())

    assert routes["reject"].called
    assert "agent_shutdown" in routes["reject"].calls.last.request.read().decode()
