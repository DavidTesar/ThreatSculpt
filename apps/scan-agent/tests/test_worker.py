"""Job execution end to end, with the HTTP side mocked and nmap stubbed.

The most important test in this file is the first one: a target outside the local
allowlist must be rejected *without nmap ever being invoked*.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx
from conftest import API_PREFIX, BASE_URL, make_settings

from threatsculpt_agent.allowlist import parse_networks
from threatsculpt_agent.api.backoff import BackoffPolicy
from threatsculpt_agent.api.client import ControlPlaneClient
from threatsculpt_agent.errors import NmapFailedError, NmapTimeoutError
from threatsculpt_agent.models import ClaimedJob
from threatsculpt_agent.nmap.runner import NmapRunResult
from threatsculpt_agent.worker import JobExecutor


class SpyRunner:
    """Stands in for NmapRunner. Records calls; can be told to fail."""

    def __init__(self, stdout: bytes = b"", error: Exception | None = None) -> None:
        self.calls: list[tuple[str, str]] = []
        self._stdout = stdout
        self._error = error

    async def run(self, target: str, profile: str) -> NmapRunResult:
        self.calls.append((target, profile))
        if self._error is not None:
            raise self._error
        return NmapRunResult(
            argv=("/usr/bin/nmap", target),
            returncode=0,
            stdout=self._stdout,
            stderr="",
            duration_seconds=1.0,
        )


def build_executor(tmp_path: Path, client: ControlPlaneClient, runner: SpyRunner, **overrides):  # type: ignore[no-untyped-def]
    return JobExecutor(
        settings=make_settings(tmp_path, **overrides),
        client=client,
        runner=runner,  # type: ignore[arg-type]
        policy=BackoffPolicy(base_seconds=0.001, max_seconds=0.002, jitter_ratio=0.0),
    )


@pytest.fixture
async def client() -> ControlPlaneClient:
    async with ControlPlaneClient(BASE_URL, api_key="tsa_test") as instance:
        yield instance


def _mock_job_endpoints(job_id: str = "job-1") -> None:
    respx.post(f"{API_PREFIX}/jobs/{job_id}/status").mock(return_value=httpx.Response(204))
    respx.post(f"{API_PREFIX}/jobs/{job_id}/reject").mock(return_value=httpx.Response(204))
    respx.post(f"{API_PREFIX}/jobs/{job_id}/results").mock(
        return_value=httpx.Response(202, json={"accepted": True})
    )


# --- the security boundary -------------------------------------------------------------


@respx.mock
@pytest.mark.parametrize(
    "target", ["8.8.8.8/32", "0.0.0.0/0", "172.16.5.0/24", "100.64.0.0/10", "11.0.0.0/8"]
)
async def test_a_target_outside_the_local_allowlist_is_never_scanned(
    tmp_path: Path, client: ControlPlaneClient, target: str
) -> None:
    _mock_job_endpoints()
    reject = respx.post(f"{API_PREFIX}/jobs/job-1/reject")
    runner = SpyRunner()
    executor = build_executor(tmp_path, client, runner)

    outcome = await executor.execute(
        ClaimedJob(job_id="job-1", target=target, profile="service"), None
    )

    assert runner.calls == []  # nmap was never invoked
    assert outcome.status == "rejected"
    assert reject.called
    body = reject.calls.last.request.read().decode()
    assert "target_not_in_local_allowlist" in body


@respx.mock
async def test_a_server_widened_allowlist_cannot_authorise_a_scan(
    tmp_path: Path, client: ControlPlaneClient
) -> None:
    """The compromised-control-plane case, exercised through the real execution path."""
    _mock_job_endpoints()
    runner = SpyRunner()
    executor = build_executor(tmp_path, client, runner)

    outcome = await executor.execute(
        ClaimedJob(job_id="job-1", target="8.8.8.8/32", profile="service"),
        parse_networks(["0.0.0.0/0"]),
    )

    assert runner.calls == []
    assert outcome.status == "rejected"


@respx.mock
async def test_a_server_narrowed_allowlist_is_honoured(
    tmp_path: Path, client: ControlPlaneClient, service_xml: bytes
) -> None:
    _mock_job_endpoints()
    runner = SpyRunner(stdout=service_xml)
    executor = build_executor(tmp_path, client, runner)

    inside = await executor.execute(
        ClaimedJob(job_id="job-1", target="10.0.4.0/24", profile="service"),
        parse_networks(["10.0.4.0/24"]),
    )
    assert inside.status == "completed"

    outside = await executor.execute(
        ClaimedJob(job_id="job-1", target="10.0.9.0/24", profile="service"),
        parse_networks(["10.0.4.0/24"]),
    )
    assert outside.status == "rejected"
    assert len(runner.calls) == 1


@respx.mock
async def test_a_malformed_target_is_rejected_before_execution(
    tmp_path: Path, client: ControlPlaneClient
) -> None:
    _mock_job_endpoints()
    runner = SpyRunner()
    executor = build_executor(tmp_path, client, runner)

    outcome = await executor.execute(
        ClaimedJob(job_id="job-1", target="10.0.4.0/24; curl evil", profile="service"), None
    )

    assert runner.calls == []
    assert outcome.status == "rejected"


@respx.mock
async def test_an_unknown_profile_is_rejected_not_guessed(
    tmp_path: Path, client: ControlPlaneClient
) -> None:
    _mock_job_endpoints()
    reject = respx.post(f"{API_PREFIX}/jobs/job-1/reject")
    runner = SpyRunner()
    executor = build_executor(tmp_path, client, runner)

    outcome = await executor.execute(
        ClaimedJob(job_id="job-1", target="10.0.4.0/24", profile="--script=vulners"), None
    )

    assert runner.calls == []
    assert outcome.status == "rejected"
    assert "unsupported_profile" in reject.calls.last.request.read().decode()


# --- the happy path ----------------------------------------------------------------------


@respx.mock
async def test_a_valid_job_scans_parses_and_submits(
    tmp_path: Path, client: ControlPlaneClient, service_xml: bytes
) -> None:
    _mock_job_endpoints()
    results = respx.post(f"{API_PREFIX}/jobs/job-1/results")
    runner = SpyRunner(stdout=service_xml)
    executor = build_executor(tmp_path, client, runner)

    outcome = await executor.execute(
        ClaimedJob(job_id="job-1", target="10.0.4.0/24", profile="service"), None
    )

    assert runner.calls == [("10.0.4.0/24", "service")]
    assert outcome.status == "completed"
    assert outcome.hosts_submitted == 1
    submitted = results.calls.last.request.read().decode()
    assert "SimpleHTTPServer" in submitted
    assert "cpe:/a:python:simplehttpserver:0.6" in submitted


@respx.mock
async def test_submitted_results_carry_no_cve_or_severity(
    tmp_path: Path, client: ControlPlaneClient, service_xml: bytes
) -> None:
    _mock_job_endpoints()
    results = respx.post(f"{API_PREFIX}/jobs/job-1/results")
    executor = build_executor(tmp_path, client, SpyRunner(stdout=service_xml))

    await executor.execute(
        ClaimedJob(job_id="job-1", target="10.0.4.0/24", profile="service"), None
    )

    body = results.calls.last.request.read().decode().lower()
    for forbidden in ("cve", "severity", "cvss", "business_risk"):
        assert forbidden not in body


@respx.mock
async def test_progress_is_reported_and_completion_is_final(
    tmp_path: Path, client: ControlPlaneClient, service_xml: bytes
) -> None:
    _mock_job_endpoints()
    status = respx.post(f"{API_PREFIX}/jobs/job-1/status")
    executor = build_executor(tmp_path, client, SpyRunner(stdout=service_xml))

    await executor.execute(
        ClaimedJob(job_id="job-1", target="10.0.4.0/24", profile="service"), None
    )

    bodies = [call.request.read().decode() for call in status.calls]
    assert any('"status":"running"' in body for body in bodies)
    assert '"status":"completed"' in bodies[-1]
    assert '"progress_percent":100' in bodies[-1]


@respx.mock
async def test_a_large_scan_is_submitted_in_several_chunks(
    tmp_path: Path, client: ControlPlaneClient, service_xml: bytes
) -> None:
    _mock_job_endpoints()
    results = respx.post(f"{API_PREFIX}/jobs/job-1/results")
    executor = build_executor(
        tmp_path, client, SpyRunner(stdout=_many_hosts(service_xml, 40)), max_payload_bytes=2048
    )

    outcome = await executor.execute(
        ClaimedJob(job_id="job-1", target="10.0.4.0/24", profile="service"), None
    )

    assert outcome.status == "completed"
    assert results.call_count > 1
    keys = [call.request.headers["Idempotency-Key"] for call in results.calls]
    assert keys == [f"job-1:{n}" for n in range(results.call_count)]


def _many_hosts(service_xml: bytes, count: int) -> bytes:
    """Clone the real host element with distinct IPs to make a big scan."""
    head, host_block = service_xml.split(b"<host ", 1)
    host_block, tail = host_block.rsplit(b"</host>", 1)
    hosts = b"".join(
        b"<host " + host_block.replace(b'addr="127.0.0.1"', f'addr="10.0.4.{n}"'.encode())
        + b"</host>"
        for n in range(1, count + 1)
    )
    return head + hosts + tail


# --- failure handling ---------------------------------------------------------------------


@respx.mock
@pytest.mark.parametrize(
    "error",
    [NmapTimeoutError("nmap exceeded its 3600s timeout"), NmapFailedError("nmap exited 1: boom")],
)
async def test_an_nmap_failure_is_reported_not_swallowed(
    tmp_path: Path, client: ControlPlaneClient, error: Exception
) -> None:
    _mock_job_endpoints()
    status = respx.post(f"{API_PREFIX}/jobs/job-1/status")
    executor = build_executor(tmp_path, client, SpyRunner(error=error))

    outcome = await executor.execute(
        ClaimedJob(job_id="job-1", target="10.0.4.0/24", profile="service"), None
    )

    assert outcome.status == "failed"
    assert outcome.detail and str(error)[:20] in outcome.detail
    assert '"status":"failed"' in status.calls.last.request.read().decode()


@respx.mock
async def test_unparseable_nmap_output_fails_the_job(
    tmp_path: Path, client: ControlPlaneClient
) -> None:
    _mock_job_endpoints()
    executor = build_executor(tmp_path, client, SpyRunner(stdout=b"not xml"))

    outcome = await executor.execute(
        ClaimedJob(job_id="job-1", target="10.0.4.0/24", profile="service"), None
    )
    assert outcome.status == "failed"


@respx.mock
async def test_a_lost_lease_drops_the_job_without_further_writes(
    tmp_path: Path, client: ControlPlaneClient, service_xml: bytes
) -> None:
    respx.post(f"{API_PREFIX}/jobs/job-1/status").mock(return_value=httpx.Response(409))
    results = respx.post(f"{API_PREFIX}/jobs/job-1/results")
    executor = build_executor(tmp_path, client, SpyRunner(stdout=service_xml))

    outcome = await executor.execute(
        ClaimedJob(job_id="job-1", target="10.0.4.0/24", profile="service"), None
    )

    assert outcome.status == "dropped"
    assert not results.called


@respx.mock
async def test_a_failing_status_update_does_not_fail_the_scan(
    tmp_path: Path, client: ControlPlaneClient, service_xml: bytes
) -> None:
    """Progress reporting is best-effort; losing it must not lose the results."""
    respx.post(f"{API_PREFIX}/jobs/job-1/status").mock(return_value=httpx.Response(500))
    respx.post(f"{API_PREFIX}/jobs/job-1/results").mock(
        return_value=httpx.Response(202, json={"accepted": True})
    )
    executor = build_executor(tmp_path, client, SpyRunner(stdout=service_xml))

    outcome = await executor.execute(
        ClaimedJob(job_id="job-1", target="10.0.4.0/24", profile="service"), None
    )
    assert outcome.status == "completed"


@respx.mock
async def test_a_transient_submission_failure_is_retried(
    tmp_path: Path, client: ControlPlaneClient, service_xml: bytes
) -> None:
    _mock_job_endpoints()
    respx.post(f"{API_PREFIX}/jobs/job-1/results").mock(
        side_effect=[
            httpx.Response(503),
            httpx.Response(202, json={"accepted": True}),
        ]
    )
    executor = build_executor(tmp_path, client, SpyRunner(stdout=service_xml))

    outcome = await executor.execute(
        ClaimedJob(job_id="job-1", target="10.0.4.0/24", profile="service"), None
    )
    assert outcome.status == "completed"


@respx.mock
async def test_release_hands_the_job_back(
    tmp_path: Path, client: ControlPlaneClient
) -> None:
    _mock_job_endpoints()
    reject = respx.post(f"{API_PREFIX}/jobs/job-1/reject")
    executor = build_executor(tmp_path, client, SpyRunner())

    outcome = await executor.release(
        ClaimedJob(job_id="job-1", target="10.0.4.0/24", profile="service")
    )

    assert outcome.status == "released"
    assert "agent_shutdown" in reject.calls.last.request.read().decode()
