"""Shared test fixtures."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from threatsculpt_agent.api.backoff import BackoffPolicy
from threatsculpt_agent.config import AgentSettings
from threatsculpt_agent.keystore import KeyStore
from threatsculpt_agent.models import (
    ClaimedJob,
    HostObservation,
    ParsedScan,
    PortObservation,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures"
BASE_URL = "https://cp.threatsculpt.test"
API_PREFIX = f"{BASE_URL}/api/v1/agent"


@pytest.fixture(autouse=True)
def _isolate_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """A developer's own TS_AGENT_* exports must not leak into the tests."""
    for name in list(os.environ):
        if name.startswith("TS_AGENT_"):
            monkeypatch.delenv(name, raising=False)


def make_settings(tmp_path: Path, **overrides: Any) -> AgentSettings:
    defaults: dict[str, Any] = {
        "control_plane_url": BASE_URL,
        "agent_name": "test-agent",
        "hostname": "scanner.test",
        "allowlist": ("10.0.0.0/8", "192.168.0.0/16"),
        "state_dir": tmp_path,
        "nmap_path": Path("/usr/bin/nmap"),
        "poll_interval_seconds": 0.01,
        "backoff_base_seconds": 0.001,
        "backoff_max_seconds": 0.01,
        "shutdown_grace_seconds": 0.05,
        "max_request_attempts": 3,
    }
    return AgentSettings(**{**defaults, **overrides})


@pytest.fixture
def settings(tmp_path: Path) -> AgentSettings:
    return make_settings(tmp_path)


@pytest.fixture
def keystore(tmp_path: Path) -> KeyStore:
    return KeyStore(tmp_path / "agent.key")


@pytest.fixture
def policy() -> BackoffPolicy:
    return BackoffPolicy(base_seconds=0.001, max_seconds=0.01, multiplier=2.0, jitter_ratio=0.0)


@pytest.fixture
def job() -> ClaimedJob:
    return ClaimedJob(job_id="job-1", target="10.0.4.0/24", profile="service")


@pytest.fixture
def service_xml() -> bytes:
    """Real nmap 7.99 output, captured by tests/fixtures/regenerate.sh."""
    return (FIXTURE_DIR / "service-localhost.xml").read_bytes()


@pytest.fixture
def discovery_xml() -> bytes:
    return (FIXTURE_DIR / "discovery-localhost.xml").read_bytes()


@pytest.fixture
def closed_ports_xml() -> bytes:
    """Real output from a small port list, where nmap lists closed ports individually."""
    return (FIXTURE_DIR / "closed-ports-localhost.xml").read_bytes()


def make_scan(hosts: tuple[HostObservation, ...]) -> ParsedScan:
    moment = datetime(2026, 8, 12, 12, 0, tzinfo=UTC)
    return ParsedScan(
        nmap_version="7.99",
        started_at=moment,
        finished_at=moment,
        hosts=hosts,
        hosts_up=len(hosts),
        hosts_total=len(hosts),
    )


def make_host(ip: str, port_count: int = 1, filler: str = "x") -> HostObservation:
    return HostObservation(
        ip=ip,
        hostname=f"host-{ip}",
        state="up",
        ports=tuple(
            PortObservation(
                port=1000 + index,
                protocol="tcp",
                state="open",
                service="http",
                product=filler * 32,
                version="1.0",
                cpes=("cpe:/a:example:example:1.0",),
            )
            for index in range(port_count)
        ),
    )


class RecordingSleeper:
    """Captures the delays a retry/backoff path asked for, without actually sleeping."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)
