"""nmap invocation: argv construction, timeouts, failure reporting."""

from __future__ import annotations

import asyncio
import os
import stat
from pathlib import Path

import pytest

from threatsculpt_agent.errors import (
    InvalidNetworkError,
    NmapFailedError,
    NmapOutputTooLargeError,
    NmapTimeoutError,
    UnknownProfileError,
)
from threatsculpt_agent.nmap.runner import NmapRunner, build_argv, detect_nmap_version
from threatsculpt_agent.profiles import SCAN_PROFILES

REAL_NMAP = Path("/usr/bin/nmap")


def _fake_nmap(tmp_path: Path, body: str) -> Path:
    """A stand-in binary, so process behaviour can be tested without scanning anything."""
    script = tmp_path / "fake-nmap"
    script.write_text(f"#!/bin/sh\n{body}\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return script


# --- argv construction ----------------------------------------------------------------


def test_argv_is_a_vector_of_fixed_flags_plus_the_target() -> None:
    argv = build_argv("/usr/bin/nmap", "service", "10.0.4.0/24")
    assert argv == ("/usr/bin/nmap", *SCAN_PROFILES["service"], "-oX", "-", "10.0.4.0/24")


def test_output_is_requested_as_xml_on_stdout() -> None:
    argv = build_argv("/usr/bin/nmap", "discovery", "10.0.4.0/24")
    assert argv[-3:-1] == ("-oX", "-")


def test_an_unknown_profile_never_reaches_argv() -> None:
    with pytest.raises(UnknownProfileError):
        build_argv("/usr/bin/nmap", "totally-custom", "10.0.4.0/24")


@pytest.mark.parametrize(
    "profile",
    ["--script=vulners", "-sS -oN /etc/passwd", "service; id", "", "SERVICE"],
)
def test_flags_cannot_be_smuggled_through_the_profile_field(profile: str) -> None:
    with pytest.raises(UnknownProfileError):
        build_argv("/usr/bin/nmap", profile, "10.0.4.0/24")


@pytest.mark.parametrize(
    "target",
    ["10.0.4.0/24 --script=http-shellshock", "; id", "$(id)", "`id`", "10.0.4.0/24|nc evil 1", "-oN"],
)
def test_shell_metacharacters_in_a_target_are_rejected_at_argv_construction(target: str) -> None:
    with pytest.raises(InvalidNetworkError):
        build_argv("/usr/bin/nmap", "service", target)


def test_the_target_is_normalised_before_execution() -> None:
    assert build_argv("/usr/bin/nmap", "service", " 10.0.4.0/24 ")[-1] == "10.0.4.0/24"


def test_the_profile_table_cannot_be_mutated_by_a_caller() -> None:
    with pytest.raises(TypeError):
        SCAN_PROFILES["service"] = ("-sS",)  # type: ignore[index]
    with pytest.raises(AttributeError):
        SCAN_PROFILES["service"].append("-oN")  # type: ignore[attr-defined]


# --- process behaviour -------------------------------------------------------------


async def test_a_hung_nmap_is_killed_at_the_timeout(tmp_path: Path) -> None:
    """A hung scan must not hold a job lease forever."""
    runner = NmapRunner(nmap_path=_fake_nmap(tmp_path, "sleep 30"), timeout_seconds=0.3)

    with pytest.raises(NmapTimeoutError, match="timeout"):
        await runner.run("10.0.4.0/24", "discovery")


async def test_a_killed_process_leaves_no_child_behind(tmp_path: Path) -> None:
    script = _fake_nmap(tmp_path, "echo $$ > '%s'; sleep 30" % (tmp_path / "pid"))
    runner = NmapRunner(nmap_path=script, timeout_seconds=0.3)

    with pytest.raises(NmapTimeoutError):
        await runner.run("10.0.4.0/24", "discovery")

    pid = int((tmp_path / "pid").read_text().strip())
    await asyncio.sleep(0.1)
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


async def test_a_nonzero_exit_reports_stderr(tmp_path: Path) -> None:
    script = _fake_nmap(tmp_path, "echo 'you requested a scan type which requires root' >&2; exit 1")
    runner = NmapRunner(nmap_path=script, timeout_seconds=5)

    with pytest.raises(NmapFailedError, match="requires root"):
        await runner.run("10.0.4.0/24", "service")


async def test_oversized_output_is_refused(tmp_path: Path) -> None:
    script = _fake_nmap(tmp_path, "head -c 20000 /dev/zero")
    runner = NmapRunner(nmap_path=script, timeout_seconds=5, max_output_bytes=1024)

    with pytest.raises(NmapOutputTooLargeError):
        await runner.run("10.0.4.0/24", "discovery")


async def test_cancellation_terminates_the_scan(tmp_path: Path) -> None:
    """Shutdown cancels the job task; the subprocess must go with it."""
    runner = NmapRunner(nmap_path=_fake_nmap(tmp_path, "sleep 30"), timeout_seconds=60)
    task = asyncio.create_task(runner.run("10.0.4.0/24", "discovery"))
    await asyncio.sleep(0.2)

    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_a_missing_nmap_binary_raises(tmp_path: Path) -> None:
    runner = NmapRunner(nmap_path=tmp_path / "does-not-exist")
    with pytest.raises(FileNotFoundError):
        await runner.run("10.0.4.0/24", "discovery")


# --- against the real nmap ------------------------------------------------------------


@pytest.mark.skipif(not REAL_NMAP.exists(), reason="nmap is not installed")
async def test_detects_the_real_nmap_version() -> None:
    version = await detect_nmap_version(REAL_NMAP)
    assert version[0].isdigit()


async def test_version_detection_never_raises(tmp_path: Path) -> None:
    assert await detect_nmap_version(tmp_path / "missing") == "unknown"


@pytest.mark.skipif(not REAL_NMAP.exists(), reason="nmap is not installed")
async def test_runs_a_real_discovery_scan_against_loopback() -> None:
    """End to end through the production code path: real nmap, real XML, real parse."""
    from threatsculpt_agent.nmap.xml_parser import parse_nmap_xml

    result = await NmapRunner(nmap_path=REAL_NMAP, timeout_seconds=120).run(
        "127.0.0.1/32", "discovery"
    )
    scan = parse_nmap_xml(result.stdout)

    assert result.returncode == 0
    assert scan.hosts[0].ip == "127.0.0.1"
    assert scan.hosts[0].state == "up"
