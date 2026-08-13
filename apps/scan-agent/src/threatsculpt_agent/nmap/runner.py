"""Invoke nmap safely.

Non-negotiables, from docs/AGENT-PROTOCOL.md:

* argument VECTOR, never a shell string. ``create_subprocess_exec`` never involves a
  shell, so target text can never be interpreted as one.
* flags come from the fixed profile map; the job supplies a profile name only.
* the target has already been validated against the local allowlist by the caller, and is
  re-parsed here as a last line of defence before it reaches argv.
* every run has a hard timeout. A hung nmap must not hold a job lease forever, so on
  timeout the process is terminated, then killed, and the failure is raised.

nmap itself is expected to hold CAP_NET_RAW as a file capability. The agent process does
not run as root and does not attempt to elevate.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path

from ..allowlist import parse_network
from ..errors import (
    NmapFailedError,
    NmapOutputTooLargeError,
    NmapTimeoutError,
)
from ..profiles import resolve_profile

log = logging.getLogger(__name__)

XML_TO_STDOUT: tuple[str, ...] = ("-oX", "-")
TERMINATE_GRACE_SECONDS = 5.0
STDERR_CAPTURE_LIMIT = 8192
VERSION_TIMEOUT_SECONDS = 15.0
_VERSION_RE = re.compile(r"Nmap version ([0-9][^\s]*)")


async def detect_nmap_version(nmap_path: Path | str) -> str:
    """Report the local nmap version for the heartbeat. Never fatal: unknown is fine."""
    try:
        process = await asyncio.create_subprocess_exec(
            str(nmap_path),
            "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=VERSION_TIMEOUT_SECONDS)
    except (OSError, TimeoutError) as exc:
        log.warning("could not determine nmap version from %s: %s", nmap_path, exc)
        return "unknown"
    match = _VERSION_RE.search(stdout.decode("utf-8", errors="replace"))
    return match.group(1) if match else "unknown"


@dataclass(frozen=True, slots=True)
class NmapRunResult:
    """The outcome of one nmap process. Immutable."""

    argv: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: str
    duration_seconds: float


def build_argv(nmap_path: Path | str, profile: str, target: str) -> tuple[str, ...]:
    """Build the full argument vector for a scan.

    Raises UnknownProfileError for an unknown profile and InvalidNetworkError for a target
    that is not a well-formed network — neither ever reaches execve.
    """
    flags = resolve_profile(profile)
    validated_target = str(parse_network(target))
    return (str(nmap_path), *flags, *XML_TO_STDOUT, validated_target)


@dataclass(frozen=True, slots=True)
class NmapRunner:
    """Runs nmap with a hard timeout and bounded output buffering."""

    nmap_path: Path = Path("/usr/bin/nmap")
    timeout_seconds: float = 3600.0
    max_output_bytes: int = 256 * 1024 * 1024

    async def run(self, target: str, profile: str) -> NmapRunResult:
        argv = build_argv(self.nmap_path, profile, target)
        log.info("running nmap: %s", " ".join(argv))
        started = time.monotonic()

        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await self._communicate(process, argv)
        duration = time.monotonic() - started
        stderr_text = stderr.decode("utf-8", errors="replace")[-STDERR_CAPTURE_LIMIT:]

        if len(stdout) > self.max_output_bytes:
            raise NmapOutputTooLargeError(
                f"nmap produced {len(stdout)} bytes, over the {self.max_output_bytes}-byte limit"
            )
        if process.returncode != 0:
            raise NmapFailedError(
                f"nmap exited {process.returncode} after {duration:.1f}s: "
                f"{stderr_text.strip() or '<no stderr>'}"
            )

        return NmapRunResult(
            argv=argv,
            returncode=process.returncode,
            stdout=stdout,
            stderr=stderr_text,
            duration_seconds=duration,
        )

    async def _communicate(
        self, process: asyncio.subprocess.Process, argv: tuple[str, ...]
    ) -> tuple[bytes, bytes]:
        try:
            return await asyncio.wait_for(process.communicate(), timeout=self.timeout_seconds)
        except TimeoutError:
            await self._terminate(process)
            raise NmapTimeoutError(
                f"nmap exceeded its {self.timeout_seconds:.0f}s timeout and was killed: "
                f"{' '.join(argv)}"
            ) from None
        except asyncio.CancelledError:
            await self._terminate(process)
            raise

    @staticmethod
    async def _terminate(process: asyncio.subprocess.Process) -> None:
        """SIGTERM, then SIGKILL if it does not exit. Never leaves an orphan scan."""
        if process.returncode is not None:
            return
        try:
            process.terminate()
            await asyncio.wait_for(process.wait(), timeout=TERMINATE_GRACE_SECONDS)
        except (TimeoutError, ProcessLookupError):
            try:
                process.kill()
                await process.wait()
            except ProcessLookupError:
                log.debug("nmap process already gone")
