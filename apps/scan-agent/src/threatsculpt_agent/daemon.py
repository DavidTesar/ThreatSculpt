"""The poll loop: heartbeat, claim, execute, submit, repeat.

Shutdown semantics (SIGTERM from systemd, SIGINT from a console):

* the loop stops claiming new work immediately;
* an in-flight job gets ``shutdown_grace_seconds`` to finish;
* if it does not finish, nmap is killed and the job is explicitly released via the reject
  endpoint, so the control plane can requeue it now instead of waiting out a 30-minute
  lease. Abandoning a lease silently is the failure mode this avoids.

Revocation: a 401 anywhere, or ``revoked: true`` on a heartbeat, wipes the stored key and
exits 0. That is a normal end of life for an agent, not a crash.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass, field

from . import AGENT_VERSION
from .allowlist import Network, parse_networks
from .api.backoff import BackoffPolicy
from .api.client import ControlPlaneClient
from .api.retry import retry_async
from .config import AgentSettings
from .errors import ApiError, AuthRevokedError, InvalidNetworkError
from .keystore import KeyStore
from .models import ClaimedJob, HeartbeatRequest, HeartbeatResponse
from .nmap.runner import NmapRunner
from .worker import JobExecutor, JobOutcome

log = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_REVOKED = 0
EXIT_FATAL = 1


@dataclass(slots=True)
class LoopState:
    """Server-pushed state. Replaced wholesale on each heartbeat, never patched in place."""

    server_allowlist: tuple[Network, ...] | None = None
    poll_interval_seconds: float = 30.0
    consecutive_failures: int = 0

    def with_heartbeat(self, response: HeartbeatResponse, default_interval: float) -> LoopState:
        return LoopState(
            server_allowlist=_parse_server_allowlist(response.allowlist),
            poll_interval_seconds=float(response.poll_interval_seconds or default_interval),
            consecutive_failures=0,
        )


def _parse_server_allowlist(raw: tuple[str, ...] | None) -> tuple[Network, ...] | None:
    """A malformed server allowlist narrows to nothing rather than silently widening."""
    if raw is None:
        return None
    try:
        return parse_networks(raw)
    except InvalidNetworkError as exc:
        log.error("control plane sent an unparseable allowlist (%s); treating it as empty", exc)
        return ()


@dataclass(slots=True)
class AgentDaemon:
    """Owns the poll loop. One instance per process."""

    settings: AgentSettings
    client: ControlPlaneClient
    keystore: KeyStore
    executor: JobExecutor
    nmap_version: str = "unknown"
    _shutdown: asyncio.Event = field(default_factory=asyncio.Event)
    _state: LoopState = field(default_factory=LoopState)

    @classmethod
    def build(
        cls,
        settings: AgentSettings,
        client: ControlPlaneClient,
        keystore: KeyStore,
        nmap_version: str = "unknown",
    ) -> AgentDaemon:
        policy = BackoffPolicy(
            base_seconds=settings.backoff_base_seconds,
            max_seconds=settings.backoff_max_seconds,
            multiplier=settings.backoff_multiplier,
            jitter_ratio=settings.backoff_jitter_ratio,
        )
        executor = JobExecutor(
            settings=settings,
            client=client,
            runner=NmapRunner(
                nmap_path=settings.nmap_path,
                timeout_seconds=settings.nmap_timeout_seconds,
                max_output_bytes=settings.nmap_max_output_bytes,
            ),
            policy=policy,
        )
        return cls(
            settings=settings,
            client=client,
            keystore=keystore,
            executor=executor,
            nmap_version=nmap_version,
        )

    def request_shutdown(self, signal_name: str = "signal") -> None:
        if not self._shutdown.is_set():
            log.info("%s received; finishing in-flight work then exiting", signal_name)
            self._shutdown.set()

    @property
    def policy(self) -> BackoffPolicy:
        return self.executor.policy

    async def run(self, max_cycles: int | None = None) -> int:
        """Poll until shutdown or revocation. Returns the process exit code."""
        cycles = 0
        while not self._shutdown.is_set():
            if _budget_spent(cycles, max_cycles):
                break
            cycles += 1
            try:
                await self._cycle()
            except AuthRevokedError as exc:
                return self._handle_revocation(exc)
            except ApiError as exc:
                delay = self._record_failure(exc)
                if _budget_spent(cycles, max_cycles):
                    break
                await self._interruptible_sleep(delay)
                continue
            # Checked before sleeping, not after: `--once` must exit now rather than
            # idle for a full poll interval first.
            if _budget_spent(cycles, max_cycles):
                break
            await self._sleep_until_next_poll()
        log.info("poll loop stopped after %d cycle(s)", cycles)
        return EXIT_OK

    # -- one poll cycle ----------------------------------------------------------

    async def _cycle(self) -> None:
        response = await retry_async(
            lambda: self.client.heartbeat(
                HeartbeatRequest(
                    version=AGENT_VERSION, nmap_version=self.nmap_version, healthy=True
                )
            ),
            policy=self.policy,
            max_attempts=self.settings.max_request_attempts,
            description="heartbeat",
        )
        self._state = self._state.with_heartbeat(response, self.settings.poll_interval_seconds)

        if self._shutdown.is_set():
            return

        claim = await retry_async(
            lambda: self.client.claim_jobs(self.settings.capacity),
            policy=self.policy,
            max_attempts=self.settings.max_request_attempts,
            description="claim",
        )
        for job in claim.jobs:
            outcome = await self._run_job(job)
            log.info("job %s finished: %s", outcome.job_id, outcome.status)
            if self._shutdown.is_set():
                break

    async def _run_job(self, job: ClaimedJob) -> JobOutcome:
        """Run one job as a task so shutdown can bound it rather than abandon it."""
        task = asyncio.create_task(self.executor.execute(job, self._state.server_allowlist))
        waiter = asyncio.create_task(self._shutdown.wait())
        done, _pending = await asyncio.wait({task, waiter}, return_when=asyncio.FIRST_COMPLETED)
        if task in done:
            waiter.cancel()
            return task.result()

        log.info(
            "job %s: shutdown requested mid-scan; allowing %.0fs to finish",
            job.job_id,
            self.settings.shutdown_grace_seconds,
        )
        return await self._finish_or_release(job, task)

    async def _finish_or_release(
        self, job: ClaimedJob, task: asyncio.Task[JobOutcome]
    ) -> JobOutcome:
        try:
            return await asyncio.wait_for(
                asyncio.shield(task), timeout=self.settings.shutdown_grace_seconds
            )
        except TimeoutError:
            log.warning(
                "job %s: grace period expired; killing nmap and releasing the job", job.job_id
            )
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            return await self.executor.release(job)

    # -- failure handling --------------------------------------------------------

    def _handle_revocation(self, exc: AuthRevokedError) -> int:
        log.warning("agent credential revoked (%s); wiping stored key and exiting", exc)
        try:
            self.keystore.wipe()
        except OSError as wipe_error:
            log.error("could not remove %s: %s", self.keystore.path, wipe_error)
            return EXIT_FATAL
        return EXIT_REVOKED

    def _record_failure(self, exc: ApiError) -> float:
        """Count the failed cycle and return how long to wait. Counting is not conditional
        on whether we go on to sleep, so the counter always reflects reality."""
        self._state = LoopState(
            server_allowlist=self._state.server_allowlist,
            poll_interval_seconds=self._state.poll_interval_seconds,
            consecutive_failures=self._state.consecutive_failures + 1,
        )
        delay = self.policy.delay_for(self._state.consecutive_failures - 1)
        log.warning(
            "poll cycle failed (%d consecutive): %s; next attempt in %.1fs",
            self._state.consecutive_failures,
            exc,
            delay,
        )
        return delay

    async def _sleep_until_next_poll(self) -> None:
        await self._interruptible_sleep(self._state.poll_interval_seconds)

    async def _interruptible_sleep(self, seconds: float) -> None:
        """Sleep, but wake immediately on SIGTERM. A 300s backoff must not delay shutdown."""
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._shutdown.wait(), timeout=seconds)


def _budget_spent(cycles: int, max_cycles: int | None) -> bool:
    return max_cycles is not None and cycles >= max_cycles
