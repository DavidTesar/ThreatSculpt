"""Execute one claimed scan job.

Order of operations, and the reason for it:

1. Validate the target against the LOCAL allowlist. Nothing below this line runs if the
   check fails — the reject is sent and nmap is never invoked.
2. Resolve the profile name to a fixed argument vector.
3. Run nmap with a hard timeout, parse its XML, submit observations in chunks.

Every control-plane call here is retried with backoff. A 401 aborts immediately and
propagates so the daemon can wipe the key; a 409 means the lease is gone, so the job is
dropped without further writes.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal

from .allowlist import Network, evaluate_target
from .api.backoff import BackoffPolicy
from .api.client import ControlPlaneClient
from .api.retry import retry_async
from .config import AgentSettings
from .errors import (
    ApiError,
    AuthRevokedError,
    JobConflictError,
    NmapError,
    SubmissionTooLargeError,
    UnknownProfileError,
    XmlParseError,
)
from .models import ClaimedJob, ParsedScan, RejectRequest, ResultSubmission, StatusRequest
from .nmap.runner import NmapRunner
from .nmap.xml_parser import parse_nmap_xml
from .profiles import resolve_profile
from .submission import build_submissions

log = logging.getLogger(__name__)

JobStatus = Literal["completed", "rejected", "failed", "released", "dropped"]

REASON_UNSUPPORTED_PROFILE = "unsupported_profile"
REASON_SHUTDOWN = "agent_shutdown"
_ERROR_DETAIL_LIMIT = 500


@dataclass(frozen=True, slots=True)
class JobOutcome:
    """What happened to one job. Immutable record, returned to the daemon."""

    job_id: str
    status: JobStatus
    hosts_submitted: int = 0
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class JobExecutor:
    """Runs jobs. Holds no per-job mutable state, so it is safe to reuse."""

    settings: AgentSettings
    client: ControlPlaneClient
    runner: NmapRunner
    policy: BackoffPolicy

    async def execute(
        self, job: ClaimedJob, server_allowlist: tuple[Network, ...] | None
    ) -> JobOutcome:
        decision = evaluate_target(job.target, self.settings.allowlist, server_allowlist)
        if not decision.allowed:
            return await self._reject(job, decision.reason or "rejected", decision.detail or "")

        try:
            resolve_profile(job.profile)
        except UnknownProfileError as exc:
            return await self._reject(job, REASON_UNSUPPORTED_PROFILE, str(exc))

        log.info("job %s: scanning %s with profile %s", job.job_id, job.target, job.profile)
        try:
            return await self._scan_and_submit(job)
        except JobConflictError as exc:
            log.warning("job %s: lease no longer held, dropping: %s", job.job_id, exc)
            return JobOutcome(job.job_id, "dropped", detail=str(exc))

    async def release(self, job: ClaimedJob, reason: str = REASON_SHUTDOWN) -> JobOutcome:
        """Hand a job back rather than letting its lease rot after a shutdown."""
        return await self._reject(job, reason, "agent shut down before the scan completed")

    # -- internals ---------------------------------------------------------------

    async def _scan_and_submit(self, job: ClaimedJob) -> JobOutcome:
        await self._report(job, "running", 5)
        try:
            run = await self.runner.run(job.target, job.profile)
            scan = parse_nmap_xml(run.stdout, include_port_states=self.settings.include_port_states)
        except (NmapError, XmlParseError) as exc:
            detail = str(exc)[:_ERROR_DETAIL_LIMIT]
            log.error("job %s: scan failed: %s", job.job_id, detail)
            await self._report(job, "failed", 100, detail=detail)
            return JobOutcome(job.job_id, "failed", detail=detail)

        log.info(
            "job %s: nmap %s finished in %.1fs, %d host(s) up of %d",
            job.job_id,
            scan.nmap_version,
            run.duration_seconds,
            scan.hosts_up,
            scan.hosts_total,
        )
        return await self._submit(job, scan)

    async def _submit(self, job: ClaimedJob, scan: ParsedScan) -> JobOutcome:
        try:
            chunks = build_submissions(scan, max_bytes=self.settings.max_payload_bytes)
        except SubmissionTooLargeError as exc:
            detail = str(exc)[:_ERROR_DETAIL_LIMIT]
            log.error("job %s: cannot chunk results: %s", job.job_id, detail)
            await self._report(job, "failed", 100, detail=detail)
            return JobOutcome(job.job_id, "failed", detail=detail)

        submitted = 0
        for chunk in chunks:
            await self._submit_chunk(job, chunk)
            submitted += len(chunk.hosts)
            # Progress is only meaningful while the job is still running. The final
            # chunk completes it server-side (§5), so reporting anything afterwards —
            # including "completed" — is refused as a conflict on a finished job.
            if not chunk.final:
                await self._report(job, "running", _progress(chunk.chunk_index, len(chunks)))

        log.info("job %s: submitted %d host(s) in %d chunk(s)", job.job_id, submitted, len(chunks))
        return JobOutcome(job.job_id, "completed", hosts_submitted=submitted)

    async def _submit_chunk(self, job: ClaimedJob, chunk: ResultSubmission) -> None:
        """One chunk, retried with backoff. The chunk is bound as a parameter rather than
        captured from a loop variable, so a retry can never resend the wrong chunk."""
        await retry_async(
            lambda: self.client.submit_results(job.job_id, chunk),
            policy=self.policy,
            max_attempts=self.settings.max_request_attempts,
            description=f"job {job.job_id} results chunk {chunk.chunk_index}",
        )

    async def _reject(self, job: ClaimedJob, reason: str, detail: str) -> JobOutcome:
        log.warning("job %s: rejecting (%s): %s", job.job_id, reason, detail)
        request = RejectRequest(reason=reason, detail=detail[:_ERROR_DETAIL_LIMIT])
        try:
            await retry_async(
                lambda: self.client.reject_job(job.job_id, request),
                policy=self.policy,
                max_attempts=self.settings.max_request_attempts,
                description=f"job {job.job_id} reject",
            )
        except AuthRevokedError:
            raise
        except ApiError as exc:
            log.error("job %s: reject call failed: %s", job.job_id, exc)
        status: JobStatus = "released" if reason == REASON_SHUTDOWN else "rejected"
        return JobOutcome(job.job_id, status, detail=detail)

    async def _report(
        self, job: ClaimedJob, status: str, percent: int, detail: str | None = None
    ) -> None:
        """Progress reporting is best-effort: a failed status POST must not fail the scan."""
        request = StatusRequest(status=status, progress_percent=percent, detail=detail)
        try:
            await retry_async(
                lambda: self.client.update_status(job.job_id, request),
                policy=self.policy,
                max_attempts=self.settings.max_request_attempts,
                description=f"job {job.job_id} status={status}",
            )
        except (AuthRevokedError, JobConflictError):
            raise
        except ApiError as exc:
            log.warning("job %s: status update (%s) failed: %s", job.job_id, status, exc)


def _progress(chunk_index: int, chunk_count: int) -> int:
    """Map chunk progress into the 10..95 band; 100 is reserved for completion."""
    if chunk_count <= 0:
        return 95
    fraction = (chunk_index + 1) / chunk_count
    return min(95, 10 + int(fraction * 85))
