"""``/agent/*`` — the machine-facing surface of docs/AGENT-PROTOCOL.md.

Every route but ``/enroll`` depends on ``current_agent``, which accepts an agent
API key and nothing else: a user JWT does not start with ``tsa_`` and so is
rejected before any lookup. The inverse holds on the dashboard routes. The two
principal types are separated by the dependency, not by a role check somebody has
to remember to write.

Decisions live in ``threatsculpt.agents`` and ``threatsculpt.scanning``; this
module is HTTP shape, audit, and nothing else.
"""

from __future__ import annotations

from datetime import UTC, datetime
from http import HTTPStatus
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Request

from threatsculpt.agents.allowlist import (
    DEFAULT_POLL_INTERVAL_SECONDS,
    authorized_networks,
    effective_allowlist,
)
from threatsculpt.agents.enrollment import consume_enrollment_token, enroll_agent
from threatsculpt.agents.schemas import (
    EnrollRequest,
    EnrollResponse,
    HeartbeatRequest,
    HeartbeatResponse,
)
from threatsculpt.api.dependencies import CurrentAgent, SessionDep
from threatsculpt.api.limits import enforce_auth_rate_limit, enforce_general_rate_limit
from threatsculpt.api.middleware import client_ip
from threatsculpt.audit.writer import record_audit
from threatsculpt.core.envelope import Envelope, ok
from threatsculpt.db.session import bind_scope
from threatsculpt.models.agent import Agent
from threatsculpt.models.audit import AuditAction
from threatsculpt.scanning import dispatch, ingest
from threatsculpt.scanning.payload import parse_body, read_capped_body
from threatsculpt.scanning.schemas import (
    ClaimRequest,
    ClaimResponse,
    JobRejectRequest,
    JobStateResponse,
    JobStatusUpdate,
    ResultsResponse,
    ResultsSubmission,
)
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope

router = APIRouter(prefix="/agent", tags=["agent"])

JobId = Annotated[UUID, Path(description="Scan job id within your organisation")]


@router.post(
    "/enroll",
    status_code=HTTPStatus.CREATED,
    response_model=Envelope[EnrollResponse],
    dependencies=[Depends(enforce_auth_rate_limit)],
    summary="Trade a one-time enrollment token for an API key",
)
async def enroll(
    request: Request, payload: EnrollRequest, session: SessionDep
) -> Envelope[EnrollResponse]:
    """Unauthenticated by construction — the token *is* the credential.

    Rate-limited per IP like the other credential-exchange endpoints, so a
    stolen-token guessing loop is bounded even though every guess fails.
    """
    consumed = await consume_enrollment_token(session, payload.enrollment_token)

    # The org comes from the consumed row, never from the request body.
    scope = OrgScope.for_system(consumed.org_id)
    await bind_scope(session, scope)

    # A brand-new agent carries no restriction of its own, so its allowlist is
    # the org's authorized networks.
    allowlist = await authorized_networks(session, scope)
    enrolled = await enroll_agent(
        session,
        scope,
        consumed,
        name=payload.name,
        version=payload.version,
        allowlist=allowlist,
    )
    await record_audit(
        session,
        scope,
        AuditAction.AGENT_ENROLLED,
        target_type="agent",
        target_id=enrolled.agent.id,
        metadata={
            "name": payload.name,
            "hostname": payload.hostname,
            "version": payload.version,
            "key_prefix": enrolled.agent.key_prefix,
        },
        ip=client_ip(request),
    )
    return ok(
        EnrollResponse(
            agent_id=enrolled.agent.id,
            api_key=enrolled.api_key,
            org_id=scope.org_id,
            allowlist=allowlist,
            poll_interval_seconds=DEFAULT_POLL_INTERVAL_SECONDS,
        )
    )


@router.post(
    "/heartbeat",
    response_model=Envelope[HeartbeatResponse],
    dependencies=[Depends(enforce_general_rate_limit)],
    summary="Report liveness and collect the current allowlist",
)
async def heartbeat(
    principal: CurrentAgent, session: SessionDep, payload: HeartbeatRequest
) -> Envelope[HeartbeatResponse]:
    """Updates ``last_seen_at`` and hands back the effective allowlist.

    ``revoked`` is always false here: a revoked key never authenticates, so a
    revoked agent gets the 401 that §6 already defines as "wipe the key and
    exit". Returning the field keeps the documented response shape.
    """
    agents = ScopedRepository(session, principal.scope, Agent)
    changes: dict[str, object] = {"last_seen_at": datetime.now(tz=UTC)}
    if payload.version is not None:
        changes["version"] = payload.version
    agent = await agents.update(principal.agent, changes)

    return ok(
        HeartbeatResponse(
            allowlist=await effective_allowlist(session, principal.scope, agent),
            poll_interval_seconds=DEFAULT_POLL_INTERVAL_SECONDS,
            revoked=not agent.is_active,
        )
    )


@router.post(
    "/jobs/claim",
    response_model=Envelope[ClaimResponse],
    dependencies=[Depends(enforce_general_rate_limit)],
    summary="Claim queued scan jobs",
)
async def claim(
    request: Request, principal: CurrentAgent, session: SessionDep, payload: ClaimRequest
) -> Envelope[ClaimResponse]:
    """``FOR UPDATE SKIP LOCKED`` — see ``scanning.sql.CLAIM_JOBS``."""
    outcome = await dispatch.claim_jobs(
        session, principal.scope, principal.agent.id, payload.capacity
    )
    for job in outcome.jobs:
        await record_audit(
            session,
            principal.scope,
            AuditAction.SCAN_JOB_CLAIMED,
            target_type="scan_job",
            target_id=job.job_id,
            metadata={"agent_id": str(principal.agent.id), "target": job.target},
            ip=client_ip(request),
        )
    return ok(ClaimResponse(jobs=outcome.jobs))


@router.post(
    "/jobs/{job_id}/status",
    response_model=Envelope[JobStateResponse],
    dependencies=[Depends(enforce_general_rate_limit)],
    summary="Report scan progress",
)
async def report_status(
    principal: CurrentAgent, session: SessionDep, job_id: JobId, payload: JobStatusUpdate
) -> Envelope[JobStateResponse]:
    job = await dispatch.report_status(
        session, principal.scope, principal.agent.id, job_id, payload
    )
    return ok(JobStateResponse(job_id=job.id, status=job.status, attempts=job.attempts))


@router.post(
    "/jobs/{job_id}/reject",
    response_model=Envelope[JobStateResponse],
    dependencies=[Depends(enforce_general_rate_limit)],
    summary="Refuse a job whose target is outside the agent's local allowlist",
)
async def reject(
    request: Request,
    principal: CurrentAgent,
    session: SessionDep,
    job_id: JobId,
    payload: JobRejectRequest,
) -> Envelope[JobStateResponse]:
    """§4. Always audited: the agent and the control plane disagreeing about what
    may be scanned is the single most interesting event in this protocol."""
    job = await dispatch.reject_job(session, principal.scope, principal.agent.id, job_id, payload)
    await record_audit(
        session,
        principal.scope,
        AuditAction.SCAN_JOB_REJECTED,
        target_type="scan_job",
        target_id=job.id,
        metadata={
            "agent_id": str(principal.agent.id),
            "reason": payload.reason,
            "detail": payload.detail,
            "resulting_status": job.status,
        },
        ip=client_ip(request),
    )
    return ok(JobStateResponse(job_id=job.id, status=job.status, attempts=job.attempts))


@router.post(
    "/jobs/{job_id}/results",
    status_code=HTTPStatus.ACCEPTED,
    response_model=Envelope[ResultsResponse],
    dependencies=[Depends(enforce_general_rate_limit)],
    summary="Submit scan observations",
)
async def submit_results(
    request: Request, principal: CurrentAgent, session: SessionDep, job_id: JobId
) -> Envelope[ResultsResponse]:
    """The body is read through a size cap rather than declared as a parameter.

    FastAPI would buffer the whole request before this function ran, which is the
    one thing the 10 MB cap in §5 exists to prevent.
    """
    body = await read_capped_body(request, ingest.MAX_RESULT_PAYLOAD_BYTES)
    payload = parse_body(ResultsSubmission, body)

    job = await dispatch.claimed_job(session, principal.scope, principal.agent.id, job_id)
    outcome = await ingest.ingest_results(session, principal.scope, job, payload)

    await record_audit(
        session,
        principal.scope,
        AuditAction.SCAN_RESULTS_INGESTED,
        target_type="scan_job",
        target_id=job.id,
        metadata={
            "agent_id": str(principal.agent.id),
            "hosts_ingested": outcome.hosts_ingested,
            "hosts_rejected": len(outcome.rejected),
            "final": payload.final,
        },
        ip=client_ip(request),
    )
    for rejected in outcome.rejected:
        # One row per refused host: "an agent tried to report a host it was never
        # asked to scan" is worth naming the host in the permanent record.
        await record_audit(
            session,
            principal.scope,
            AuditAction.SCAN_RESULT_HOST_REJECTED,
            target_type="scan_job",
            target_id=job.id,
            metadata={
                "agent_id": str(principal.agent.id),
                "ip": rejected.ip,
                "reason": rejected.reason,
                "job_target": job.target,
            },
            ip=client_ip(request),
        )

    return ok(
        ResultsResponse(
            accepted=True,
            hosts_ingested=outcome.hosts_ingested,
            hosts_rejected=outcome.rejected,
        )
    )
