"""``/agents`` — how an operator enrols and revokes scanners.

Admin-only, per docs/API.md. Enrolling a scanner is granting something the right
to send packets at the customer's network, and revoking one is the only way to
stop a compromised host: neither belongs to an analyst.

``POST`` issues an *enrollment token*, not an agent. The agent row appears when a
machine actually presents the token at ``/agent/enroll``, so an operator who
issues a token and never uses it leaves no half-real agent behind.
"""

from __future__ import annotations

from http import HTTPStatus
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Request

from threatsculpt.agents.allowlist import authorized_networks
from threatsculpt.agents.enrollment import issue_enrollment_token
from threatsculpt.agents.schemas import (
    AgentAllowlistUpdate,
    AgentOut,
    EnrollmentTokenCreate,
    EnrollmentTokenOut,
)
from threatsculpt.api.dependencies import RequireAdmin, SessionDep
from threatsculpt.api.limits import enforce_general_rate_limit
from threatsculpt.api.middleware import client_ip
from threatsculpt.audit.writer import record_audit
from threatsculpt.core.envelope import Envelope, ok
from threatsculpt.core.errors import ConflictError, SemanticValidationError
from threatsculpt.core.pagination import PaginationParams, pagination_params
from threatsculpt.models.agent import Agent, AgentStatus
from threatsculpt.models.audit import AuditAction
from threatsculpt.scanning.targets import narrow_to
from threatsculpt.tenancy.repository import ScopedRepository

router = APIRouter(
    prefix="/agents",
    tags=["agents"],
    dependencies=[Depends(enforce_general_rate_limit)],
)

AgentId = Annotated[UUID, Path(description="Agent id within your organisation")]
PaginationDep = Annotated[PaginationParams, Depends(pagination_params)]


@router.get("", response_model=Envelope[list[AgentOut]], summary="List agents")
async def list_agents(
    principal: RequireAdmin, session: SessionDep, pagination: PaginationDep
) -> Envelope[list[AgentOut]]:
    repository = ScopedRepository(session, principal.scope, Agent)
    page = await repository.list(pagination, order_by=[Agent.created_at.desc()])
    return ok([AgentOut.model_validate(item) for item in page.items], meta=page.meta)


@router.post(
    "",
    status_code=HTTPStatus.CREATED,
    response_model=Envelope[EnrollmentTokenOut],
    summary="Issue a one-time enrollment token",
)
async def create_enrollment_token(
    request: Request,
    principal: RequireAdmin,
    session: SessionDep,
    payload: EnrollmentTokenCreate,
) -> Envelope[EnrollmentTokenOut]:
    """The token is returned once. Nothing can retrieve it again."""
    issued = await issue_enrollment_token(
        session, principal.scope, created_by_user_id=principal.user.id
    )
    await record_audit(
        session,
        principal.scope,
        AuditAction.AGENT_ENROLLMENT_TOKEN_ISSUED,
        target_type="enrollment_token",
        target_id=issued.token_id,
        # The note, never the token. An audit row that captured the credential
        # would defeat storing only its hash.
        metadata={"note": payload.note, "expires_at": issued.expires_at.isoformat()},
        ip=client_ip(request),
    )
    return ok(EnrollmentTokenOut(enrollment_token=issued.plaintext, expires_at=issued.expires_at))


@router.get("/{agent_id}", response_model=Envelope[AgentOut], summary="Fetch an agent")
async def get_agent(
    principal: RequireAdmin, session: SessionDep, agent_id: AgentId
) -> Envelope[AgentOut]:
    repository = ScopedRepository(session, principal.scope, Agent)
    return ok(AgentOut.model_validate(await repository.get_or_404(agent_id)))


@router.patch(
    "/{agent_id}/allowlist",
    response_model=Envelope[AgentOut],
    summary="Narrow an agent to a subset of the authorized networks",
)
async def update_allowlist(
    request: Request,
    principal: RequireAdmin,
    session: SessionDep,
    agent_id: AgentId,
    payload: AgentAllowlistUpdate,
) -> Envelope[AgentOut]:
    """Store the **effective** list, not the submitted one.

    The narrowing itself was always correct — ``agents.allowlist`` may only ever
    subtract from the org's authorized networks, and ``effective_allowlist``
    enforces that on every heartbeat. What was wrong was the record of it. The
    submitted list was stored verbatim, so ``GET /agents/{id}`` reported
    ``['0.0.0.0/0', '8.8.8.0/24', '10.1.0.0/16']`` while the agent was being sent
    ``['10.1.0.0/16']`` — an operator reading the API during an incident would
    have concluded the scanner was pointed at the internet. Narrowing before the
    write makes the stored value the value that is in force.

    A request whose entries all fall outside the authorized networks is refused
    rather than stored empty. Empty means *no per-agent restriction*, which
    widens the agent to every authorized network — the exact opposite of what
    somebody submitting a list of ranges intended. Clearing the restriction is
    still available, by sending an empty list explicitly.
    """
    repository = ScopedRepository(session, principal.scope, Agent)
    agent = await repository.get_or_404(agent_id)
    before = tuple(agent.allowlist or ())

    requested = tuple(payload.allowlist)
    authorized = await authorized_networks(session, principal.scope)
    effective = narrow_to(authorized, requested) if requested else ()
    dropped = tuple(entry for entry in requested if entry not in effective)

    if requested and not effective:
        raise SemanticValidationError(
            "None of the requested ranges are inside a network this organisation has "
            "registered and marked authorized, so the agent would be left unrestricted. "
            "Send an empty list to deliberately remove the restriction.",
            field="allowlist",
            code="allowlist_outside_authorized_networks",
        )

    updated = await repository.update(agent, {"allowlist": list(effective)})
    await record_audit(
        session,
        principal.scope,
        AuditAction.AGENT_ALLOWLIST_UPDATED,
        target_type="agent",
        target_id=agent_id,
        # Before and after, plus what the org's authorisation removed from the
        # request. During an incident the dropped entries are the interesting
        # part: they are what somebody asked a scanner to point at.
        metadata={
            "name": agent.name,
            "before": list(before),
            "after": list(effective),
            "requested": list(requested),
            "dropped_outside_authorized_networks": list(dropped),
        },
        ip=client_ip(request),
    )
    return ok(AgentOut.model_validate(updated))


@router.delete(
    "/{agent_id}",
    status_code=HTTPStatus.OK,
    response_model=Envelope[AgentOut],
    summary="Revoke an agent",
)
async def revoke_agent(
    request: Request, principal: RequireAdmin, session: SessionDep, agent_id: AgentId
) -> Envelope[AgentOut]:
    """Revocation is a status change, not a delete.

    The agent's scan history has to keep pointing at something, and "which
    scanner produced this result" is exactly the question an incident asks. The
    key stops authenticating immediately — ``find_agent_by_key_hash`` filters on
    ``status = 'active'`` — so a revoked agent is locked out on its next call.
    """
    repository = ScopedRepository(session, principal.scope, Agent)
    agent = await repository.get_or_404(agent_id)
    if agent.status == AgentStatus.REVOKED.value:
        raise ConflictError("This agent is already revoked.")

    revoked = await repository.update(agent, {"status": AgentStatus.REVOKED.value})
    await record_audit(
        session,
        principal.scope,
        AuditAction.AGENT_REVOKED,
        target_type="agent",
        target_id=agent_id,
        metadata={"name": agent.name, "key_prefix": agent.key_prefix},
        ip=client_ip(request),
    )
    return ok(AgentOut.model_validate(revoked))
