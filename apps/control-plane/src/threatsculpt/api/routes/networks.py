"""``/networks`` — registered CIDRs and their scan authorisation.

Reference implementation of the resource pattern every other tenant-scoped
router should copy: role dependency on the route, ``ScopedRepository`` for all
access, ``get_or_404`` so a cross-tenant id is indistinguishable from a missing
one, and an audit row on every write.

Two things here are not boilerplate, and both concern the ``authorized`` flag:

* granting it over public address space goes through
  ``scanning.authorization``, which requires a written, attributed assertion
  rather than a bare boolean;
* **withdrawing** it goes through ``scanning.containment``, which stops the scan
  jobs that were queued or already leased against the range. Every write that can
  remove coverage — the PATCH and the DELETE — calls it. That is the fix for the
  case where an operator revoked permission and the next agent poll was handed
  the target anyway.
"""

from __future__ import annotations

from datetime import UTC, datetime
from http import HTTPStatus
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Request

from threatsculpt.api.dependencies import RequireAdmin, RequireAnalyst, SessionDep
from threatsculpt.api.limits import enforce_general_rate_limit
from threatsculpt.api.middleware import client_ip
from threatsculpt.api.schemas import NetworkCreate, NetworkOut, NetworkUpdate
from threatsculpt.audit.writer import record_audit
from threatsculpt.core.envelope import Envelope, ok
from threatsculpt.core.pagination import PaginationParams, pagination_params
from threatsculpt.models.audit import AuditAction
from threatsculpt.models.inventory import Network
from threatsculpt.scanning.authorization import validate_authorization
from threatsculpt.scanning.containment import RevalidationOutcome, revalidate_open_jobs
from threatsculpt.tenancy.repository import ScopedRepository

router = APIRouter(
    prefix="/networks",
    tags=["networks"],
    dependencies=[Depends(enforce_general_rate_limit)],
)

NetworkId = Annotated[UUID, Path(description="Network id within your organisation")]
PaginationDep = Annotated[PaginationParams, Depends(pagination_params)]


def _assertion_columns(*, authorized: bool, user_id: UUID | None) -> dict[str, object]:
    """Attribution to store alongside a network whose ``authorized`` flag is set.

    Cleared when authorisation is withdrawn: leaving the old name and timestamp
    on a de-authorised network would read as a live assertion, and re-granting
    later must produce a fresh record rather than resurrect a stale one.
    """
    if not authorized:
        return {"authorized_by_user_id": None, "authorized_at": None}
    return {"authorized_by_user_id": user_id, "authorized_at": datetime.now(tz=UTC)}


def _withdrawal_metadata(outcome: RevalidationOutcome) -> dict[str, object]:
    """What the network's own audit row says about the jobs this write stopped."""
    return {
        "scan_jobs_cancelled": outcome.count,
        "scan_jobs_cancelled_while_leased": outcome.leased_count,
    }


@router.get("", response_model=Envelope[list[NetworkOut]], summary="List networks")
async def list_networks(
    principal: RequireAnalyst,
    session: SessionDep,
    pagination: PaginationDep,
) -> Envelope[list[NetworkOut]]:
    repository = ScopedRepository(session, principal.scope, Network)
    page = await repository.list(pagination, order_by=[Network.created_at.desc()])
    return ok(
        [NetworkOut.model_validate(item) for item in page.items],
        meta=page.meta,
    )


@router.post(
    "",
    status_code=HTTPStatus.CREATED,
    response_model=Envelope[NetworkOut],
    summary="Register a network",
)
async def create_network(
    request: Request,
    principal: RequireAdmin,
    session: SessionDep,
    payload: NetworkCreate,
) -> Envelope[NetworkOut]:
    """Public address space needs a written assertion; RFC1918 does not."""
    assertion = validate_authorization(
        payload.cidr,
        authorized=payload.authorized,
        authorization_note=payload.authorization_note,
    )
    repository = ScopedRepository(session, principal.scope, Network)
    network = await repository.create(
        name=payload.name,
        cidr=payload.cidr,
        authorized=payload.authorized,
        authorization_note=payload.authorization_note,
        **_assertion_columns(authorized=payload.authorized, user_id=principal.user.id),
    )
    await record_audit(
        session,
        principal.scope,
        AuditAction.NETWORK_CREATED,
        target_type="network",
        target_id=network.id,
        metadata={
            "cidr": payload.cidr,
            "authorized": payload.authorized,
            "network_class": assertion.network_class.value,
            # Named ``assertion_note`` rather than ``authorization_note``: the
            # audit scrubber redacts any key matching /authorization/, which is
            # right for a header and wrong for the one field whose whole purpose
            # is to survive into the permanent record. The network row can be
            # deleted; this is what is left to answer "who said we could".
            "assertion_note": payload.authorization_note,
            "written_assertion_required": assertion.requires_written_assertion,
        },
        ip=client_ip(request),
    )
    return ok(NetworkOut.model_validate(network))


@router.get("/{network_id}", response_model=Envelope[NetworkOut], summary="Fetch a network")
async def get_network(
    principal: RequireAnalyst, session: SessionDep, network_id: NetworkId
) -> Envelope[NetworkOut]:
    repository = ScopedRepository(session, principal.scope, Network)
    return ok(NetworkOut.model_validate(await repository.get_or_404(network_id)))


@router.patch("/{network_id}", response_model=Envelope[NetworkOut], summary="Update a network")
async def update_network(
    request: Request,
    principal: RequireAdmin,
    session: SessionDep,
    network_id: NetworkId,
    payload: NetworkUpdate,
) -> Envelope[NetworkOut]:
    """Re-validates the org's open scan jobs afterwards, always.

    Whether this edit removed coverage is a question about CIDR arithmetic across
    every one of the org's networks, and answering it here would be a second
    implementation of the rule that could disagree with the first. So the edit
    lands and ``revalidate_open_jobs`` re-asks the only question that matters —
    is each open job's target still inside *some* authorized network — which is
    correct for a withdrawal, a no-op for a rename, and correct for the case
    where a wider network still covers the target.
    """
    repository = ScopedRepository(session, principal.scope, Network)
    network = await repository.get_or_404(network_id)
    changes = dict(payload.changes())

    authorized = bool(changes.get("authorized", network.authorized))
    note = changes.get("authorization_note", network.authorization_note)
    assertion = validate_authorization(
        network.cidr,
        authorized=authorized,
        authorization_note=note if isinstance(note, str) else None,
    )
    if "authorized" in changes:
        changes.update(_assertion_columns(authorized=authorized, user_id=principal.user.id))

    updated = await repository.update(network, changes) if changes else network
    outcome = await revalidate_open_jobs(session, principal.scope, ip=client_ip(request))

    await record_audit(
        session,
        principal.scope,
        AuditAction.NETWORK_UPDATED,
        target_type="network",
        target_id=network_id,
        metadata={
            "fields": sorted(changes),
            "authorized": authorized,
            "network_class": assertion.network_class.value,
            **_withdrawal_metadata(outcome),
        },
        ip=client_ip(request),
    )
    return ok(NetworkOut.model_validate(updated))


@router.delete(
    "/{network_id}",
    status_code=HTTPStatus.OK,
    response_model=Envelope[None],
    summary="Delete a network",
)
async def delete_network(
    request: Request,
    principal: RequireAdmin,
    session: SessionDep,
    network_id: NetworkId,
) -> Envelope[None]:
    """Destructive, so ``admin`` or above. v1 let an unauthenticated caller do this.

    Deleting a network is the bluntest form of withdrawing authorisation, so the
    same re-validation runs. ``scan_jobs.network_id`` is ``ON DELETE SET NULL``,
    which means the job survives the delete with its ``target`` intact — without
    this pass it would survive as an orphan nobody had authorised and still be
    dispatched on the next poll.
    """
    repository = ScopedRepository(session, principal.scope, Network)
    network = await repository.get_or_404(network_id)
    cidr = network.cidr
    await repository.delete(network)
    outcome = await revalidate_open_jobs(session, principal.scope, ip=client_ip(request))
    await record_audit(
        session,
        principal.scope,
        AuditAction.NETWORK_DELETED,
        target_type="network",
        target_id=network_id,
        metadata={"cidr": cidr, **_withdrawal_metadata(outcome)},
        ip=client_ip(request),
    )
    return ok(None)
