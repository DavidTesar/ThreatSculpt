"""``/networks`` — registered CIDRs and their scan authorisation.

Reference implementation of the resource pattern every other tenant-scoped
router should copy: role dependency on the route, ``ScopedRepository`` for all
access, ``get_or_404`` so a cross-tenant id is indistinguishable from a missing
one, and an audit row on every write.
"""

from __future__ import annotations

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
from threatsculpt.tenancy.repository import ScopedRepository

router = APIRouter(
    prefix="/networks",
    tags=["networks"],
    dependencies=[Depends(enforce_general_rate_limit)],
)

NetworkId = Annotated[UUID, Path(description="Network id within your organisation")]
PaginationDep = Annotated[PaginationParams, Depends(pagination_params)]


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
    repository = ScopedRepository(session, principal.scope, Network)
    network = await repository.create(
        name=payload.name,
        cidr=payload.cidr,
        authorized=payload.authorized,
        authorization_note=payload.authorization_note,
    )
    await record_audit(
        session,
        principal.scope,
        AuditAction.NETWORK_CREATED,
        target_type="network",
        target_id=network.id,
        metadata={"cidr": payload.cidr, "authorized": payload.authorized},
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
    repository = ScopedRepository(session, principal.scope, Network)
    network = await repository.get_or_404(network_id)
    changes = payload.changes()
    updated = await repository.update(network, changes) if changes else network
    await record_audit(
        session,
        principal.scope,
        AuditAction.NETWORK_UPDATED,
        target_type="network",
        target_id=network_id,
        metadata={"fields": sorted(changes)},
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
    """Destructive, so ``admin`` or above. v1 let an unauthenticated caller do this."""
    repository = ScopedRepository(session, principal.scope, Network)
    network = await repository.get_or_404(network_id)
    await repository.delete(network)
    await record_audit(
        session,
        principal.scope,
        AuditAction.NETWORK_DELETED,
        target_type="network",
        target_id=network_id,
        ip=client_ip(request),
    )
    return ok(None)
