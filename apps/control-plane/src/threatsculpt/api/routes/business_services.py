"""``/business-services`` — the asset→business mapping layer.

Same pattern as ``networks``; read access is ``analyst`` and mutation is
``admin``, per the table in docs/API.md.
"""

from __future__ import annotations

from http import HTTPStatus
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Request

from threatsculpt.api.dependencies import RequireAdmin, RequireAnalyst, SessionDep
from threatsculpt.api.limits import enforce_general_rate_limit
from threatsculpt.api.middleware import client_ip
from threatsculpt.api.schemas import (
    BusinessServiceCreate,
    BusinessServiceOut,
    BusinessServiceUpdate,
)
from threatsculpt.audit.writer import record_audit
from threatsculpt.core.envelope import Envelope, ok
from threatsculpt.core.pagination import PaginationParams, pagination_params
from threatsculpt.models.audit import AuditAction
from threatsculpt.models.inventory import BusinessService
from threatsculpt.tenancy.repository import ScopedRepository

router = APIRouter(
    prefix="/business-services",
    tags=["business-services"],
    dependencies=[Depends(enforce_general_rate_limit)],
)

ServiceId = Annotated[UUID, Path(description="Business service id within your organisation")]
PaginationDep = Annotated[PaginationParams, Depends(pagination_params)]


@router.get("", response_model=Envelope[list[BusinessServiceOut]], summary="List services")
async def list_services(
    principal: RequireAnalyst,
    session: SessionDep,
    pagination: PaginationDep,
) -> Envelope[list[BusinessServiceOut]]:
    repository = ScopedRepository(session, principal.scope, BusinessService)
    page = await repository.list(pagination, order_by=[BusinessService.name.asc()])
    return ok(
        [BusinessServiceOut.model_validate(item) for item in page.items],
        meta=page.meta,
    )


@router.post(
    "",
    status_code=HTTPStatus.CREATED,
    response_model=Envelope[BusinessServiceOut],
    summary="Define a business service",
)
async def create_service(
    request: Request,
    principal: RequireAnalyst,
    session: SessionDep,
    payload: BusinessServiceCreate,
) -> Envelope[BusinessServiceOut]:
    repository = ScopedRepository(session, principal.scope, BusinessService)
    service = await repository.create(
        name=payload.name,
        description=payload.description,
        criticality=payload.criticality.value,
        revenue_at_risk=payload.revenue_at_risk,
        owner_name=payload.owner_name,
        owner_email=str(payload.owner_email) if payload.owner_email else None,
    )
    await record_audit(
        session,
        principal.scope,
        AuditAction.BUSINESS_SERVICE_CREATED,
        target_type="business_service",
        target_id=service.id,
        metadata={"criticality": payload.criticality.value},
        ip=client_ip(request),
    )
    return ok(BusinessServiceOut.model_validate(service))


@router.get("/{service_id}", response_model=Envelope[BusinessServiceOut], summary="Fetch a service")
async def get_service(
    principal: RequireAnalyst, session: SessionDep, service_id: ServiceId
) -> Envelope[BusinessServiceOut]:
    repository = ScopedRepository(session, principal.scope, BusinessService)
    return ok(BusinessServiceOut.model_validate(await repository.get_or_404(service_id)))


@router.patch(
    "/{service_id}", response_model=Envelope[BusinessServiceOut], summary="Update a service"
)
async def update_service(
    request: Request,
    principal: RequireAdmin,
    session: SessionDep,
    service_id: ServiceId,
    payload: BusinessServiceUpdate,
) -> Envelope[BusinessServiceOut]:
    repository = ScopedRepository(session, principal.scope, BusinessService)
    service = await repository.get_or_404(service_id)
    changes = _normalise(payload.changes())
    updated = await repository.update(service, changes) if changes else service
    await record_audit(
        session,
        principal.scope,
        AuditAction.BUSINESS_SERVICE_UPDATED,
        target_type="business_service",
        target_id=service_id,
        metadata={"fields": sorted(changes)},
        ip=client_ip(request),
    )
    return ok(BusinessServiceOut.model_validate(updated))


@router.delete(
    "/{service_id}",
    status_code=HTTPStatus.OK,
    response_model=Envelope[None],
    summary="Delete a service",
)
async def delete_service(
    request: Request,
    principal: RequireAdmin,
    session: SessionDep,
    service_id: ServiceId,
) -> Envelope[None]:
    repository = ScopedRepository(session, principal.scope, BusinessService)
    service = await repository.get_or_404(service_id)
    await repository.delete(service)
    await record_audit(
        session,
        principal.scope,
        AuditAction.BUSINESS_SERVICE_DELETED,
        target_type="business_service",
        target_id=service_id,
        ip=client_ip(request),
    )
    return ok(None)


def _normalise(changes: dict[str, object]) -> dict[str, object]:
    """Return a new dict with enum/email values flattened for the ORM."""
    from threatsculpt.models.inventory import Criticality

    return {
        key: (value.value if isinstance(value, Criticality) else value)
        for key, value in changes.items()
    }
