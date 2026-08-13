"""Request and response models for ``/assets``."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from threatsculpt.models.inventory import Exposure


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class ServiceLink(StrictModel):
    id: UUID
    name: str
    criticality: str


class AssetOut(StrictModel):
    id: UUID
    ip: str
    hostname: str | None = None
    mac: str | None = None
    os_family: str | None = None
    os_version: str | None = None
    exposure: Exposure
    network_id: UUID | None = None
    #: Rolled up in the same query as the asset, not fetched per row.
    open_findings: int = 0
    worst_finding_score: Decimal | None = None
    services: list[ServiceLink] = Field(default_factory=list)
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None


class AssetUpdate(StrictModel):
    """Operator corrections to what a scan inferred.

    ``ip`` is absent on purpose: it is the asset's identity and is unique per
    org, so changing it is creating a different asset.
    """

    hostname: Annotated[str | None, Field(max_length=255)] = None
    exposure: Exposure | None = None
    os_family: Annotated[str | None, Field(max_length=64)] = None
    os_version: Annotated[str | None, Field(max_length=64)] = None
    network_id: UUID | None = None

    def changes(self) -> dict[str, object]:
        return {
            key: (value.value if isinstance(value, Exposure) else value)
            for key, value in self.model_dump(exclude_unset=True).items()
        }


class AssetServicesUpdate(StrictModel):
    """Full replacement of the asset -> business service mapping.

    PUT rather than PATCH because partial mapping updates are ambiguous: an
    operator sending one id almost always means "this is the list", and a
    dropped mapping silently keeping a stale criticality would misprice every
    finding on the host.
    """

    service_ids: Annotated[list[UUID], Field(max_length=100)]
