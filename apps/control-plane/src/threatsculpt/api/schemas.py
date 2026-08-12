"""Request/response models for the resource routes.

Same discipline as the auth schemas: ``extra="forbid"``, and no field anywhere
that names a tenant.
"""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from threatsculpt.models.inventory import Criticality


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


class FromAttributes(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, from_attributes=True)


def _validate_cidr(value: str) -> str:
    """Parse with ``ipaddress`` so only a real network reaches the database.

    ``strict=False`` accepts ``10.0.4.12/24`` and normalises it to the network
    address, which is what a ``cidr`` column stores anyway.
    """
    try:
        network: IPv4Network | IPv6Network = ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"not a valid CIDR block: {value!r}") from exc
    return str(network)


class NetworkCreate(StrictModel):
    name: Annotated[str, Field(min_length=1, max_length=200)]
    cidr: Annotated[str, Field(min_length=1, max_length=64)]
    authorized: bool = False
    authorization_note: Annotated[str | None, Field(max_length=1000)] = None

    @field_validator("cidr")
    @classmethod
    def _check_cidr(cls, value: str) -> str:
        return _validate_cidr(value)


class NetworkUpdate(StrictModel):
    """All fields optional; ``cidr`` is immutable once assets reference it."""

    name: Annotated[str | None, Field(min_length=1, max_length=200)] = None
    authorized: bool | None = None
    authorization_note: Annotated[str | None, Field(max_length=1000)] = None

    def changes(self) -> dict[str, object]:
        return self.model_dump(exclude_unset=True, exclude_none=False)


class NetworkOut(FromAttributes):
    id: UUID
    name: str
    cidr: str
    authorized: bool
    authorization_note: str | None
    created_at: datetime
    updated_at: datetime


class BusinessServiceCreate(StrictModel):
    name: Annotated[str, Field(min_length=1, max_length=200)]
    description: Annotated[str | None, Field(max_length=2000)] = None
    criticality: Criticality
    revenue_at_risk: Annotated[Decimal | None, Field(ge=0, max_digits=14, decimal_places=2)] = None
    owner_name: Annotated[str | None, Field(max_length=200)] = None
    owner_email: EmailStr | None = None


class BusinessServiceUpdate(StrictModel):
    name: Annotated[str | None, Field(min_length=1, max_length=200)] = None
    description: Annotated[str | None, Field(max_length=2000)] = None
    criticality: Criticality | None = None
    revenue_at_risk: Annotated[Decimal | None, Field(ge=0, max_digits=14, decimal_places=2)] = None
    owner_name: Annotated[str | None, Field(max_length=200)] = None
    owner_email: EmailStr | None = None

    def changes(self) -> dict[str, object]:
        return self.model_dump(exclude_unset=True, exclude_none=False)


class BusinessServiceOut(FromAttributes):
    id: UUID
    name: str
    description: str | None
    criticality: str
    revenue_at_risk: Decimal | None
    owner_name: str | None
    owner_email: str | None
    created_at: datetime
    updated_at: datetime


class HealthOut(StrictModel):
    status: str
    environment: str


class ReadinessOut(StrictModel):
    status: str
    database: str
