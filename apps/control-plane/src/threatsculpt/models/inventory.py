"""Networks, business services, assets, and the asset→service mapping.

``business_services`` is the layer that makes this a business-impact product
rather than another CVE list, and ``asset_services`` is the join that turns
"CVE-2021-44228 on 10.0.4.12" into "Payment processing is exposed".
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from enum import StrEnum

from sqlalchemy import CheckConstraint, ForeignKey, Index, Numeric, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from threatsculpt.db.base import TenantModel
from threatsculpt.db.types import Cidr, Inet, MacAddr, PgUUID


class Criticality(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Exposure(StrEnum):
    INTERNET = "internet"
    DMZ = "dmz"
    INTERNAL = "internal"
    ISOLATED = "isolated"


class Network(TenantModel):
    """A CIDR the org claims to own. Scans refuse unless ``authorized``."""

    __tablename__ = "networks"
    __table_args__ = (UniqueConstraint("org_id", "cidr", name="uq_networks_org_id_cidr"),)

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    cidr: Mapped[str] = mapped_column(Cidr, nullable=False)
    authorized: Mapped[bool] = mapped_column(nullable=False, default=False, server_default="false")
    authorization_note: Mapped[str | None] = mapped_column(String(1000))
    #: Who asserted permission to scan this range, and when. Together with the
    #: note these are the "authorization record" docs/SECURITY.md describes; a
    #: boolean on its own records nothing. Required for public address space,
    #: optional for RFC1918 — see ``scanning.authorization``.
    authorized_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL")
    )
    authorized_at: Mapped[datetime | None] = mapped_column()


class BusinessService(TenantModel):
    __tablename__ = "business_services"
    __table_args__ = (
        CheckConstraint(
            "criticality IN ('critical','high','medium','low')",
            name="business_services_criticality_valid",
        ),
        CheckConstraint(
            "revenue_at_risk IS NULL OR revenue_at_risk >= 0",
            name="business_services_revenue_non_negative",
        ),
    )

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(String(2000))
    criticality: Mapped[str] = mapped_column(String(32), nullable=False)
    revenue_at_risk: Mapped[Decimal | None] = mapped_column(Numeric(14, 2))
    owner_name: Mapped[str | None] = mapped_column(String(200))
    owner_email: Mapped[str | None] = mapped_column(String(320))


class Asset(TenantModel):
    """A host discovered by a scan or entered by hand."""

    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("org_id", "ip", name="uq_assets_org_id_ip"),
        CheckConstraint(
            "exposure IN ('internet','dmz','internal','isolated')", name="assets_exposure_valid"
        ),
        Index("ix_assets_org_id_exposure", "org_id", "exposure"),
    )

    network_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("networks.id", ondelete="SET NULL")
    )
    ip: Mapped[str] = mapped_column(Inet, nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(255))
    mac: Mapped[str | None] = mapped_column(MacAddr)
    os_family: Mapped[str | None] = mapped_column(String(64))
    os_version: Mapped[str | None] = mapped_column(String(64))
    exposure: Mapped[str] = mapped_column(
        String(32), nullable=False, default=Exposure.INTERNAL.value, server_default="internal"
    )
    first_seen_at: Mapped[datetime | None] = mapped_column()
    last_seen_at: Mapped[datetime | None] = mapped_column()


class AssetService(TenantModel):
    """Join: which business services an asset supports."""

    __tablename__ = "asset_services"
    __table_args__ = (
        UniqueConstraint(
            "asset_id", "business_service_id", name="uq_asset_services_asset_id_business_service_id"
        ),
        Index("ix_asset_services_business_service_id", "business_service_id"),
    )

    asset_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    business_service_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("business_services.id", ondelete="CASCADE"), nullable=False
    )
