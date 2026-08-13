"""Seeding helpers for the scoring, enrichment, findings and dashboard suites.

Inventory that a real deployment gets from a scan (assets, scan results, ports)
has no operator-facing create endpoint, so it is seeded directly — but always
through ``scoped_session``, so every insert passes the same tenancy guard and
RLS policy the application does. Seeding with a superuser connection would
quietly prove nothing about isolation.

Named ``scoring_factories`` rather than ``factories`` to sit alongside the
existing shared helper without colliding with it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from threatsculpt.db.session import scoped_session
from threatsculpt.models.cpe_match import VulnerabilityCpeMatch
from threatsculpt.models.finding import Vulnerability
from threatsculpt.models.inventory import Asset, AssetService, BusinessService
from threatsculpt.models.scan import Port, ScanJob, ScanResult
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope

LOG4J_CPE = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
HTTPD_CPE = "cpe:/a:apache:http_server:2.4.49"


@dataclass(frozen=True, slots=True)
class SeededAsset:
    asset_id: UUID
    port_id: UUID
    scan_job_id: UUID


def scope_for(org_id: UUID) -> OrgScope:
    return OrgScope.for_system(org_id)


async def seed_vulnerability(
    factory: async_sessionmaker[AsyncSession],
    org_id: UUID,
    *,
    cve_id: str = "CVE-2021-44228",
    cvss_base: str | None = "10.0",
    exploit_maturity: str = "none",
    kev_listed: bool = False,
    criteria_cpe: str = "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
    version_end_excluding: str | None = "2.15.0",
    severity: str = "critical",
) -> str:
    """``vulnerabilities`` is global, but a scope is still needed to open a session.

    Idempotent on ``cve_id`` precisely because the table is *not* tenant-scoped:
    seeding "the same CVE" for two orgs in a cross-tenant test is one row, not
    two, and a helper that pretended otherwise would fail on the primary key.
    """
    parsed_vendor, parsed_product = _identity_of(criteria_cpe)
    async with scoped_session(factory, scope_for(org_id)) as session:
        if await session.get(Vulnerability, cve_id) is None:
            session.add(
                Vulnerability(
                    cve_id=cve_id,
                    description=f"{cve_id} description",
                    cvss_base=Decimal(cvss_base) if cvss_base is not None else None,
                    severity=severity,
                    cpes=[criteria_cpe],
                    kev_listed=kev_listed,
                    exploit_maturity=exploit_maturity,
                )
            )
            await session.flush()
            session.add(
                VulnerabilityCpeMatch(
                    cve_id=cve_id,
                    cpe23=criteria_cpe,
                    vendor=parsed_vendor,
                    product=parsed_product,
                    version_end_excluding=version_end_excluding,
                    vulnerable=True,
                )
            )
    return cve_id


def _identity_of(cpe23: str) -> tuple[str, str]:
    from threatsculpt.enrichment.cpe import parse_cpe

    parsed = parse_cpe(cpe23)
    assert parsed is not None, cpe23
    return parsed.vendor, parsed.product


async def seed_asset_with_port(
    factory: async_sessionmaker[AsyncSession],
    org_id: UUID,
    *,
    ip: str = "10.0.4.12",
    hostname: str | None = "app-01",
    exposure: str = "internet",
    network_id: UUID | None = None,
    cpe: tuple[str, ...] = (LOG4J_CPE,),
    product: str | None = "Apache log4j",
    version: str | None = "2.14.1",
    port_number: int = 8080,
) -> SeededAsset:
    """One asset, one scan job, one scan result, one port — the minimum a finding needs."""
    scope = scope_for(org_id)
    async with scoped_session(factory, scope) as session:
        assets = ScopedRepository(session, scope, Asset)
        asset = await assets.create(
            ip=ip,
            hostname=hostname,
            exposure=exposure,
            network_id=network_id,
            first_seen_at=datetime.now(UTC),
            last_seen_at=datetime.now(UTC),
        )
        jobs = ScopedRepository(session, scope, ScanJob)
        job = await jobs.create(target="10.0.0.0/8", profile="service", status="completed")
        results = ScopedRepository(session, scope, ScanResult)
        result = await results.create(scan_job_id=job.id, asset_id=asset.id, state="up", raw={})
        ports = ScopedRepository(session, scope, Port)
        port = await ports.create(
            scan_result_id=result.id,
            asset_id=asset.id,
            port=port_number,
            protocol="tcp",
            state="open",
            service="http",
            product=product,
            version=version,
            cpe=list(cpe),
        )
        return SeededAsset(asset_id=asset.id, port_id=port.id, scan_job_id=job.id)


async def map_asset_to_service(
    factory: async_sessionmaker[AsyncSession],
    org_id: UUID,
    asset_id: UUID,
    business_service_id: UUID,
) -> None:
    scope = scope_for(org_id)
    async with scoped_session(factory, scope) as session:
        await ScopedRepository(session, scope, AssetService).create(
            asset_id=asset_id, business_service_id=business_service_id
        )


async def seed_business_service(
    factory: async_sessionmaker[AsyncSession],
    org_id: UUID,
    *,
    name: str = "Payment processing",
    criticality: str = "critical",
    revenue_at_risk: str | None = "4200000.00",
) -> UUID:
    scope = scope_for(org_id)
    async with scoped_session(factory, scope) as session:
        service = await ScopedRepository(session, scope, BusinessService).create(
            name=name,
            criticality=criticality,
            revenue_at_risk=Decimal(revenue_at_risk) if revenue_at_risk else None,
        )
        return service.id


async def age_finding(
    factory: async_sessionmaker[AsyncSession],
    org_id: UUID,
    *,
    days: int,
    resolved_days_ago: int | None = None,
) -> None:
    """Backdate every finding in the org, so the 30-day windows have history to see."""
    from sqlalchemy import update

    from threatsculpt.core.scoped_sql import execute_scoped
    from threatsculpt.models.finding import Finding

    scope = scope_for(org_id)
    now = datetime.now(UTC)
    values: dict[str, Any] = {"first_seen_at": now - timedelta(days=days)}
    if resolved_days_ago is not None:
        values["resolved_at"] = now - timedelta(days=resolved_days_ago)
    async with scoped_session(factory, scope) as session:
        await execute_scoped(
            session,
            scope,
            update(Finding).where(Finding.org_id == org_id).values(**values),
        )


async def add_user_and_login(
    client: Any,
    factory: async_sessionmaker[AsyncSession],
    org_id: UUID,
    slug: str,
    role: str,
) -> dict[str, str]:
    """A second user in the org with ``role``, plus its auth header."""
    from tests.factories import API, DEFAULT_PASSWORD
    from threatsculpt.models.user import User
    from threatsculpt.security.passwords import hash_password

    email = f"{role}@{slug}.example"
    scope = scope_for(org_id)
    async with scoped_session(factory, scope) as session:
        await ScopedRepository(session, scope, User).create(
            email=email,
            password_hash=hash_password(DEFAULT_PASSWORD),
            full_name=f"{role} user",
            role=role,
            status="active",
        )
    response = await client.post(
        f"{API}/auth/login", json={"email": email, "password": DEFAULT_PASSWORD}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['data']['access_token']}"}


async def run_enrichment(
    factory: async_sessionmaker[AsyncSession], org_id: UUID, **kwargs: Any
) -> Any:
    from threatsculpt.enrichment.service import generate_findings

    scope = scope_for(org_id)
    async with scoped_session(factory, scope) as session:
        return await generate_findings(session, scope, **kwargs)


async def load_findings(factory: async_sessionmaker[AsyncSession], org_id: UUID) -> tuple[Any, ...]:
    """Read an org's findings the way the application must: scoped.

    A bare ``session.execute(select(Finding))`` is refused by the tenancy guard,
    which is the point — the tests cannot read customer data by a route the
    application itself could not take.
    """
    from sqlalchemy import select

    from threatsculpt.core.scoped_sql import execute_scoped
    from threatsculpt.models.finding import Finding

    scope = scope_for(org_id)
    async with scoped_session(factory, scope) as session:
        result = await execute_scoped(
            session,
            scope,
            select(Finding).where(Finding.org_id == org_id).order_by(Finding.cve_id),
        )
        rows = tuple(result.scalars().all())
        for row in rows:
            session.expunge(row)
        return rows


async def set_finding_status(
    factory: async_sessionmaker[AsyncSession], org_id: UUID, status: str
) -> None:
    from sqlalchemy import update

    from threatsculpt.core.scoped_sql import execute_scoped
    from threatsculpt.models.finding import Finding

    scope = scope_for(org_id)
    async with scoped_session(factory, scope) as session:
        await execute_scoped(
            session,
            scope,
            update(Finding).where(Finding.org_id == org_id).values(status=status),
        )
