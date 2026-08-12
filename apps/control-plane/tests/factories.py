"""Helpers for building tenants through the public API.

Tenants are created the way a real customer would create them — by calling
``/auth/register`` — so the fixtures exercise the same code path under test
rather than inserting rows behind it.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from httpx import AsyncClient

API = "/api/v1"
DEFAULT_PASSWORD = "correct-horse-battery-staple"


@dataclass(frozen=True, slots=True)
class Tenant:
    """A registered org plus its owner's credentials."""

    org_id: UUID
    org_slug: str
    user_id: UUID
    email: str
    password: str
    access_token: str
    refresh_token: str

    @property
    def auth_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}

    def with_token(self, access_token: str) -> Tenant:
        """Return a copy carrying a different access token. Never mutates."""
        return Tenant(
            org_id=self.org_id,
            org_slug=self.org_slug,
            user_id=self.user_id,
            email=self.email,
            password=self.password,
            access_token=access_token,
            refresh_token=self.refresh_token,
        )


async def register_tenant(
    client: AsyncClient,
    slug: str,
    *,
    email: str | None = None,
    password: str = DEFAULT_PASSWORD,
) -> Tenant:
    address = email or f"owner@{slug}.example"
    response = await client.post(
        f"{API}/auth/register",
        json={
            "org_name": slug.replace("-", " ").title(),
            "org_slug": slug,
            "email": address,
            "password": password,
            "full_name": "Test Owner",
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()["data"]
    return Tenant(
        org_id=UUID(body["org"]["id"]),
        org_slug=body["org"]["slug"],
        user_id=UUID(body["user"]["id"]),
        email=address,
        password=password,
        access_token=body["access_token"],
        refresh_token=response.cookies.get("ts_refresh") or "",
    )


async def create_network(
    client: AsyncClient, tenant: Tenant, *, name: str = "HQ", cidr: str = "10.0.0.0/8"
) -> UUID:
    response = await client.post(
        f"{API}/networks",
        json={"name": name, "cidr": cidr, "authorized": True},
        headers=tenant.auth_header,
    )
    assert response.status_code == 201, response.text
    return UUID(response.json()["data"]["id"])


async def create_business_service(
    client: AsyncClient, tenant: Tenant, *, name: str = "Payment processing"
) -> UUID:
    response = await client.post(
        f"{API}/business-services",
        json={"name": name, "criticality": "critical", "revenue_at_risk": "4200000.00"},
        headers=tenant.auth_header,
    )
    assert response.status_code == 201, response.text
    return UUID(response.json()["data"]["id"])
