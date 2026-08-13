"""Helpers for building tenants through the public API.

Tenants are created the way a real customer would create them — by calling
``/auth/register`` — so the fixtures exercise the same code path under test
rather than inserting rows behind it.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from uuid import UUID

from httpx import AsyncClient

from threatsculpt.auth.delivery import MemoryEmailSender

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


def memory_sender(client: AsyncClient) -> MemoryEmailSender:
    """The app's in-process email sender.

    Reached through the transport because a test that only has an ``AsyncClient``
    still needs to read what was "sent" — the conftest settings select the memory
    sender precisely so it can.
    """
    sender = client._transport.app.state.email_sender  # type: ignore[attr-defined]
    assert isinstance(sender, MemoryEmailSender), (
        "the suite requires email_delivery='memory'; see tests/conftest.py"
    )
    return sender


async def verify_email(client: AsyncClient, email: str) -> None:
    """Complete verification for ``email`` the way its owner would.

    Registration only *claims* an address. Until control is proved the account
    is not a login candidate and holds no slot, so a fixture that skipped this
    would build a tenant that cannot log in — and, worse, would let a test pass
    while exercising an account state no real customer is ever in.
    """
    token = memory_sender(client).latest_token_for(email)
    assert token is not None, f"no verification token was issued for {email!r}"
    response = await client.post(f"{API}/auth/verify-email", json={"token": token})
    assert response.status_code == 200, response.text


async def register_tenant(
    client: AsyncClient,
    slug: str,
    *,
    email: str | None = None,
    password: str = DEFAULT_PASSWORD,
    verified: bool = True,
) -> Tenant:
    """Register an org and, by default, prove its owner's address.

    ``verified=False`` leaves the account in the claimed-but-unproved state, for
    tests that are about that state itself.
    """
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
    if verified:
        await verify_email(client, address)
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


async def register_tenants_sharing_email(
    client: AsyncClient,
    slugs: Sequence[str],
    *,
    email: str,
    password_for: Callable[[str], str] | None = None,
) -> tuple[Tenant, ...]:
    """Register several orgs whose owners all use ``email``.

    ``users`` is unique on ``(org_id, email)``, not on ``email``, so this is a
    supported state — and the normal one for a consultancy whose staff hold
    accounts in several client orgs. The default fixtures derive the address from
    the org slug, which means nothing routinely exercises it; the login path
    behaves quite differently once a second candidate exists, so it needs a
    fixture that produces one.

    Each org gets a distinct password by default, so a test can tell which
    account a login actually authenticated against.
    """
    chosen = password_for or (lambda slug: f"{slug}-password-not-shared")
    return tuple(
        [await register_tenant(client, slug, email=email, password=chosen(slug)) for slug in slugs]
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
