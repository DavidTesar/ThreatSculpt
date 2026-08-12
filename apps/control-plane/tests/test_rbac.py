"""Role enforcement: ``owner`` > ``admin`` > ``analyst`` > ``viewer``."""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from tests.factories import API, DEFAULT_PASSWORD, Tenant, register_tenant
from threatsculpt.db.session import scoped_session
from threatsculpt.models.user import Role, User, outranks_or_equals
from threatsculpt.security.passwords import hash_password
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope


async def _add_user(session_factory: async_sessionmaker, tenant: Tenant, role: Role) -> str:
    """Insert a second user in ``tenant``'s org with the given role."""
    email = f"{role.value}@{tenant.org_slug}.example"
    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        repository = ScopedRepository(session, scope, User)
        await repository.create(
            email=email,
            password_hash=hash_password(DEFAULT_PASSWORD),
            full_name=f"{role.value} user",
            role=role.value,
            status="active",
        )
    return email


async def _login(client: AsyncClient, email: str) -> dict[str, str]:
    response = await client.post(
        f"{API}/auth/login", json={"email": email, "password": DEFAULT_PASSWORD}
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['data']['access_token']}"}


@pytest.mark.parametrize(
    ("actual", "required", "expected"),
    [
        ("owner", "admin", True),
        ("owner", "owner", True),
        ("admin", "admin", True),
        ("admin", "owner", False),
        ("analyst", "admin", False),
        ("analyst", "viewer", True),
        ("viewer", "viewer", True),
        ("viewer", "analyst", False),
        ("nonsense", "viewer", False),
    ],
)
def test_role_ladder(actual: str, required: str, expected: bool) -> None:
    assert outranks_or_equals(actual, required) is expected


async def test_viewer_cannot_list_networks(
    client: AsyncClient, session_factory: async_sessionmaker
) -> None:
    """``/networks`` needs analyst; a viewer is authenticated but not permitted."""
    tenant = await register_tenant(client, "acme")
    email = await _add_user(session_factory, tenant, Role.VIEWER)
    headers = await _login(client, email)

    response = await client.get(f"{API}/networks", headers=headers)

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


async def test_analyst_can_read_but_not_create_networks(
    client: AsyncClient, session_factory: async_sessionmaker
) -> None:
    tenant = await register_tenant(client, "acme")
    email = await _add_user(session_factory, tenant, Role.ANALYST)
    headers = await _login(client, email)

    assert (await client.get(f"{API}/networks", headers=headers)).status_code == 200

    created = await client.post(
        f"{API}/networks",
        json={"name": "HQ", "cidr": "10.0.0.0/8", "authorized": True},
        headers=headers,
    )
    assert created.status_code == 403


async def test_analyst_cannot_delete_a_network(
    client: AsyncClient, session_factory: async_sessionmaker
) -> None:
    """Destructive operations require admin or above (docs/ARCHITECTURE.md)."""
    tenant = await register_tenant(client, "acme")
    response = await client.post(
        f"{API}/networks",
        json={"name": "HQ", "cidr": "10.0.0.0/8", "authorized": True},
        headers=tenant.auth_header,
    )
    network_id = response.json()["data"]["id"]

    email = await _add_user(session_factory, tenant, Role.ANALYST)
    headers = await _login(client, email)

    assert (await client.delete(f"{API}/networks/{network_id}", headers=headers)).status_code == 403


async def test_admin_can_create_and_delete_networks(
    client: AsyncClient, session_factory: async_sessionmaker
) -> None:
    tenant = await register_tenant(client, "acme")
    email = await _add_user(session_factory, tenant, Role.ADMIN)
    headers = await _login(client, email)

    created = await client.post(
        f"{API}/networks",
        json={"name": "HQ", "cidr": "10.0.0.0/8", "authorized": True},
        headers=headers,
    )
    assert created.status_code == 201

    network_id = created.json()["data"]["id"]
    assert (await client.delete(f"{API}/networks/{network_id}", headers=headers)).status_code == 200


async def test_analyst_can_create_a_business_service(
    client: AsyncClient, session_factory: async_sessionmaker
) -> None:
    """docs/API.md gives ``POST /business-services`` to analyst, unlike networks."""
    tenant = await register_tenant(client, "acme")
    email = await _add_user(session_factory, tenant, Role.ANALYST)
    headers = await _login(client, email)

    response = await client.post(
        f"{API}/business-services",
        json={"name": "Payment processing", "criticality": "critical"},
        headers=headers,
    )

    assert response.status_code == 201


async def test_disabled_user_cannot_authenticate(
    client: AsyncClient, session_factory: async_sessionmaker
) -> None:
    tenant = await register_tenant(client, "acme")

    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        repository = ScopedRepository(session, scope, User)
        user = await repository.get_or_404(tenant.user_id)
        await repository.update(user, {"status": "disabled"})

    response = await client.get(f"{API}/auth/me", headers=tenant.auth_header)

    assert response.status_code == 401


async def test_role_change_invalidates_an_outstanding_access_token(
    client: AsyncClient, session_factory: async_sessionmaker
) -> None:
    """A demoted user must not keep their old privileges for the token's lifetime."""
    tenant = await register_tenant(client, "acme")

    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        repository = ScopedRepository(session, scope, User)
        user = await repository.get_or_404(tenant.user_id)
        await repository.update(user, {"role": Role.VIEWER.value})

    response = await client.get(f"{API}/auth/me", headers=tenant.auth_header)

    assert response.status_code == 401
