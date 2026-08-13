"""``PATCH /agents/{id}/allowlist`` — the write that changes what a scanner aims at.

Every other write in this service audits. This one did not, which made it the
single operator action an incident most wants a before/after for and the single
one there was no record of.

It also stored the submitted list verbatim while sending the agent a narrowed
one, so ``GET /agents/{id}`` showed ``['0.0.0.0/0', '8.8.8.0/24', '10.1.0.0/16']``
for an agent that was actually being told ``['10.1.0.0/16']``. The narrowing was
correct; the record of it was misleading, at exactly the moment somebody would be
relying on it.
"""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.agent_fixtures import EnrolledAgent, enroll_agent
from tests.factories import API, create_network, register_tenant
from threatsculpt.core.pagination import PaginationParams
from threatsculpt.db.session import scoped_session
from threatsculpt.models.audit import AuditLog
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope


async def _heartbeat_allowlist(client: AsyncClient, agent: EnrolledAgent) -> list[str]:
    response = await client.post(
        f"{API}/agent/heartbeat", json={"healthy": True}, headers=agent.auth_header
    )
    assert response.status_code == 200, response.text
    allowlist: list[str] = response.json()["data"]["allowlist"]
    return allowlist


async def test_the_stored_list_is_the_list_in_force(client: AsyncClient) -> None:
    """What the API reports and what the agent receives are the same thing."""
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant, cidr="10.0.0.0/8")
    agent = await enroll_agent(client, tenant)

    update = await client.patch(
        f"{API}/agents/{agent.agent_id}/allowlist",
        json={"allowlist": ["0.0.0.0/0", "8.8.8.0/24", "10.1.0.0/16"]},
        headers=tenant.auth_header,
    )
    assert update.status_code == 200, update.text
    assert update.json()["data"]["allowlist"] == ["10.1.0.0/16"]

    fetched = await client.get(f"{API}/agents/{agent.agent_id}", headers=tenant.auth_header)
    assert fetched.json()["data"]["allowlist"] == ["10.1.0.0/16"]
    assert await _heartbeat_allowlist(client, agent) == ["10.1.0.0/16"]


async def test_the_change_is_audited_with_before_and_after(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant, cidr="10.0.0.0/8")
    agent = await enroll_agent(client, tenant)

    await client.patch(
        f"{API}/agents/{agent.agent_id}/allowlist",
        json={"allowlist": ["10.1.0.0/16"]},
        headers=tenant.auth_header,
    )
    await client.patch(
        f"{API}/agents/{agent.agent_id}/allowlist",
        json={"allowlist": ["0.0.0.0/0", "8.8.8.0/24", "10.2.0.0/16"]},
        headers=tenant.auth_header,
    )

    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        audit = ScopedRepository(session, scope, AuditLog)
        rows = await audit.list(
            PaginationParams(per_page=50),
            AuditLog.action == "agent.allowlist_updated",
            order_by=[AuditLog.created_at.asc()],
        )

    assert rows.total == 2
    latest = rows.items[-1].audit_metadata
    assert latest["before"] == ["10.1.0.0/16"]
    assert latest["after"] == ["10.2.0.0/16"]
    assert latest["requested"] == ["0.0.0.0/0", "8.8.8.0/24", "10.2.0.0/16"]
    # The interesting half during an incident: what somebody asked a scanner to
    # point at that the org's authorisation refused.
    assert latest["dropped_outside_authorized_networks"] == ["0.0.0.0/0", "8.8.8.0/24"]


async def test_a_request_entirely_outside_the_authorized_networks_is_refused(
    client: AsyncClient,
) -> None:
    """Storing the narrowed list would otherwise widen the agent to everything.

    An empty ``allowlist`` means *no per-agent restriction*, so silently reducing
    a list of unauthorised ranges to empty would hand the agent the org's whole
    authorized set — the opposite of what was asked for.
    """
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant, cidr="10.0.0.0/8")
    agent = await enroll_agent(client, tenant)

    response = await client.patch(
        f"{API}/agents/{agent.agent_id}/allowlist",
        json={"allowlist": ["8.8.8.0/24"]},
        headers=tenant.auth_header,
    )
    assert response.status_code == 422, response.text
    assert response.json()["error"]["code"] == "allowlist_outside_authorized_networks"
    assert await _heartbeat_allowlist(client, agent) == ["10.0.0.0/8"]


async def test_an_empty_list_deliberately_clears_the_restriction(
    client: AsyncClient,
) -> None:
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant, cidr="10.0.0.0/8")
    agent = await enroll_agent(client, tenant)

    await client.patch(
        f"{API}/agents/{agent.agent_id}/allowlist",
        json={"allowlist": ["10.1.0.0/16"]},
        headers=tenant.auth_header,
    )
    assert await _heartbeat_allowlist(client, agent) == ["10.1.0.0/16"]

    cleared = await client.patch(
        f"{API}/agents/{agent.agent_id}/allowlist",
        json={"allowlist": []},
        headers=tenant.auth_header,
    )
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["data"]["allowlist"] == []
    assert await _heartbeat_allowlist(client, agent) == ["10.0.0.0/8"]


async def test_another_tenants_agent_is_not_reachable(client: AsyncClient) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    await create_network(client, beta, cidr="10.0.0.0/8")
    beta_agent = await enroll_agent(client, beta)

    response = await client.patch(
        f"{API}/agents/{beta_agent.agent_id}/allowlist",
        json={"allowlist": ["10.1.0.0/16"]},
        headers=alpha.auth_header,
    )
    assert response.status_code == 404, response.text
