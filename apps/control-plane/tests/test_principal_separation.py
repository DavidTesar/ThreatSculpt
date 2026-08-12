"""The two principal types must not substitute for each other.

An agent key must not authenticate a dashboard route, and a user token must not
authenticate an agent route. The agent *endpoints* belong to another workstream,
so this suite mounts a probe route on the real dependency to prove the
dependency itself is correct before anything is built on it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from fastapi import APIRouter, FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from tests.factories import API, Tenant, register_tenant
from threatsculpt.api.dependencies import CurrentAgent
from threatsculpt.db.session import scoped_session
from threatsculpt.models.agent import Agent
from threatsculpt.security.tokens import (
    AGENT_KEY_PREFIX,
    generate_opaque_token,
    hash_token,
    key_prefix_of,
)
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope

PROBE_PATH = "/api/v1/agent/_probe"


@pytest.fixture
def agent_probe_app(app: FastAPI) -> FastAPI:
    """Mount a minimal route guarded by ``current_agent``.

    Test-only: the real agent endpoints are another agent's deliverable. What is
    under test here is the dependency, not any particular endpoint.
    """
    probe = APIRouter()

    @probe.get(PROBE_PATH)
    async def _probe(principal: CurrentAgent) -> dict[str, str]:
        return {"agent_id": str(principal.agent.id), "org_id": str(principal.scope.org_id)}

    app.include_router(probe)
    return app


@pytest.fixture
async def probe_client(agent_probe_app: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=agent_probe_app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


async def _enroll_agent(session_factory: async_sessionmaker, tenant: Tenant) -> str:
    """Create an agent row and return its plaintext key (stored only as SHA-256)."""
    key = generate_opaque_token(AGENT_KEY_PREFIX)
    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        repository = ScopedRepository(session, scope, Agent)
        await repository.create(
            name="hq-dc-scanner-01",
            api_key_hash=hash_token(key),
            key_prefix=key_prefix_of(key),
            status="active",
            version="2.0.0",
            allowlist=["10.0.0.0/8"],
        )
    return key


async def test_agent_key_authenticates_an_agent_route(
    probe_client: AsyncClient, session_factory: async_sessionmaker
) -> None:
    tenant = await register_tenant(probe_client, "acme")
    key = await _enroll_agent(session_factory, tenant)

    response = await probe_client.get(PROBE_PATH, headers={"Authorization": f"Bearer {key}"})

    assert response.status_code == 200
    assert response.json()["org_id"] == str(tenant.org_id)


async def test_agent_key_is_rejected_on_a_dashboard_route(
    probe_client: AsyncClient, session_factory: async_sessionmaker
) -> None:
    tenant = await register_tenant(probe_client, "acme")
    key = await _enroll_agent(session_factory, tenant)

    response = await probe_client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {key}"})

    assert response.status_code == 401


async def test_user_token_is_rejected_on_an_agent_route(
    probe_client: AsyncClient, session_factory: async_sessionmaker
) -> None:
    tenant = await register_tenant(probe_client, "acme")
    await _enroll_agent(session_factory, tenant)

    response = await probe_client.get(PROBE_PATH, headers=tenant.auth_header)

    assert response.status_code == 401


async def test_revoked_agent_key_stops_working(
    probe_client: AsyncClient, session_factory: async_sessionmaker
) -> None:
    tenant = await register_tenant(probe_client, "acme")
    key = await _enroll_agent(session_factory, tenant)
    headers = {"Authorization": f"Bearer {key}"}
    assert (await probe_client.get(PROBE_PATH, headers=headers)).status_code == 200

    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        repository = ScopedRepository(session, scope, Agent)
        agent = await repository.find_one(Agent.api_key_hash == hash_token(key))
        assert agent is not None
        await repository.update(agent, {"status": "revoked"})

    assert (await probe_client.get(PROBE_PATH, headers=headers)).status_code == 401


async def test_one_orgs_agent_key_does_not_authenticate_into_another_org(
    probe_client: AsyncClient, session_factory: async_sessionmaker
) -> None:
    alpha = await register_tenant(probe_client, "alpha")
    beta = await register_tenant(probe_client, "beta")
    alpha_key = await _enroll_agent(session_factory, alpha)

    response = await probe_client.get(PROBE_PATH, headers={"Authorization": f"Bearer {alpha_key}"})

    assert response.json()["org_id"] == str(alpha.org_id)
    assert response.json()["org_id"] != str(beta.org_id)


async def test_unknown_agent_key_is_rejected(probe_client: AsyncClient) -> None:
    await register_tenant(probe_client, "acme")
    fabricated = generate_opaque_token(AGENT_KEY_PREFIX)

    response = await probe_client.get(PROBE_PATH, headers={"Authorization": f"Bearer {fabricated}"})

    assert response.status_code == 401


@pytest.mark.parametrize(
    "header",
    ["", "Bearer", "Basic abc123", "Bearer    ", "token abc"],
)
async def test_malformed_authorization_headers_are_rejected(
    client: AsyncClient, header: str
) -> None:
    headers = {"Authorization": header} if header else {}

    response = await client.get(f"{API}/auth/me", headers=headers)

    assert response.status_code == 401
