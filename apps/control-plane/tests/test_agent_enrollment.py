"""Enrollment: one token, one agent, once.

The property under test is not "the endpoint works" but "the endpoint cannot be
made to work twice". docs/AGENT-PROTOCOL.md §1 requires a conditional UPDATE
precisely because a read-then-write would let one token enrol two agents, so the
concurrency test below is the one that would catch a regression to the naive
implementation — a sequential test would pass against either.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.agent_fixtures import enroll_agent, issue_enrollment_token
from tests.factories import API, register_tenant
from threatsculpt.db.session import scoped_session
from threatsculpt.models.agent import Agent
from threatsculpt.models.token import EnrollmentToken
from threatsculpt.security.tokens import ENROLLMENT_TOKEN_PREFIX, generate_opaque_token, hash_token
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope


async def test_enrollment_returns_a_key_and_the_orgs_allowlist(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    await client.post(
        f"{API}/networks",
        json={"name": "HQ", "cidr": "10.0.0.0/8", "authorized": True},
        headers=tenant.auth_header,
    )
    token = await issue_enrollment_token(client, tenant)

    response = await client.post(
        f"{API}/agent/enroll",
        json={
            "enrollment_token": token,
            "name": "hq-dc-scanner-01",
            "version": "2.0.0",
            "hostname": "scanner01.corp.local",
        },
    )

    assert response.status_code == 201, response.text
    body = response.json()["data"]
    assert body["api_key"].startswith("tsa_")
    assert body["org_id"] == str(tenant.org_id)
    assert body["allowlist"] == ["10.0.0.0/8"]
    assert body["poll_interval_seconds"] == 30


async def test_only_the_hash_of_the_key_is_stored(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    tenant = await register_tenant(client, "acme")
    agent = await enroll_agent(client, tenant)

    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        repository = ScopedRepository(session, scope, Agent)
        row = await repository.get_or_404(agent.agent_id)
        assert row.api_key_hash == hash_token(agent.api_key)
        assert agent.api_key not in row.api_key_hash
        assert row.key_prefix == agent.api_key[:8]


async def test_a_token_cannot_be_used_twice(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    token = await issue_enrollment_token(client, tenant)
    await enroll_agent(client, tenant, token=token)

    second = await client.post(
        f"{API}/agent/enroll",
        json={"enrollment_token": token, "name": "second-scanner"},
    )

    assert second.status_code == 401
    assert second.json()["error"]["code"] == "enrollment_token_invalid"


async def test_concurrent_enrollment_with_one_token_produces_one_agent(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """The race §1 exists to close.

    Both requests arrive with the same valid token. The conditional UPDATE
    serialises them on the row lock; the loser re-evaluates ``used_at IS NULL``
    against the committed row and matches nothing.
    """
    tenant = await register_tenant(client, "acme")
    token = await issue_enrollment_token(client, tenant)

    responses = await asyncio.gather(
        *(
            client.post(
                f"{API}/agent/enroll",
                json={"enrollment_token": token, "name": f"scanner-{index}"},
            )
            for index in range(2)
        )
    )

    statuses = sorted(response.status_code for response in responses)
    assert statuses == [201, 401], [response.text for response in responses]

    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        repository = ScopedRepository(session, scope, Agent)
        assert await repository.count() == 1


async def test_an_expired_token_is_refused(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    tenant = await register_tenant(client, "acme")
    token = await issue_enrollment_token(client, tenant)

    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        repository = ScopedRepository(session, scope, EnrollmentToken)
        row = await repository.find_one(EnrollmentToken.token_hash == hash_token(token))
        assert row is not None
        await repository.update(row, {"expires_at": datetime.now(tz=UTC) - timedelta(minutes=1)})

    response = await client.post(
        f"{API}/agent/enroll", json={"enrollment_token": token, "name": "late-scanner"}
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "enrollment_token_invalid"


async def test_an_unknown_token_is_refused(client: AsyncClient) -> None:
    await register_tenant(client, "acme")
    fabricated = generate_opaque_token(ENROLLMENT_TOKEN_PREFIX)

    response = await client.post(
        f"{API}/agent/enroll", json={"enrollment_token": fabricated, "name": "impostor"}
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "enrollment_token_invalid"


async def test_one_orgs_token_enrols_into_that_org_only(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """The org comes from the consumed row, so there is nothing to point elsewhere."""
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    token = await issue_enrollment_token(client, alpha)

    response = await client.post(
        f"{API}/agent/enroll", json={"enrollment_token": token, "name": "alpha-scanner"}
    )

    assert response.json()["data"]["org_id"] == str(alpha.org_id)

    beta_scope = OrgScope.for_system(beta.org_id)
    async with scoped_session(session_factory, beta_scope) as session:
        assert await ScopedRepository(session, beta_scope, Agent).count() == 0


async def test_issuing_a_token_requires_admin(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    invite = await client.post(f"{API}/agents", json={}, headers=tenant.auth_header)
    assert invite.status_code == 201  # the registering user is an owner

    anonymous = await client.post(f"{API}/agents", json={})
    assert anonymous.status_code == 401


async def test_the_enrollment_token_is_never_returned_again(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    agent = await enroll_agent(client, tenant)

    listing = await client.get(f"{API}/agents", headers=tenant.auth_header)

    assert listing.status_code == 200
    payload = listing.text
    assert agent.api_key not in payload
    assert "enrollment_token" not in payload
    assert listing.json()["data"][0]["key_prefix"] == agent.api_key[:8]


async def test_revoking_an_agent_stops_its_key_immediately(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    agent = await enroll_agent(client, tenant)
    assert (
        await client.post(
            f"{API}/agent/heartbeat", json={"healthy": True}, headers=agent.auth_header
        )
    ).status_code == 200

    revoke = await client.delete(f"{API}/agents/{agent.agent_id}", headers=tenant.auth_header)
    assert revoke.status_code == 200
    assert revoke.json()["data"]["status"] == "revoked"

    after = await client.post(
        f"{API}/agent/heartbeat", json={"healthy": True}, headers=agent.auth_header
    )
    assert after.status_code == 401
