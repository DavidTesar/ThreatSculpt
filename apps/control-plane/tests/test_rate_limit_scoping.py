"""The general limit is per *user*, as docs/API.md says — not per source IP.

It was per IP: the limiter was a router-level dependency, and FastAPI resolves
those before ``current_user``, so ``request.state.actor_id`` was never set and
the key fell back to the client address. Every colleague behind one office NAT or
VPN egress shared one bucket, and an unauthenticated flood from that address
spent the allowance of every real user behind it — while a dashboard page fires
several queries in parallel.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from tests.factories import API, register_tenant
from threatsculpt.app import create_app
from threatsculpt.config import Settings
from threatsculpt.db.engine import build_engine, build_session_factory

USER_LIMIT = 5
ANONYMOUS_LIMIT = 4
PROTECTED = f"{API}/networks"


@pytest.fixture
async def limited_app(settings: Settings) -> AsyncIterator[FastAPI]:
    """Limits low enough to reach, and deliberately different from each other."""
    tightened = settings.model_copy(
        update={
            "general_rate_limit_per_minute": USER_LIMIT,
            "anonymous_rate_limit_per_minute": ANONYMOUS_LIMIT,
        }
    )
    application = create_app(tightened)
    engine = build_engine(tightened)
    application.state.engine = engine
    application.state.session_factory = build_session_factory(engine)
    try:
        yield application
    finally:
        await engine.dispose()


@pytest.fixture
async def limited_client(limited_app: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=limited_app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


async def _statuses(client: AsyncClient, headers: dict[str, str], count: int) -> list[int]:
    return [(await client.get(PROTECTED, headers=headers)).status_code for _ in range(count)]


async def test_two_users_from_one_address_do_not_share_a_bucket(
    limited_client: AsyncClient,
) -> None:
    """The office-NAT case. Same client, same IP, two principals."""
    first = await register_tenant(limited_client, "acme")
    second = await register_tenant(limited_client, "beta")

    assert await _statuses(limited_client, first.auth_header, USER_LIMIT) == [200] * USER_LIMIT
    assert (await limited_client.get(PROTECTED, headers=first.auth_header)).status_code == 429

    # The second user's allowance is untouched by the first exhausting theirs.
    assert await _statuses(limited_client, second.auth_header, USER_LIMIT) == [200] * USER_LIMIT


async def test_an_unauthenticated_flood_does_not_spend_a_users_allowance(
    limited_client: AsyncClient,
) -> None:
    """1000 anonymous 401s used to leave every authenticated user at 429."""
    tenant = await register_tenant(limited_client, "acme")

    exhausted = [
        (await limited_client.get(PROTECTED)).status_code for _ in range(ANONYMOUS_LIMIT + 3)
    ]
    assert exhausted[:ANONYMOUS_LIMIT] == [401] * ANONYMOUS_LIMIT
    assert exhausted[ANONYMOUS_LIMIT:] == [429, 429, 429]

    assert await _statuses(limited_client, tenant.auth_header, USER_LIMIT) == [200] * USER_LIMIT


async def test_a_worthless_credential_is_charged_to_the_anonymous_bucket(
    limited_client: AsyncClient,
) -> None:
    """Otherwise a garbage ``Authorization`` header buys an unmetered flood."""
    tenant = await register_tenant(limited_client, "acme")
    junk = {"Authorization": "Bearer not-a-real-token-at-all"}

    statuses = await _statuses(limited_client, junk, ANONYMOUS_LIMIT + 2)
    assert statuses[:ANONYMOUS_LIMIT] == [401] * ANONYMOUS_LIMIT
    assert statuses[ANONYMOUS_LIMIT:] == [429, 429]

    assert (await limited_client.get(PROTECTED, headers=tenant.auth_header)).status_code == 200


async def test_the_limit_follows_the_user_across_endpoints(limited_client: AsyncClient) -> None:
    """One allowance per user, not one per router."""
    tenant = await register_tenant(limited_client, "acme")

    paths = [f"{API}/networks", f"{API}/business-services", f"{API}/assets", f"{API}/findings"]
    statuses = [
        (await limited_client.get(path, headers=tenant.auth_header)).status_code
        for path in [paths[index % len(paths)] for index in range(USER_LIMIT)]
    ]
    assert statuses == [200] * USER_LIMIT

    assert (
        await limited_client.get(f"{API}/assets", headers=tenant.auth_header)
    ).status_code == 429


async def test_authenticated_requests_do_not_consume_the_anonymous_bucket(
    limited_client: AsyncClient,
) -> None:
    tenant = await register_tenant(limited_client, "acme")

    assert await _statuses(limited_client, tenant.auth_header, USER_LIMIT) == [200] * USER_LIMIT

    anonymous = [(await limited_client.get(PROTECTED)).status_code for _ in range(ANONYMOUS_LIMIT)]
    assert anonymous == [401] * ANONYMOUS_LIMIT
