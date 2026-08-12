"""Per-account lockout and per-IP rate limiting on the auth endpoints."""

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.factories import API, register_tenant
from threatsculpt.app import create_app
from threatsculpt.config import Settings
from threatsculpt.db.engine import build_engine, build_session_factory

MAX_FAILURES = 3


@pytest.fixture
async def strict_app(settings: Settings) -> AsyncIterator[FastAPI]:
    """An app with production-shaped limits, so the thresholds are reachable."""
    tightened = settings.model_copy(
        update={
            "max_failed_logins": MAX_FAILURES,
            "login_lockout_minutes": 15,
            "auth_rate_limit_per_minute": 5,
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
async def strict_client(strict_app: FastAPI) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=strict_app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as http:
        yield http


async def test_failed_attempts_accumulate_on_the_account(
    strict_client: AsyncClient, strict_app: FastAPI
) -> None:
    tenant = await register_tenant(strict_client, "acme")

    for _ in range(2):
        await strict_client.post(
            f"{API}/auth/login", json={"email": tenant.email, "password": "wrong-password"}
        )

    engine: AsyncEngine = strict_app.state.engine
    async with engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"),
            {"org": str(tenant.org_id)},
        )
        count = (
            await connection.execute(
                text("SELECT failed_login_count FROM users WHERE id = :uid"),
                {"uid": tenant.user_id},
            )
        ).scalar_one()

    assert count == 2


async def test_account_locks_after_the_threshold(
    strict_client: AsyncClient, strict_app: FastAPI
) -> None:
    tenant = await register_tenant(strict_client, "acme")

    for _ in range(MAX_FAILURES):
        await strict_client.post(
            f"{API}/auth/login", json={"email": tenant.email, "password": "wrong-password"}
        )

    engine: AsyncEngine = strict_app.state.engine
    async with engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"),
            {"org": str(tenant.org_id)},
        )
        locked_until = (
            await connection.execute(
                text("SELECT locked_until FROM users WHERE id = :uid"), {"uid": tenant.user_id}
            )
        ).scalar_one()

    assert locked_until is not None


async def test_a_locked_account_rejects_even_the_correct_password(
    strict_client: AsyncClient,
) -> None:
    """And with the same generic error, so lockout state is not observable."""
    tenant = await register_tenant(strict_client, "acme")
    for _ in range(MAX_FAILURES):
        await strict_client.post(
            f"{API}/auth/login", json={"email": tenant.email, "password": "wrong-password"}
        )

    response = await strict_client.post(
        f"{API}/auth/login", json={"email": tenant.email, "password": tenant.password}
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_credentials"


async def test_a_successful_login_clears_the_failure_counter(
    strict_client: AsyncClient, strict_app: FastAPI
) -> None:
    tenant = await register_tenant(strict_client, "acme")
    await strict_client.post(
        f"{API}/auth/login", json={"email": tenant.email, "password": "wrong-password"}
    )

    ok_login = await strict_client.post(
        f"{API}/auth/login", json={"email": tenant.email, "password": tenant.password}
    )
    assert ok_login.status_code == 200

    engine: AsyncEngine = strict_app.state.engine
    async with engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"),
            {"org": str(tenant.org_id)},
        )
        count = (
            await connection.execute(
                text("SELECT failed_login_count FROM users WHERE id = :uid"),
                {"uid": tenant.user_id},
            )
        ).scalar_one()

    assert count == 0


async def test_auth_endpoints_are_rate_limited_per_ip(strict_client: AsyncClient) -> None:
    payload = {"email": "nobody@acme.example", "password": "whatever-goes-here"}

    statuses = [
        (await strict_client.post(f"{API}/auth/login", json=payload)).status_code for _ in range(7)
    ]

    assert statuses[:5] == [401] * 5
    assert statuses[5:] == [429, 429]


async def test_rate_limited_response_carries_retry_after(
    strict_client: AsyncClient,
) -> None:
    payload = {"email": "nobody@acme.example", "password": "whatever-goes-here"}
    for _ in range(5):
        await strict_client.post(f"{API}/auth/login", json=payload)

    limited = await strict_client.post(f"{API}/auth/login", json=payload)

    assert limited.status_code == 429
    assert int(limited.headers["Retry-After"]) > 0
    assert limited.json()["error"]["code"] == "rate_limited"
