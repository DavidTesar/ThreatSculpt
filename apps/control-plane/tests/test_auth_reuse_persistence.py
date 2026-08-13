"""Refresh-token reuse: the detection has to outlive the rejection.

``api.dependencies.get_session`` rolls the request transaction back on any
exception, so a security record written just before ``raise`` is discarded by the
same rejection it documents. That made family revocation a no-op precisely in the
case it exists for — a stolen token kept working, and the
``auth.refresh_reuse_detected`` row a SOC watches for was never written.

The route returns 401 either way, so only the *database* can tell the two apart.
"""

from __future__ import annotations

from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.factories import API, register_tenant

REFRESH_COOKIE = "ts_refresh"
COOKIE_PATH = "/api/v1/auth"
COOKIE_DOMAIN = "testserver.local"


def _present(client: AsyncClient, token: str) -> None:
    client.cookies.clear()
    client.cookies.set(REFRESH_COOKIE, token, domain=COOKIE_DOMAIN, path=COOKIE_PATH)


async def _audit_actions(engine: AsyncEngine, org_id: object) -> list[str]:
    async with engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"), {"org": str(org_id)}
        )
        rows = (
            await connection.execute(
                text("SELECT action FROM audit_log WHERE org_id = :org ORDER BY created_at"),
                {"org": str(org_id)},
            )
        ).all()
    return [row.action for row in rows]


async def _live_token_count(engine: AsyncEngine, org_id: object) -> int:
    async with engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"), {"org": str(org_id)}
        )
        return int(
            (
                await connection.execute(
                    text(
                        "SELECT count(*) FROM refresh_tokens "
                        "WHERE org_id = :org AND revoked_at IS NULL"
                    ),
                    {"org": str(org_id)},
                )
            ).scalar_one()
        )


async def test_the_stolen_session_dies_when_reuse_is_detected(
    client: AsyncClient, app_engine: AsyncEngine
) -> None:
    """The attacker rotates first; the victim's replay must kill what they hold."""
    tenant = await register_tenant(client, "acme")
    stolen = tenant.refresh_token

    _present(client, stolen)
    attacker = await client.post(f"{API}/auth/refresh")
    assert attacker.status_code == 200
    attacker_token = client.cookies.get(REFRESH_COOKIE)
    assert attacker_token is not None

    _present(client, stolen)
    replay = await client.post(f"{API}/auth/refresh")
    assert replay.status_code == 401

    _present(client, attacker_token)
    after = await client.post(f"{API}/auth/refresh")
    assert after.status_code == 401, "the attacker's live token survived the revocation"
    assert await _live_token_count(app_engine, tenant.org_id) == 0


async def test_the_detection_is_recorded_even_though_the_request_is_rejected(
    client: AsyncClient, app_engine: AsyncEngine
) -> None:
    tenant = await register_tenant(client, "acme")
    stolen = tenant.refresh_token

    _present(client, stolen)
    assert (await client.post(f"{API}/auth/refresh")).status_code == 200

    _present(client, stolen)
    assert (await client.post(f"{API}/auth/refresh")).status_code == 401

    assert "auth.refresh_reuse_detected" in await _audit_actions(app_engine, tenant.org_id)


async def test_the_audit_row_carries_how_many_tokens_it_killed(
    client: AsyncClient, app_engine: AsyncEngine
) -> None:
    """A count of zero would mean the revocation ran against nothing."""
    tenant = await register_tenant(client, "acme")

    _present(client, tenant.refresh_token)
    assert (await client.post(f"{API}/auth/refresh")).status_code == 200
    _present(client, tenant.refresh_token)
    assert (await client.post(f"{API}/auth/refresh")).status_code == 401

    async with app_engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"),
            {"org": str(tenant.org_id)},
        )
        revoked = (
            await connection.execute(
                text(
                    "SELECT (metadata->>'revoked_count')::int FROM audit_log "
                    "WHERE org_id = :org AND action = 'auth.refresh_reuse_detected'"
                ),
                {"org": str(tenant.org_id)},
            )
        ).scalar_one()

    assert revoked >= 1


async def test_a_token_that_was_never_issued_records_nothing(
    client: AsyncClient, app_engine: AsyncEngine
) -> None:
    """Only a real family gets revoked. A guessed value is just a 401."""
    tenant = await register_tenant(client, "acme")

    _present(client, "tsr_this-value-was-never-issued-by-anyone")
    assert (await client.post(f"{API}/auth/refresh")).status_code == 401

    assert "auth.refresh_reuse_detected" not in await _audit_actions(app_engine, tenant.org_id)
    assert await _live_token_count(app_engine, tenant.org_id) == 1
