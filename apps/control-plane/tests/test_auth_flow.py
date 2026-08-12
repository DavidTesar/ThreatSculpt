"""Registration, login, refresh rotation, family revocation, and logout."""

from __future__ import annotations

from httpx import AsyncClient

from tests.factories import API, DEFAULT_PASSWORD, register_tenant

REFRESH_COOKIE = "ts_refresh"
COOKIE_PATH = "/api/v1/auth"


def _current_refresh_cookie(client: AsyncClient) -> str:
    """The refresh cookie currently in the jar.

    Asserts rather than returning ``None``: a missing cookie would otherwise be
    compared against another missing cookie and the rotation assertions would
    pass without a token ever existing.
    """
    token = client.cookies.get(REFRESH_COOKIE)
    assert token is not None, "expected a refresh cookie in the jar"
    return token


def _replace_refresh_cookie(client: AsyncClient, token: str) -> None:
    """Put exactly one refresh cookie in the jar.

    ``cookies.set`` alone would leave the rotated cookie in place alongside the
    replayed one, and the test would silently assert on the wrong credential.
    """
    client.cookies.clear()
    client.cookies.set(REFRESH_COOKIE, token, domain="testserver", path=COOKIE_PATH)


async def test_register_creates_org_and_owner(client: AsyncClient) -> None:
    response = await client.post(
        f"{API}/auth/register",
        json={
            "org_name": "Acme Corp",
            "org_slug": "acme",
            "email": "owner@acme.example",
            "password": DEFAULT_PASSWORD,
        },
    )

    assert response.status_code == 201
    body = response.json()
    assert body["error"] is None
    assert body["data"]["org"]["slug"] == "acme"
    assert body["data"]["org"]["plan"] == "trial"
    assert body["data"]["user"]["role"] == "owner"
    assert body["data"]["access_token"]


async def test_register_sets_httponly_refresh_cookie(client: AsyncClient) -> None:
    response = await client.post(
        f"{API}/auth/register",
        json={
            "org_name": "Acme Corp",
            "org_slug": "acme",
            "email": "owner@acme.example",
            "password": DEFAULT_PASSWORD,
        },
    )

    cookie_header = response.headers["set-cookie"]
    assert "HttpOnly" in cookie_header
    assert "SameSite=lax" in cookie_header.lower().replace("samesite=lax", "SameSite=lax")
    assert "ts_refresh=" in cookie_header


async def test_register_never_returns_the_refresh_token_in_the_body(
    client: AsyncClient,
) -> None:
    response = await client.post(
        f"{API}/auth/register",
        json={
            "org_name": "Acme Corp",
            "org_slug": "acme",
            "email": "owner@acme.example",
            "password": DEFAULT_PASSWORD,
        },
    )

    assert "refresh_token" not in response.text


async def test_register_rejects_duplicate_slug(client: AsyncClient) -> None:
    await register_tenant(client, "acme")

    response = await client.post(
        f"{API}/auth/register",
        json={
            "org_name": "Acme Two",
            "org_slug": "acme",
            "email": "second@acme.example",
            "password": DEFAULT_PASSWORD,
        },
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "conflict"
    assert response.json()["error"]["field"] == "org_slug"


async def test_register_rejects_short_password(client: AsyncClient) -> None:
    response = await client.post(
        f"{API}/auth/register",
        json={
            "org_name": "Acme",
            "org_slug": "acme",
            "email": "owner@acme.example",
            "password": "short",
        },
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "validation_error"
    assert response.json()["error"]["field"] == "password"


async def test_register_rejects_an_org_id_in_the_body(client: AsyncClient) -> None:
    """No endpoint accepts a tenant identifier; sending one is a 400, not a no-op."""
    response = await client.post(
        f"{API}/auth/register",
        json={
            "org_name": "Acme",
            "org_slug": "acme",
            "email": "owner@acme.example",
            "password": DEFAULT_PASSWORD,
            "org_id": "00000000-0000-0000-0000-000000000000",
        },
    )

    assert response.status_code == 400


async def test_login_succeeds_and_returns_access_token(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")

    response = await client.post(
        f"{API}/auth/login", json={"email": tenant.email, "password": tenant.password}
    )

    assert response.status_code == 200
    assert response.json()["data"]["access_token"]
    assert response.json()["data"]["token_type"] == "bearer"


async def test_unknown_email_and_wrong_password_are_indistinguishable(
    client: AsyncClient,
) -> None:
    """docs/API.md: identical response for 'no such user' and 'wrong password'."""
    tenant = await register_tenant(client, "acme")

    wrong_password = await client.post(
        f"{API}/auth/login", json={"email": tenant.email, "password": "definitely-not-it"}
    )
    unknown_email = await client.post(
        f"{API}/auth/login", json={"email": "nobody@acme.example", "password": tenant.password}
    )

    assert wrong_password.status_code == unknown_email.status_code == 401
    assert wrong_password.json() == unknown_email.json()


async def test_me_returns_user_org_and_role(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")

    response = await client.get(f"{API}/auth/me", headers=tenant.auth_header)

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["user"]["email"] == tenant.email
    assert data["user"]["role"] == "owner"
    assert data["org"]["id"] == str(tenant.org_id)


async def test_me_requires_authentication(client: AsyncClient) -> None:
    response = await client.get(f"{API}/auth/me")

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthenticated"


async def test_me_rejects_a_tampered_token(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    forged = tenant.access_token[:-4] + "AAAA"

    response = await client.get(f"{API}/auth/me", headers={"Authorization": f"Bearer {forged}"})

    assert response.status_code == 401


async def test_refresh_rotates_the_token(client: AsyncClient) -> None:
    await register_tenant(client, "acme")
    original = client.cookies.get("ts_refresh")

    response = await client.post(f"{API}/auth/refresh")

    assert response.status_code == 200
    assert response.json()["data"]["access_token"]
    assert client.cookies.get("ts_refresh") != original


async def test_refresh_without_a_cookie_is_unauthenticated(client: AsyncClient) -> None:
    response = await client.post(f"{API}/auth/refresh")

    assert response.status_code == 401


async def test_reusing_a_rotated_token_revokes_the_whole_family(
    client: AsyncClient,
) -> None:
    """The theft-detection signal: a spent token invalidates every sibling."""
    await register_tenant(client, "acme")
    stolen = _current_refresh_cookie(client)

    first = await client.post(f"{API}/auth/refresh")
    assert first.status_code == 200
    current = _current_refresh_cookie(client)
    assert current != stolen

    _replace_refresh_cookie(client, stolen)
    replay = await client.post(f"{API}/auth/refresh")
    assert replay.status_code == 401

    # The token the legitimate user held is now dead too.
    _replace_refresh_cookie(client, current)
    after_revocation = await client.post(f"{API}/auth/refresh")
    assert after_revocation.status_code == 401


async def test_logout_revokes_the_refresh_family(client: AsyncClient) -> None:
    await register_tenant(client, "acme")
    token = _current_refresh_cookie(client)

    logout = await client.post(f"{API}/auth/logout")
    assert logout.status_code == 200
    assert logout.json()["data"]["revoked"] is True

    _replace_refresh_cookie(client, token)
    assert (await client.post(f"{API}/auth/refresh")).status_code == 401


async def test_logout_without_a_cookie_still_succeeds(client: AsyncClient) -> None:
    response = await client.post(f"{API}/auth/logout")

    assert response.status_code == 200
    assert response.json()["data"]["revoked"] is False


async def test_password_hash_is_argon2id(client: AsyncClient, app_engine: object) -> None:
    from sqlalchemy import text

    tenant = await register_tenant(client, "acme")

    async with app_engine.begin() as connection:  # type: ignore[attr-defined]
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"),
            {"org": str(tenant.org_id)},
        )
        stored = (
            await connection.execute(
                text("SELECT password_hash FROM users WHERE id = :uid"), {"uid": tenant.user_id}
            )
        ).scalar_one()

    assert stored.startswith("$argon2id$")
    assert DEFAULT_PASSWORD not in stored
