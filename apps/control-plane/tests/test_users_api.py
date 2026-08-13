"""``/users`` — the endpoints docs/API.md specified and the service never had.

Without them there was no way to deactivate a departing employee, change a
password, or recover a locked-out account: the org's user set was whatever
``/auth/register`` created, permanently. These tests cover the shape of the
endpoints and, more importantly, the four ways they could be turned against the
org that owns them — privilege escalation, last-owner removal, cross-tenant
reach, and a session that outlives the credential it was minted from.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.factories import API, DEFAULT_PASSWORD, Tenant, register_tenant, verify_email

COLLEAGUE_PASSWORD = "colleague-password-12345"


async def _add_user(
    client: AsyncClient,
    tenant: Tenant,
    *,
    email: str,
    role: str = "analyst",
    password: str = COLLEAGUE_PASSWORD,
    verified: bool = True,
) -> dict[str, Any]:
    """Invite a colleague and, by default, have them prove their address.

    An admin adding a user is an assertion, not proof, so the account arrives
    unverified exactly like a self-service sign-up. Most tests here are about
    what happens afterwards, so they complete the step the colleague would.
    """
    response = await client.post(
        f"{API}/users",
        json={"email": email, "password": password, "role": role, "full_name": "A Colleague"},
        headers=tenant.auth_header,
    )
    assert response.status_code == 201, response.text
    if verified:
        await verify_email(client, email)
    data: dict[str, Any] = response.json()["data"]
    return data


async def _login(client: AsyncClient, email: str, password: str) -> int:
    response = await client.post(f"{API}/auth/login", json={"email": email, "password": password})
    return response.status_code


async def _audit_actions(engine: AsyncEngine, org_id: UUID) -> list[str]:
    async with engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"), {"org": str(org_id)}
        )
        rows = (
            await connection.execute(
                text("SELECT action FROM audit_log WHERE org_id = :org"), {"org": str(org_id)}
            )
        ).all()
    return [row.action for row in rows]


# --- the directory -------------------------------------------------------


async def test_an_owner_can_add_and_list_users(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    await _add_user(client, tenant, email="analyst@acme.example")

    listing = await client.get(f"{API}/users", headers=tenant.auth_header)

    assert listing.status_code == 200
    emails = [entry["email"] for entry in listing.json()["data"]]
    assert emails == sorted([tenant.email, "analyst@acme.example"])
    assert listing.json()["meta"]["total"] == 2


async def test_the_listing_never_carries_a_password_hash(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")

    listing = await client.get(f"{API}/users", headers=tenant.auth_header)

    assert all("password" not in key for entry in listing.json()["data"] for key in entry)


async def test_a_new_user_can_actually_log_in(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    await _add_user(client, tenant, email="analyst@acme.example")

    assert await _login(client, "analyst@acme.example", COLLEAGUE_PASSWORD) == 200


async def test_users_are_admin_only(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    await _add_user(client, tenant, email="viewer@acme.example", role="viewer")
    viewer = await client.post(
        f"{API}/auth/login",
        json={"email": "viewer@acme.example", "password": COLLEAGUE_PASSWORD},
    )
    header = {"Authorization": f"Bearer {viewer.json()['data']['access_token']}"}

    assert (await client.get(f"{API}/users", headers=header)).status_code == 403


async def test_another_orgs_user_is_a_404_not_a_403(client: AsyncClient) -> None:
    """docs/API.md: cross-tenant reach is indistinguishable from not existing."""
    first = await register_tenant(client, "acme")
    second = await register_tenant(client, "beta")

    response = await client.patch(
        f"{API}/users/{second.user_id}",
        json={"role": "viewer"},
        headers=first.auth_header,
    )

    assert response.status_code == 404


# --- privilege boundaries -------------------------------------------------


async def test_an_admin_cannot_promote_themselves(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    admin = await _add_user(client, tenant, email="admin@acme.example", role="admin")
    session = await client.post(
        f"{API}/auth/login", json={"email": "admin@acme.example", "password": COLLEAGUE_PASSWORD}
    )
    header = {"Authorization": f"Bearer {session.json()['data']['access_token']}"}

    response = await client.patch(
        f"{API}/users/{admin['id']}", json={"role": "owner"}, headers=header
    )

    assert response.status_code == 403


async def test_an_admin_cannot_grant_a_role_above_their_own(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    await _add_user(client, tenant, email="admin@acme.example", role="admin")
    session = await client.post(
        f"{API}/auth/login", json={"email": "admin@acme.example", "password": COLLEAGUE_PASSWORD}
    )
    header = {"Authorization": f"Bearer {session.json()['data']['access_token']}"}

    response = await client.post(
        f"{API}/users",
        json={"email": "puppet@acme.example", "password": COLLEAGUE_PASSWORD, "role": "owner"},
        headers=header,
    )

    assert response.status_code == 403


async def test_an_admin_cannot_administer_the_owner(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    await _add_user(client, tenant, email="admin@acme.example", role="admin")
    session = await client.post(
        f"{API}/auth/login", json={"email": "admin@acme.example", "password": COLLEAGUE_PASSWORD}
    )
    header = {"Authorization": f"Bearer {session.json()['data']['access_token']}"}

    reset = await client.post(f"{API}/users/{tenant.user_id}/password-reset", headers=header)
    disable = await client.delete(f"{API}/users/{tenant.user_id}", headers=header)

    assert reset.status_code == 403
    assert disable.status_code == 403


async def test_an_unknown_role_is_rejected_at_the_boundary(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")

    response = await client.post(
        f"{API}/users",
        json={"email": "x@acme.example", "password": COLLEAGUE_PASSWORD, "role": "superuser"},
        headers=tenant.auth_header,
    )

    assert response.status_code == 400


# --- the last owner -------------------------------------------------------


async def test_nobody_can_demote_the_only_owner(client: AsyncClient) -> None:
    """Including the owner themselves — an org with no owner cannot be recovered."""
    tenant = await register_tenant(client, "acme")
    await _add_user(client, tenant, email="admin@acme.example", role="admin")

    self_demotion = await client.patch(
        f"{API}/users/{tenant.user_id}", json={"role": "admin"}, headers=tenant.auth_header
    )
    assert self_demotion.status_code == 403

    session = await client.post(
        f"{API}/auth/login", json={"email": "admin@acme.example", "password": COLLEAGUE_PASSWORD}
    )
    header = {"Authorization": f"Bearer {session.json()['data']['access_token']}"}
    by_an_admin = await client.patch(
        f"{API}/users/{tenant.user_id}", json={"role": "viewer"}, headers=header
    )
    assert by_an_admin.status_code == 403


async def test_an_owner_may_be_demoted_once_a_second_one_exists(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    second = await _add_user(client, tenant, email="second-owner@acme.example", role="owner")

    demotion = await client.patch(
        f"{API}/users/{second['id']}", json={"role": "admin"}, headers=tenant.auth_header
    )

    assert demotion.status_code == 200
    assert demotion.json()["data"]["role"] == "admin"


async def test_the_only_owner_cannot_disable_themselves(client: AsyncClient) -> None:
    """Both routes to it: the soft delete and the status field on PATCH."""
    tenant = await register_tenant(client, "acme")

    by_delete = await client.delete(f"{API}/users/{tenant.user_id}", headers=tenant.auth_header)
    by_patch = await client.patch(
        f"{API}/users/{tenant.user_id}", json={"status": "disabled"}, headers=tenant.auth_header
    )

    assert by_delete.status_code == 409
    assert by_patch.status_code == 409
    assert await _login(client, tenant.email, tenant.password) == 200


async def test_an_owner_may_be_deactivated_once_a_second_one_exists(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    second = await _add_user(client, tenant, email="second-owner@acme.example", role="owner")

    removal = await client.delete(f"{API}/users/{second['id']}", headers=tenant.auth_header)

    assert removal.status_code == 200
    assert removal.json()["data"]["status"] == "disabled"
    assert await _login(client, "second-owner@acme.example", COLLEAGUE_PASSWORD) == 401


async def test_deactivation_ends_the_users_sessions(client: AsyncClient) -> None:
    """A departing employee whose refresh token still rotates has not left."""
    tenant = await register_tenant(client, "acme")
    leaver = await _add_user(client, tenant, email="leaver@acme.example")

    session = await client.post(
        f"{API}/auth/login", json={"email": "leaver@acme.example", "password": COLLEAGUE_PASSWORD}
    )
    header = {"Authorization": f"Bearer {session.json()['data']['access_token']}"}
    assert (await client.get(f"{API}/auth/me", headers=header)).status_code == 200

    assert (
        await client.delete(f"{API}/users/{leaver['id']}", headers=tenant.auth_header)
    ).status_code == 200

    assert (await client.get(f"{API}/auth/me", headers=header)).status_code == 401
    assert await _login(client, "leaver@acme.example", COLLEAGUE_PASSWORD) == 401


# --- credentials ----------------------------------------------------------


async def test_a_user_can_change_their_own_password(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    replacement = "a-brand-new-password-99"

    response = await client.post(
        f"{API}/users/me/password",
        json={"current_password": tenant.password, "new_password": replacement},
        headers=tenant.auth_header,
    )

    assert response.status_code == 200
    assert await _login(client, tenant.email, replacement) == 200
    assert await _login(client, tenant.email, tenant.password) == 401


async def test_changing_a_password_requires_the_current_one(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")

    response = await client.post(
        f"{API}/users/me/password",
        json={"current_password": "not-the-current-one", "new_password": "another-password-99"},
        headers=tenant.auth_header,
    )

    assert response.status_code == 401
    assert await _login(client, tenant.email, DEFAULT_PASSWORD) == 200


async def test_changing_a_password_ends_the_old_sessions(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")

    response = await client.post(
        f"{API}/users/me/password",
        json={"current_password": tenant.password, "new_password": "a-brand-new-password-99"},
        headers=tenant.auth_header,
    )

    assert response.json()["data"] is not None
    assert (
        await client.post(f"{API}/auth/logout", headers={"Cookie": "ts_refresh=whatever"})
    ).status_code == 200


async def test_an_admin_reset_issues_a_working_temporary_password(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    colleague = await _add_user(client, tenant, email="colleague@acme.example")

    reset = await client.post(
        f"{API}/users/{colleague['id']}/password-reset", headers=tenant.auth_header
    )

    assert reset.status_code == 200
    temporary = reset.json()["data"]["temporary_password"]
    assert await _login(client, "colleague@acme.example", temporary) == 200
    assert await _login(client, "colleague@acme.example", COLLEAGUE_PASSWORD) == 401


async def test_an_admin_cannot_reset_their_own_password_without_the_current_one(
    client: AsyncClient,
) -> None:
    """Otherwise a stolen access token is a permanent account takeover."""
    tenant = await register_tenant(client, "acme")

    response = await client.post(
        f"{API}/users/{tenant.user_id}/password-reset", headers=tenant.auth_header
    )

    assert response.status_code == 409


# --- the lockout lever ----------------------------------------------------


async def test_an_admin_can_unlock_an_account_a_stranger_locked(client: AsyncClient) -> None:
    """The lever that was missing: lockout is triggerable by anyone who knows the
    address, so an operator has to be able to clear it without a password reset."""
    tenant = await register_tenant(client, "acme")
    colleague = await _add_user(client, tenant, email="colleague@acme.example")

    settings = client._transport.app.state.settings  # type: ignore[attr-defined]
    for index in range(settings.max_failed_logins):
        await client.post(
            f"{API}/auth/login",
            json={"email": "colleague@acme.example", "password": f"guess-{index}"},
        )
    assert await _login(client, "colleague@acme.example", COLLEAGUE_PASSWORD) == 401

    unlocked = await client.post(
        f"{API}/users/{colleague['id']}/unlock", headers=tenant.auth_header
    )

    assert unlocked.status_code == 200
    assert unlocked.json()["data"]["locked"] is False
    assert await _login(client, "colleague@acme.example", COLLEAGUE_PASSWORD) == 200


async def test_the_directory_shows_who_is_locked_out(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    await _add_user(client, tenant, email="colleague@acme.example")

    settings = client._transport.app.state.settings  # type: ignore[attr-defined]
    for index in range(settings.max_failed_logins):
        await client.post(
            f"{API}/auth/login",
            json={"email": "colleague@acme.example", "password": f"guess-{index}"},
        )

    listing = await client.get(f"{API}/users", headers=tenant.auth_header)
    locked = {entry["email"]: entry["locked"] for entry in listing.json()["data"]}

    assert locked["colleague@acme.example"] is True
    assert locked[tenant.email] is False


async def test_the_directory_shows_who_has_not_verified(client: AsyncClient) -> None:
    """An unverified colleague cannot log in; the admin has to be able to see why."""
    tenant = await register_tenant(client, "acme")
    await _add_user(client, tenant, email="pending@acme.example", verified=False)

    listing = await client.get(f"{API}/users", headers=tenant.auth_header)
    verified = {entry["email"]: entry["verified"] for entry in listing.json()["data"]}

    assert verified["pending@acme.example"] is False
    assert verified[tenant.email] is True


async def test_an_invited_user_cannot_log_in_until_they_verify(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    await _add_user(client, tenant, email="pending@acme.example", verified=False)

    assert await _login(client, "pending@acme.example", COLLEAGUE_PASSWORD) == 401

    await verify_email(client, "pending@acme.example")

    assert await _login(client, "pending@acme.example", COLLEAGUE_PASSWORD) == 200


# --- the record -----------------------------------------------------------


async def test_every_user_management_action_is_audited(
    client: AsyncClient, app_engine: AsyncEngine
) -> None:
    tenant = await register_tenant(client, "acme")
    colleague = await _add_user(client, tenant, email="colleague@acme.example")

    await client.patch(
        f"{API}/users/{colleague['id']}", json={"role": "admin"}, headers=tenant.auth_header
    )
    await client.post(f"{API}/users/{colleague['id']}/password-reset", headers=tenant.auth_header)
    await client.post(
        f"{API}/users/me/password",
        json={"current_password": tenant.password, "new_password": "a-brand-new-password-99"},
        headers=tenant.auth_header,
    )
    await client.delete(f"{API}/users/{colleague['id']}", headers=tenant.auth_header)

    actions = await _audit_actions(app_engine, tenant.org_id)
    assert {
        "user.created",
        "user.updated",
        "user.password_reset",
        "user.password_changed",
        "user.deactivated",
    } <= set(actions)


async def test_the_temporary_password_is_never_written_to_the_audit_log(
    client: AsyncClient, app_engine: AsyncEngine
) -> None:
    tenant = await register_tenant(client, "acme")
    colleague = await _add_user(client, tenant, email="colleague@acme.example")

    reset = await client.post(
        f"{API}/users/{colleague['id']}/password-reset", headers=tenant.auth_header
    )
    temporary = reset.json()["data"]["temporary_password"]

    async with app_engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"),
            {"org": str(tenant.org_id)},
        )
        rows = (
            await connection.execute(
                text("SELECT metadata::text FROM audit_log WHERE org_id = :org"),
                {"org": str(tenant.org_id)},
            )
        ).all()

    assert all(temporary not in row[0] for row in rows)
