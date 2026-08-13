"""An unproved claim on an address must buy the claimant nothing.

Registration is open — anyone can submit any address — and it has to stay open,
because refusing a registration is itself how one party denies another a sign-up.
Two findings came out of treating an open claim as if it meant something:

* a stranger's claim on a victim's address joined the victim in the login
  candidate set, where failed guesses reached lockout on an account in an org the
  victim had never heard of;
* capping how many accounts one address may hold, and counting claims towards
  that cap, let ten unauthenticated POSTs stop an address's real owner from ever
  signing up.

Both die if a claim counts for nothing until control is proved. These tests are
that property from every direction an attacker would come at it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.factories import (
    API,
    DEFAULT_PASSWORD,
    memory_sender,
    register_tenant,
    verify_email,
)
from threatsculpt.tenancy.credentials import MAX_LOGIN_CANDIDATES

VICTIM = "ciso@bigcorp.example"


async def _register(client: AsyncClient, slug: str, email: str, password: str) -> int:
    response = await client.post(
        f"{API}/auth/register",
        json={
            "org_name": slug.replace("-", " ").title(),
            "org_slug": slug,
            "email": email,
            "password": password,
            "full_name": "Somebody",
        },
    )
    return response.status_code


async def _login(client: AsyncClient, email: str, password: str) -> int:
    response = await client.post(f"{API}/auth/login", json={"email": email, "password": password})
    return response.status_code


async def _expire_token(engine: AsyncEngine, org_id: object) -> None:
    """Age the outstanding claim past its window without waiting for it."""
    async with engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"), {"org": str(org_id)}
        )
        await connection.execute(
            text("UPDATE users SET verification_expires_at = :past WHERE org_id = :org"),
            {"past": datetime.now(tz=UTC) - timedelta(minutes=1), "org": str(org_id)},
        )


# --- the squatting case ---------------------------------------------------


async def test_squatting_an_address_does_not_stop_its_owner_registering(
    client: AsyncClient,
) -> None:
    """The finding that a capacity check on unverified claims created.

    An attacker who has never controlled the address fills every slot with
    claims; the owner then meets a 409 they did not cause and cannot clear.
    """
    for index in range(MAX_LOGIN_CANDIDATES):
        assert await _register(client, f"squat-{index}", VICTIM, "attacker-password-1") == 201

    assert await _register(client, "bigcorp", VICTIM, DEFAULT_PASSWORD) == 201


async def test_the_owner_can_verify_and_log_in_after_being_squatted(
    client: AsyncClient,
) -> None:
    """Registering is not enough on its own; the owner must end up with an account."""
    for index in range(MAX_LOGIN_CANDIDATES):
        assert await _register(client, f"squat-{index}", VICTIM, "attacker-password-1") == 201

    assert await _register(client, "bigcorp", VICTIM, DEFAULT_PASSWORD) == 201
    await verify_email(client, VICTIM)

    assert await _login(client, VICTIM, DEFAULT_PASSWORD) == 200


async def test_a_squatter_cannot_log_in_to_the_address_they_claimed(
    client: AsyncClient,
) -> None:
    await _register(client, "squat-0", VICTIM, "attacker-password-1")

    assert await _login(client, VICTIM, "attacker-password-1") == 401


async def test_unverified_claims_never_fill_the_window(client: AsyncClient) -> None:
    """Twice the cap in claims, and the cap is still entirely free."""
    for index in range(MAX_LOGIN_CANDIDATES * 2):
        assert await _register(client, f"squat-{index}", VICTIM, "attacker-password-1") == 201

    for index in range(MAX_LOGIN_CANDIDATES):
        assert await _register(client, f"real-{index}", VICTIM, f"real-password-{index}") == 201
        await verify_email(client, VICTIM)
        assert await _login(client, VICTIM, f"real-password-{index}") == 200


async def test_an_unverified_claim_cannot_absorb_another_orgs_failed_attempts(
    client: AsyncClient, app_engine: AsyncEngine
) -> None:
    """The original cross-tenant lockout, at its root rather than its symptom."""
    victim = await register_tenant(client, "bigcorp", email=VICTIM)
    assert await _register(client, "squat-0", VICTIM, "attacker-password-1") == 201

    settings = client._transport.app.state.settings  # type: ignore[attr-defined]
    for index in range(settings.max_failed_logins + 2):
        await client.post(f"{API}/auth/login", json={"email": VICTIM, "password": f"g-{index}"})

    async with app_engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"),
            {"org": str(victim.org_id)},
        )
        rows = (
            await connection.execute(
                text("SELECT locked_until IS NOT NULL AS locked FROM users WHERE org_id = :org"),
                {"org": str(victim.org_id)},
            )
        ).all()

    # The victim's own account is locked — that is the documented policy for
    # failures against a real account. What matters is that the squat never
    # entered the candidate set at all, so it neither absorbed an attempt nor
    # was charged one on somebody else's behalf.
    assert [row.locked for row in rows] == [True]


# --- the state machine ----------------------------------------------------


async def test_registration_returns_a_working_session_before_verification(
    client: AsyncClient,
) -> None:
    """The registrant is holding the browser; they keep the session they got.

    What they do not get until the address is proved is a password login, which
    is the thing that would make a claim on somebody else's address matter.
    """
    tenant = await register_tenant(client, "acme", verified=False)

    assert (await client.get(f"{API}/auth/me", headers=tenant.auth_header)).status_code == 200
    assert await _login(client, tenant.email, tenant.password) == 401


async def test_verifying_is_what_turns_a_claim_into_an_account(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme", verified=False)

    assert await _login(client, tenant.email, tenant.password) == 401
    await verify_email(client, tenant.email)
    assert await _login(client, tenant.email, tenant.password) == 200


async def test_a_spent_token_cannot_be_used_again(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme", verified=False)
    token = memory_sender(client).latest_token_for(tenant.email)
    assert token is not None

    assert (await client.post(f"{API}/auth/verify-email", json={"token": token})).status_code == 200
    replay = await client.post(f"{API}/auth/verify-email", json={"token": token})

    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "verification_token_invalid"


async def test_an_unknown_token_is_refused(client: AsyncClient) -> None:
    response = await client.post(
        f"{API}/auth/verify-email", json={"token": "tsv_nobody-ever-issued-this-value"}
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "verification_token_invalid"


async def test_an_expired_claim_can_no_longer_be_verified(
    client: AsyncClient, app_engine: AsyncEngine
) -> None:
    """ "Expires after a short window" has to mean the claim actually dies."""
    tenant = await register_tenant(client, "acme", verified=False)
    token = memory_sender(client).latest_token_for(tenant.email)
    assert token is not None
    await _expire_token(app_engine, tenant.org_id)

    response = await client.post(f"{API}/auth/verify-email", json={"token": token})

    assert response.status_code == 401
    assert await _login(client, tenant.email, tenant.password) == 401


async def test_an_expired_claim_can_be_replaced_by_its_owner(client: AsyncClient) -> None:
    """The registrant still holds a session, so they can ask for another token."""
    tenant = await register_tenant(client, "acme", verified=False)
    first = memory_sender(client).latest_token_for(tenant.email)

    resent = await client.post(f"{API}/auth/verify-email/resend", headers=tenant.auth_header)
    assert resent.status_code == 200
    assert resent.json()["data"]["verified"] is False

    second = memory_sender(client).latest_token_for(tenant.email)
    assert second != first

    stale = await client.post(f"{API}/auth/verify-email", json={"token": first})
    assert stale.status_code == 401, "re-issuing must invalidate the previous token"

    fresh = await client.post(f"{API}/auth/verify-email", json={"token": second})
    assert fresh.status_code == 200


async def test_resending_requires_authentication(client: AsyncClient) -> None:
    """An unauthenticated resend would aim this service's mail wherever asked."""
    await register_tenant(client, "acme", verified=False)

    assert (await client.post(f"{API}/auth/verify-email/resend")).status_code == 401


async def test_resending_for_an_already_verified_account_is_a_conflict(
    client: AsyncClient,
) -> None:
    tenant = await register_tenant(client, "acme")

    response = await client.post(f"{API}/auth/verify-email/resend", headers=tenant.auth_header)

    assert response.status_code == 409


# --- what an unverified session may actually do ---------------------------


async def test_an_unverified_session_can_reach_only_the_way_out_of_being_unverified(
    client: AsyncClient,
) -> None:
    """The whole permitted surface, asserted as a set rather than case by case."""
    tenant = await register_tenant(client, "acme", verified=False)

    assert (await client.get(f"{API}/auth/me", headers=tenant.auth_header)).status_code == 200
    assert (
        await client.post(f"{API}/auth/verify-email/resend", headers=tenant.auth_header)
    ).status_code == 200
    assert (await client.post(f"{API}/auth/logout")).status_code == 200


@pytest.mark.parametrize(
    ("method", "path", "body"),
    [
        ("GET", "/networks", None),
        ("POST", "/networks", {"name": "lan", "cidr": "10.0.0.0/8", "authorized": True}),
        ("GET", "/assets", None),
        ("GET", "/findings", None),
        ("GET", "/dashboard/executive", None),
        ("POST", "/scans", {"target": "10.0.0.0/24", "profile": "vulnerability"}),
        ("POST", "/agents", {"note": "x"}),
        ("GET", "/users", None),
        ("POST", "/users", {"email": "x@acme.example", "password": DEFAULT_PASSWORD}),
        ("POST", "/reports", {"type": "executive_summary", "format": "pdf"}),
    ],
)
async def test_an_unverified_session_reaches_nothing_else(
    client: AsyncClient, method: str, path: str, body: dict[str, object] | None
) -> None:
    """Registering an address you do not control must buy no reach into the product.

    Scan targets and agent enrollment tokens especially: this service sends
    unsolicited packets at what it is pointed at, and every one of these actions
    would land in the audit log attributed to the address that was claimed.
    """
    tenant = await register_tenant(client, "acme", verified=False)

    response = await client.request(method, f"{API}{path}", json=body, headers=tenant.auth_header)

    assert response.status_code == 403, f"{method} {path} was reachable unverified"
    assert response.json()["error"]["code"] == "email_not_verified"


async def test_an_unverified_session_cannot_renew_itself(client: AsyncClient) -> None:
    """The durable half: a 30-day session that rotates forever without proof."""
    tenant = await register_tenant(client, "acme", verified=False)

    rotated = await client.post(
        f"{API}/auth/refresh", headers={"Cookie": f"ts_refresh={tenant.refresh_token}"}
    )

    assert rotated.status_code == 403
    assert rotated.json()["error"]["code"] == "email_not_verified"


async def test_verifying_restores_the_full_surface(client: AsyncClient) -> None:
    """The gate is the verification state, not something the session lost."""
    tenant = await register_tenant(client, "acme", verified=False)
    assert (await client.get(f"{API}/networks", headers=tenant.auth_header)).status_code == 403

    await verify_email(client, tenant.email)

    assert (await client.get(f"{API}/networks", headers=tenant.auth_header)).status_code == 200
    assert (
        await client.post(
            f"{API}/auth/refresh", headers={"Cookie": f"ts_refresh={tenant.refresh_token}"}
        )
    ).status_code == 200


async def test_an_unverified_admin_cannot_invite_anyone(client: AsyncClient) -> None:
    """Otherwise the claim propagates: one unproved address mints more accounts."""
    tenant = await register_tenant(client, "acme", verified=False)

    response = await client.post(
        f"{API}/users",
        json={"email": "cfo@bigcorp.example", "password": DEFAULT_PASSWORD, "role": "admin"},
        headers=tenant.auth_header,
    )

    assert response.status_code == 403


# --- the record -----------------------------------------------------------


async def test_verification_is_audited(client: AsyncClient, app_engine: AsyncEngine) -> None:
    tenant = await register_tenant(client, "acme")

    async with app_engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"),
            {"org": str(tenant.org_id)},
        )
        actions = [
            row.action
            for row in (
                await connection.execute(
                    text("SELECT action FROM audit_log WHERE org_id = :org"),
                    {"org": str(tenant.org_id)},
                )
            ).all()
        ]

    assert "auth.email_verified" in actions


async def test_the_token_is_never_stored_in_plaintext(
    client: AsyncClient, app_engine: AsyncEngine
) -> None:
    tenant = await register_tenant(client, "acme", verified=False)
    token = memory_sender(client).latest_token_for(tenant.email)
    assert token is not None

    async with app_engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"),
            {"org": str(tenant.org_id)},
        )
        stored = (
            await connection.execute(
                text("SELECT verification_token_hash FROM users WHERE org_id = :org"),
                {"org": str(tenant.org_id)},
            )
        ).scalar_one()

    assert stored is not None
    assert token not in stored
    assert len(stored) == 64
