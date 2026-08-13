"""One email address, several orgs — the state nothing else in the suite creates.

``users`` is unique on ``(org_id, email)``, so this is supported by design and
normal for the MSSP market. Login used to bind the request's tenant scope once
per candidate, which made the second candidate a ``TenancyViolationError``: a 500
on a correct password, an unauthenticated CRITICAL log, and a clean oracle for
"this address exists in more than one org". Every test here is a property that
broke as soon as a second candidate existed.
"""

from __future__ import annotations

import logging

import pytest
from httpx import AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from tests.factories import (
    API,
    DEFAULT_PASSWORD,
    memory_sender,
    register_tenant,
    register_tenants_sharing_email,
)
from threatsculpt.tenancy.credentials import MAX_LOGIN_CANDIDATES

SHARED = "consultant@bigcorp.example"


async def _failure_state(engine: AsyncEngine, org_id: object, user_id: object) -> tuple[int, bool]:
    async with engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('threatsculpt.org_id', :org, true)"), {"org": str(org_id)}
        )
        row = (
            await connection.execute(
                text(
                    "SELECT failed_login_count, locked_until IS NOT NULL AS locked "
                    "FROM users WHERE id = :uid"
                ),
                {"uid": user_id},
            )
        ).one()
    return int(row.failed_login_count), bool(row.locked)


async def test_every_org_owner_can_log_in_with_their_own_password(client: AsyncClient) -> None:
    first, second, third = await register_tenants_sharing_email(
        client, ["org-a", "org-b", "org-c"], email=SHARED
    )

    for tenant in (first, second, third):
        response = await client.post(
            f"{API}/auth/login", json={"email": SHARED, "password": tenant.password}
        )
        assert response.status_code == 200, response.text


async def test_the_token_issued_belongs_to_the_org_whose_password_was_used(
    client: AsyncClient,
) -> None:
    """Not just *a* session — the session for the account that owns that password."""
    first, second = await register_tenants_sharing_email(client, ["org-a", "org-b"], email=SHARED)

    response = await client.post(
        f"{API}/auth/login", json={"email": SHARED, "password": second.password}
    )
    assert response.status_code == 200
    me = await client.get(
        f"{API}/auth/me",
        headers={"Authorization": f"Bearer {response.json()['data']['access_token']}"},
    )

    assert me.json()["data"]["org"]["id"] == str(second.org_id)
    assert me.json()["data"]["org"]["id"] != str(first.org_id)


async def test_a_wrong_password_is_401_not_500(client: AsyncClient) -> None:
    await register_tenants_sharing_email(client, ["org-a", "org-b"], email=SHARED)

    response = await client.post(
        f"{API}/auth/login", json={"email": SHARED, "password": "not-either-of-them"}
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_credentials"


async def test_login_never_raises_a_tenancy_violation(
    client: AsyncClient, caplog: pytest.LogCaptureFixture
) -> None:
    """The CRITICAL channel is for a real isolation bug, not for ordinary traffic.

    An unauthenticated caller who can drive the top alert channel with a login
    form buries the one signal it exists to carry.
    """
    await register_tenants_sharing_email(client, ["org-a", "org-b"], email=SHARED)

    with caplog.at_level(logging.CRITICAL):
        for password in (DEFAULT_PASSWORD, "wrong-password-here", "another-wrong-one"):
            await client.post(f"{API}/auth/login", json={"email": SHARED, "password": password})

    assert [record.message for record in caplog.records if record.levelno >= logging.CRITICAL] == []


async def test_a_failed_attempt_is_charged_to_every_candidate_it_was_tried_against(
    client: AsyncClient, app_engine: AsyncEngine
) -> None:
    """Not to whichever row sorted first — that is somebody else's account."""
    first, second = await register_tenants_sharing_email(client, ["org-a", "org-b"], email=SHARED)

    await client.post(f"{API}/auth/login", json={"email": SHARED, "password": "wrong-for-both"})

    assert (await _failure_state(app_engine, first.org_id, first.user_id))[0] == 1
    assert (await _failure_state(app_engine, second.org_id, second.user_id))[0] == 1


async def test_one_orgs_successful_logins_do_not_lock_out_another(
    client: AsyncClient, app_engine: AsyncEngine
) -> None:
    """The second org's owner logging in is not evidence against the first org's.

    Counting it as a failure would mean any tenant sharing an address with
    another could lock that other tenant out simply by using the product.
    """
    victim, other = await register_tenants_sharing_email(client, ["victim", "other"], email=SHARED)

    for _ in range(12):
        response = await client.post(
            f"{API}/auth/login", json={"email": SHARED, "password": other.password}
        )
        assert response.status_code == 200

    attempts, locked = await _failure_state(app_engine, victim.org_id, victim.user_id)
    assert (attempts, locked) == (0, False)

    still_works = await client.post(
        f"{API}/auth/login", json={"email": SHARED, "password": victim.password}
    )
    assert still_works.status_code == 200


async def test_an_org_slug_still_narrows_to_one_candidate(client: AsyncClient) -> None:
    first, second = await register_tenants_sharing_email(client, ["org-a", "org-b"], email=SHARED)

    response = await client.post(
        f"{API}/auth/login",
        json={"email": SHARED, "password": second.password, "org_slug": second.org_slug},
    )
    assert response.status_code == 200

    mismatched = await client.post(
        f"{API}/auth/login",
        json={"email": SHARED, "password": second.password, "org_slug": first.org_slug},
    )
    assert mismatched.status_code == 401


async def test_the_candidate_window_cannot_be_filled_past_the_limit(client: AsyncClient) -> None:
    """The read limit never silently drops an account, because writes respect it.

    Otherwise anyone could pre-register a victim's work address in enough
    throwaway orgs to push the victim's own account outside the window that
    login searches, and the victim would simply never authenticate again.

    The limit binds at *verification*, which is the moment a slot is actually
    taken. Filling it therefore takes ``MAX_LOGIN_CANDIDATES`` proofs of control
    of the same mailbox, so the party who hits it owns the address — see
    ``test_unverified_claims_never_fill_the_window`` for the case that matters.
    """
    slugs = [f"tenant-{index}" for index in range(MAX_LOGIN_CANDIDATES)]
    await register_tenants_sharing_email(client, slugs, email=SHARED)

    registered = await client.post(
        f"{API}/auth/register",
        json={
            "org_name": "One More",
            "org_slug": "one-more",
            "email": SHARED,
            "password": DEFAULT_PASSWORD,
            "full_name": "Also Them",
        },
    )
    assert registered.status_code == 201, "registration itself is never refused"

    overflow = await client.post(
        f"{API}/auth/verify-email",
        json={"token": memory_sender(client).latest_token_for(SHARED)},
    )

    assert overflow.status_code == 409
    assert overflow.json()["error"]["field"] == "email"


async def test_every_account_inside_a_full_window_can_still_log_in(client: AsyncClient) -> None:
    """The point of the cap: every account that exists is reachable."""
    slugs = [f"tenant-{index}" for index in range(MAX_LOGIN_CANDIDATES)]
    tenants = await register_tenants_sharing_email(client, slugs, email=SHARED)

    last = tenants[-1]
    response = await client.post(
        f"{API}/auth/login", json={"email": SHARED, "password": last.password}
    )

    assert response.status_code == 200


async def test_a_distinct_address_is_unaffected_by_a_full_window(client: AsyncClient) -> None:
    slugs = [f"squat-{index}" for index in range(MAX_LOGIN_CANDIDATES)]
    await register_tenants_sharing_email(client, slugs, email=SHARED)

    tenant = await register_tenant(client, "unrelated", email="someone@else.example")

    response = await client.post(
        f"{API}/auth/login", json={"email": tenant.email, "password": tenant.password}
    )
    assert response.status_code == 200
