"""``authorized`` has to be a record, not a boolean anybody can set.

docs/ARCHITECTURE.md promised that *public-internet ranges are rejected unless
the org has an uploaded authorization record*, and docs/SECURITY.md calls the
flag *the record that you asserted you had permission*. Neither was true:
``0.0.0.0/0`` could be registered as authorized and a scan of ``1.1.1.1`` queued
under it, both with 201.

The rule these describe, from ``scanning.authorization``: private ranges are
unchanged, public ranges need a written and attributed assertion, and a range
spanning both is refused outright.
"""

from __future__ import annotations

from httpx import AsyncClient, Response
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.factories import API, Tenant, register_tenant
from threatsculpt.db.session import scoped_session
from threatsculpt.models.audit import AuditLog
from threatsculpt.models.inventory import Network
from threatsculpt.scanning.authorization import (
    MIN_PUBLIC_PREFIX_LENGTH,
    NetworkClass,
    classify,
)
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope

NOTE = "Engagement letter TS-2026-014, signed by the customer's CISO on 2026-07-01."


async def _register(
    client: AsyncClient,
    tenant: Tenant,
    cidr: str,
    *,
    authorized: bool = True,
    note: str | None = None,
    name: str = "Range",
) -> Response:
    body: dict[str, object] = {"name": name, "cidr": cidr, "authorized": authorized}
    if note is not None:
        body["authorization_note"] = note
    return await client.post(f"{API}/networks", json=body, headers=tenant.auth_header)


def _error(response: Response) -> dict[str, str]:
    return response.json()["error"]


# --- classification ---------------------------------------------------------


def test_ranges_are_classified_by_what_they_cover() -> None:
    assert classify("10.0.0.0/8") is NetworkClass.PRIVATE
    assert classify("192.168.4.0/24") is NetworkClass.PRIVATE
    assert classify("172.16.0.0/12") is NetworkClass.PRIVATE
    assert classify("fd00::/8") is NetworkClass.PRIVATE

    assert classify("8.8.8.0/24") is NetworkClass.PUBLIC
    assert classify("2606:4700::/32") is NetworkClass.PUBLIC

    # Spanning both. 0.0.0.0/0 is the extreme case, but any block that swallows
    # a reserved range along with public space is the same mistake.
    assert classify("0.0.0.0/0") is NetworkClass.MIXED
    assert classify("::/0") is NetworkClass.MIXED
    # 192.168.0.0/15 covers 192.168.0.0-192.169.255.255: RFC1918 space plus public.
    assert classify("192.168.0.0/15") is NetworkClass.MIXED
    assert classify("not-a-cidr") is NetworkClass.MIXED


# --- private ranges are unchanged -------------------------------------------


async def test_a_private_range_needs_no_note(client: AsyncClient) -> None:
    """The ordinary case this product exists for. No new friction."""
    tenant = await register_tenant(client, "acme")
    response = await _register(client, tenant, "10.0.0.0/8")
    assert response.status_code == 201, response.text
    assert response.json()["data"]["authorized"] is True


# --- public ranges need a record --------------------------------------------


async def test_a_public_range_cannot_be_authorized_on_a_bare_boolean(
    client: AsyncClient,
) -> None:
    tenant = await register_tenant(client, "acme")
    response = await _register(client, tenant, "8.8.8.0/24")
    assert response.status_code == 422, response.text
    assert _error(response)["code"] == "authorization_record_required"
    assert _error(response)["field"] == "authorization_note"


async def test_a_blank_note_is_not_a_record(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    response = await _register(client, tenant, "8.8.8.0/24", note="   ")
    assert response.status_code == 422, response.text
    assert _error(response)["code"] == "authorization_record_required"


async def test_a_public_range_with_a_note_is_recorded_and_attributed(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    tenant = await register_tenant(client, "acme")
    response = await _register(client, tenant, "8.8.8.0/24", note=NOTE)
    assert response.status_code == 201, response.text

    body = response.json()["data"]
    assert body["authorization_note"] == NOTE
    assert body["authorized_by_user_id"] == str(tenant.user_id)
    assert body["authorized_at"] is not None

    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        audit = ScopedRepository(session, scope, AuditLog)
        row = await audit.find_one(AuditLog.action == "network.created")
        assert row is not None
        assert row.audit_metadata["network_class"] == "public"
        assert row.audit_metadata["written_assertion_required"] is True
        assert row.audit_metadata["assertion_note"] == NOTE


async def test_an_unauthorized_public_range_is_still_an_inventory_entry(
    client: AsyncClient,
) -> None:
    """Recording a range you do not yet have permission for is reasonable.

    The note is required to *assert* permission, not to write the range down.
    """
    tenant = await register_tenant(client, "acme")
    response = await _register(client, tenant, "8.8.8.0/24", authorized=False)
    assert response.status_code == 201, response.text
    assert response.json()["data"]["authorized_at"] is None


# --- absurd ranges are refused outright -------------------------------------


async def test_the_whole_internet_is_refused_with_or_without_a_note(
    client: AsyncClient,
) -> None:
    tenant = await register_tenant(client, "acme")
    for authorized, note in ((True, NOTE), (True, None), (False, None)):
        response = await _register(client, tenant, "0.0.0.0/0", authorized=authorized, note=note)
        assert response.status_code == 422, response.text
        assert _error(response)["code"] == "network_range_not_ownable"
        assert _error(response)["field"] == "cidr"


async def test_ipv6_default_route_is_refused(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    response = await _register(client, tenant, "::/0", note=NOTE)
    assert response.status_code == 422, response.text
    assert _error(response)["code"] == "network_range_not_ownable"


async def test_a_public_block_larger_than_one_record_may_claim_is_refused(
    client: AsyncClient,
) -> None:
    """A note does not buy an arbitrary slice of the internet."""
    tenant = await register_tenant(client, "acme")
    too_big = f"1.0.0.0/{MIN_PUBLIC_PREFIX_LENGTH[4] - 1}"
    response = await _register(client, tenant, too_big, note=NOTE)
    assert response.status_code == 422, response.text
    assert _error(response)["code"] == "public_range_too_large"

    at_the_limit = f"1.0.0.0/{MIN_PUBLIC_PREFIX_LENGTH[4]}"
    allowed = await _register(client, tenant, at_the_limit, note=NOTE, name="Ours")
    assert allowed.status_code == 201, allowed.text


# --- the flag cannot be flipped past the check ------------------------------


async def test_patch_cannot_authorize_a_public_range_without_a_note(
    client: AsyncClient,
) -> None:
    """The gap a create-time-only check would leave."""
    tenant = await register_tenant(client, "acme")
    created = await _register(client, tenant, "8.8.8.0/24", authorized=False)
    network_id = created.json()["data"]["id"]

    response = await client.patch(
        f"{API}/networks/{network_id}", json={"authorized": True}, headers=tenant.auth_header
    )
    assert response.status_code == 422, response.text
    assert _error(response)["code"] == "authorization_record_required"


async def test_patch_authorizes_a_public_range_when_the_note_arrives_with_it(
    client: AsyncClient,
) -> None:
    tenant = await register_tenant(client, "acme")
    created = await _register(client, tenant, "8.8.8.0/24", authorized=False)
    network_id = created.json()["data"]["id"]

    response = await client.patch(
        f"{API}/networks/{network_id}",
        json={"authorized": True, "authorization_note": NOTE},
        headers=tenant.auth_header,
    )
    assert response.status_code == 200, response.text
    assert response.json()["data"]["authorized_by_user_id"] == str(tenant.user_id)


async def test_withdrawing_authorisation_clears_the_attribution(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """A stale name and timestamp on a de-authorised network would read as live."""
    tenant = await register_tenant(client, "acme")
    created = await _register(client, tenant, "8.8.8.0/24", note=NOTE)
    network_id = created.json()["data"]["id"]

    response = await client.patch(
        f"{API}/networks/{network_id}", json={"authorized": False}, headers=tenant.auth_header
    )
    assert response.status_code == 200, response.text
    body = response.json()["data"]
    assert body["authorized"] is False
    assert body["authorized_by_user_id"] is None
    assert body["authorized_at"] is None

    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        networks = ScopedRepository(session, scope, Network)
        stored = await networks.find_one(Network.cidr == "8.8.8.0/24")
        assert stored is not None
        assert stored.authorized_at is None
        # The note survives: it is the record of what was asserted, and history
        # is not rewritten by withdrawing.
        assert stored.authorization_note == NOTE


# --- and the scan that motivated all of it ----------------------------------


async def test_a_scan_of_a_third_party_cannot_be_queued_under_a_self_granted_range(
    client: AsyncClient,
) -> None:
    """The end-to-end shape of the original finding."""
    tenant = await register_tenant(client, "acme")
    assert (await _register(client, tenant, "0.0.0.0/0")).status_code == 422

    scan = await client.post(
        f"{API}/scans",
        json={"target": "1.1.1.1/32", "profile": "vulnerability"},
        headers=tenant.auth_header,
    )
    assert scan.status_code == 422, scan.text
    assert _error(scan)["code"] == "network_not_authorized"
