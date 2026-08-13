"""``/assets``: filters, the business-service mapping, re-scoring, tenancy."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.factories import API, Tenant, create_network, register_tenant
from tests.scoring_factories import (
    add_user_and_login,
    run_enrichment,
    seed_asset_with_port,
    seed_business_service,
    seed_vulnerability,
)

Factory = async_sessionmaker[AsyncSession]


@pytest.fixture
async def tenant(client: AsyncClient, session_factory: Factory) -> Tenant:
    org = await register_tenant(client, "assets-org")
    await seed_vulnerability(session_factory, org.org_id)
    await seed_asset_with_port(session_factory, org.org_id, ip="10.0.4.12", hostname="app-01")
    await run_enrichment(session_factory, org.org_id)
    return org


async def _first_asset(client: AsyncClient, tenant: Tenant) -> dict[str, Any]:
    response = await client.get(f"{API}/assets", headers=tenant.auth_header)
    assert response.status_code == 200, response.text
    return response.json()["data"][0]


# --- listing ---------------------------------------------------------------


async def test_listing_rolls_up_risk_without_a_second_request(
    client: AsyncClient, tenant: Tenant
) -> None:
    asset = await _first_asset(client, tenant)

    assert asset["ip"] == "10.0.4.12"
    assert asset["hostname"] == "app-01"
    assert asset["open_findings"] == 1
    assert Decimal(asset["worst_finding_score"]) > 0


async def test_resolved_findings_leave_the_open_count(client: AsyncClient, tenant: Tenant) -> None:
    listed = await client.get(f"{API}/findings", headers=tenant.auth_header)
    finding_id = listed.json()["data"][0]["id"]
    await client.patch(
        f"{API}/findings/{finding_id}", json={"status": "remediated"}, headers=tenant.auth_header
    )

    asset = await _first_asset(client, tenant)

    assert asset["open_findings"] == 0
    assert asset["worst_finding_score"] is None


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("exposure=internet", 1),
        ("exposure=isolated", 0),
        ("q=app-01", 1),
        ("q=10.0.4", 1),
        ("q=nothing-like-this", 0),
    ],
)
async def test_filters(client: AsyncClient, tenant: Tenant, query: str, expected: int) -> None:
    response = await client.get(f"{API}/assets?{query}", headers=tenant.auth_header)
    assert response.status_code == 200
    assert len(response.json()["data"]) == expected


async def test_a_wildcard_in_the_search_term_is_a_literal(
    client: AsyncClient, tenant: Tenant
) -> None:
    """Unescaped, ``%`` would match the whole estate and read as a broken filter."""
    response = await client.get(f"{API}/assets?q=%25", headers=tenant.auth_header)
    assert response.status_code == 200
    assert response.json()["data"] == []


async def test_network_filter(
    client: AsyncClient, tenant: Tenant, session_factory: Factory
) -> None:
    network_id = await create_network(client, tenant)
    asset = await _first_asset(client, tenant)
    await client.patch(
        f"{API}/assets/{asset['id']}",
        json={"network_id": str(network_id)},
        headers=tenant.auth_header,
    )

    response = await client.get(f"{API}/assets?network_id={network_id}", headers=tenant.auth_header)
    assert len(response.json()["data"]) == 1


async def test_an_unknown_network_is_rejected_with_a_named_field(
    client: AsyncClient, tenant: Tenant
) -> None:
    asset = await _first_asset(client, tenant)
    response = await client.patch(
        f"{API}/assets/{asset['id']}",
        json={"network_id": "00000000-0000-0000-0000-000000000000"},
        headers=tenant.auth_header,
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "network_not_found"


# --- exposure changes re-score ---------------------------------------------


async def test_changing_exposure_rescores_the_assets_findings(
    client: AsyncClient, tenant: Tenant
) -> None:
    """A stale score here is a wrong number on the executive dashboard."""
    # Arrange
    asset = await _first_asset(client, tenant)
    before = Decimal(asset["worst_finding_score"])

    # Act
    response = await client.patch(
        f"{API}/assets/{asset['id']}", json={"exposure": "isolated"}, headers=tenant.auth_header
    )

    # Assert
    assert response.status_code == 200
    after = Decimal(response.json()["data"]["worst_finding_score"])
    assert after < before

    listed = await client.get(f"{API}/findings", headers=tenant.auth_header)
    factors = listed.json()["data"][0]
    detail = await client.get(f"{API}/findings/{factors['id']}", headers=tenant.auth_header)
    assert detail.json()["data"]["score_factors"]["exposure"]["value"] == "isolated"


async def test_editing_an_unrelated_field_does_not_rescore(
    client: AsyncClient, tenant: Tenant
) -> None:
    asset = await _first_asset(client, tenant)
    before = Decimal(asset["worst_finding_score"])

    response = await client.patch(
        f"{API}/assets/{asset['id']}", json={"hostname": "renamed"}, headers=tenant.auth_header
    )

    assert Decimal(response.json()["data"]["worst_finding_score"]) == before


# --- service mapping --------------------------------------------------------


async def test_mapping_an_asset_to_a_service_rescores_and_names_the_service(
    client: AsyncClient, tenant: Tenant, session_factory: Factory
) -> None:
    # Arrange
    service_id = await seed_business_service(session_factory, tenant.org_id)
    asset = await _first_asset(client, tenant)
    before = Decimal(asset["worst_finding_score"])

    # Act
    response = await client.put(
        f"{API}/assets/{asset['id']}/services",
        json={"service_ids": [str(service_id)]},
        headers=tenant.auth_header,
    )

    # Assert
    assert response.status_code == 200
    body = response.json()["data"]
    assert [item["name"] for item in body["services"]] == ["Payment processing"]
    assert Decimal(body["worst_finding_score"]) > before

    listed = await client.get(f"{API}/findings", headers=tenant.auth_header)
    detail = await client.get(
        f"{API}/findings/{listed.json()['data'][0]['id']}", headers=tenant.auth_header
    )
    assert detail.json()["data"]["services_affected"] == ["Payment processing"]


async def test_the_mapping_is_a_full_replacement(
    client: AsyncClient, tenant: Tenant, session_factory: Factory
) -> None:
    first = await seed_business_service(session_factory, tenant.org_id, name="Payments")
    second = await seed_business_service(
        session_factory, tenant.org_id, name="Reporting", criticality="low"
    )
    asset = await _first_asset(client, tenant)

    await client.put(
        f"{API}/assets/{asset['id']}/services",
        json={"service_ids": [str(first), str(second)]},
        headers=tenant.auth_header,
    )
    response = await client.put(
        f"{API}/assets/{asset['id']}/services",
        json={"service_ids": [str(second)]},
        headers=tenant.auth_header,
    )

    assert [item["name"] for item in response.json()["data"]["services"]] == ["Reporting"]


async def test_clearing_the_mapping_is_allowed(
    client: AsyncClient, tenant: Tenant, session_factory: Factory
) -> None:
    service_id = await seed_business_service(session_factory, tenant.org_id)
    asset = await _first_asset(client, tenant)
    await client.put(
        f"{API}/assets/{asset['id']}/services",
        json={"service_ids": [str(service_id)]},
        headers=tenant.auth_header,
    )

    response = await client.put(
        f"{API}/assets/{asset['id']}/services",
        json={"service_ids": []},
        headers=tenant.auth_header,
    )

    assert response.status_code == 200
    assert response.json()["data"]["services"] == []


async def test_an_unknown_service_id_rejects_the_whole_request(
    client: AsyncClient, tenant: Tenant, session_factory: Factory
) -> None:
    good = await seed_business_service(session_factory, tenant.org_id)
    asset = await _first_asset(client, tenant)

    response = await client.put(
        f"{API}/assets/{asset['id']}/services",
        json={"service_ids": [str(good), "00000000-0000-0000-0000-000000000000"]},
        headers=tenant.auth_header,
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "business_service_not_found"
    unchanged = await client.get(f"{API}/assets/{asset['id']}", headers=tenant.auth_header)
    assert unchanged.json()["data"]["services"] == []


# --- RBAC -------------------------------------------------------------------


async def test_viewer_can_read_but_not_edit_assets(
    client: AsyncClient, tenant: Tenant, session_factory: Factory
) -> None:
    viewer = await add_user_and_login(
        client, session_factory, tenant.org_id, tenant.org_slug, "viewer"
    )
    asset = await _first_asset(client, tenant)

    assert (await client.get(f"{API}/assets", headers=viewer)).status_code == 200
    patched = await client.patch(
        f"{API}/assets/{asset['id']}", json={"exposure": "dmz"}, headers=viewer
    )
    assert patched.status_code == 403
    mapped = await client.put(
        f"{API}/assets/{asset['id']}/services", json={"service_ids": []}, headers=viewer
    )
    assert mapped.status_code == 403


# --- tenancy ----------------------------------------------------------------


async def test_assets_do_not_cross_tenants(
    client: AsyncClient, session_factory: Factory, tenant: Tenant
) -> None:
    other = await register_tenant(client, "assets-beta")
    await seed_asset_with_port(session_factory, other.org_id, ip="192.168.1.1", hostname="beta-01")

    response = await client.get(f"{API}/assets", headers=other.auth_header)

    body = response.json()
    assert body["meta"]["total"] == 1
    assert body["data"][0]["ip"] == "192.168.1.1"


async def test_fetching_another_orgs_asset_is_404(
    client: AsyncClient, session_factory: Factory, tenant: Tenant
) -> None:
    other = await register_tenant(client, "assets-gamma")
    asset = await _first_asset(client, tenant)

    response = await client.get(f"{API}/assets/{asset['id']}", headers=other.auth_header)

    assert response.status_code == 404


async def test_mapping_another_orgs_asset_is_404(
    client: AsyncClient, session_factory: Factory, tenant: Tenant
) -> None:
    other = await register_tenant(client, "assets-delta")
    service_id = await seed_business_service(session_factory, other.org_id)
    asset = await _first_asset(client, tenant)

    response = await client.put(
        f"{API}/assets/{asset['id']}/services",
        json={"service_ids": [str(service_id)]},
        headers=other.auth_header,
    )

    assert response.status_code == 404


async def test_an_asset_cannot_be_mapped_to_another_orgs_service(
    client: AsyncClient, session_factory: Factory, tenant: Tenant
) -> None:
    """The foreign id is simply unknown here — it cannot be used to probe."""
    other = await register_tenant(client, "assets-epsilon")
    foreign_service = await seed_business_service(session_factory, other.org_id)
    asset = await _first_asset(client, tenant)

    response = await client.put(
        f"{API}/assets/{asset['id']}/services",
        json={"service_ids": [str(foreign_service)]},
        headers=tenant.auth_header,
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "business_service_not_found"
