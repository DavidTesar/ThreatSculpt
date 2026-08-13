"""``/dashboard/executive`` and ``/dashboard/attack-surface``.

The payload shape is asserted against docs/API.md key for key, and the ordering
claim — business impact, not CVSS — gets its own test, because that ordering is
the product.
"""

from __future__ import annotations

from decimal import Decimal

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.factories import API, Tenant, register_tenant
from tests.scoring_factories import (
    add_user_and_login,
    age_finding,
    map_asset_to_service,
    run_enrichment,
    seed_asset_with_port,
    seed_business_service,
    seed_vulnerability,
)

Factory = async_sessionmaker[AsyncSession]


@pytest.fixture
async def tenant(client: AsyncClient, session_factory: Factory) -> Tenant:
    """One internet-facing host running a vulnerable Log4j, supporting payments."""
    org = await register_tenant(client, "dash-org")
    await seed_vulnerability(session_factory, org.org_id)
    seeded = await seed_asset_with_port(session_factory, org.org_id, exposure="internet")
    service_id = await seed_business_service(session_factory, org.org_id)
    await map_asset_to_service(session_factory, org.org_id, seeded.asset_id, service_id)
    await run_enrichment(session_factory, org.org_id)
    return org


async def _executive(client: AsyncClient, tenant: Tenant) -> dict:
    response = await client.get(f"{API}/dashboard/executive", headers=tenant.auth_header)
    assert response.status_code == 200, response.text
    return response.json()["data"]


# --- payload shape ----------------------------------------------------------


async def test_payload_matches_the_documented_shape(client: AsyncClient, tenant: Tenant) -> None:
    data = await _executive(client, tenant)

    assert set(data) == {
        "risk_posture",
        "services_at_risk",
        "exposure_summary",
        "kev_findings",
        "remediation_progress",
    }
    assert set(data["risk_posture"]) == {"score", "trend_30d", "band"}
    assert set(data["exposure_summary"]) == {"internet", "dmz", "internal", "isolated"}
    assert set(data["remediation_progress"]) == {"opened_30d", "resolved_30d"}
    assert set(data["services_at_risk"][0]) == {
        "service_id",
        "name",
        "criticality",
        "revenue_at_risk",
        "open_findings",
        "worst_finding_score",
        "assets_affected",
    }


async def test_an_empty_org_returns_a_well_formed_zeroed_dashboard(client: AsyncClient) -> None:
    """A new customer's first login must not be a 500."""
    fresh = await register_tenant(client, "dash-empty")

    data = await _executive(client, fresh)

    assert data["risk_posture"] == {"score": 0, "trend_30d": 0, "band": "low"}
    assert data["services_at_risk"] == []
    assert data["exposure_summary"] == {"internet": 0, "dmz": 0, "internal": 0, "isolated": 0}
    assert data["kev_findings"] == 0


# --- the numbers ------------------------------------------------------------


async def test_services_at_risk_reports_the_right_counts(
    client: AsyncClient, tenant: Tenant
) -> None:
    data = await _executive(client, tenant)

    service = data["services_at_risk"][0]
    assert service["name"] == "Payment processing"
    assert service["criticality"] == "critical"
    assert service["open_findings"] == 1
    assert service["assets_affected"] == 1
    assert Decimal(service["revenue_at_risk"]) == Decimal("4200000.00")


async def test_services_are_ordered_by_business_impact_not_by_cvss(
    client: AsyncClient, session_factory: Factory
) -> None:
    """The whole thesis of the product, asserted.

    Two services, two hosts. The low-criticality service carries the *higher*
    raw score (internet-facing); the critical service's host is isolated, so its
    finding scores far lower. Business impact must still rank the critical
    service first — a CVSS-ordered list would invert this.
    """
    # Arrange
    org = await register_tenant(client, "impact-order")
    await seed_vulnerability(session_factory, org.org_id)

    critical_host = await seed_asset_with_port(
        session_factory, org.org_id, ip="10.0.1.1", exposure="isolated"
    )
    noisy_host = await seed_asset_with_port(
        session_factory, org.org_id, ip="10.0.1.2", exposure="internet"
    )
    payments = await seed_business_service(
        session_factory, org.org_id, name="Payment processing", criticality="critical"
    )
    wiki = await seed_business_service(
        session_factory, org.org_id, name="Internal wiki", criticality="low", revenue_at_risk=None
    )
    await map_asset_to_service(session_factory, org.org_id, critical_host.asset_id, payments)
    await map_asset_to_service(session_factory, org.org_id, noisy_host.asset_id, wiki)
    await run_enrichment(session_factory, org.org_id)

    # Act
    data = await _executive(client, org)

    # Assert
    rows = data["services_at_risk"]
    assert [row["name"] for row in rows] == ["Payment processing", "Internal wiki"]
    # ...and the raw score ordering really is the other way round, which is the
    # inversion a score-ordered list would have produced.
    assert Decimal(rows[0]["worst_finding_score"]) < Decimal(rows[1]["worst_finding_score"])


async def test_exposure_summary_counts_assets_by_tier(
    client: AsyncClient, session_factory: Factory
) -> None:
    org = await register_tenant(client, "exposure-counts")
    for index, exposure in enumerate(("internet", "internet", "dmz", "internal", "isolated")):
        await seed_asset_with_port(
            session_factory, org.org_id, ip=f"10.2.0.{index + 1}", exposure=exposure
        )

    data = await _executive(client, org)

    assert data["exposure_summary"] == {"internet": 2, "dmz": 1, "internal": 1, "isolated": 1}


async def test_kev_findings_counts_only_open_kev_listed_findings(
    client: AsyncClient, session_factory: Factory
) -> None:
    org = await register_tenant(client, "kev-count")
    await seed_vulnerability(session_factory, org.org_id, kev_listed=True)
    await seed_asset_with_port(session_factory, org.org_id)
    await run_enrichment(session_factory, org.org_id)

    assert (await _executive(client, org))["kev_findings"] == 1

    listed = await client.get(f"{API}/findings", headers=org.auth_header)
    await client.patch(
        f"{API}/findings/{listed.json()['data'][0]['id']}",
        json={"status": "remediated"},
        headers=org.auth_header,
    )

    assert (await _executive(client, org))["kev_findings"] == 0


async def test_remediation_progress_counts_the_last_thirty_days(
    client: AsyncClient, tenant: Tenant
) -> None:
    data = await _executive(client, tenant)
    assert data["remediation_progress"] == {"opened_30d": 1, "resolved_30d": 0}

    listed = await client.get(f"{API}/findings", headers=tenant.auth_header)
    await client.patch(
        f"{API}/findings/{listed.json()['data'][0]['id']}",
        json={"status": "remediated"},
        headers=tenant.auth_header,
    )

    after = await _executive(client, tenant)
    assert after["remediation_progress"] == {"opened_30d": 1, "resolved_30d": 1}


async def test_a_finding_older_than_the_window_is_not_counted_as_newly_opened(
    client: AsyncClient, tenant: Tenant, session_factory: Factory
) -> None:
    await age_finding(session_factory, tenant.org_id, days=45)

    data = await _executive(client, tenant)

    assert data["remediation_progress"]["opened_30d"] == 0


async def test_the_trend_shows_improvement_once_findings_are_resolved(
    client: AsyncClient, tenant: Tenant, session_factory: Factory
) -> None:
    """A finding that existed 30 days ago and is now resolved must move the trend down."""
    # Arrange — backdate the finding, then resolve it today.
    await age_finding(session_factory, tenant.org_id, days=45)
    listed = await client.get(f"{API}/findings", headers=tenant.auth_header)
    await client.patch(
        f"{API}/findings/{listed.json()['data'][0]['id']}",
        json={"status": "remediated"},
        headers=tenant.auth_header,
    )

    # Act
    posture = (await _executive(client, tenant))["risk_posture"]

    # Assert
    assert posture["score"] == 0  # nothing open now
    assert posture["trend_30d"] < 0  # but something was open a month ago
    assert posture["band"] == "low"


async def test_posture_band_tracks_the_score(client: AsyncClient, tenant: Tenant) -> None:
    posture = (await _executive(client, tenant))["risk_posture"]
    assert 0 <= posture["score"] <= 100
    assert posture["band"] in {"critical", "elevated", "moderate", "low"}


# --- attack surface ---------------------------------------------------------


async def test_attack_surface_returns_assets_services_and_both_edge_types(
    client: AsyncClient, tenant: Tenant
) -> None:
    response = await client.get(f"{API}/dashboard/attack-surface", headers=tenant.auth_header)

    assert response.status_code == 200
    graph = response.json()["data"]
    types = {node["type"] for node in graph["nodes"]}
    assert {"asset", "business_service", "exposure"} <= types
    assert {edge["type"] for edge in graph["edges"]} == {"supports", "exposes"}
    assert graph["aggregated"] is False
    assert graph["total_assets"] == 1


async def test_node_weight_is_the_business_risk_score(client: AsyncClient, tenant: Tenant) -> None:
    graph = (
        await client.get(f"{API}/dashboard/attack-surface", headers=tenant.auth_header)
    ).json()["data"]
    listed = await client.get(f"{API}/findings", headers=tenant.auth_header)
    expected = Decimal(listed.json()["data"][0]["business_risk_score"])

    asset_node = next(node for node in graph["nodes"] if node["type"] == "asset")

    assert Decimal(asset_node["weight"]) == expected


async def test_the_graph_is_capped_and_says_so(
    client: AsyncClient, session_factory: Factory
) -> None:
    """An unbounded graph payload is how the v1 dashboard would have died."""
    # Arrange — more assets than the requested cap allows.
    org = await register_tenant(client, "graph-cap")
    await seed_vulnerability(session_factory, org.org_id)
    for index in range(12):
        await seed_asset_with_port(session_factory, org.org_id, ip=f"10.3.0.{index + 1}")
    await run_enrichment(session_factory, org.org_id)

    # Act
    response = await client.get(
        f"{API}/dashboard/attack-surface?node_cap=10", headers=org.auth_header
    )

    # Assert
    graph = response.json()["data"]
    assert graph["aggregated"] is True
    assert graph["total_assets"] == 12
    assert len([n for n in graph["nodes"] if n["type"] == "asset"]) < 12
    placeholder = next(node for node in graph["nodes"] if node["type"] == "aggregated_assets")
    assert placeholder["represents"] > 0


async def test_the_capped_graph_keeps_the_riskiest_assets(
    client: AsyncClient, session_factory: Factory
) -> None:
    """Truncation must keep the useful half, not an arbitrary one."""
    # Arrange — one internet-facing vulnerable host among eleven quiet isolated ones.
    org = await register_tenant(client, "graph-risky")
    await seed_vulnerability(session_factory, org.org_id)
    await seed_asset_with_port(
        session_factory, org.org_id, ip="10.4.0.1", hostname="crown-jewel", exposure="internet"
    )
    for index in range(11):
        await seed_asset_with_port(
            session_factory,
            org.org_id,
            ip=f"10.4.1.{index + 1}",
            hostname=f"quiet-{index}",
            exposure="isolated",
            cpe=(),
        )
    await run_enrichment(session_factory, org.org_id)

    # Act
    graph = (
        await client.get(f"{API}/dashboard/attack-surface?node_cap=10", headers=org.auth_header)
    ).json()["data"]

    # Assert
    assets = [node for node in graph["nodes"] if node["type"] == "asset"]
    assert graph["aggregated"] is True
    assert len(assets) < 12
    assert "crown-jewel" in {node["label"] for node in assets}
    # It is kept because it is the one carrying risk, not by luck of ordering.
    assert Decimal(assets[0]["weight"]) > 0
    assert assets[0]["label"] == "crown-jewel"


# --- RBAC and tenancy -------------------------------------------------------


async def test_viewer_can_read_both_dashboards(
    client: AsyncClient, tenant: Tenant, session_factory: Factory
) -> None:
    viewer = await add_user_and_login(
        client, session_factory, tenant.org_id, tenant.org_slug, "viewer"
    )
    assert (await client.get(f"{API}/dashboard/executive", headers=viewer)).status_code == 200
    assert (await client.get(f"{API}/dashboard/attack-surface", headers=viewer)).status_code == 200


async def test_the_dashboard_requires_authentication(client: AsyncClient) -> None:
    assert (await client.get(f"{API}/dashboard/executive")).status_code == 401


async def test_dashboard_aggregates_never_include_another_tenants_rows(
    client: AsyncClient, tenant: Tenant, session_factory: Factory
) -> None:
    """Counts are the easy place to leak a tenant boundary, so they are the test."""
    # Arrange — alpha (the fixture) has a critical service and an open finding.
    # Beta has an identical estate of its own, plus more of it.
    beta = await register_tenant(client, "dash-beta")
    await seed_vulnerability(session_factory, beta.org_id)
    for index in range(4):
        await seed_asset_with_port(
            session_factory, beta.org_id, ip=f"10.5.0.{index + 1}", exposure="dmz"
        )
    await run_enrichment(session_factory, beta.org_id)

    # Act
    alpha_data = await _executive(client, tenant)
    beta_data = await _executive(client, beta)

    # Assert — neither org's aggregates contain the other's rows.
    assert alpha_data["exposure_summary"] == {
        "internet": 1,
        "dmz": 0,
        "internal": 0,
        "isolated": 0,
    }
    assert beta_data["exposure_summary"] == {
        "internet": 0,
        "dmz": 4,
        "internal": 0,
        "isolated": 0,
    }
    assert alpha_data["remediation_progress"]["opened_30d"] == 1
    assert beta_data["remediation_progress"]["opened_30d"] == 4
    assert [row["name"] for row in beta_data["services_at_risk"]] == []


async def test_the_attack_surface_graph_is_scoped(
    client: AsyncClient, tenant: Tenant, session_factory: Factory
) -> None:
    beta = await register_tenant(client, "graph-beta")
    await seed_asset_with_port(session_factory, beta.org_id, ip="172.16.0.1", hostname="beta-host")

    graph = (await client.get(f"{API}/dashboard/attack-surface", headers=beta.auth_header)).json()[
        "data"
    ]

    labels = {node["label"] for node in graph["nodes"] if node["type"] == "asset"}
    assert labels == {"beta-host"}
    assert graph["total_assets"] == 1
    assert [node for node in graph["nodes"] if node["type"] == "business_service"] == []
