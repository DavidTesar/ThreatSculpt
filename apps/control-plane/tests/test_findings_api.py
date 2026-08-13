"""``/findings`` and ``/assets`` over HTTP: filters, transitions, RBAC, tenancy."""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.factories import API, Tenant, register_tenant
from tests.scoring_factories import (
    add_user_and_login,
    map_asset_to_service,
    run_enrichment,
    seed_asset_with_port,
    seed_business_service,
    seed_vulnerability,
)

Factory = async_sessionmaker[AsyncSession]


async def _tenant_with_a_finding(
    client: AsyncClient, factory: Factory, slug: str, **asset_kwargs: Any
) -> tuple[Tenant, Any]:
    tenant = await register_tenant(client, slug)
    await seed_vulnerability(factory, tenant.org_id)
    seeded = await seed_asset_with_port(factory, tenant.org_id, **asset_kwargs)
    await run_enrichment(factory, tenant.org_id)
    return tenant, seeded


@pytest.fixture
async def tenant(client: AsyncClient, session_factory: Factory) -> Tenant:
    org, _ = await _tenant_with_a_finding(client, session_factory, "findings-org")
    return org


# --- listing ---------------------------------------------------------------


async def test_listing_returns_the_envelope_and_pagination_meta(
    client: AsyncClient, tenant: Tenant
) -> None:
    response = await client.get(f"{API}/findings", headers=tenant.auth_header)

    assert response.status_code == 200
    body = response.json()
    assert body["error"] is None
    assert body["meta"] == {"page": 1, "per_page": 50, "total": 1}
    finding = body["data"][0]
    assert finding["cve"]["cve_id"] == "CVE-2021-44228"
    assert finding["asset"]["ip"] == "10.0.4.12"
    assert finding["match"]["confidence"] == "high"


async def test_findings_are_sorted_by_business_risk_descending(
    client: AsyncClient, session_factory: Factory
) -> None:
    """The default ordering is the product's central claim, so it is asserted."""
    # Arrange — same CVE, three hosts, three exposures.
    tenant = await register_tenant(client, "sorted-org")
    await seed_vulnerability(session_factory, tenant.org_id)
    for index, exposure in enumerate(("isolated", "internal", "internet")):
        await seed_asset_with_port(
            session_factory, tenant.org_id, ip=f"10.0.4.{index + 1}", exposure=exposure
        )
    await run_enrichment(session_factory, tenant.org_id)

    # Act
    response = await client.get(f"{API}/findings", headers=tenant.auth_header)

    # Assert
    rows = response.json()["data"]
    assert [row["asset"]["exposure"] for row in rows] == ["internet", "internal", "isolated"]
    scores = [Decimal(row["business_risk_score"]) for row in rows]
    assert scores == sorted(scores, reverse=True)


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("status=open", 1),
        ("status=remediated", 0),
        ("severity=critical", 1),
        ("severity=low", 0),
        ("kev_only=true", 0),
        ("min_confidence=high", 1),
    ],
)
async def test_filters(client: AsyncClient, tenant: Tenant, query: str, expected: int) -> None:
    response = await client.get(f"{API}/findings?{query}", headers=tenant.auth_header)
    assert response.status_code == 200
    assert len(response.json()["data"]) == expected


async def test_unknown_severity_is_rejected_rather_than_returning_nothing(
    client: AsyncClient, tenant: Tenant
) -> None:
    response = await client.get(f"{API}/findings?severity=spicy", headers=tenant.auth_header)
    assert response.status_code == 400
    assert response.json()["error"]["field"] == "severity"


async def test_service_filter_matches_only_assets_supporting_that_service(
    client: AsyncClient, session_factory: Factory
) -> None:
    tenant, seeded = await _tenant_with_a_finding(client, session_factory, "svc-filter")
    await seed_asset_with_port(session_factory, tenant.org_id, ip="10.0.9.9")
    await run_enrichment(session_factory, tenant.org_id)
    service_id = await seed_business_service(session_factory, tenant.org_id)
    await map_asset_to_service(session_factory, tenant.org_id, seeded.asset_id, service_id)

    response = await client.get(
        f"{API}/findings?service_id={service_id}", headers=tenant.auth_header
    )

    rows = response.json()["data"]
    assert len(rows) == 1
    assert rows[0]["asset"]["id"] == str(seeded.asset_id)


async def test_asset_filter(client: AsyncClient, session_factory: Factory) -> None:
    tenant, seeded = await _tenant_with_a_finding(client, session_factory, "asset-filter")
    response = await client.get(
        f"{API}/findings?asset_id={seeded.asset_id}", headers=tenant.auth_header
    )
    assert len(response.json()["data"]) == 1


# --- detail ----------------------------------------------------------------


async def test_detail_carries_the_score_explanation(client: AsyncClient, tenant: Tenant) -> None:
    """An unexplained score does not persuade an executive; the detail must explain."""
    listed = await client.get(f"{API}/findings", headers=tenant.auth_header)
    finding_id = listed.json()["data"][0]["id"]

    response = await client.get(f"{API}/findings/{finding_id}", headers=tenant.auth_header)

    assert response.status_code == 200
    detail = response.json()["data"]
    factors = detail["score_factors"]
    assert set(factors) >= {
        "cvss_base",
        "exploit_maturity",
        "exposure",
        "asset_criticality",
        "services_affected",
    }
    assert factors["exposure"]["value"] == "internet"
    assert detail["match"]["rationale"]
    assert detail["description"]


async def test_unknown_finding_is_a_404(client: AsyncClient, tenant: Tenant) -> None:
    missing = "00000000-0000-0000-0000-000000000000"
    response = await client.get(f"{API}/findings/{missing}", headers=tenant.auth_header)
    assert response.status_code == 404


# --- transitions -----------------------------------------------------------


async def test_status_transition_updates_and_audits(
    client: AsyncClient, tenant: Tenant, session_factory: Factory
) -> None:
    listed = await client.get(f"{API}/findings", headers=tenant.auth_header)
    finding_id = listed.json()["data"][0]["id"]

    response = await client.patch(
        f"{API}/findings/{finding_id}",
        json={"status": "accepted_risk", "note": "compensating control in place"},
        headers=tenant.auth_header,
    )

    assert response.status_code == 200
    assert response.json()["data"]["status"] == "accepted_risk"
    assert response.json()["data"]["resolved_at"] is None
    assert await _audit_actions(session_factory, tenant) >= {"finding.status_changed"}


async def test_resolving_stamps_resolved_at_and_reopening_clears_it(
    client: AsyncClient, tenant: Tenant
) -> None:
    listed = await client.get(f"{API}/findings", headers=tenant.auth_header)
    finding_id = listed.json()["data"][0]["id"]

    resolved = await client.patch(
        f"{API}/findings/{finding_id}", json={"status": "remediated"}, headers=tenant.auth_header
    )
    assert resolved.json()["data"]["resolved_at"] is not None

    reopened = await client.patch(
        f"{API}/findings/{finding_id}", json={"status": "open"}, headers=tenant.auth_header
    )
    assert reopened.json()["data"]["resolved_at"] is None


async def test_an_illegal_transition_is_rejected(client: AsyncClient, tenant: Tenant) -> None:
    """``remediated -> accepted_risk`` skips reopening, so it is not a transition."""
    listed = await client.get(f"{API}/findings", headers=tenant.auth_header)
    finding_id = listed.json()["data"][0]["id"]
    await client.patch(
        f"{API}/findings/{finding_id}", json={"status": "remediated"}, headers=tenant.auth_header
    )

    response = await client.patch(
        f"{API}/findings/{finding_id}",
        json={"status": "accepted_risk"},
        headers=tenant.auth_header,
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_status_transition"


async def test_a_no_op_transition_is_rejected(client: AsyncClient, tenant: Tenant) -> None:
    listed = await client.get(f"{API}/findings", headers=tenant.auth_header)
    finding_id = listed.json()["data"][0]["id"]
    response = await client.patch(
        f"{API}/findings/{finding_id}", json={"status": "open"}, headers=tenant.auth_header
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "status_unchanged"


async def test_the_score_is_not_patchable(client: AsyncClient, tenant: Tenant) -> None:
    """The score is a computation, not an opinion. ``extra="forbid"`` enforces it."""
    listed = await client.get(f"{API}/findings", headers=tenant.auth_header)
    finding_id = listed.json()["data"][0]["id"]

    response = await client.patch(
        f"{API}/findings/{finding_id}",
        json={"status": "accepted_risk", "business_risk_score": "1.00"},
        headers=tenant.auth_header,
    )
    assert response.status_code == 400


async def test_viewer_cannot_patch_a_finding(
    client: AsyncClient, tenant: Tenant, session_factory: Factory
) -> None:
    viewer = await add_user_and_login(
        client, session_factory, tenant.org_id, tenant.org_slug, "viewer"
    )
    listed = await client.get(f"{API}/findings", headers=viewer)
    finding_id = listed.json()["data"][0]["id"]

    response = await client.patch(
        f"{API}/findings/{finding_id}", json={"status": "accepted_risk"}, headers=viewer
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


async def test_viewer_can_read_findings(
    client: AsyncClient, tenant: Tenant, session_factory: Factory
) -> None:
    viewer = await add_user_and_login(
        client, session_factory, tenant.org_id, tenant.org_slug, "viewer"
    )
    assert (await client.get(f"{API}/findings", headers=viewer)).status_code == 200


# --- tenancy ---------------------------------------------------------------


async def test_one_org_never_sees_another_orgs_findings(
    client: AsyncClient, session_factory: Factory
) -> None:
    _, alpha_seed = await _tenant_with_a_finding(client, session_factory, "f-alpha")
    beta, _ = await _tenant_with_a_finding(client, session_factory, "f-beta", ip="10.0.4.99")

    listed = await client.get(f"{API}/findings", headers=beta.auth_header)
    rows = listed.json()["data"]

    assert len(rows) == 1
    assert rows[0]["asset"]["ip"] == "10.0.4.99"
    assert str(alpha_seed.asset_id) not in {row["asset"]["id"] for row in rows}


async def test_the_total_count_does_not_leak_across_tenants(
    client: AsyncClient, session_factory: Factory
) -> None:
    """An aggregate is the easy place to leak: the count must be scoped too."""
    alpha, _ = await _tenant_with_a_finding(client, session_factory, "count-alpha")
    for index in range(3):
        await seed_asset_with_port(session_factory, alpha.org_id, ip=f"10.1.0.{index + 1}")
    await run_enrichment(session_factory, alpha.org_id)
    beta, _ = await _tenant_with_a_finding(client, session_factory, "count-beta", ip="10.9.9.9")

    response = await client.get(f"{API}/findings", headers=beta.auth_header)

    assert response.json()["meta"]["total"] == 1


async def test_fetching_another_orgs_finding_is_404_not_403(
    client: AsyncClient, session_factory: Factory
) -> None:
    """403 would confirm the row exists — an information leak by itself."""
    alpha, _ = await _tenant_with_a_finding(client, session_factory, "x-alpha")
    beta, _ = await _tenant_with_a_finding(client, session_factory, "x-beta", ip="10.0.4.98")
    alpha_listed = await client.get(f"{API}/findings", headers=alpha.auth_header)
    alpha_finding_id = alpha_listed.json()["data"][0]["id"]

    response = await client.get(f"{API}/findings/{alpha_finding_id}", headers=beta.auth_header)

    assert response.status_code == 404


async def test_patching_another_orgs_finding_is_404(
    client: AsyncClient, session_factory: Factory
) -> None:
    alpha, _ = await _tenant_with_a_finding(client, session_factory, "p-alpha")
    beta, _ = await _tenant_with_a_finding(client, session_factory, "p-beta", ip="10.0.4.97")
    alpha_listed = await client.get(f"{API}/findings", headers=alpha.auth_header)
    alpha_finding_id = alpha_listed.json()["data"][0]["id"]

    response = await client.patch(
        f"{API}/findings/{alpha_finding_id}",
        json={"status": "false_positive"},
        headers=beta.auth_header,
    )

    assert response.status_code == 404
    still_open = await client.get(f"{API}/findings/{alpha_finding_id}", headers=alpha.auth_header)
    assert still_open.json()["data"]["status"] == "open"


async def test_filtering_by_another_orgs_service_id_returns_nothing(
    client: AsyncClient, session_factory: Factory
) -> None:
    """A foreign id must be inert, not a cross-tenant join."""
    alpha, alpha_seed = await _tenant_with_a_finding(client, session_factory, "sf-alpha")
    alpha_service = await seed_business_service(session_factory, alpha.org_id)
    await map_asset_to_service(session_factory, alpha.org_id, alpha_seed.asset_id, alpha_service)
    beta, _ = await _tenant_with_a_finding(client, session_factory, "sf-beta", ip="10.0.4.96")

    response = await client.get(
        f"{API}/findings?service_id={alpha_service}", headers=beta.auth_header
    )

    assert response.status_code == 200
    assert response.json()["data"] == []


async def _audit_actions(factory: Factory, tenant: Tenant) -> set[str]:
    from sqlalchemy import select

    from threatsculpt.core.scoped_sql import execute_scoped
    from threatsculpt.db.session import scoped_session
    from threatsculpt.models.audit import AuditLog
    from threatsculpt.tenancy.scope import OrgScope

    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(factory, scope) as session:
        result = await execute_scoped(
            session,
            scope,
            select(AuditLog.action).where(AuditLog.org_id == tenant.org_id),
        )
        return set(result.scalars().all())
