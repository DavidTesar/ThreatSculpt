"""Principal separation and cross-tenant isolation on the real agent routes.

``tests/test_principal_separation.py`` proved the *dependency* is correct against
a probe route, before these endpoints existed. This suite proves the endpoints
actually use it — a route that forgot ``CurrentAgent`` would pass that suite and
fail this one.

The cross-tenant table below is exhaustive on purpose: every agent endpoint, not
a representative sample. An endpoint added later without a row here is the one
that will leak.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from httpx import AsyncClient

from tests.agent_fixtures import claim_one, create_scan, enroll_agent, host, results_body
from tests.factories import API, create_network, register_tenant


async def test_heartbeat_records_liveness_and_returns_the_allowlist(
    client: AsyncClient,
) -> None:
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)
    agent = await enroll_agent(client, tenant)

    response = await client.post(
        f"{API}/agent/heartbeat",
        json={"version": "2.0.1", "nmap_version": "7.94", "healthy": True},
        headers=agent.auth_header,
    )

    assert response.status_code == 200, response.text
    body = response.json()["data"]
    assert body["allowlist"] == ["10.0.0.0/8"]
    assert body["poll_interval_seconds"] == 30
    assert body["revoked"] is False

    listing = await client.get(f"{API}/agents", headers=tenant.auth_header)
    row = listing.json()["data"][0]
    assert row["last_seen_at"] is not None
    assert row["version"] == "2.0.1"


async def test_an_agent_allowlist_can_only_narrow_the_orgs_networks(
    client: AsyncClient,
) -> None:
    """docs/AGENT-PROTOCOL.md §4: the server list may narrow, never widen."""
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant, cidr="10.0.0.0/8")
    agent = await enroll_agent(client, tenant)

    update = await client.patch(
        f"{API}/agents/{agent.agent_id}/allowlist",
        json={"allowlist": ["10.0.4.0/24", "192.168.0.0/16"]},
        headers=tenant.auth_header,
    )
    assert update.status_code == 200, update.text

    heartbeat = await client.post(
        f"{API}/agent/heartbeat", json={"healthy": True}, headers=agent.auth_header
    )

    # 10.0.4.0/24 is inside the authorized 10.0.0.0/8 and survives.
    # 192.168.0.0/16 is not authorized for this org and is dropped.
    assert heartbeat.json()["data"]["allowlist"] == ["10.0.4.0/24"]


# --- principal separation ---------------------------------------------------

AGENT_ENDPOINTS = (
    ("POST", "/agent/heartbeat", {"healthy": True}),
    ("POST", "/agent/jobs/claim", {"capacity": 1}),
)


@pytest.mark.parametrize(("method", "path", "body"), AGENT_ENDPOINTS)
async def test_a_user_jwt_is_rejected_on_agent_routes(
    client: AsyncClient, method: str, path: str, body: dict[str, object]
) -> None:
    tenant = await register_tenant(client, "acme")

    response = await client.request(method, f"{API}{path}", json=body, headers=tenant.auth_header)

    assert response.status_code == 401, response.text


DASHBOARD_ENDPOINTS = (
    ("GET", "/auth/me"),
    ("GET", "/networks"),
    ("GET", "/scans"),
    ("GET", "/agents"),
)


@pytest.mark.parametrize(("method", "path"), DASHBOARD_ENDPOINTS)
async def test_an_agent_key_is_rejected_on_dashboard_routes(
    client: AsyncClient, method: str, path: str
) -> None:
    tenant = await register_tenant(client, "acme")
    agent = await enroll_agent(client, tenant)

    response = await client.request(method, f"{API}{path}", headers=agent.auth_header)

    assert response.status_code == 401, response.text


async def test_an_agent_key_cannot_create_a_scan(client: AsyncClient) -> None:
    """The most consequential dashboard write an agent might reach for."""
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)
    agent = await enroll_agent(client, tenant)

    response = await client.post(
        f"{API}/scans",
        json={"target": "10.0.4.0/24", "profile": "service"},
        headers=agent.auth_header,
    )

    assert response.status_code == 401


# --- cross-tenant -----------------------------------------------------------


async def test_an_agent_cannot_claim_another_orgs_job(client: AsyncClient) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    await create_network(client, alpha)
    await create_scan(client, alpha)
    beta_agent = await enroll_agent(client, beta, name="beta-scanner")

    assert await claim_one(client, beta_agent) == []


async def test_an_agent_cannot_report_status_on_another_orgs_job(client: AsyncClient) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    await create_network(client, alpha)
    alpha_job = await create_scan(client, alpha)
    alpha_agent = await enroll_agent(client, alpha, name="alpha-scanner")
    await claim_one(client, alpha_agent)
    beta_agent = await enroll_agent(client, beta, name="beta-scanner")

    response = await client.post(
        f"{API}/agent/jobs/{alpha_job}/status",
        json={"status": "running", "progress_percent": 99},
        headers=beta_agent.auth_header,
    )

    assert response.status_code == 409
    # Identical to the answer for a job id that does not exist anywhere, so the
    # response confirms nothing about another org's data.
    unknown = await client.post(
        f"{API}/agent/jobs/{uuid4()}/status",
        json={"status": "running"},
        headers=beta_agent.auth_header,
    )
    assert unknown.status_code == response.status_code
    assert unknown.json()["error"]["code"] == response.json()["error"]["code"]


async def test_an_agent_cannot_reject_another_orgs_job(client: AsyncClient) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    await create_network(client, alpha)
    alpha_job = await create_scan(client, alpha)
    alpha_agent = await enroll_agent(client, alpha, name="alpha-scanner")
    await claim_one(client, alpha_agent)
    beta_agent = await enroll_agent(client, beta, name="beta-scanner")

    response = await client.post(
        f"{API}/agent/jobs/{alpha_job}/reject",
        json={"reason": "target_not_in_local_allowlist"},
        headers=beta_agent.auth_header,
    )

    assert response.status_code == 409
    still_claimed = await client.get(f"{API}/scans/{alpha_job}", headers=alpha.auth_header)
    assert still_claimed.json()["data"]["status"] == "claimed"


async def test_an_agent_cannot_submit_results_for_another_orgs_job(client: AsyncClient) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    await create_network(client, alpha)
    alpha_job = await create_scan(client, alpha)
    alpha_agent = await enroll_agent(client, alpha, name="alpha-scanner")
    await claim_one(client, alpha_agent)
    beta_agent = await enroll_agent(client, beta, name="beta-scanner")

    response = await client.post(
        f"{API}/agent/jobs/{alpha_job}/results",
        json=results_body((host("10.0.4.12"),)),
        headers=beta_agent.auth_header,
    )

    assert response.status_code == 409
    assert (await client.get(f"{API}/scans/{alpha_job}", headers=alpha.auth_header)).json()["data"][
        "status"
    ] == "claimed"


async def test_an_admin_cannot_revoke_another_orgs_agent(client: AsyncClient) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    alpha_agent = await enroll_agent(client, alpha, name="alpha-scanner")

    response = await client.delete(f"{API}/agents/{alpha_agent.agent_id}", headers=beta.auth_header)

    assert response.status_code == 404
    still_working = await client.post(
        f"{API}/agent/heartbeat", json={"healthy": True}, headers=alpha_agent.auth_header
    )
    assert still_working.status_code == 200


async def test_agents_are_only_listed_to_their_own_org(client: AsyncClient) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    await enroll_agent(client, alpha, name="alpha-scanner")

    listing = await client.get(f"{API}/agents", headers=beta.auth_header)

    assert listing.status_code == 200
    assert listing.json()["data"] == []
