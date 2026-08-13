"""``/scans`` — the control plane's half of scan-target authorisation.

docs/ARCHITECTURE.md calls this non-negotiable: a scan job is an instruction to
send packets at a network, so the target must be inside a CIDR the org registered
*and* marked authorized. v1 passed an unvalidated user string into a subprocess.
"""

from __future__ import annotations

from uuid import uuid4

import pytest
from httpx import AsyncClient

from tests.agent_fixtures import claim_one, create_scan, enroll_agent
from tests.factories import API, Tenant, create_network, register_tenant


async def _register_network(
    client: AsyncClient, tenant: Tenant, *, cidr: str, authorized: bool
) -> str:
    response = await client.post(
        f"{API}/networks",
        json={"name": f"net-{cidr}", "cidr": cidr, "authorized": authorized},
        headers=tenant.auth_header,
    )
    assert response.status_code == 201, response.text
    network_id: str = response.json()["data"]["id"]
    return network_id


async def test_a_scan_inside_an_authorized_network_is_queued(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    network_id = await _register_network(client, tenant, cidr="10.0.0.0/8", authorized=True)

    response = await client.post(
        f"{API}/scans",
        json={"target": "10.0.4.0/24", "profile": "service"},
        headers=tenant.auth_header,
    )

    assert response.status_code == 201, response.text
    body = response.json()["data"]
    assert body["status"] == "queued"
    assert body["target"] == "10.0.4.0/24"
    assert body["network_id"] == network_id
    assert body["attempts"] == 0


async def test_a_scan_against_an_unauthorized_network_is_refused(client: AsyncClient) -> None:
    """The network is registered — the org owns it — but nobody authorised scanning."""
    tenant = await register_tenant(client, "acme")
    await _register_network(client, tenant, cidr="10.0.0.0/8", authorized=False)

    response = await client.post(
        f"{API}/scans",
        json={"target": "10.0.4.0/24", "profile": "service"},
        headers=tenant.auth_header,
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "network_not_authorized"


async def test_a_scan_against_an_unregistered_range_is_refused(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    await _register_network(client, tenant, cidr="10.0.0.0/8", authorized=True)

    response = await client.post(
        f"{API}/scans",
        json={"target": "8.8.8.0/24", "profile": "discovery"},
        headers=tenant.auth_header,
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "network_not_authorized"


async def test_naming_an_authorized_network_does_not_bypass_containment(
    client: AsyncClient,
) -> None:
    """An explicit ``network_id`` is not a way to opt out of the target check."""
    tenant = await register_tenant(client, "acme")
    network_id = await _register_network(client, tenant, cidr="10.0.0.0/8", authorized=True)

    response = await client.post(
        f"{API}/scans",
        json={"target": "8.8.8.0/24", "profile": "service", "network_id": network_id},
        headers=tenant.auth_header,
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "network_not_authorized"


async def test_another_orgs_network_id_is_a_404(client: AsyncClient) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    beta_network = await _register_network(client, beta, cidr="10.0.0.0/8", authorized=True)
    await _register_network(client, alpha, cidr="10.0.0.0/8", authorized=True)

    response = await client.post(
        f"{API}/scans",
        json={"target": "10.0.4.0/24", "profile": "service", "network_id": beta_network},
        headers=alpha.auth_header,
    )

    assert response.status_code == 404


@pytest.mark.parametrize("target", ["not-a-cidr", "10.0.4.0/99", "10.0.4.0/24; DROP TABLE"])
async def test_a_malformed_target_is_rejected_before_the_database(
    client: AsyncClient, target: str
) -> None:
    tenant = await register_tenant(client, "acme")
    await _register_network(client, tenant, cidr="10.0.0.0/8", authorized=True)

    response = await client.post(
        f"{API}/scans",
        json={"target": target, "profile": "service"},
        headers=tenant.auth_header,
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "validation_error"


async def test_the_api_accepts_a_profile_name_and_not_nmap_flags(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    await _register_network(client, tenant, cidr="10.0.0.0/8", authorized=True)

    response = await client.post(
        f"{API}/scans",
        json={"target": "10.0.4.0/24", "profile": "-sS -p- --script vuln"},
        headers=tenant.auth_header,
    )

    assert response.status_code == 400


async def test_scans_are_listed_and_fetched_only_within_your_org(client: AsyncClient) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    await create_network(client, alpha)
    alpha_job = await create_scan(client, alpha)

    assert (await client.get(f"{API}/scans", headers=beta.auth_header)).json()["data"] == []
    cross = await client.get(f"{API}/scans/{alpha_job}", headers=beta.auth_header)
    missing = await client.get(f"{API}/scans/{uuid4()}", headers=beta.auth_header)
    assert cross.status_code == 404
    assert cross.json() == missing.json()


async def test_cancelling_releases_the_lease_and_locks_the_agent_out(
    client: AsyncClient,
) -> None:
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)
    job_id = await create_scan(client, tenant)
    agent = await enroll_agent(client, tenant)
    await claim_one(client, agent)

    cancel = await client.post(f"{API}/scans/{job_id}/cancel", headers=tenant.auth_header)

    assert cancel.status_code == 200, cancel.text
    assert cancel.json()["data"]["status"] == "cancelled"

    orphaned = await client.post(
        f"{API}/agent/jobs/{job_id}/status",
        json={"status": "running"},
        headers=agent.auth_header,
    )
    assert orphaned.status_code == 409


async def test_a_finished_job_cannot_be_cancelled(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)
    job_id = await create_scan(client, tenant)
    assert (
        await client.post(f"{API}/scans/{job_id}/cancel", headers=tenant.auth_header)
    ).status_code == 200

    again = await client.post(f"{API}/scans/{job_id}/cancel", headers=tenant.auth_header)

    assert again.status_code == 409
    assert again.json()["error"]["code"] == "conflict"


async def test_a_cancelled_job_is_not_claimable(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)
    job_id = await create_scan(client, tenant)
    agent = await enroll_agent(client, tenant)
    await client.post(f"{API}/scans/{job_id}/cancel", headers=tenant.auth_header)

    assert await claim_one(client, agent) == []


async def test_creating_a_scan_requires_authentication(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)

    response = await client.post(
        f"{API}/scans", json={"target": "10.0.4.0/24", "profile": "service"}
    )

    assert response.status_code == 401
    assert (await client.get(f"{API}/scans", headers=tenant.auth_header)).json()["data"] == []


async def test_the_scan_list_can_be_filtered_by_status(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)
    queued = await create_scan(client, tenant, target="10.0.4.0/24")
    cancelled = await create_scan(client, tenant, target="10.0.5.0/24")
    await client.post(f"{API}/scans/{cancelled}/cancel", headers=tenant.auth_header)

    response = await client.get(f"{API}/scans?status=queued", headers=tenant.auth_header)

    assert response.status_code == 200
    ids = [row["id"] for row in response.json()["data"]]
    assert ids == [str(queued)]
    assert response.json()["meta"]["total"] == 1
