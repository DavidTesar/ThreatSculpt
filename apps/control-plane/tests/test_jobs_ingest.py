"""Result ingest: validation, idempotency, and the v1 port-sharing bug.

docs/AGENT-PROTOCOL.md §5 — *never trust a client, including your own agent*. An
enrolled agent is a machine on a customer network; these tests describe what
happens when it submits something nobody asked it to collect.
"""

from __future__ import annotations

from uuid import UUID

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.agent_fixtures import (
    EnrolledAgent,
    claim_one,
    create_scan,
    enroll_agent,
    host,
    port,
    read_job,
    results_body,
)
from tests.factories import API, Tenant, create_network, register_tenant
from threatsculpt.core.pagination import PaginationParams
from threatsculpt.db.session import scoped_session
from threatsculpt.models.audit import AuditLog
from threatsculpt.models.inventory import Asset
from threatsculpt.models.scan import Port, ScanResult
from threatsculpt.scanning.ingest import MAX_RESULT_PAYLOAD_BYTES
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope


async def _prepared_job(client: AsyncClient, tenant: Tenant) -> tuple[UUID, EnrolledAgent]:
    """A registered network, an authorized scan, and an agent holding its lease."""
    await create_network(client, tenant)
    job_id = await create_scan(client, tenant)
    agent = await enroll_agent(client, tenant)
    await claim_one(client, agent)
    return job_id, agent


async def _ports_of(
    session_factory: async_sessionmaker[AsyncSession], org_id: UUID, ip: str
) -> list[int]:
    scope = OrgScope.for_system(org_id)
    async with scoped_session(session_factory, scope) as session:
        assets = ScopedRepository(session, scope, Asset)
        asset = await assets.find_one(Asset.ip == ip)
        assert asset is not None
        ports = ScopedRepository(session, scope, Port)
        page = await ports.list(
            PaginationParams(per_page=200), Port.asset_id == asset.id, order_by=[Port.port.asc()]
        )
        return [row.port for row in page.items]


async def test_hosts_inside_the_target_are_ingested(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    tenant = await register_tenant(client, "acme")
    job_id, agent = await _prepared_job(client, tenant)

    response = await client.post(
        f"{API}/agent/jobs/{job_id}/results",
        json=results_body((host("10.0.4.12", ports=(port(443),)),)),
        headers=agent.auth_header,
    )

    assert response.status_code == 202, response.text
    body = response.json()["data"]
    assert body == {"accepted": True, "hosts_ingested": 1, "hosts_rejected": []}
    assert await _ports_of(session_factory, tenant.org_id, "10.0.4.12") == [443]
    assert (await read_job(session_factory, tenant.org_id, job_id))["status"] == "completed"


async def test_a_host_outside_the_jobs_target_is_rejected(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """The job was for 10.0.4.0/24. 10.0.9.9 is in the org's network but not in
    this job's target, so it is refused even though the agent is legitimate."""
    tenant = await register_tenant(client, "acme")
    job_id, agent = await _prepared_job(client, tenant)

    response = await client.post(
        f"{API}/agent/jobs/{job_id}/results",
        json=results_body((host("10.0.4.12"), host("10.0.9.9"))),
        headers=agent.auth_header,
    )

    assert response.status_code == 202, response.text
    body = response.json()["data"]
    assert body["hosts_ingested"] == 1
    assert body["hosts_rejected"] == [{"ip": "10.0.9.9", "reason": "outside_job_target"}]

    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        assets = ScopedRepository(session, scope, Asset)
        assert await assets.find_one(Asset.ip == "10.0.9.9") is None


async def test_a_host_outside_every_registered_network_is_rejected(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Second half of the §5 check.

    The network is deleted after the job is created, so the target range is no
    longer one the org claims. The submission is then refused even though the
    address is inside the job's own target.
    """
    tenant = await register_tenant(client, "acme")
    network_id = await create_network(client, tenant)
    job_id = await create_scan(client, tenant)
    agent = await enroll_agent(client, tenant)
    await claim_one(client, agent)
    assert (
        await client.delete(f"{API}/networks/{network_id}", headers=tenant.auth_header)
    ).status_code == 200

    response = await client.post(
        f"{API}/agent/jobs/{job_id}/results",
        json=results_body((host("10.0.4.12"),)),
        headers=agent.auth_header,
    )

    assert response.status_code == 202, response.text
    body = response.json()["data"]
    assert body["hosts_ingested"] == 0
    assert body["hosts_rejected"] == [{"ip": "10.0.4.12", "reason": "outside_registered_networks"}]


async def test_a_rejected_host_is_audit_logged(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    tenant = await register_tenant(client, "acme")
    job_id, agent = await _prepared_job(client, tenant)

    await client.post(
        f"{API}/agent/jobs/{job_id}/results",
        json=results_body((host("192.168.50.4"),)),
        headers=agent.auth_header,
    )

    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        audit = ScopedRepository(session, scope, AuditLog)
        row = await audit.find_one(AuditLog.action == "scan_result.host_rejected")
        assert row is not None
        assert row.actor_type == "agent"
        assert row.audit_metadata["ip"] == "192.168.50.4"


async def test_a_retried_chunk_does_not_duplicate(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Idempotent on ``(job_id, host_ip)``.

    The second submission is the same batch replayed, as an agent would after a
    timeout it could not distinguish from a failure.
    """
    tenant = await register_tenant(client, "acme")
    job_id, agent = await _prepared_job(client, tenant)
    body = results_body((host("10.0.4.12", ports=(port(443), port(22, service="ssh"))),))

    first = await client.post(
        f"{API}/agent/jobs/{job_id}/results",
        json=body,
        headers=agent.auth_header,
    )
    second = await client.post(
        f"{API}/agent/jobs/{job_id}/results",
        json=body,
        headers=agent.auth_header,
    )

    assert first.status_code == 202
    # The job completed on the first batch, so the replay is refused by the
    # lease check rather than being applied twice.
    assert second.status_code == 409

    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        assets = ScopedRepository(session, scope, Asset)
        assert await assets.count() == 1
        results = ScopedRepository(session, scope, ScanResult)
        assert await results.count() == 1
    assert await _ports_of(session_factory, tenant.org_id, "10.0.4.12") == [22, 443]


async def test_a_replayed_chunk_within_one_job_replaces_rather_than_appends(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Same host twice while the job is still running: one result, one set of ports."""
    tenant = await register_tenant(client, "acme")
    job_id, agent = await _prepared_job(client, tenant)
    chunk = results_body((host("10.0.4.12", ports=(port(443),)),), final=False)

    for _ in range(2):
        response = await client.post(
            f"{API}/agent/jobs/{job_id}/results",
            json=chunk,
            headers=agent.auth_header,
        )
        assert response.status_code == 202, response.text

    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        results = ScopedRepository(session, scope, ScanResult)
        assert await results.count() == 1
        ports = ScopedRepository(session, scope, Port)
        assert await ports.count() == 1
    assert (await read_job(session_factory, tenant.org_id, job_id))["status"] == "running"


async def test_ports_are_not_shared_between_hosts(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """The v1 bug, named in docs/DATA-MODEL.md.

    v1 accumulated ports into one list reused across hosts, so host #2 inherited
    host #1's open ports — a false finding on a real asset.
    """
    tenant = await register_tenant(client, "acme")
    job_id, agent = await _prepared_job(client, tenant)

    response = await client.post(
        f"{API}/agent/jobs/{job_id}/results",
        json=results_body(
            (
                host("10.0.4.12", ports=(port(443), port(80, service="http"))),
                host("10.0.4.13", ports=(port(22, service="ssh"),)),
                host("10.0.4.14"),
            )
        ),
        headers=agent.auth_header,
    )

    assert response.status_code == 202, response.text
    assert await _ports_of(session_factory, tenant.org_id, "10.0.4.12") == [80, 443]
    assert await _ports_of(session_factory, tenant.org_id, "10.0.4.13") == [22]
    assert await _ports_of(session_factory, tenant.org_id, "10.0.4.14") == []


async def test_an_oversized_payload_is_refused(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    job_id, agent = await _prepared_job(client, tenant)
    oversized = (
        b'{"hosts": [{"ip": "10.0.4.12", "hostname": "'
        + b"a" * (MAX_RESULT_PAYLOAD_BYTES + 1024)
        + b'"}]}'
    )

    response = await client.post(
        f"{API}/agent/jobs/{job_id}/results",
        content=oversized,
        headers={**agent.auth_header, "content-type": "application/json"},
    )

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"


async def test_a_malformed_host_address_is_a_400_not_a_500(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    job_id, agent = await _prepared_job(client, tenant)

    response = await client.post(
        f"{API}/agent/jobs/{job_id}/results",
        json=results_body(({"ip": "10.0.4.999", "state": "up", "ports": []},)),
        headers=agent.auth_header,
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "validation_error"


async def test_a_malformed_mac_is_a_400_not_a_database_error(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    job_id, agent = await _prepared_job(client, tenant)

    response = await client.post(
        f"{API}/agent/jobs/{job_id}/results",
        json=results_body(({"ip": "10.0.4.12", "mac": "not-a-mac", "ports": []},)),
        headers=agent.auth_header,
    )

    assert response.status_code == 400


async def test_rescanning_updates_the_asset_rather_than_duplicating(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)
    agent = await enroll_agent(client, tenant)

    for hostname in ("db01.corp.local", "db01-renamed.corp.local"):
        job_id = await create_scan(client, tenant)
        await claim_one(client, agent)
        response = await client.post(
            f"{API}/agent/jobs/{job_id}/results",
            json=results_body(({"ip": "10.0.4.12", "hostname": hostname, "ports": []},)),
            headers=agent.auth_header,
        )
        assert response.status_code == 202, response.text

    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        assets = ScopedRepository(session, scope, Asset)
        assert await assets.count() == 1
        asset = await assets.find_one(Asset.ip == "10.0.4.12")
        assert asset is not None
        assert asset.hostname == "db01-renamed.corp.local"
        # Two jobs, two results for the same asset — history is kept.
        assert await ScopedRepository(session, scope, ScanResult).count() == 2
