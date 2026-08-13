"""One in-cap ingest request must not buy minutes of server time.

The measured defect: 9.57 MB, 4,096 hosts and 368,640 ports — every one of those
inside a documented cap — took **335 seconds** in one write transaction on one
pooled connection, RSS 197→609 MB, from a single agent API key against a limiter
that permits 100 requests a minute. The per-host caps bounded the wrong thing:
1,024 ports on a busy host is plausible, 4,096 such hosts at once is not.

Three changes, one test group each: a cap on the batch as a whole, deduplication
of hosts within a batch, and storage that does not issue a round trip per row.
The containment filtering ingest exists for is unchanged and is covered by
``test_jobs_ingest``; these are only about how much work one request can buy.
"""

from __future__ import annotations

import time

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.agent_fixtures import EnrolledAgent, claim_one, create_scan, enroll_agent, port
from tests.factories import API, Tenant, create_network, register_tenant
from threatsculpt.core.pagination import PaginationParams
from threatsculpt.db.session import scoped_session
from threatsculpt.models.inventory import Asset
from threatsculpt.models.scan import Port, ScanResult
from threatsculpt.scanning.schemas import MAX_PORTS_PER_SUBMISSION
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope


async def _prepared(client: AsyncClient, tenant: Tenant) -> tuple[str, EnrolledAgent]:
    """The registered network is a /8, so the job target can hold a large batch."""
    await create_network(client, tenant)
    job_id = await create_scan(client, tenant, target="10.0.0.0/8")
    agent = await enroll_agent(client, tenant)
    await claim_one(client, agent)
    return str(job_id), agent


#: One host observation, in the shape §5 defines. Typed concretely so the port
#: counts below are arithmetic rather than casts.
Host = dict[str, object]


def _hosts(count: int, ports_each: int, *, start: int = 0) -> list[Host]:
    return [
        {
            "ip": f"10.0.{(start + i) // 256}.{(start + i) % 256}",
            "state": "up",
            "ports": [port(number) for number in range(1, ports_each + 1)],
        }
        for i in range(count)
    ]


def _ports_in(hosts: list[Host]) -> list[int]:
    return [len(host["ports"]) for host in hosts if isinstance(host["ports"], list)]


# --- the batch-wide cap -----------------------------------------------------


async def test_a_batch_over_the_port_cap_is_refused(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    tenant = await register_tenant(client, "acme")
    job_id, agent = await _prepared(client, tenant)

    hosts = _hosts(21, 1000)
    per_host = _ports_in(hosts)
    assert sum(per_host) > MAX_PORTS_PER_SUBMISSION
    assert max(per_host) <= 1024, "each host is individually legal; the batch is not"

    response = await client.post(
        f"{API}/agent/jobs/{job_id}/results",
        json={"hosts": hosts, "final": False},
        headers=agent.auth_header,
    )

    assert response.status_code == 400, response.text
    assert str(MAX_PORTS_PER_SUBMISSION) in response.json()["error"]["message"]

    # Refused at the schema boundary, so nothing was written and no transaction
    # was opened to write it in.
    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        assert await ScopedRepository(session, scope, Asset).count() == 0
        assert await ScopedRepository(session, scope, Port).count() == 0


async def test_a_batch_at_the_cap_is_accepted(client: AsyncClient) -> None:
    """The cap is a ceiling, not an off-by-one that rejects the legal maximum."""
    tenant = await register_tenant(client, "acme")
    job_id, agent = await _prepared(client, tenant)

    hosts = _hosts(MAX_PORTS_PER_SUBMISSION // 1000, 1000)
    remainder = MAX_PORTS_PER_SUBMISSION % 1000
    if remainder:
        hosts.extend(_hosts(1, remainder, start=len(hosts)))
    assert sum(_ports_in(hosts)) == MAX_PORTS_PER_SUBMISSION

    response = await client.post(
        f"{API}/agent/jobs/{job_id}/results",
        json={"hosts": hosts, "final": False},
        headers=agent.auth_header,
    )
    assert response.status_code == 202, response.text


async def test_a_chunked_submission_is_the_supported_way_past_the_cap(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """§5 already provides for splitting a large scan; the cap points at it."""
    tenant = await register_tenant(client, "acme")
    job_id, agent = await _prepared(client, tenant)

    for index in range(2):
        response = await client.post(
            f"{API}/agent/jobs/{job_id}/results",
            json={"hosts": _hosts(10, 100, start=index * 10), "final": index == 1},
            headers=agent.auth_header,
        )
        assert response.status_code == 202, response.text

    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        assert await ScopedRepository(session, scope, Asset).count() == 20
        assert await ScopedRepository(session, scope, Port).count() == 2000


# --- deduplication within one batch -----------------------------------------


async def test_the_same_host_twice_in_one_batch_stores_one_of_it(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """The upserts cannot affect one row twice in a single statement, and the
    last observation is the one an agent means."""
    tenant = await register_tenant(client, "acme")
    job_id, agent = await _prepared(client, tenant)

    response = await client.post(
        f"{API}/agent/jobs/{job_id}/results",
        json={
            "hosts": [
                {"ip": "10.0.4.12", "state": "up", "ports": [port(22, service="ssh")]},
                {"ip": "10.0.4.12", "state": "up", "ports": [port(443)]},
            ],
            "final": True,
        },
        headers=agent.auth_header,
    )
    assert response.status_code == 202, response.text
    assert response.json()["data"]["hosts_ingested"] == 1

    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        assert await ScopedRepository(session, scope, Asset).count() == 1
        assert await ScopedRepository(session, scope, ScanResult).count() == 1
        ports = ScopedRepository(session, scope, Port)
        page = await ports.list(PaginationParams(per_page=50), order_by=[Port.port.asc()])
        assert [row.port for row in page.items] == [443]


# --- and what it costs now --------------------------------------------------


async def test_the_largest_legal_batch_completes_promptly(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """A guard against the row-at-a-time shape coming back.

    The threshold is loose on purpose — this runs on whatever CI is given, and
    the failure it exists to catch is two orders of magnitude away, not two
    percent. The original code needed 335 s for a batch of this kind.
    """
    tenant = await register_tenant(client, "acme")
    job_id, agent = await _prepared(client, tenant)

    hosts = _hosts(200, 100)
    started = time.perf_counter()
    response = await client.post(
        f"{API}/agent/jobs/{job_id}/results",
        json={"hosts": hosts, "final": True},
        headers=agent.auth_header,
    )
    elapsed = time.perf_counter() - started

    assert response.status_code == 202, response.text
    assert response.json()["data"]["hosts_ingested"] == 200
    assert elapsed < 20.0, f"20,000 ports took {elapsed:.1f}s; the per-row shape is back"

    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        assert await ScopedRepository(session, scope, Port).count() == 20_000
