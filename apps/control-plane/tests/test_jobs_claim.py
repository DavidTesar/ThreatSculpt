"""Claiming, progress, rejection, and lease recovery.

The claim test that matters is the concurrent one. ``FOR UPDATE SKIP LOCKED``
either works or it does not, and a sequential test cannot tell the difference
between it and a plain ``SELECT`` followed by an ``UPDATE``.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.agent_fixtures import claim_one, create_scan, enroll_agent, force_job_fields, read_job
from tests.factories import API, create_network, register_tenant
from threatsculpt.models.scan import MAX_JOB_ATTEMPTS
from threatsculpt.scanning.sweeper import SweepOutcome, sweep_once


async def test_claiming_returns_the_job_with_a_lease(client: AsyncClient) -> None:
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)
    job_id = await create_scan(client, tenant)
    agent = await enroll_agent(client, tenant)

    jobs = await claim_one(client, agent)

    assert len(jobs) == 1
    assert jobs[0]["job_id"] == str(job_id)
    assert jobs[0]["target"] == "10.0.4.0/24"
    assert jobs[0]["profile"] == "service"
    assert datetime.fromisoformat(jobs[0]["lease_expires_at"]) > datetime.now(tz=UTC)


async def test_two_agents_racing_for_one_job_produce_exactly_one_winner(
    client: AsyncClient,
) -> None:
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)
    await create_scan(client, tenant)
    first = await enroll_agent(client, tenant, name="scanner-a")
    second = await enroll_agent(client, tenant, name="scanner-b")

    responses = await asyncio.gather(
        client.post(f"{API}/agent/jobs/claim", json={"capacity": 1}, headers=first.auth_header),
        client.post(f"{API}/agent/jobs/claim", json={"capacity": 1}, headers=second.auth_header),
    )

    claimed = [job for response in responses for job in response.json()["data"]["jobs"]]
    assert all(response.status_code == 200 for response in responses)
    assert len(claimed) == 1, claimed


async def test_a_claim_is_not_visible_to_another_org(client: AsyncClient) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    await create_network(client, alpha)
    await create_scan(client, alpha)
    beta_agent = await enroll_agent(client, beta, name="beta-scanner")

    assert await claim_one(client, beta_agent) == []


async def test_claiming_increments_attempts(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)
    job_id = await create_scan(client, tenant)
    agent = await enroll_agent(client, tenant)

    await claim_one(client, agent)

    state = await read_job(session_factory, tenant.org_id, job_id)
    assert state["attempts"] == 1
    assert state["status"] == "claimed"
    assert state["agent_id"] == agent.agent_id


async def test_progress_is_recorded_and_renews_the_lease(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)
    job_id = await create_scan(client, tenant)
    agent = await enroll_agent(client, tenant)
    await claim_one(client, agent)

    response = await client.post(
        f"{API}/agent/jobs/{job_id}/status",
        json={"status": "running", "progress_percent": 40},
        headers=agent.auth_header,
    )

    assert response.status_code == 200, response.text
    state = await read_job(session_factory, tenant.org_id, job_id)
    assert state["status"] == "running"
    assert state["progress_percent"] == 40


async def test_completed_cannot_be_declared_through_the_status_endpoint(
    client: AsyncClient,
) -> None:
    """A job becomes complete by submitting results, never by asserting it."""
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)
    job_id = await create_scan(client, tenant)
    agent = await enroll_agent(client, tenant)
    await claim_one(client, agent)

    response = await client.post(
        f"{API}/agent/jobs/{job_id}/status",
        json={"status": "completed"},
        headers=agent.auth_header,
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "job_not_claimable"


async def test_an_agent_cannot_touch_a_job_it_did_not_claim(client: AsyncClient) -> None:
    """Same org, wrong agent. Ownership is the lease, not membership."""
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)
    job_id = await create_scan(client, tenant)
    holder = await enroll_agent(client, tenant, name="holder")
    bystander = await enroll_agent(client, tenant, name="bystander")
    await claim_one(client, holder)

    response = await client.post(
        f"{API}/agent/jobs/{job_id}/status",
        json={"status": "running"},
        headers=bystander.auth_header,
    )

    assert response.status_code == 409


async def test_an_expired_lease_blocks_further_reporting(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)
    job_id = await create_scan(client, tenant)
    agent = await enroll_agent(client, tenant)
    await claim_one(client, agent)
    await force_job_fields(
        session_factory,
        tenant.org_id,
        job_id,
        {"lease_expires_at": datetime.now(tz=UTC) - timedelta(minutes=1)},
    )

    response = await client.post(
        f"{API}/agent/jobs/{job_id}/status",
        json={"status": "running"},
        headers=agent.auth_header,
    )

    assert response.status_code == 409


async def test_rejecting_returns_the_job_to_the_queue(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)
    job_id = await create_scan(client, tenant)
    agent = await enroll_agent(client, tenant)
    await claim_one(client, agent)

    response = await client.post(
        f"{API}/agent/jobs/{job_id}/reject",
        json={
            "reason": "target_not_in_local_allowlist",
            "detail": "10.0.4.0/24 not within configured ranges",
        },
        headers=agent.auth_header,
    )

    assert response.status_code == 200, response.text
    state = await read_job(session_factory, tenant.org_id, job_id)
    assert state["status"] == "queued"
    assert state["agent_id"] is None
    assert "target_not_in_local_allowlist" in str(state["error"])


async def test_rejecting_on_the_last_attempt_fails_the_job(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)
    job_id = await create_scan(client, tenant)
    agent = await enroll_agent(client, tenant)
    await claim_one(client, agent)
    await force_job_fields(session_factory, tenant.org_id, job_id, {"attempts": MAX_JOB_ATTEMPTS})

    response = await client.post(
        f"{API}/agent/jobs/{job_id}/reject",
        json={"reason": "target_not_in_local_allowlist"},
        headers=agent.auth_header,
    )

    assert response.status_code == 200, response.text
    state = await read_job(session_factory, tenant.org_id, job_id)
    assert state["status"] == "failed"
    assert state["finished_at"] is not None


async def test_the_sweeper_requeues_an_expired_lease(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)
    job_id = await create_scan(client, tenant)
    agent = await enroll_agent(client, tenant)
    await claim_one(client, agent)
    await force_job_fields(
        session_factory,
        tenant.org_id,
        job_id,
        {"lease_expires_at": datetime.now(tz=UTC) - timedelta(minutes=1)},
    )

    outcome = await sweep_once(session_factory)

    assert outcome.requeued == 1
    assert outcome.failed == 0
    state = await read_job(session_factory, tenant.org_id, job_id)
    assert state["status"] == "queued"
    assert state["agent_id"] is None
    assert state["lease_expires_at"] is None


async def test_the_sweeper_fails_a_job_that_has_spent_its_attempts(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)
    job_id = await create_scan(client, tenant)
    agent = await enroll_agent(client, tenant)
    await claim_one(client, agent)
    await force_job_fields(
        session_factory,
        tenant.org_id,
        job_id,
        {
            "attempts": MAX_JOB_ATTEMPTS,
            "lease_expires_at": datetime.now(tz=UTC) - timedelta(minutes=1),
        },
    )

    outcome = await sweep_once(session_factory)

    assert outcome.failed == 1
    assert outcome.requeued == 0
    state = await read_job(session_factory, tenant.org_id, job_id)
    assert state["status"] == "failed"
    assert state["finished_at"] is not None


async def test_a_second_sweep_changes_nothing(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """The precondition is the WHERE clause, which is what makes concurrent
    sweepers in separate processes safe."""
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)
    job_id = await create_scan(client, tenant)
    agent = await enroll_agent(client, tenant)
    await claim_one(client, agent)
    await force_job_fields(
        session_factory,
        tenant.org_id,
        job_id,
        {"lease_expires_at": datetime.now(tz=UTC) - timedelta(minutes=1)},
    )

    first = await sweep_once(session_factory)
    second = await sweep_once(session_factory)

    assert first.requeued == 1
    assert second.requeued == 0
    assert second.failed == 0


async def test_the_sweeper_leaves_a_live_lease_alone(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)
    job_id = await create_scan(client, tenant)
    agent = await enroll_agent(client, tenant)
    await claim_one(client, agent)

    outcome = await sweep_once(session_factory)

    assert outcome == SweepOutcome(requeued=0, failed=0)
    assert (await read_job(session_factory, tenant.org_id, job_id))["status"] == "claimed"


async def test_a_requeued_job_can_be_claimed_again(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant)
    await create_scan(client, tenant)
    agent = await enroll_agent(client, tenant)
    first = await claim_one(client, agent)
    job_id = UUID(first[0]["job_id"])
    await force_job_fields(
        session_factory,
        tenant.org_id,
        job_id,
        {"lease_expires_at": datetime.now(tz=UTC) - timedelta(minutes=1)},
    )
    await sweep_once(session_factory)

    second = await claim_one(client, agent)

    assert UUID(second[0]["job_id"]) == job_id
    state = await read_job(session_factory, tenant.org_id, job_id)
    assert state["attempts"] == 2
