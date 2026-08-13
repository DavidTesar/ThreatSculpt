"""Withdrawing scan authorisation has to actually stop the scan.

The defect these describe had no attacker in it. An operator marked a network
``authorized: false``, or deleted it outright, and the next agent poll was still
handed the job — target, ``vulnerability`` profile and all. The product kept
sending unsolicited packets at a range the customer had explicitly withdrawn
permission for, which is the one failure here with a legal consequence rather
than a technical one.

Two independent mechanisms have to hold, so each is tested on its own:

* ``scanning.sql.CLAIM_JOBS`` will not dispatch a job whose target no longer sits
  inside an authorized network, whatever state the row was left in;
* ``scanning.containment.revalidate_open_jobs`` cancels the open jobs on the
  write that removed the coverage, including ones an agent already holds.
"""

from __future__ import annotations

from uuid import UUID

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.agent_fixtures import EnrolledAgent, claim_one, create_scan, enroll_agent, read_job
from tests.factories import API, Tenant, create_network, register_tenant
from threatsculpt.core.pagination import PaginationParams
from threatsculpt.db.session import scoped_session
from threatsculpt.models.audit import AuditLog
from threatsculpt.models.scan import ScanStatus
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope


async def _claim(client: AsyncClient, agent: EnrolledAgent, capacity: int = 5) -> list[dict]:
    response = await client.post(
        f"{API}/agent/jobs/claim", json={"capacity": capacity}, headers=agent.auth_header
    )
    assert response.status_code == 200, response.text
    jobs: list[dict] = response.json()["data"]["jobs"]
    return jobs


async def _audit_actions(
    session_factory: async_sessionmaker[AsyncSession], org_id: UUID
) -> list[str]:
    scope = OrgScope.for_system(org_id)
    async with scoped_session(session_factory, scope) as session:
        rows = await ScopedRepository(session, scope, AuditLog).list(
            PaginationParams(per_page=200), order_by=[AuditLog.created_at.asc()]
        )
        return [row.action for row in rows.items]


async def _queued_job(client: AsyncClient, tenant: Tenant) -> tuple[UUID, UUID, EnrolledAgent]:
    """A registered /8, an authorized job inside it, and an enrolled agent."""
    network_id = await create_network(client, tenant)
    job_id = await create_scan(client, tenant, profile="vulnerability")
    agent = await enroll_agent(client, tenant)
    return network_id, job_id, agent


# --- the claim predicate ----------------------------------------------------


async def test_a_deauthorised_range_is_never_dispatched(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    tenant = await register_tenant(client, "acme")
    network_id, job_id, agent = await _queued_job(client, tenant)

    off = await client.patch(
        f"{API}/networks/{network_id}", json={"authorized": False}, headers=tenant.auth_header
    )
    assert off.status_code == 200, off.text

    assert await _claim(client, agent) == []
    assert (await read_job(session_factory, tenant.org_id, job_id))["status"] == (
        ScanStatus.CANCELLED.value
    )


async def test_a_deleted_network_is_never_dispatched(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """``scan_jobs.network_id`` is ``ON DELETE SET NULL``, so the job outlives the
    network with its ``target`` intact. It must not outlive its authorisation."""
    tenant = await register_tenant(client, "acme")
    network_id, job_id, agent = await _queued_job(client, tenant)

    gone = await client.delete(f"{API}/networks/{network_id}", headers=tenant.auth_header)
    assert gone.status_code == 200, gone.text

    assert await _claim(client, agent) == []
    assert (await read_job(session_factory, tenant.org_id, job_id))["status"] == (
        ScanStatus.CANCELLED.value
    )


async def test_the_claim_refuses_even_when_the_job_was_left_queued(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """The claim predicate on its own, with the cancellation pass undone.

    Belt and braces are only belt and braces if each is tested without the other.
    The job is put back to ``queued`` behind the API, exactly as a crashed
    request or a hand-edited row would leave it.
    """
    tenant = await register_tenant(client, "acme")
    network_id, job_id, agent = await _queued_job(client, tenant)
    await client.patch(
        f"{API}/networks/{network_id}", json={"authorized": False}, headers=tenant.auth_header
    )

    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        from threatsculpt.models.scan import ScanJob

        jobs = ScopedRepository(session, scope, ScanJob)
        assert (
            await jobs.update_where(
                {"status": ScanStatus.QUEUED.value, "finished_at": None, "error": None},
                ScanJob.id == job_id,
            )
            == 1
        )

    assert await _claim(client, agent) == []


async def test_a_still_covered_target_keeps_running(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Re-validate, do not blanket-cancel.

    The org authorises both ``10.0.0.0/8`` and ``10.0.4.0/24`` and then removes
    the ``/24``. Permission for ``10.0.4.0/24`` has not been withdrawn — the
    ``/8`` still covers it — so the job is still authorised and still dispatched.
    """
    tenant = await register_tenant(client, "acme")
    await create_network(client, tenant, name="Corp", cidr="10.0.0.0/8")
    narrow_id = await create_network(client, tenant, name="HQ", cidr="10.0.4.0/24")
    job_id = await create_scan(client, tenant)
    agent = await enroll_agent(client, tenant)

    gone = await client.delete(f"{API}/networks/{narrow_id}", headers=tenant.auth_header)
    assert gone.status_code == 200, gone.text

    claimed = await _claim(client, agent)
    assert [UUID(job["job_id"]) for job in claimed] == [job_id]
    assert (await read_job(session_factory, tenant.org_id, job_id))["status"] == (
        ScanStatus.CLAIMED.value
    )


async def test_an_unrelated_network_edit_stops_nothing(client: AsyncClient) -> None:
    """Renaming a network must not cancel anything; the pass runs on every write."""
    tenant = await register_tenant(client, "acme")
    network_id, job_id, agent = await _queued_job(client, tenant)

    renamed = await client.patch(
        f"{API}/networks/{network_id}", json={"name": "Corporate"}, headers=tenant.auth_header
    )
    assert renamed.status_code == 200, renamed.text

    claimed = await _claim(client, agent)
    assert [UUID(job["job_id"]) for job in claimed] == [job_id]


# --- jobs an agent is already holding ---------------------------------------


async def test_a_leased_job_is_cancelled_and_the_agent_is_refused(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """The claim predicate cannot reach this one — the job is already claimed.

    Cancelling releases the lease, which is the only lever the control plane has:
    the agent finds out by being refused on its next call, and needs no push
    channel to be told.
    """
    tenant = await register_tenant(client, "acme")
    network_id, job_id, agent = await _queued_job(client, tenant)
    assert len(await claim_one(client, agent)) == 1

    off = await client.patch(
        f"{API}/networks/{network_id}", json={"authorized": False}, headers=tenant.auth_header
    )
    assert off.status_code == 200, off.text

    stored = await read_job(session_factory, tenant.org_id, job_id)
    assert stored["status"] == ScanStatus.CANCELLED.value
    assert stored["lease_expires_at"] is None
    assert stored["agent_id"] is None

    progress = await client.post(
        f"{API}/agent/jobs/{job_id}/status",
        json={"status": "running", "progress_percent": 40},
        headers=agent.auth_header,
    )
    assert progress.status_code == 409, progress.text


async def test_a_finished_job_is_left_alone(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """History is not rewritten. A completed scan stays completed."""
    tenant = await register_tenant(client, "acme")
    network_id, job_id, agent = await _queued_job(client, tenant)
    await claim_one(client, agent)
    submitted = await client.post(
        f"{API}/agent/jobs/{job_id}/results",
        json={"hosts": [{"ip": "10.0.4.12"}], "final": True},
        headers=agent.auth_header,
    )
    assert submitted.status_code == 202, submitted.text

    await client.delete(f"{API}/networks/{network_id}", headers=tenant.auth_header)

    assert (await read_job(session_factory, tenant.org_id, job_id))["status"] == (
        ScanStatus.COMPLETED.value
    )


# --- the record of it -------------------------------------------------------


async def test_the_withdrawal_is_audited_per_job(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    tenant = await register_tenant(client, "acme")
    network_id, job_id, agent = await _queued_job(client, tenant)
    await claim_one(client, agent)

    await client.patch(
        f"{API}/networks/{network_id}", json={"authorized": False}, headers=tenant.auth_header
    )

    assert "scan_job.authorization_withdrawn" in await _audit_actions(
        session_factory, tenant.org_id
    )

    scope = OrgScope.for_system(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        audit = ScopedRepository(session, scope, AuditLog)
        row = await audit.find_one(AuditLog.action == "scan_job.authorization_withdrawn")
        assert row is not None
        assert row.target_id == str(job_id)
        assert row.audit_metadata["previous_status"] == ScanStatus.CLAIMED.value
        assert row.audit_metadata["was_leased_to_an_agent"] is True

        network_row = await audit.find_one(AuditLog.action == "network.updated")
        assert network_row is not None
        assert network_row.audit_metadata["scan_jobs_cancelled"] == 1
        assert network_row.audit_metadata["scan_jobs_cancelled_while_leased"] == 1


async def test_withdrawal_does_not_reach_another_tenant(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """One org's revocation must not touch another org's identical range."""
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    alpha_network, _, _ = await _queued_job(client, alpha)
    _, beta_job, beta_agent = await _queued_job(client, beta)

    await client.delete(f"{API}/networks/{alpha_network}", headers=alpha.auth_header)

    assert (await read_job(session_factory, beta.org_id, beta_job))["status"] == (
        ScanStatus.QUEUED.value
    )
    assert [UUID(job["job_id"]) for job in await _claim(client, beta_agent)] == [beta_job]
