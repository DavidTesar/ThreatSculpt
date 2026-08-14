"""The path from a finished scan to a finding, end to end.

Before this existed, ``generate_findings`` had no caller in ``src/`` at all: a
customer could scan a network correctly and the dashboard stayed empty forever.
So the assertions here are deliberately about the *connection* rather than about
matching, which ``test_enrichment_pipeline`` already covers — that ingest queues
the job, that the worker picks it up on its own, that it covers every port, and
that it never reaches past the org it was given.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.agent_fixtures import (
    EnrolledAgent,
    claim_one,
    create_scan,
    enroll_agent,
    force_job_fields,
    host,
    results_body,
)
from tests.factories import API, Tenant, create_network, register_tenant
from tests.scoring_factories import (
    LOG4J_CPE,
    scope_for,
    seed_asset_with_port,
    seed_vulnerability,
)
from threatsculpt.core.scoped_sql import execute_scoped
from threatsculpt.db.session import bind_scope, scoped_session
from threatsculpt.enrichment import worker
from threatsculpt.enrichment.service import PORTS_PER_PAGE, generate_all_findings, generate_findings
from threatsculpt.enrichment.worker import ENRICHMENT_LEASE, enrich_once, enrich_org
from threatsculpt.models.finding import Finding
from threatsculpt.models.inventory import Asset
from threatsculpt.models.scan import (
    MAX_ENRICHMENT_ATTEMPTS,
    EnrichmentStatus,
    Port,
    ScanJob,
    ScanResult,
)
from threatsculpt.tenancy.repository import ScopedRepository

Factory = async_sessionmaker[AsyncSession]

#: A ``-p-`` sweep of a /24 with twenty open ports on every live host: 5,080
#: ports, eighty above ``PORTS_PER_PAGE``. The number is the point — the pipeline
#: used to enrich whichever 5,000 of them the planner returned first.
HOSTS_IN_A_SLASH_24 = 254
OPEN_PORTS_PER_HOST = 20
PORTS_IN_A_FULL_SWEEP = HOSTS_IN_A_SLASH_24 * OPEN_PORTS_PER_HOST

#: Rows per INSERT while seeding. The extended query protocol binds at most
#: 65,535 parameters in one statement, which a 5,080-row insert would exceed.
SEED_BATCH_SIZE = 500


@pytest.fixture
async def tenant(client: AsyncClient) -> Tenant:
    return await register_tenant(client, "worker-org")


# --- helpers ----------------------------------------------------------------


async def _enrichment_state(factory: Factory, org_id: UUID, job_id: UUID) -> dict[str, Any]:
    scope = scope_for(org_id)
    async with scoped_session(factory, scope) as session:
        job = await ScopedRepository(session, scope, ScanJob).get_or_404(job_id)
        return {
            "status": job.status,
            "enrichment_status": job.enrichment_status,
            "enrichment_attempts": job.enrichment_attempts,
            "lease": job.enrichment_lease_expires_at,
        }


async def _finding_port_ids(factory: Factory, org_id: UUID) -> list[UUID]:
    scope = scope_for(org_id)
    async with scoped_session(factory, scope) as session:
        result = await execute_scoped(
            session, scope, select(Finding.port_id).where(Finding.org_id == org_id)
        )
        return [row.port_id for row in result.all()]


async def _every_finding_org_id(factory: Factory, org_id: UUID) -> set[UUID]:
    """Org ids on findings, read under ``org_id``'s own scope.

    Scoped rather than global on purpose: an unscoped read is refused by the
    tenancy guard, so the only honest way to ask "did anything of B's appear" is
    to look with B's own scope and expect nothing.
    """
    scope = scope_for(org_id)
    async with scoped_session(factory, scope) as session:
        result = await execute_scoped(
            session, scope, select(Finding.org_id).where(Finding.org_id == org_id)
        )
        return {row.org_id for row in result.all()}


async def _seed_full_sweep(factory: Factory, org_id: UUID) -> tuple[UUID, tuple[UUID, ...]]:
    """One completed ``vulnerability`` job over a /24, queued for enrichment.

    Seeded as Core inserts rather than one ORM object per row: 254 assets, 254
    scan results and 5,080 ports is a fixture, not a test of the ORM.
    """
    scope = scope_for(org_id)
    async with scoped_session(factory, scope) as session:
        job = await ScopedRepository(session, scope, ScanJob).create(
            target="10.0.4.0/24",
            profile="vulnerability",
            status="completed",
            enrichment_status=EnrichmentStatus.PENDING.value,
        )
        asset_ids = await _insert_returning(
            session,
            scope,
            Asset,
            [
                {
                    "org_id": org_id,
                    "ip": f"10.0.4.{index + 1}",
                    "hostname": f"host-{index + 1}",
                    "exposure": "internal",
                }
                for index in range(HOSTS_IN_A_SLASH_24)
            ],
            Asset.id,
        )
        result_ids = await _insert_returning(
            session,
            scope,
            ScanResult,
            [
                {"org_id": org_id, "scan_job_id": job.id, "asset_id": asset_id, "state": "up"}
                for asset_id in asset_ids
            ],
            ScanResult.id,
        )
        port_ids = await _insert_returning(
            session,
            scope,
            Port,
            [
                {
                    "org_id": org_id,
                    "scan_result_id": result_id,
                    "asset_id": asset_id,
                    "port": 8000 + offset,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http",
                    "product": "Apache log4j",
                    "version": "2.14.1",
                    "cpe": [LOG4J_CPE],
                }
                for asset_id, result_id in zip(asset_ids, result_ids, strict=True)
                for offset in range(OPEN_PORTS_PER_HOST)
            ],
            Port.id,
        )
        return job.id, port_ids


async def _insert_returning(
    session: AsyncSession,
    scope: Any,
    model: Any,
    rows: list[dict[str, Any]],
    id_column: Any,
) -> tuple[UUID, ...]:
    inserted: list[UUID] = []
    for index in range(0, len(rows), SEED_BATCH_SIZE):
        batch = rows[index : index + SEED_BATCH_SIZE]
        result = await execute_scoped(
            session, scope, pg_insert(model).values(batch).returning(id_column)
        )
        inserted.extend(result.scalars().all())
    return tuple(inserted)


async def _queued_job(client: AsyncClient, tenant: Tenant) -> tuple[UUID, EnrolledAgent]:
    await create_network(client, tenant)
    job_id = await create_scan(client, tenant)
    agent = await enroll_agent(client, tenant)
    await claim_one(client, agent)
    return job_id, agent


# --- ingest queues the job --------------------------------------------------


async def test_the_final_result_batch_queues_the_job_for_enrichment(
    client: AsyncClient, session_factory: Factory, tenant: Tenant
) -> None:
    """The connection that did not exist: completing a job schedules its findings."""
    # Arrange
    job_id, agent = await _queued_job(client, tenant)

    # Act
    response = await client.post(
        f"{API}/agent/jobs/{job_id}/results",
        json=results_body((host("10.0.4.12"),)),
        headers=agent.auth_header,
    )

    # Assert
    assert response.status_code == 202, response.text
    state = await _enrichment_state(session_factory, tenant.org_id, job_id)
    assert state["status"] == "completed"
    assert state["enrichment_status"] == EnrichmentStatus.PENDING.value


async def test_a_non_final_batch_does_not_queue_the_job(
    client: AsyncClient, session_factory: Factory, tenant: Tenant
) -> None:
    """A chunked scan is queued when it finishes, not when it starts."""
    job_id, agent = await _queued_job(client, tenant)

    response = await client.post(
        f"{API}/agent/jobs/{job_id}/results",
        json=results_body((host("10.0.4.12"),), final=False),
        headers=agent.auth_header,
    )

    assert response.status_code == 202, response.text
    state = await _enrichment_state(session_factory, tenant.org_id, job_id)
    assert state["status"] == "running"
    assert state["enrichment_status"] is None


# --- the worker -------------------------------------------------------------


async def test_the_worker_turns_a_queued_job_into_findings(
    session_factory: Factory, tenant: Tenant
) -> None:
    # Arrange
    org = tenant.org_id
    await seed_vulnerability(session_factory, org)
    seeded = await seed_asset_with_port(session_factory, org)
    await force_job_fields(
        session_factory,
        org,
        seeded.scan_job_id,
        {"enrichment_status": EnrichmentStatus.PENDING.value},
    )

    # Act
    outcome = await enrich_once(session_factory)

    # Assert
    assert outcome.jobs_enriched == 1
    assert outcome.findings_written == 1
    assert await _finding_port_ids(session_factory, org) == [seeded.port_id]
    state = await _enrichment_state(session_factory, org, seeded.scan_job_id)
    assert state["enrichment_status"] == EnrichmentStatus.COMPLETE.value
    assert state["enrichment_attempts"] == 1
    assert state["lease"] is None


async def test_a_job_nobody_queued_is_left_alone(session_factory: Factory, tenant: Tenant) -> None:
    """A pass must not enrich jobs that never completed — the queue is the trigger."""
    org = tenant.org_id
    await seed_vulnerability(session_factory, org)
    seeded = await seed_asset_with_port(session_factory, org)

    outcome = await enrich_once(session_factory)

    assert outcome.jobs_enriched == 0
    assert await _finding_port_ids(session_factory, org) == []
    state = await _enrichment_state(session_factory, org, seeded.scan_job_id)
    assert state["enrichment_status"] is None
    assert state["enrichment_attempts"] == 0


async def test_a_second_pass_does_not_re_enrich_a_completed_job(
    session_factory: Factory, tenant: Tenant
) -> None:
    org = tenant.org_id
    await seed_vulnerability(session_factory, org)
    seeded = await seed_asset_with_port(session_factory, org)
    await force_job_fields(
        session_factory,
        org,
        seeded.scan_job_id,
        {"enrichment_status": EnrichmentStatus.PENDING.value},
    )
    await enrich_once(session_factory)

    second = await enrich_once(session_factory)

    assert second.jobs_enriched == 0
    assert (await _enrichment_state(session_factory, org, seeded.scan_job_id))[
        "enrichment_attempts"
    ] == 1


# --- paging -----------------------------------------------------------------


async def test_a_sweep_above_the_page_cap_is_enriched_completely(
    session_factory: Factory, tenant: Tenant
) -> None:
    """5,080 ports through the real worker: every one enriched, exactly once.

    The fixture is deliberately above ``PORTS_PER_PAGE``. Before deterministic
    paging this produced findings for whichever 5,000 ports the planner reached
    first, and a different 5,000 on the next run.
    """
    # Arrange
    org = tenant.org_id
    await seed_vulnerability(session_factory, org)
    job_id, port_ids = await _seed_full_sweep(session_factory, org)
    assert len(port_ids) == PORTS_IN_A_FULL_SWEEP > PORTS_PER_PAGE

    # Act
    outcome = await enrich_once(session_factory)

    # Assert — one finding per port, and the set is the whole sweep.
    assert outcome.jobs_enriched == 1
    enriched = await _finding_port_ids(session_factory, org)
    assert len(enriched) == PORTS_IN_A_FULL_SWEEP
    assert set(enriched) == set(port_ids)
    assert (await _enrichment_state(session_factory, org, job_id))["enrichment_status"] == (
        EnrichmentStatus.COMPLETE.value
    )


async def test_the_walk_pages_rather_than_truncating(
    session_factory: Factory, tenant: Tenant
) -> None:
    """One page stops at the cap; the walk does not, and the pages are disjoint."""
    # Arrange
    org = tenant.org_id
    await seed_vulnerability(session_factory, org)
    _, port_ids = await _seed_full_sweep(session_factory, org)
    scope = scope_for(org)

    # Act
    async with scoped_session(session_factory, scope) as session:
        first = await generate_findings(session, scope)
        second = await generate_findings(session, scope, after_port_id=first.last_port_id)
    async with scoped_session(session_factory, scope) as session:
        walked = await generate_all_findings(session, scope)

    # Assert — the cap is real, and the walk is what gets past it.
    assert first.ports_examined == PORTS_PER_PAGE
    assert second.ports_examined == PORTS_IN_A_FULL_SWEEP - PORTS_PER_PAGE
    assert walked.pages == 2
    assert walked.ports_examined == PORTS_IN_A_FULL_SWEEP == len(port_ids)


async def test_paging_is_stable_across_runs(session_factory: Factory, tenant: Tenant) -> None:
    """The same page twice returns the same ports — an ordering, not a guess."""
    org = tenant.org_id
    await seed_vulnerability(session_factory, org)
    await _seed_full_sweep(session_factory, org)
    scope = scope_for(org)

    async with scoped_session(session_factory, scope) as session:
        first = await generate_findings(session, scope)
    async with scoped_session(session_factory, scope) as session:
        again = await generate_findings(session, scope)

    assert first.last_port_id == again.last_port_id


async def test_a_page_of_ports_with_no_match_still_advances(
    session_factory: Factory, tenant: Tenant
) -> None:
    """The cursor belongs to the page, not to what matched.

    With an empty mirror no page produces a finding, so a cursor taken from the
    matches would never move and the walk would repeat page one forever.
    """
    org = tenant.org_id
    await _seed_full_sweep(session_factory, org)  # no vulnerability seeded
    scope = scope_for(org)

    async with scoped_session(session_factory, scope) as session:
        walked = await generate_all_findings(session, scope, page_size=1000)

    assert walked.ports_examined == PORTS_IN_A_FULL_SWEEP
    assert walked.findings_written == 0


async def test_a_walk_whose_last_page_is_exactly_full_still_terminates(
    session_factory: Factory, tenant: Tenant
) -> None:
    """The off-by-one: six ports at a page size of three is three pages, not two."""
    org = tenant.org_id
    await seed_vulnerability(session_factory, org)
    for index in range(6):
        await seed_asset_with_port(session_factory, org, ip=f"10.0.9.{index + 1}")
    scope = scope_for(org)

    async with scoped_session(session_factory, scope) as session:
        walked = await generate_all_findings(session, scope, page_size=3)

    assert walked.pages == 3
    assert walked.ports_examined == 6
    assert walked.findings_written == 6


async def test_an_unusable_page_size_is_refused_at_the_boundary(
    session_factory: Factory, tenant: Tenant
) -> None:
    scope = scope_for(tenant.org_id)
    async with scoped_session(session_factory, scope) as session:
        with pytest.raises(ValueError, match="page_size"):
            await generate_findings(session, scope, page_size=0)


# --- tenancy ----------------------------------------------------------------


async def test_one_orgs_pass_writes_no_row_carrying_another_orgs_id(
    client: AsyncClient, session_factory: Factory
) -> None:
    """Both orgs have the same vulnerable host queued. Only A is enriched."""
    # Arrange
    alpha = await register_tenant(client, "worker-alpha")
    beta = await register_tenant(client, "worker-beta")
    for org in (alpha.org_id, beta.org_id):
        await seed_vulnerability(session_factory, org)
        seeded = await seed_asset_with_port(session_factory, org, ip="10.0.4.12")
        await force_job_fields(
            session_factory,
            org,
            seeded.scan_job_id,
            {"enrichment_status": EnrichmentStatus.PENDING.value},
        )

    # Act
    outcome = await enrich_org(session_factory, alpha.org_id)

    # Assert
    assert outcome.jobs_enriched == 1
    assert await _every_finding_org_id(session_factory, alpha.org_id) == {alpha.org_id}
    assert await _every_finding_org_id(session_factory, beta.org_id) == set()


# --- lease and attempts -----------------------------------------------------


async def test_a_lapsed_lease_returns_the_job_to_the_queue(
    session_factory: Factory, tenant: Tenant
) -> None:
    """The worker that claimed it died. Nothing else would ever pick it up."""
    org = tenant.org_id
    await seed_vulnerability(session_factory, org)
    seeded = await seed_asset_with_port(session_factory, org)
    await force_job_fields(
        session_factory,
        org,
        seeded.scan_job_id,
        {
            "enrichment_status": EnrichmentStatus.RUNNING.value,
            "enrichment_attempts": 1,
            "enrichment_lease_expires_at": _long_expired(),
        },
    )

    outcome = await enrich_once(session_factory)

    assert outcome.jobs_enriched == 1
    state = await _enrichment_state(session_factory, org, seeded.scan_job_id)
    assert state["enrichment_status"] == EnrichmentStatus.COMPLETE.value
    assert state["enrichment_attempts"] == 2


async def test_a_held_lease_is_left_alone(session_factory: Factory, tenant: Tenant) -> None:
    """A job another worker is still working on is not taken from it."""
    org = tenant.org_id
    await seed_vulnerability(session_factory, org)
    seeded = await seed_asset_with_port(session_factory, org)
    await force_job_fields(
        session_factory,
        org,
        seeded.scan_job_id,
        {
            "enrichment_status": EnrichmentStatus.RUNNING.value,
            "enrichment_attempts": 1,
            "enrichment_lease_expires_at": _not_yet_expired(),
        },
    )

    outcome = await enrich_once(session_factory)

    assert outcome.jobs_enriched == 0
    assert (await _enrichment_state(session_factory, org, seeded.scan_job_id))[
        "enrichment_attempts"
    ] == 1


async def test_a_job_that_exhausts_every_attempt_is_abandoned(
    session_factory: Factory, tenant: Tenant
) -> None:
    """Better a job marked failed than one handed to a fourth worker to kill."""
    org = tenant.org_id
    await seed_vulnerability(session_factory, org)
    seeded = await seed_asset_with_port(session_factory, org)
    await force_job_fields(
        session_factory,
        org,
        seeded.scan_job_id,
        {
            "enrichment_status": EnrichmentStatus.RUNNING.value,
            "enrichment_attempts": MAX_ENRICHMENT_ATTEMPTS,
            "enrichment_lease_expires_at": _long_expired(),
        },
    )

    outcome = await enrich_once(session_factory)

    assert outcome.jobs_failed == 1
    assert outcome.jobs_enriched == 0
    state = await _enrichment_state(session_factory, org, seeded.scan_job_id)
    assert state["enrichment_status"] == EnrichmentStatus.FAILED.value
    assert state["lease"] is None
    # The scan itself succeeded; only enrichment did not.
    assert state["status"] == "completed"


async def test_a_failing_job_does_not_take_the_pass_down_with_it(
    session_factory: Factory, tenant: Tenant, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One tenant's broken job must not stop the process, or every org stalls."""
    org = tenant.org_id
    await seed_vulnerability(session_factory, org)
    seeded = await seed_asset_with_port(session_factory, org)
    await force_job_fields(
        session_factory,
        org,
        seeded.scan_job_id,
        {"enrichment_status": EnrichmentStatus.PENDING.value},
    )

    async def _explode(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("matcher exploded")

    monkeypatch.setattr(worker, "generate_all_findings", _explode)
    outcome = await enrich_once(session_factory)

    assert outcome.jobs_enriched == 0
    assert await _finding_port_ids(session_factory, org) == []
    # Claimed and leased, so a later pass retries it rather than losing it.
    state = await _enrichment_state(session_factory, org, seeded.scan_job_id)
    assert state["enrichment_status"] == EnrichmentStatus.RUNNING.value
    assert state["enrichment_attempts"] == 1
    assert state["lease"] is not None


async def test_a_concurrent_worker_skips_a_job_already_being_claimed(
    session_factory: Factory, tenant: Tenant
) -> None:
    """``FOR UPDATE SKIP LOCKED``: two workers polling together take one job each.

    The first claim is held open — uncommitted — while the second runs, which is
    exactly the window in which a claim without SKIP LOCKED hands the same job
    to both.
    """
    org = tenant.org_id
    seeded = await seed_asset_with_port(session_factory, org)
    await force_job_fields(
        session_factory,
        org,
        seeded.scan_job_id,
        {"enrichment_status": EnrichmentStatus.PENDING.value},
    )
    scope = scope_for(org)

    async with session_factory() as first_session:
        await bind_scope(first_session, scope)
        first = await worker._claim(first_session, scope, 10)

        async with session_factory() as second_session:
            await bind_scope(second_session, scope)
            second = await worker._claim(second_session, scope, 10)

        await first_session.rollback()

    assert first == (seeded.scan_job_id,)
    assert second == ()


def _long_expired() -> Any:
    from datetime import UTC, datetime, timedelta

    return datetime.now(tz=UTC) - timedelta(hours=1)


def _not_yet_expired() -> Any:
    from datetime import UTC, datetime

    return datetime.now(tz=UTC) + ENRICHMENT_LEASE
