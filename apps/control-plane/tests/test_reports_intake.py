"""Admission control on ``POST /reports``.

Measured before the fix, on a tenant with 30,000 findings: one render took
4.1 s, and sixty requests — all identical, all inside the 100/min limiter — made
the sixtieth ``POST`` take **37 s to be accepted**, because the renders share an
event loop with the request handlers and starve them. That lands on every tenant
on the worker, not only the one that asked. After the fix the same sixty requests
are accepted in 0.6 s.

Coalescing, the concurrency ceiling and retention are tested separately here
because they fail differently: the first is a correctness property (the same
request must not become two renders), the second is a refusal, the third is a
deletion.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from httpx import AsyncClient, Response
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.factories import API, Tenant, register_tenant
from threatsculpt.core.pagination import PaginationParams
from threatsculpt.db.session import scoped_session
from threatsculpt.models.report import Report, ReportStatus
from threatsculpt.reports import intake, runner
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope


async def _request(client: AsyncClient, tenant: Tenant, **body: object) -> Response:
    payload: dict[str, object] = {"format": "html", **body}
    return await client.post(f"{API}/reports", json=payload, headers=tenant.auth_header)


async def _report_count(session_factory: async_sessionmaker[AsyncSession], org_id: UUID) -> int:
    scope = OrgScope.for_system(org_id)
    async with scoped_session(session_factory, scope) as session:
        return await ScopedRepository(session, scope, Report).count()


@asynccontextmanager
async def held_renders(client: AsyncClient) -> AsyncIterator[None]:
    """Take every render permit, so admitted reports stay ``queued``.

    Without this these tests race the renderer: an empty org renders in
    milliseconds, so whether a second request coalesces depends on how fast the
    first one finished. Holding the permits makes "queued" the state under test
    rather than a timing accident, which is also the state that matters — the
    behaviour exists for the moment a worker is busy.
    """
    app_state = client._transport.app.state  # type: ignore[attr-defined]
    permit = runner.render_permit(app_state)
    for _ in range(runner.MAX_CONCURRENT_RENDERS):
        await permit.acquire()
    try:
        yield
    finally:
        for _ in range(runner.MAX_CONCURRENT_RENDERS):
            permit.release()
        await runner.drain(app_state)


# --- coalescing -------------------------------------------------------------


async def test_identical_queued_requests_become_one_render(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    tenant = await register_tenant(client, "acme")

    async with held_renders(client):
        first = await _request(client, tenant)
        assert first.status_code == 202, first.text
        report_id = first.json()["data"]["report_id"]

        repeats = [await _request(client, tenant) for _ in range(10)]
        assert all(response.status_code == 202 for response in repeats)
        assert {response.json()["data"]["report_id"] for response in repeats} == {report_id}

        assert await _report_count(session_factory, tenant.org_id) == 1


async def test_a_different_scope_is_a_different_report(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Coalescing must key on everything that determines the output."""
    tenant = await register_tenant(client, "acme")

    async with held_renders(client):
        first = await _request(client, tenant)
        second = await _request(client, tenant, scope={"service_ids": [str(uuid4())]})

        assert first.status_code == 202 and second.status_code == 202, second.text
        assert first.json()["data"]["report_id"] != second.json()["data"]["report_id"]
        assert await _report_count(session_factory, tenant.org_id) == 2


async def test_coalescing_does_not_reach_across_tenants(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")

    async with held_renders(client):
        first = await _request(client, alpha)
        second = await _request(client, beta)

        assert first.json()["data"]["report_id"] != second.json()["data"]["report_id"]
        assert await _report_count(session_factory, alpha.org_id) == 1
        assert await _report_count(session_factory, beta.org_id) == 1


async def test_a_finished_report_is_not_coalesced_onto(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Asking again after one is ready means "give me a current one"."""
    tenant = await register_tenant(client, "acme")
    first = await _request(client, tenant)
    await runner.drain(client._transport.app.state)  # type: ignore[attr-defined]

    second = await _request(client, tenant)
    assert second.json()["data"]["report_id"] != first.json()["data"]["report_id"]
    await runner.drain(client._transport.app.state)  # type: ignore[attr-defined]


# --- the concurrency ceiling ------------------------------------------------


async def test_an_org_past_its_ceiling_is_refused_with_retry_after(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Distinct scopes, so coalescing cannot absorb them."""
    tenant = await register_tenant(client, "acme")

    accepted = 0
    refused = None
    async with held_renders(client):
        for _ in range(intake.MAX_PENDING_REPORTS_PER_ORG + 2):
            response = await _request(client, tenant, scope={"service_ids": [str(uuid4())]})
            if response.status_code == 202:
                accepted += 1
            else:
                refused = response
                break

        assert accepted == intake.MAX_PENDING_REPORTS_PER_ORG
        assert refused is not None
        assert refused.status_code == 429, refused.text
        assert refused.headers.get("Retry-After") == str(intake.RETRY_AFTER_SECONDS)

    # Once the queue drains the org can request again.
    again = await _request(client, tenant, scope={"service_ids": [str(uuid4())]})
    assert again.status_code == 202, again.text
    await runner.drain(client._transport.app.state)  # type: ignore[attr-defined]


async def test_one_orgs_ceiling_does_not_refuse_another(client: AsyncClient) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")

    async with held_renders(client):
        for _ in range(intake.MAX_PENDING_REPORTS_PER_ORG):
            assert (
                await _request(client, alpha, scope={"service_ids": [str(uuid4())]})
            ).status_code == 202

        assert (await _request(client, alpha)).status_code == 429
        assert (await _request(client, beta)).status_code == 202


async def test_renders_are_bounded_on_the_worker(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """The semaphore, not the row count: admitted work still has to be paced."""
    tenant = await register_tenant(client, "acme")
    app_state = client._transport.app.state  # type: ignore[attr-defined]

    async with held_renders(client):
        for _ in range(intake.MAX_PENDING_REPORTS_PER_ORG):
            assert (
                await _request(client, tenant, scope={"service_ids": [str(uuid4())]})
            ).status_code == 202

        # Admitted, scheduled, and none of them started: the permits are all held.
        assert len(getattr(app_state, runner.TASKS_ATTR)) == intake.MAX_PENDING_REPORTS_PER_ORG
        assert runner.render_permit(app_state).locked()

        scope = OrgScope.for_system(tenant.org_id)
        async with scoped_session(session_factory, scope) as session:
            queued = await ScopedRepository(session, scope, Report).count(
                Report.status == ReportStatus.QUEUED.value
            )
        assert queued == intake.MAX_PENDING_REPORTS_PER_ORG


# --- retention --------------------------------------------------------------


async def test_reports_past_the_retention_window_are_removed(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    tenant = await register_tenant(client, "acme")
    first = await _request(client, tenant)
    await runner.drain(client._transport.app.state)  # type: ignore[attr-defined]
    old_id = first.json()["data"]["report_id"]

    scope = OrgScope.for_system(tenant.org_id)
    stale = datetime.now(tz=UTC) - timedelta(days=intake.REPORT_RETENTION_DAYS + 1)
    async with scoped_session(session_factory, scope) as session:
        repository = ScopedRepository(session, scope, Report)
        assert await repository.update_where({"created_at": stale}) == 1

    # The next request carries the purge.
    assert (await _request(client, tenant)).status_code == 202
    await runner.drain(client._transport.app.state)  # type: ignore[attr-defined]

    gone = await client.get(f"{API}/reports/{old_id}", headers=tenant.auth_header)
    assert gone.status_code == 404


async def test_only_the_newest_reports_are_kept(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    """Bounded storage even inside the retention window."""
    tenant = await register_tenant(client, "acme")
    scope = OrgScope.for_system(tenant.org_id)
    now = datetime.now(tz=UTC)

    async with scoped_session(session_factory, scope) as session:
        repository = ScopedRepository(session, scope, Report)
        for index in range(intake.MAX_STORED_REPORTS_PER_ORG + 5):
            created = await repository.create(
                type="executive_summary",
                format="html",
                status=ReportStatus.READY.value,
                scope={},
                content="<html></html>",
                byte_size=13,
            )
            await repository.update(created, {"created_at": now - timedelta(minutes=index)})

        removed = await intake.purge_expired(session, scope)
        assert removed == 5

        remaining = await repository.list(PaginationParams(per_page=1))
        assert remaining.total == intake.MAX_STORED_REPORTS_PER_ORG


async def test_purging_one_org_leaves_another_alone(
    client: AsyncClient, session_factory: async_sessionmaker[AsyncSession]
) -> None:
    alpha = await register_tenant(client, "alpha")
    beta = await register_tenant(client, "beta")
    await _request(client, beta)
    await runner.drain(client._transport.app.state)  # type: ignore[attr-defined]

    beta_scope = OrgScope.for_system(beta.org_id)
    stale = datetime.now(tz=UTC) - timedelta(days=intake.REPORT_RETENTION_DAYS + 1)
    async with scoped_session(session_factory, beta_scope) as session:
        await ScopedRepository(session, beta_scope, Report).update_where({"created_at": stale})

    alpha_scope = OrgScope.for_system(alpha.org_id)
    async with scoped_session(session_factory, alpha_scope) as session:
        assert await intake.purge_expired(session, alpha_scope) == 0

    assert await _report_count(session_factory, beta.org_id) == 1
