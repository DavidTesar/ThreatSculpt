"""Helpers for the agent and scan-job suites.

Deliberately not named ``test_*``: pytest must not collect it. Everything here
drives the real HTTP endpoints rather than inserting rows, so the fixtures
exercise the same enrollment and authorisation paths the tests are about.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.factories import API, Tenant
from threatsculpt.db.session import scoped_session
from threatsculpt.models.scan import ScanJob
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope


@dataclass(frozen=True, slots=True)
class EnrolledAgent:
    """An agent as a test sees it: an id and the key it will present."""

    agent_id: UUID
    api_key: str

    @property
    def auth_header(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}"}


async def issue_enrollment_token(client: AsyncClient, tenant: Tenant) -> str:
    response = await client.post(f"{API}/agents", json={}, headers=tenant.auth_header)
    assert response.status_code == 201, response.text
    token: str = response.json()["data"]["enrollment_token"]
    return token


async def enroll_agent(
    client: AsyncClient,
    tenant: Tenant,
    *,
    name: str = "hq-dc-scanner-01",
    token: str | None = None,
) -> EnrolledAgent:
    enrollment_token = token or await issue_enrollment_token(client, tenant)
    response = await client.post(
        f"{API}/agent/enroll",
        json={"enrollment_token": enrollment_token, "name": name, "version": "2.0.0"},
    )
    assert response.status_code == 201, response.text
    body = response.json()["data"]
    return EnrolledAgent(agent_id=UUID(body["agent_id"]), api_key=body["api_key"])


async def create_scan(
    client: AsyncClient,
    tenant: Tenant,
    *,
    target: str = "10.0.4.0/24",
    profile: str = "service",
) -> UUID:
    response = await client.post(
        f"{API}/scans",
        json={"target": target, "profile": profile},
        headers=tenant.auth_header,
    )
    assert response.status_code == 201, response.text
    return UUID(response.json()["data"]["id"])


async def claim_one(client: AsyncClient, agent: EnrolledAgent) -> list[dict[str, Any]]:
    response = await client.post(
        f"{API}/agent/jobs/claim", json={"capacity": 1}, headers=agent.auth_header
    )
    assert response.status_code == 200, response.text
    jobs: list[dict[str, Any]] = response.json()["data"]["jobs"]
    return jobs


async def force_job_fields(
    session_factory: async_sessionmaker[AsyncSession],
    org_id: UUID,
    job_id: UUID,
    changes: dict[str, object],
) -> None:
    """Reach past the API to age a lease or spend attempts.

    Some states — an expired lease, a job on its last attempt — are only
    reachable in production by waiting. Setting them directly is the only way to
    test the code that handles them.
    """
    scope = OrgScope.for_system(org_id)
    async with scoped_session(session_factory, scope) as session:
        repository = ScopedRepository(session, scope, ScanJob)
        job = await repository.get_or_404(job_id)
        await repository.update(job, changes)


async def read_job(
    session_factory: async_sessionmaker[AsyncSession], org_id: UUID, job_id: UUID
) -> dict[str, object]:
    """A snapshot of the row, taken outside any request."""
    scope = OrgScope.for_system(org_id)
    async with scoped_session(session_factory, scope) as session:
        repository = ScopedRepository(session, scope, ScanJob)
        job = await repository.get_or_404(job_id)
        return {
            "status": job.status,
            "attempts": job.attempts,
            "agent_id": job.agent_id,
            "lease_expires_at": job.lease_expires_at,
            "error": job.error,
            "progress_percent": job.progress_percent,
            "finished_at": job.finished_at,
        }


def host(ip: str, *, ports: tuple[dict[str, object], ...] = ()) -> dict[str, object]:
    """One host observation in the shape docs/AGENT-PROTOCOL.md §5 defines."""
    return {"ip": ip, "state": "up", "ports": list(ports)}


def port(number: int, *, service: str = "https") -> dict[str, object]:
    return {"port": number, "protocol": "tcp", "state": "open", "service": service}


def results_body(
    hosts: tuple[dict[str, object], ...],
    *,
    final: bool = True,
    finished_at: datetime | None = None,
) -> dict[str, object]:
    body: dict[str, object] = {"hosts": list(hosts), "final": final}
    if finished_at is not None:
        body["finished_at"] = finished_at.isoformat()
    return body
