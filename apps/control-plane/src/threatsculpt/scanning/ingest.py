"""Result ingest — a security boundary, not a formality.

docs/AGENT-PROTOCOL.md §5: *the control plane re-validates every submitted host
IP against the job's target CIDR and the org's registered networks. Never trust a
client, including your own agent.* An enrolled agent is a machine on a customer
network; if it is compromised, this endpoint is where the compromise would try to
write data about hosts nobody authorised a scan of.

So every host is checked twice before anything is written:

1. inside the job's ``target`` — the range this particular job was for;
2. inside a network the org has registered — the ranges the org claims at all.

Failing either drops the host, records an audit row, and lets the rest of the
batch through. Rejecting the whole submission for one bad host would let a single
malformed address discard a legitimate scan.

Ingest is idempotent on ``(job_id, host_ip)``: a retried chunk upserts onto its
existing ``scan_result`` and replaces that result's ports rather than adding a
second set. Ports are attached to exactly one ``scan_result``; v1 accumulated
them into one list shared across hosts, so host #2 inherited host #1's open
ports — a false finding on a real asset.

The writing itself lives in ``scanning.persistence``. What stays here is the
decision about what may be written at all, which is the part with a security
consequence.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.core.scoped_sql import execute_scoped
from threatsculpt.models.scan import ScanJob, ScanStatus
from threatsculpt.scanning.dispatch import LEASE_DURATION
from threatsculpt.scanning.persistence import store_hosts
from threatsculpt.scanning.schemas import (
    HostObservation,
    RejectedHost,
    ResultsSubmission,
)
from threatsculpt.scanning.sql import HOSTS_INSIDE_REGISTERED_NETWORKS
from threatsculpt.scanning.targets import network_contains_address
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope

#: docs/AGENT-PROTOCOL.md §5. Enforced on the raw body before parsing, because a
#: cap applied after deserialisation has already paid the cost it exists to avoid.
MAX_RESULT_PAYLOAD_BYTES = 10 * 1024 * 1024

OUTSIDE_TARGET = "outside_job_target"
OUTSIDE_REGISTERED_NETWORKS = "outside_registered_networks"


@dataclass(frozen=True, slots=True)
class IngestOutcome:
    hosts_ingested: int
    rejected: tuple[RejectedHost, ...]


def _deduplicated(hosts: tuple[HostObservation, ...]) -> tuple[HostObservation, ...]:
    """One observation per address, last submission winning.

    A batch may legally name the same host twice — nothing in §5 forbids it, and
    the storage layer's upserts cannot affect one row twice in a single
    statement. Last wins because within one batch the later entry is the later
    observation, which is the same rule a retried chunk already follows.
    """
    latest: dict[str, HostObservation] = {}
    for host in hosts:
        latest[host.ip] = host
    return tuple(latest.values())


async def _accepted_hosts(
    session: AsyncSession, scope: OrgScope, job: ScanJob, hosts: tuple[HostObservation, ...]
) -> tuple[tuple[HostObservation, ...], tuple[RejectedHost, ...]]:
    """Split the batch into hosts we may store and hosts we must refuse."""
    rejected: list[RejectedHost] = []
    in_target: list[HostObservation] = []
    for host in hosts:
        if network_contains_address(job.target, host.ip):
            in_target.append(host)
        else:
            rejected.append(RejectedHost(ip=host.ip, reason=OUTSIDE_TARGET))

    if not in_target:
        return (), tuple(rejected)

    result = await execute_scoped(
        session,
        scope,
        HOSTS_INSIDE_REGISTERED_NETWORKS,
        {"ips": [host.ip for host in in_target], "org_id": scope.org_id},
    )
    registered = {row.ip for row in result.all()}

    accepted = tuple(host for host in in_target if host.ip in registered)
    rejected.extend(
        RejectedHost(ip=host.ip, reason=OUTSIDE_REGISTERED_NETWORKS)
        for host in in_target
        if host.ip not in registered
    )
    return accepted, tuple(rejected)


async def ingest_results(
    session: AsyncSession,
    scope: OrgScope,
    job: ScanJob,
    payload: ResultsSubmission,
) -> IngestOutcome:
    """Validate, store, and — when the batch is the last one — complete the job."""
    now = datetime.now(tz=UTC)
    accepted, rejected = await _accepted_hosts(session, scope, job, _deduplicated(payload.hosts))

    await store_hosts(session, scope, job, accepted, now)

    await _finalise(session, scope, job, payload, now)
    return IngestOutcome(hosts_ingested=len(accepted), rejected=rejected)


async def _finalise(
    session: AsyncSession,
    scope: OrgScope,
    job: ScanJob,
    payload: ResultsSubmission,
    now: datetime,
) -> None:
    """Advance the job. Non-final chunks keep it running and renew the lease."""
    repository = ScopedRepository(session, scope, ScanJob)
    changes: dict[str, Any] = {"started_at": job.started_at or payload.started_at or now}

    if payload.final:
        changes["status"] = ScanStatus.COMPLETED.value
        changes["finished_at"] = payload.finished_at or now
        changes["lease_expires_at"] = None
        changes["progress_percent"] = 100
    else:
        changes["status"] = ScanStatus.RUNNING.value
        changes["lease_expires_at"] = now + LEASE_DURATION

    await repository.update(job, changes)
