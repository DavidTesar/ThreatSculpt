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

Ingest is idempotent on ``(job_id, host_ip)``: a retried chunk finds its existing
``scan_result`` and replaces that result's ports rather than adding a second set.
Ports are built **inside** the per-host loop and attached to exactly one
``scan_result``. v1 accumulated them into one list shared across hosts, so host #2
inherited host #1's open ports — a false finding on a real asset.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.core.scoped_sql import execute_scoped
from threatsculpt.models.inventory import Asset
from threatsculpt.models.scan import Port, ScanJob, ScanResult, ScanStatus
from threatsculpt.scanning.dispatch import LEASE_DURATION
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


async def _upsert_asset(
    session: AsyncSession, scope: OrgScope, job: ScanJob, host: HostObservation, now: datetime
) -> Asset:
    """One row per ``(org_id, ip)``; a rescan updates it rather than duplicating."""
    repository = ScopedRepository(session, scope, Asset)
    observed: dict[str, Any] = {
        "hostname": host.hostname,
        "mac": host.mac,
        "os_family": host.os.family if host.os else None,
        "os_version": host.os.version if host.os else None,
        "last_seen_at": now,
    }
    # A field the scan did not observe must not erase what is already known.
    known = {key: value for key, value in observed.items() if value is not None}

    existing = await repository.find_one(Asset.ip == host.ip)
    if existing is not None:
        return await repository.update(existing, known)
    return await repository.create(
        network_id=job.network_id, ip=host.ip, first_seen_at=now, **known
    )


async def _store_host(
    session: AsyncSession, scope: OrgScope, job: ScanJob, host: HostObservation, now: datetime
) -> None:
    """Write one host's asset, scan result, and ports. Idempotent per (job, asset)."""
    asset = await _upsert_asset(session, scope, job, host, now)

    results = ScopedRepository(session, scope, ScanResult)
    raw = host.model_dump(mode="json")
    existing = await results.find_one(
        ScanResult.scan_job_id == job.id, ScanResult.asset_id == asset.id
    )
    if existing is not None:
        scan_result = await results.update(existing, {"state": host.state, "raw": raw})
    else:
        scan_result = await results.create(
            scan_job_id=job.id, asset_id=asset.id, state=host.state, raw=raw
        )

    ports = ScopedRepository(session, scope, Port)
    # Replace rather than append: a retried chunk must leave exactly one set of
    # ports, and a rescan must not accumulate ports that have since closed.
    await ports.delete_where(Port.scan_result_id == scan_result.id)
    for observation in host.ports:
        await ports.create(
            scan_result_id=scan_result.id,
            asset_id=asset.id,
            port=observation.port,
            protocol=observation.protocol,
            state=observation.state,
            service=observation.service,
            product=observation.product,
            version=observation.version,
            cpe=list(observation.cpes),
        )


async def ingest_results(
    session: AsyncSession,
    scope: OrgScope,
    job: ScanJob,
    payload: ResultsSubmission,
) -> IngestOutcome:
    """Validate, store, and — when the batch is the last one — complete the job."""
    now = datetime.now(tz=UTC)
    accepted, rejected = await _accepted_hosts(session, scope, job, payload.hosts)

    for host in accepted:
        await _store_host(session, scope, job, host, now)

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
