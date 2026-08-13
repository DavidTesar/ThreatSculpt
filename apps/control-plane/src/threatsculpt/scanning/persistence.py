"""Writing a validated result batch, in a fixed number of round trips.

Split out of ``ingest`` because the two answer different questions. ``ingest``
decides *what may be stored* — the security boundary in docs/AGENT-PROTOCOL.md
§5 — and this module decides *how it gets stored*. Keeping them apart means the
containment filtering can be read without wading through upsert mechanics, and
that a change made for speed cannot quietly become a change to what is accepted.

**Why this is not a loop of ``ScopedRepository.create``.** That is what it was,
and ``create`` flushes. One host cost three round trips plus one per port, all
inside a single write transaction. Measured on a payload comfortably inside every
documented cap (9.57 MB, 4,096 hosts, 368,640 ports — all legal per
``scanning.schemas``): **335 seconds**, RSS 197→609 MB, one pooled connection and
one open write transaction held for the whole of it, from a single agent API key
against a limiter that permits 100 requests a minute. It is equally a landmine
for an honest ``-p-`` scan of a busy /24.

The shape here is four statements, whatever the batch size:

1. one upsert of every asset, ``RETURNING`` the ids;
2. one upsert of every scan result, ``RETURNING`` the ids;
3. one delete of the ports belonging to those results;
4. one insert of every port.

``ON CONFLICT`` rather than select-then-branch does more than save a round trip:
it makes the idempotency in §5 a property of the statement instead of a property
of a race-free interleaving. Two chunks of one job arriving at once cannot both
decide the asset is missing.

Each is handed its rows as **executemany parameters**, never as a literal
``VALUES`` list. That is not a stylistic preference: a 1,000-row ``VALUES`` is a
distinct statement with 9,000 bind parameters that SQLAlchemy has to compile from
scratch every time, and measured here the compilation cost dominated the database
work — 4,000 hosts took 6.2 s with literal values against 0.9 s as executemany.
It also removes the 65,535-parameter statement ceiling as something callers have
to think about, since the driver decides the batching.

Both upserts require each conflict key to appear at most once per batch —
PostgreSQL refuses to affect a row twice in one ``ON CONFLICT`` — which is why
``ingest`` deduplicates hosts by IP before calling here.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, insert
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.core.scoped_sql import execute_scoped
from threatsculpt.models.inventory import Asset
from threatsculpt.models.scan import Port, ScanJob, ScanResult
from threatsculpt.scanning.schemas import HostObservation
from threatsculpt.tenancy.repository import ScopedRepository
from threatsculpt.tenancy.scope import OrgScope

#: Columns an existing asset keeps unless this scan observed something better.
#: ``network_id``, ``first_seen_at`` and ``exposure`` are absent on purpose: they
#: are set when the asset is discovered and are not the scan's to overwrite —
#: ``exposure`` in particular is an operator's classification and drives scoring.
_ASSET_PRESERVED_COLUMNS = ("hostname", "mac", "os_family", "os_version")


async def store_hosts(
    session: AsyncSession,
    scope: OrgScope,
    job: ScanJob,
    hosts: Sequence[HostObservation],
    now: datetime,
) -> int:
    """Persist a batch of accepted hosts. Returns the number of ports written.

    ``hosts`` must already be filtered by ``ingest`` and free of duplicate IPs.
    """
    if not hosts:
        return 0

    asset_ids = await _upsert_assets(session, scope, job, hosts, now)
    result_ids = await _upsert_scan_results(session, scope, job, hosts, asset_ids)
    await _replace_ports(session, scope, hosts, asset_ids, result_ids)
    return sum(len(host.ports) for host in hosts)


async def _upsert_assets(
    session: AsyncSession,
    scope: OrgScope,
    job: ScanJob,
    hosts: Sequence[HostObservation],
    now: datetime,
) -> dict[str, UUID]:
    """One row per ``(org_id, ip)``; a rescan updates it rather than duplicating."""
    rows = [
        {
            "org_id": scope.org_id,
            "network_id": job.network_id,
            "ip": host.ip,
            "hostname": host.hostname,
            "mac": host.mac,
            "os_family": host.os.family if host.os else None,
            "os_version": host.os.version if host.os else None,
            "first_seen_at": now,
            "last_seen_at": now,
        }
        for host in hosts
    ]

    statement = pg_insert(Asset)
    # COALESCE, not assignment: a field this scan did not observe must not erase
    # what an earlier one learned. This is the ``known = {...}`` filter the
    # row-at-a-time version applied in Python, expressed in the upsert.
    preserved = {
        column: func.coalesce(statement.excluded[column], Asset.__table__.c[column])
        for column in _ASSET_PRESERVED_COLUMNS
    }
    upsert = statement.on_conflict_do_update(
        index_elements=[Asset.org_id, Asset.ip],
        set_={**preserved, "last_seen_at": statement.excluded.last_seen_at},
    ).returning(Asset.id, Asset.ip)

    result = await execute_scoped(session, scope, upsert, rows)
    return {str(row.ip): row.id for row in result.all()}


async def _upsert_scan_results(
    session: AsyncSession,
    scope: OrgScope,
    job: ScanJob,
    hosts: Sequence[HostObservation],
    asset_ids: dict[str, UUID],
) -> dict[UUID, UUID]:
    """One row per ``(job, asset)``, per docs/AGENT-PROTOCOL.md §5. Keyed by asset id."""
    rows = [
        {
            "org_id": scope.org_id,
            "scan_job_id": job.id,
            "asset_id": asset_ids[host.ip],
            "state": host.state,
            "raw": host.model_dump(mode="json"),
        }
        for host in hosts
        if host.ip in asset_ids
    ]

    statement = pg_insert(ScanResult)
    upsert = statement.on_conflict_do_update(
        index_elements=[ScanResult.scan_job_id, ScanResult.asset_id],
        set_={"state": statement.excluded.state, "raw": statement.excluded.raw},
    ).returning(ScanResult.id, ScanResult.asset_id)

    if not rows:
        return {}

    result = await execute_scoped(session, scope, upsert, rows)
    return {row.asset_id: row.id for row in result.all()}


async def _replace_ports(
    session: AsyncSession,
    scope: OrgScope,
    hosts: Sequence[HostObservation],
    asset_ids: dict[str, UUID],
    result_ids: dict[UUID, UUID],
) -> None:
    """Replace rather than append.

    A retried chunk must leave exactly one set of ports, and a rescan must not
    accumulate ports that have since closed. Deleting every affected result's
    ports in one statement before inserting keeps both true without a per-port
    conflict key.
    """
    ports = ScopedRepository(session, scope, Port)
    affected = list(result_ids.values())
    if affected:
        await ports.delete_where(Port.scan_result_id.in_(affected))

    rows: list[dict[str, Any]] = []
    for host in hosts:
        asset_id = asset_ids.get(host.ip)
        scan_result_id = result_ids.get(asset_id) if asset_id is not None else None
        if asset_id is None or scan_result_id is None:
            continue
        rows.extend(
            {
                "org_id": scope.org_id,
                "scan_result_id": scan_result_id,
                "asset_id": asset_id,
                "port": observation.port,
                "protocol": observation.protocol,
                "state": observation.state,
                "service": observation.service,
                "product": observation.product,
                "version": observation.version,
                "cpe": list(observation.cpes),
            }
            for observation in host.ports
        )

    if rows:
        # executemany: no RETURNING is needed, so the driver batches these
        # without the parameter accounting the upserts above have to do.
        await execute_scoped(session, scope, insert(Port), rows)
