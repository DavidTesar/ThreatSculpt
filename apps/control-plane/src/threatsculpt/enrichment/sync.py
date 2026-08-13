"""Syncing the global CVE mirror from NVD and CISA KEV.

``vulnerabilities`` and ``vulnerability_cpe_matches`` hold no customer data, so
they are outside the tenancy guard and are written with a plain session. One
sync serves every tenant — the point of doing enrichment server-side rather than
on the agent.

The two feeds write disjoint sets of columns on purpose. NVD owns the CVE's
description, score and configurations; KEV owns ``kev_listed`` and
``kev_due_date``. If the CVE sync also wrote the KEV columns, every NVD refresh
would silently un-flag every known-exploited vulnerability until the next KEV
run — a window in which the highest-risk findings in the product would score as
if nobody had ever exploited them.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.enrichment.feeds import VulnerabilityFeed, parse_cve_entry, parse_kev_entry
from threatsculpt.enrichment.records import CveRecord, KevRecord, SyncReport
from threatsculpt.models.cpe_match import VulnerabilityCpeMatch
from threatsculpt.models.finding import ExploitMaturity, Vulnerability

logger = logging.getLogger(__name__)

#: Rows per INSERT. Large enough to be one round trip for a normal delta, small
#: enough that a full catalogue refresh does not build a megabyte-scale statement.
BATCH_SIZE: Final = 500


async def sync_all(session: AsyncSession, feed: VulnerabilityFeed) -> SyncReport:
    """Sync CVEs then KEV. Order matters: KEV flags rows the CVE pass created."""
    report = await sync_cves(session, feed)
    flagged = await sync_kev(session, feed)
    return report.with_kev(flagged)


async def sync_cves(session: AsyncSession, feed: VulnerabilityFeed) -> SyncReport:
    entries = await feed.fetch_cves()
    records: list[CveRecord] = []
    skipped: list[str] = []
    for entry in entries:
        parsed = parse_cve_entry(entry)
        if parsed is None:
            skipped.append(str(entry.get("cve", entry))[:64])
            continue
        records.append(parsed)

    upserted = await _upsert_vulnerabilities(session, records)
    matches = await _upsert_cpe_matches(session, records)
    logger.info(
        "cve mirror synced",
        extra={"cves": upserted, "cpe_matches": matches, "skipped": len(skipped)},
    )
    return SyncReport(cves_upserted=upserted, cpe_matches_upserted=matches, skipped=tuple(skipped))


async def sync_kev(session: AsyncSession, feed: VulnerabilityFeed) -> int:
    """Flag known-exploited CVEs, creating stub rows for any NVD has not given us."""
    entries = await feed.fetch_kev()
    records = [record for record in map(parse_kev_entry, entries) if record is not None]
    if not records:
        return 0

    known = await _existing_cve_ids(session, tuple(record.cve_id for record in records))
    await _insert_kev_stubs(session, [r for r in records if r.cve_id not in known])
    await _flag_kev(session, records)
    return len(records)


async def _upsert_vulnerabilities(session: AsyncSession, records: Sequence[CveRecord]) -> int:
    """Upsert on ``cve_id``, deliberately leaving the KEV columns untouched."""
    if not records:
        return 0
    now = datetime.now(UTC)
    rows = [
        {
            "cve_id": record.cve_id,
            "description": record.description,
            "cvss_base": record.cvss_base,
            "cvss_vector": record.cvss_vector,
            "severity": record.severity,
            "cpes": list(record.cpes),
            "exploit_maturity": record.exploit_maturity,
            "published_at": record.published_at,
            "last_synced_at": now,
        }
        for record in records
    ]
    for batch in _batched(rows):
        statement = pg_insert(Vulnerability).values(batch)
        await session.execute(
            statement.on_conflict_do_update(
                index_elements=[Vulnerability.cve_id],
                set_={
                    column: statement.excluded[column]
                    for column in (
                        "description",
                        "cvss_base",
                        "cvss_vector",
                        "severity",
                        "cpes",
                        "published_at",
                        "last_synced_at",
                    )
                },
            )
        )
    await _raise_maturity(session, records)
    return len(rows)


async def _raise_maturity(session: AsyncSession, records: Sequence[CveRecord]) -> None:
    """Only ever raise the maturity tier, never lower it.

    NVD's exploit signal is a reference tag, which comes and goes as references
    are re-curated. A CVE that was ``poc`` yesterday and has no tagged reference
    today has not become less exploitable, and letting the sync walk it back
    down would make findings drift downward for a documentation change.
    """
    ranked = {ExploitMaturity.NONE.value: 0, ExploitMaturity.POC.value: 1}
    upgrades = [record for record in records if ranked.get(record.exploit_maturity, 2) > 0]
    for record in upgrades:
        await session.execute(
            update(Vulnerability)
            .where(
                Vulnerability.cve_id == record.cve_id,
                Vulnerability.exploit_maturity == ExploitMaturity.NONE.value,
            )
            .values(exploit_maturity=record.exploit_maturity)
        )


async def _upsert_cpe_matches(session: AsyncSession, records: Sequence[CveRecord]) -> int:
    rows: list[dict[str, Any]] = [
        {
            "cve_id": record.cve_id,
            "cpe23": match.cpe23,
            "vendor": match.vendor,
            "product": match.product,
            "version_start_including": match.version_range.start_including,
            "version_start_excluding": match.version_range.start_excluding,
            "version_end_including": match.version_range.end_including,
            "version_end_excluding": match.version_range.end_excluding,
            "vulnerable": match.vulnerable,
        }
        for record in records
        for match in record.cpe_matches
    ]
    for batch in _batched(rows):
        statement = pg_insert(VulnerabilityCpeMatch).values(batch)
        await session.execute(
            statement.on_conflict_do_update(
                index_elements=["cve_id", "cpe23"],
                set_={
                    column: statement.excluded[column]
                    for column in (
                        "vendor",
                        "product",
                        "version_start_including",
                        "version_start_excluding",
                        "version_end_including",
                        "version_end_excluding",
                        "vulnerable",
                    )
                },
            )
        )
    return len(rows)


async def _existing_cve_ids(session: AsyncSession, cve_ids: tuple[str, ...]) -> set[str]:
    if not cve_ids:
        return set()
    result = await session.execute(
        select(Vulnerability.cve_id).where(Vulnerability.cve_id.in_(cve_ids))
    )
    return set(result.scalars().all())


async def _insert_kev_stubs(session: AsyncSession, missing: Sequence[KevRecord]) -> None:
    """A KEV entry we have no NVD record for still has to be scoreable.

    Dropping it would mean the catalogue of vulnerabilities *known to be under
    active exploitation* is the one feed whose entries we silently discard.
    """
    if not missing:
        return
    rows = [{"cve_id": record.cve_id, "cpes": []} for record in missing]
    for batch in _batched(rows):
        await session.execute(
            pg_insert(Vulnerability).values(batch).on_conflict_do_nothing(index_elements=["cve_id"])
        )


async def _flag_kev(session: AsyncSession, records: Sequence[KevRecord]) -> None:
    for record in records:
        values: dict[str, Any] = {"kev_listed": True, "kev_due_date": record.due_date}
        if record.known_ransomware_use:
            # Use in a ransomware campaign is weaponisation evidence in a way a
            # tagged reference is not.
            values["exploit_maturity"] = ExploitMaturity.WEAPONIZED.value
        await session.execute(
            update(Vulnerability).where(Vulnerability.cve_id == record.cve_id).values(**values)
        )


def _batched(rows: Sequence[dict[str, Any]]) -> list[Sequence[dict[str, Any]]]:
    return [rows[index : index + BATCH_SIZE] for index in range(0, len(rows), BATCH_SIZE)]
