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

Two entry points, and the difference matters:

``sync_all`` walks the feed inside the caller's transaction and commits nothing.
It is what a test or a small seeding script wants.

``sync_mirror`` is what production runs. It plans its work from the persisted
watermark, and **commits after every page** so an interrupted sync resumes where
it stopped. A cold NVD sync is hours long; one that cannot resume never finishes
on a connection that drops.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy import Date, String, select, update, values
from sqlalchemy import column as sql_column
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from threatsculpt.enrichment.feeds import (
    SyncWindow,
    VulnerabilityFeed,
    parse_cve_entry,
    parse_kev_entry,
)
from threatsculpt.enrichment.records import CveRecord, KevRecord, SyncReport
from threatsculpt.enrichment.watermark import (
    SyncLeg,
    complete_leg,
    load_watermark,
    plan_legs,
    save_progress,
)
from threatsculpt.models.cpe_match import VulnerabilityCpeMatch
from threatsculpt.models.feed_sync_state import KEV_FEED, NVD_FEED
from threatsculpt.models.finding import ExploitMaturity, Vulnerability

logger = logging.getLogger(__name__)

#: Rows per INSERT. Large enough to be one round trip for a normal delta, small
#: enough that a full catalogue refresh does not build a megabyte-scale statement.
BATCH_SIZE: Final = 500

#: Maturity tiers this sync is allowed to raise *from*. Anything above rank 0 is
#: an upgrade; see ``_raise_maturity`` for why it is one-directional.
_MATURITY_RANK: Final = {ExploitMaturity.NONE.value: 0, ExploitMaturity.POC.value: 1}


async def sync_all(session: AsyncSession, feed: VulnerabilityFeed) -> SyncReport:
    """Sync CVEs then KEV in the caller's transaction. Order matters: KEV flags
    rows the CVE pass created."""
    report = await sync_cves(session, feed)
    flagged = await sync_kev(session, feed)
    return report.with_kev(flagged)


async def sync_mirror(
    session: AsyncSession, feed: VulnerabilityFeed, *, now: datetime | None = None
) -> SyncReport:
    """The production sync: resumable, watermarked, committing as it goes."""
    moment = now or datetime.now(UTC)
    report = await _sync_cve_legs(session, feed, moment)
    flagged = await sync_kev(session, feed)
    await complete_leg(session, KEV_FEED, moment, completed_at=moment)
    await session.commit()
    logger.info(
        "cve mirror sync finished",
        extra={
            "cves": report.cves_upserted,
            "cpe_matches": report.cpe_matches_upserted,
            "kev_flagged": flagged,
        },
    )
    return report.with_kev(flagged)


async def _sync_cve_legs(
    session: AsyncSession, feed: VulnerabilityFeed, now: datetime
) -> SyncReport:
    legs = plan_legs(await load_watermark(session, NVD_FEED), now)
    logger.info(
        "cve sync planned",
        extra={"legs": len(legs), "resume_index": legs[0].start_index if legs else 0},
    )
    total = SyncReport()
    for leg in legs:
        total = total.merged_with(await _run_leg(session, feed, leg, now))
    return total


async def _run_leg(
    session: AsyncSession, feed: VulnerabilityFeed, leg: SyncLeg, now: datetime
) -> SyncReport:
    """One window, page by page, each page durable before the next is asked for."""
    total = SyncReport()
    async for page in feed.iter_cve_pages(window=leg.window, start_index=leg.start_index):
        total = total.merged_with(await _sync_page(session, page.entries))
        await save_progress(session, NVD_FEED, leg.window, page.next_index)
        await session.commit()
    await complete_leg(session, NVD_FEED, leg.completed_watermark(now), completed_at=now)
    await session.commit()
    return total


async def sync_cves(
    session: AsyncSession,
    feed: VulnerabilityFeed,
    *,
    window: SyncWindow | None = None,
    start_index: int = 0,
) -> SyncReport:
    """Walk every page of one window into the mirror, without committing."""
    total = SyncReport()
    async for page in feed.iter_cve_pages(window=window, start_index=start_index):
        total = total.merged_with(await _sync_page(session, page.entries))
    logger.info(
        "cve mirror synced",
        extra={
            "cves": total.cves_upserted,
            "cpe_matches": total.cpe_matches_upserted,
            "skipped": len(total.skipped),
        },
    )
    return total


async def _sync_page(session: AsyncSession, entries: Sequence[Mapping[str, Any]]) -> SyncReport:
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

    One statement per distinct target tier per batch, rather than one per CVE:
    NVD's parser only ever yields ``none`` or ``poc``, so a 2,000-row page that
    would have cost up to 2,000 round trips costs one.
    """
    by_tier: dict[str, list[str]] = {}
    for record in records:
        if _MATURITY_RANK.get(record.exploit_maturity, 2) > 0:
            by_tier.setdefault(record.exploit_maturity, []).append(record.cve_id)

    for tier, cve_ids in by_tier.items():
        for batch in _batched(cve_ids):
            await session.execute(
                update(Vulnerability)
                .where(
                    Vulnerability.cve_id.in_(batch),
                    Vulnerability.exploit_maturity == ExploitMaturity.NONE.value,
                )
                .values(exploit_maturity=tier)
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
    """Flag a whole KEV batch in two statements rather than one per entry.

    ``kev_due_date`` differs per row, so the batch travels as a ``VALUES`` list
    joined into the UPDATE. The catalogue is ~1,300 entries and grows weekly; at
    one round trip each that is the slowest part of an otherwise trivial sync.
    """
    for batch in _batched(records):
        source = values(
            sql_column("cve_id", String), sql_column("due_date", Date), name="kev_batch"
        ).data([(record.cve_id, record.due_date) for record in batch])
        await session.execute(
            update(Vulnerability)
            .where(Vulnerability.cve_id == source.c.cve_id)
            .values(kev_listed=True, kev_due_date=source.c.due_date)
        )

    # Use in a ransomware campaign is weaponisation evidence in a way a tagged
    # reference is not, so it is the one signal allowed to set the top tier.
    ransomware = [record.cve_id for record in records if record.known_ransomware_use]
    for batch_ids in _batched(ransomware):
        await session.execute(
            update(Vulnerability)
            .where(Vulnerability.cve_id.in_(batch_ids))
            .values(exploit_maturity=ExploitMaturity.WEAPONIZED.value)
        )


def _batched[T](rows: Sequence[T]) -> list[Sequence[T]]:
    return [rows[index : index + BATCH_SIZE] for index in range(0, len(rows), BATCH_SIZE)]
