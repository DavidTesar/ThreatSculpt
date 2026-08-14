"""The KEV and maturity updates, which used to be one statement per record.

A 2,000-row NVD page could issue up to 2,000 UPDATEs, and the KEV catalogue
(~1,300 entries, growing weekly) issued one per entry every run. Both are now
single statements per batch — but ``kev_due_date`` differs per row, so the KEV
batch travels as a ``VALUES`` list joined into the UPDATE, and that join is the
kind of thing that is either exactly right or silently assigns every row the
same date. These tests exist to tell those two apart.
"""

from __future__ import annotations

from datetime import date
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.factories import register_tenant
from threatsculpt.enrichment.feeds import StaticFeed
from threatsculpt.enrichment.sync import sync_cves, sync_kev
from threatsculpt.models.finding import Vulnerability

Factory = async_sessionmaker[AsyncSession]


def cve_entry(cve_id: str, *, exploit_tag: bool) -> dict[str, Any]:
    references = [{"url": "https://example.test/poc", "tags": ["Exploit"]}] if exploit_tag else []
    return {"cve": {"id": cve_id, "references": references}}


def kev_entry(cve_id: str, due: str, *, ransomware: bool = False) -> dict[str, Any]:
    return {
        "cveID": cve_id,
        "dueDate": due,
        "knownRansomwareCampaignUse": "Known" if ransomware else "Unknown",
    }


@pytest.fixture
async def tenant_org(client: AsyncClient) -> Any:
    return await register_tenant(client, "batch-org")


async def mirror(session: AsyncSession) -> dict[str, Vulnerability]:
    rows = (await session.execute(select(Vulnerability))).scalars().all()
    return {row.cve_id: row for row in rows}


async def test_each_kev_entry_keeps_its_own_due_date(
    session_factory: Factory, tenant_org: Any
) -> None:
    """The failure mode of a VALUES join done wrong: everyone gets row one's date."""
    entries = tuple(
        kev_entry(f"CVE-2026-{index:04d}", f"2026-0{index}-15") for index in range(1, 6)
    )

    async with session_factory() as session:
        await sync_kev(session, StaticFeed(kev_items=entries))
        await session.commit()

    async with session_factory() as session:
        rows = await mirror(session)

    assert len(rows) == 5
    for index in range(1, 6):
        row = rows[f"CVE-2026-{index:04d}"]
        assert row.kev_listed is True
        assert row.kev_due_date == date(2026, index, 15)


async def test_a_kev_entry_with_no_due_date_is_still_flagged(
    session_factory: Factory, tenant_org: Any
) -> None:
    """A NULL in the VALUES list must not poison the column's inferred type."""
    entries = (
        kev_entry("CVE-2026-1001", "2026-03-01"),
        {"cveID": "CVE-2026-1002"},
    )

    async with session_factory() as session:
        await sync_kev(session, StaticFeed(kev_items=entries))
        await session.commit()

    async with session_factory() as session:
        rows = await mirror(session)

    assert rows["CVE-2026-1001"].kev_due_date == date(2026, 3, 1)
    assert rows["CVE-2026-1002"].kev_listed is True
    assert rows["CVE-2026-1002"].kev_due_date is None


async def test_only_the_ransomware_entries_are_weaponised(
    session_factory: Factory, tenant_org: Any
) -> None:
    entries = (
        kev_entry("CVE-2026-2001", "2026-03-01", ransomware=True),
        kev_entry("CVE-2026-2002", "2026-03-01"),
        kev_entry("CVE-2026-2003", "2026-03-01", ransomware=True),
    )

    async with session_factory() as session:
        await sync_kev(session, StaticFeed(kev_items=entries))
        await session.commit()

    async with session_factory() as session:
        rows = await mirror(session)

    assert rows["CVE-2026-2001"].exploit_maturity == "weaponized"
    assert rows["CVE-2026-2003"].exploit_maturity == "weaponized"
    assert rows["CVE-2026-2002"].exploit_maturity == "none"


async def test_maturity_rises_for_the_tagged_cves_only(
    session_factory: Factory, tenant_org: Any
) -> None:
    entries = (
        cve_entry("CVE-2026-3001", exploit_tag=True),
        cve_entry("CVE-2026-3002", exploit_tag=False),
        cve_entry("CVE-2026-3003", exploit_tag=True),
    )

    async with session_factory() as session:
        await sync_cves(session, StaticFeed(cve_items=entries))
        await session.commit()

    async with session_factory() as session:
        rows = await mirror(session)

    assert rows["CVE-2026-3001"].exploit_maturity == "poc"
    assert rows["CVE-2026-3003"].exploit_maturity == "poc"
    assert rows["CVE-2026-3002"].exploit_maturity == "none"


async def test_a_weaponised_cve_is_not_walked_back_down_by_a_later_nvd_pass(
    session_factory: Factory, tenant_org: Any
) -> None:
    """The one-directional rule, now that the update is batched rather than per row."""
    async with session_factory() as session:
        await sync_cves(
            session, StaticFeed(cve_items=(cve_entry("CVE-2026-4001", exploit_tag=True),))
        )
        await sync_kev(
            session,
            StaticFeed(kev_items=(kev_entry("CVE-2026-4001", "2026-03-01", ransomware=True),)),
        )
        await session.commit()

    # NVD re-curates the references away; the CVE is no less exploitable.
    async with session_factory() as session:
        await sync_cves(
            session, StaticFeed(cve_items=(cve_entry("CVE-2026-4001", exploit_tag=False),))
        )
        await session.commit()

    async with session_factory() as session:
        rows = await mirror(session)
    assert rows["CVE-2026-4001"].exploit_maturity == "weaponized"


async def test_a_batch_larger_than_one_chunk_updates_every_row(
    session_factory: Factory, tenant_org: Any
) -> None:
    """BATCH_SIZE is 500; 1,200 entries must not leave 700 of them unflagged."""
    entries = tuple(kev_entry(f"CVE-2027-{index:04d}", "2027-06-01") for index in range(1200))

    async with session_factory() as session:
        await sync_kev(session, StaticFeed(kev_items=entries))
        await session.commit()

    async with session_factory() as session:
        rows = await mirror(session)

    assert len(rows) == 1200
    assert all(row.kev_listed for row in rows.values())
    assert all(row.kev_due_date == date(2027, 6, 1) for row in rows.values())
