"""Seed one CVE matching the e2e scan's real observation, then run enrichment.

Used only by ``deploy/e2e.sh``. It exists because nothing in the control plane's
request path calls ``generate_findings`` — ingesting results creates assets and
ports but never findings, so the dashboard would be permanently empty in a live
deployment. See docs/RUNBOOK.md, "Findings are never generated".

Everything here is the application's own code and models. The only thing this
script supplies that production does not is the *trigger*, plus a single CVE
standing in for an NVD mirror sync (``enrichment.sync.sync_all`` likewise has no
production caller).
"""

from __future__ import annotations

import asyncio
import sys
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select

from threatsculpt.config import get_settings
from threatsculpt.db.engine import build_engine, build_session_factory
from threatsculpt.db.session import bind_scope
from threatsculpt.enrichment.service import generate_findings
from threatsculpt.models.cpe_match import VulnerabilityCpeMatch
from threatsculpt.models.finding import Vulnerability
from threatsculpt.tenancy.scope import OrgScope

#: Not a real CVE. It describes the software the e2e scan genuinely observes —
#: Python's http.server, which nmap fingerprints as SimpleHTTPServer.
CVE_ID = "CVE-2026-31337"
VENDOR = "python"
PRODUCT = "simplehttpserver"


async def seed_mirror(factory) -> None:  # type: ignore[no-untyped-def]
    """Insert one CVE and its vulnerable-configuration row, if absent."""
    async with factory() as session:
        if await session.scalar(select(Vulnerability).where(Vulnerability.cve_id == CVE_ID)):
            print(f"{CVE_ID} already present in the mirror")
            return

        now = datetime.now(tz=UTC)
        session.add(
            Vulnerability(
                cve_id=CVE_ID,
                description=(
                    "Directory traversal in Python SimpleHTTPServer allows a remote "
                    "attacker to read files outside the served root."
                ),
                cvss_base=9.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                severity="critical",
                cpes=[f"cpe:/a:{VENDOR}:{PRODUCT}"],
                kev_listed=True,
                exploit_maturity="weaponized",
                published_at=now,
                last_synced_at=now,
            )
        )
        # The match row carries an FK to the CVE, so the parent must exist first.
        await session.flush()
        session.add(
            VulnerabilityCpeMatch(
                cve_id=CVE_ID,
                cpe23=f"cpe:2.3:a:{VENDOR}:{PRODUCT}:*:*:*:*:*:*:*:*",
                vendor=VENDOR,
                product=PRODUCT,
                version_end_including="0.6",
                vulnerable=True,
            )
        )
        await session.commit()
        print(f"seeded {CVE_ID} — CVSS 9.8, KEV-listed, weaponized")


async def enrich(factory, org_id: UUID) -> int:  # type: ignore[no-untyped-def]
    async with factory() as session:
        scope = OrgScope.for_system(org_id)
        await bind_scope(session, scope)
        report = await generate_findings(session, scope)
        await session.commit()
        print(
            f"enrichment: ports_examined={report.ports_examined} "
            f"findings_written={report.findings_written} "
            f"high={report.high_confidence} medium={report.medium_confidence} "
            f"low={report.low_confidence}"
        )
        return report.findings_written


async def main(org_id: str) -> int:
    engine = build_engine(get_settings())
    factory = build_session_factory(engine)
    try:
        await seed_mirror(factory)
        written = await enrich(factory, UUID(org_id))
    finally:
        await engine.dispose()
    if written < 1:
        print("no findings were written — the enrichment pipeline did not match", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: e2e_enrich.py <org_id>")
    raise SystemExit(asyncio.run(main(sys.argv[1])))
