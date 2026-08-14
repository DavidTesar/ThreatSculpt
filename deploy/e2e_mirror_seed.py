"""Seed the CVE mirror through the real sync, from a static feed.

Used only by ``deploy/e2e.sh``. The e2e cannot reach nvd.nist.gov — a gate that
depends on somebody else's uptime is a gate that fails for reasons that are not
about this code — so it supplies ``StaticFeed``, which is the seam
``enrichment.feeds`` already exists to provide, and runs the same
``enrichment.sync.sync_all`` a scheduled mirror refresh would.

Everything downstream of this is production code invoked exactly as production
invokes it: the parsers, the upserts, the KEV flagging, and then the enrichment
worker, which the script starts as its own process and waits for.

**This script is a stand-in for one thing only:** the mirror sync has no
production entry point yet (docs/RUNBOOK.md, "The CVE mirror is never synced").
When one lands, this file goes and the e2e calls it instead. It deliberately
does *not* call ``generate_findings``: if it did, the script would prove nothing
about whether a running system produces findings, which is the whole point of
the assertions that follow it.

The payload describes what the scan genuinely observes — Python's
``http.server``, which nmap fingerprints as SimpleHTTPServer.
"""

from __future__ import annotations

import asyncio
import sys
from typing import Any

from threatsculpt.config import get_settings
from threatsculpt.db.engine import build_engine, build_session_factory
from threatsculpt.enrichment.feeds import StaticFeed
from threatsculpt.enrichment.sync import sync_all

#: Not a real CVE. It describes real software, in the shape NVD publishes.
CVE_ID = "CVE-2026-31337"
VENDOR = "python"
PRODUCT = "simplehttpserver"

NVD_ENTRY: dict[str, Any] = {
    "cve": {
        "id": CVE_ID,
        "published": "2026-01-05T00:00:00.000Z",
        "descriptions": [
            {
                "lang": "en",
                "value": (
                    "Directory traversal in Python SimpleHTTPServer allows a remote "
                    "attacker to read files outside the served root."
                ),
            }
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 9.8,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseSeverity": "CRITICAL",
                    }
                }
            ]
        },
        "references": [{"url": "https://example.test/advisory", "tags": ["Exploit"]}],
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": (
                                    f"cpe:2.3:a:{VENDOR}:{PRODUCT}:*:*:*:*:*:*:*:*"
                                ),
                                "versionEndIncluding": "0.6",
                            }
                        ],
                    }
                ]
            }
        ],
    }
}

#: KEV is what makes this finding score as a known-exploited one. Listed with
#: ransomware use, so the sync raises its maturity to ``weaponized`` — the same
#: path a real KEV entry takes.
KEV_ENTRY: dict[str, Any] = {
    "cveID": CVE_ID,
    "vendorProject": "Python",
    "product": "SimpleHTTPServer",
    "dueDate": "2026-02-01",
    "knownRansomwareCampaignUse": "Known",
}


async def main() -> int:
    engine = build_engine(get_settings())
    factory = build_session_factory(engine)
    feed = StaticFeed(cve_items=(NVD_ENTRY,), kev_items=(KEV_ENTRY,))
    try:
        # ``vulnerabilities`` and ``vulnerability_cpe_matches`` hold no customer
        # data, so they are outside the tenancy guard and take a plain session.
        # One mirror serves every tenant — the point of enriching server-side.
        async with factory() as session:
            report = await sync_all(session, feed)
            await session.commit()
    finally:
        await engine.dispose()

    print(
        f"mirror sync: cves={report.cves_upserted} "
        f"cpe_matches={report.cpe_matches_upserted} kev={report.kev_flagged} "
        f"skipped={len(report.skipped)}"
    )
    if report.cves_upserted < 1 or report.cpe_matches_upserted < 1:
        print("the mirror sync wrote nothing usable", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
