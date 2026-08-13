"""Enrichment against a real database: mirror sync, finding upsert, re-scoring.

The feed is injected, so nothing here touches the network. That is a property of
the design rather than of the test setup — ``VulnerabilityFeed`` is a protocol
and the production implementation is the only thing that owns an HTTP client.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from tests.factories import register_tenant
from tests.scoring_factories import (
    HTTPD_CPE,
    load_findings,
    map_asset_to_service,
    run_enrichment,
    scope_for,
    seed_asset_with_port,
    seed_business_service,
    seed_vulnerability,
    set_finding_status,
)
from threatsculpt.db.session import scoped_session
from threatsculpt.enrichment.feeds import StaticFeed
from threatsculpt.enrichment.scoring_service import rescore_findings
from threatsculpt.enrichment.sync import sync_all, sync_cves, sync_kev
from threatsculpt.models.cpe_match import VulnerabilityCpeMatch
from threatsculpt.models.finding import Vulnerability

Factory = async_sessionmaker[AsyncSession]


NVD_ENTRY: dict[str, Any] = {
    "cve": {
        "id": "CVE-2021-44228",
        "published": "2021-12-10T10:15:09.143Z",
        "descriptions": [
            {"lang": "es", "value": "descripcion"},
            {"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against ..."},
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 10.0,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        "baseSeverity": "CRITICAL",
                    }
                }
            ]
        },
        "references": [{"url": "https://example.test/poc", "tags": ["Exploit"]}],
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "2.0",
                                "versionEndExcluding": "2.15.0",
                            },
                            {
                                "vulnerable": False,
                                "criteria": "cpe:2.3:o:redhat:enterprise_linux:8:*:*:*:*:*:*:*",
                            },
                        ],
                    }
                ]
            }
        ],
    }
}

KEV_ENTRY: dict[str, Any] = {
    "cveID": "CVE-2021-44228",
    "vendorProject": "Apache",
    "product": "Log4j2",
    "dueDate": "2021-12-24",
    "knownRansomwareCampaignUse": "Known",
}


@pytest.fixture
async def tenant_org(client: AsyncClient) -> Any:
    return await register_tenant(client, "enrich-org")


# --- mirror sync -----------------------------------------------------------


async def test_sync_writes_the_cve_and_its_version_range(
    session_factory: Factory, tenant_org: Any
) -> None:
    # Arrange
    feed = StaticFeed(cve_items=(NVD_ENTRY,))
    scope = scope_for(tenant_org.org_id)

    # Act
    async with scoped_session(session_factory, scope) as session:
        report = await sync_cves(session, feed)

    # Assert
    assert report.cves_upserted == 1
    async with scoped_session(session_factory, scope) as session:
        cve = await session.get(Vulnerability, "CVE-2021-44228")
        assert cve is not None
        assert cve.cvss_base == Decimal("10.0")
        assert cve.severity == "critical"
        assert cve.exploit_maturity == "poc"  # from the Exploit-tagged reference
        assert cve.description is not None and cve.description.startswith("Apache Log4j2")

        matches = (await session.execute(select(VulnerabilityCpeMatch))).scalars().all()
        # The non-vulnerable platform row is stored but flagged, not treated as affected.
        vulnerable = [row for row in matches if row.vulnerable]
        assert len(vulnerable) == 1
        assert vulnerable[0].version_start_including == "2.0"
        assert vulnerable[0].version_end_excluding == "2.15.0"


async def test_sync_is_idempotent(session_factory: Factory, tenant_org: Any) -> None:
    feed = StaticFeed(cve_items=(NVD_ENTRY,))
    scope = scope_for(tenant_org.org_id)
    for _ in range(2):
        async with scoped_session(session_factory, scope) as session:
            await sync_cves(session, feed)

    async with scoped_session(session_factory, scope) as session:
        rows = (await session.execute(select(VulnerabilityCpeMatch))).scalars().all()
    assert len({row.cpe23 for row in rows}) == len(rows)


async def test_kev_sync_flags_and_records_ransomware_weaponisation(
    session_factory: Factory, tenant_org: Any
) -> None:
    feed = StaticFeed(cve_items=(NVD_ENTRY,), kev_items=(KEV_ENTRY,))
    scope = scope_for(tenant_org.org_id)

    async with scoped_session(session_factory, scope) as session:
        await sync_all(session, feed)

    async with scoped_session(session_factory, scope) as session:
        cve = await session.get(Vulnerability, "CVE-2021-44228")
        assert cve is not None
        assert cve.kev_listed is True
        assert cve.kev_due_date is not None
        assert cve.exploit_maturity == "weaponized"


async def test_a_kev_entry_nvd_has_not_published_still_gets_a_row(
    session_factory: Factory, tenant_org: Any
) -> None:
    """Dropping it would discard the one feed that lists confirmed exploitation."""
    feed = StaticFeed(kev_items=({"cveID": "CVE-2099-0001", "dueDate": "2099-01-01"},))
    scope = scope_for(tenant_org.org_id)

    async with scoped_session(session_factory, scope) as session:
        flagged = await sync_kev(session, feed)

    assert flagged == 1
    async with scoped_session(session_factory, scope) as session:
        stub = await session.get(Vulnerability, "CVE-2099-0001")
        assert stub is not None and stub.kev_listed is True


async def test_a_later_cve_sync_does_not_unflag_kev(
    session_factory: Factory, tenant_org: Any
) -> None:
    """The regression this guards: every NVD refresh silently clearing KEV."""
    scope = scope_for(tenant_org.org_id)
    async with scoped_session(session_factory, scope) as session:
        await sync_all(session, StaticFeed(cve_items=(NVD_ENTRY,), kev_items=(KEV_ENTRY,)))
    async with scoped_session(session_factory, scope) as session:
        await sync_cves(session, StaticFeed(cve_items=(NVD_ENTRY,)))

    async with scoped_session(session_factory, scope) as session:
        cve = await session.get(Vulnerability, "CVE-2021-44228")
        assert cve is not None and cve.kev_listed is True


async def test_malformed_feed_entries_are_skipped_not_fatal(
    session_factory: Factory, tenant_org: Any
) -> None:
    feed = StaticFeed(cve_items=({"cve": {"id": "not-a-cve"}}, {"nonsense": True}, NVD_ENTRY))
    scope = scope_for(tenant_org.org_id)

    async with scoped_session(session_factory, scope) as session:
        report = await sync_cves(session, feed)

    assert report.cves_upserted == 1
    assert len(report.skipped) == 2


async def test_a_feed_returning_an_error_page_yields_nothing_rather_than_raising(
    session_factory: Factory, tenant_org: Any
) -> None:
    scope = scope_for(tenant_org.org_id)
    async with scoped_session(session_factory, scope) as session:
        report = await sync_cves(session, StaticFeed())
    assert report.cves_upserted == 0


# --- finding generation -----------------------------------------------------


async def test_enrichment_creates_a_scored_finding_with_its_explanation(
    session_factory: Factory, tenant_org: Any
) -> None:
    # Arrange
    org = tenant_org.org_id
    await seed_vulnerability(session_factory, org)
    seeded = await seed_asset_with_port(session_factory, org, exposure="internet")
    service_id = await seed_business_service(session_factory, org)
    await map_asset_to_service(session_factory, org, seeded.asset_id, service_id)

    # Act
    report = await run_enrichment(session_factory, org)

    # Assert
    assert report.findings_written == 1
    assert report.high_confidence == 1
    (finding,) = await load_findings(session_factory, org)
    if True:
        assert finding.cve_id == "CVE-2021-44228"
        assert finding.match_confidence == "high"
        assert finding.match_method == "cpe_version_range"
        factors = finding.score_factors
        assert factors["exposure"] == {"value": "internet", "multiplier": 1.4}
        assert factors["asset_criticality"] == {"value": "critical", "multiplier": 1.3}
        assert factors["services_affected"] == ["Payment processing"]
        assert finding.business_risk_score > Decimal("0")


async def test_a_rescan_updates_last_seen_rather_than_duplicating(
    session_factory: Factory, tenant_org: Any
) -> None:
    org = tenant_org.org_id
    await seed_vulnerability(session_factory, org)
    await seed_asset_with_port(session_factory, org)

    first = await run_enrichment(session_factory, org)
    (original,) = await load_findings(session_factory, org)
    original_first_seen = original.first_seen_at

    second = await run_enrichment(session_factory, org)

    assert first.findings_written == second.findings_written == 1
    rows = await load_findings(session_factory, org)
    assert len(rows) == 1
    assert rows[0].first_seen_at == original_first_seen
    assert rows[0].last_seen_at is not None


async def test_a_rescan_does_not_reopen_a_triaged_finding(
    session_factory: Factory, tenant_org: Any
) -> None:
    """An operator's decision outlives the scanner running again."""
    org = tenant_org.org_id
    await seed_vulnerability(session_factory, org)
    await seed_asset_with_port(session_factory, org)
    await run_enrichment(session_factory, org)
    await set_finding_status(session_factory, org, "accepted_risk")

    await run_enrichment(session_factory, org)

    (finding,) = await load_findings(session_factory, org)
    assert finding.status == "accepted_risk"


async def test_a_patched_version_produces_no_finding(
    session_factory: Factory, tenant_org: Any
) -> None:
    org = tenant_org.org_id
    await seed_vulnerability(session_factory, org)
    await seed_asset_with_port(
        session_factory,
        org,
        cpe=("cpe:2.3:a:apache:log4j:2.17.1:*:*:*:*:*:*:*",),
        version="2.17.1",
    )

    report = await run_enrichment(session_factory, org)

    assert report.findings_written == 0


async def test_unrelated_software_produces_no_finding(
    session_factory: Factory, tenant_org: Any
) -> None:
    org = tenant_org.org_id
    await seed_vulnerability(session_factory, org)
    await seed_asset_with_port(
        session_factory, org, cpe=(HTTPD_CPE,), product="Apache httpd", version="2.4.49"
    )

    assert (await run_enrichment(session_factory, org)).findings_written == 0


async def test_a_version_free_observation_is_recorded_as_low_confidence(
    session_factory: Factory, tenant_org: Any
) -> None:
    org = tenant_org.org_id
    await seed_vulnerability(session_factory, org)
    await seed_asset_with_port(
        session_factory, org, cpe=("cpe:/a:apache:log4j",), product=None, version=None
    )

    report = await run_enrichment(session_factory, org)

    assert report.low_confidence == 1
    (finding,) = await load_findings(session_factory, org)
    if True:
        assert finding.match_confidence == "low"
        assert finding.match_rationale is not None
        assert "no version was reported" in finding.match_rationale


async def test_enrichment_can_be_narrowed_to_one_scan_job(
    session_factory: Factory, tenant_org: Any
) -> None:
    org = tenant_org.org_id
    await seed_vulnerability(session_factory, org)
    first = await seed_asset_with_port(session_factory, org, ip="10.0.4.12")
    await seed_asset_with_port(session_factory, org, ip="10.0.4.13")

    report = await run_enrichment(session_factory, org, scan_job_id=first.scan_job_id)

    assert report.ports_examined == 1
    assert report.findings_written == 1


# --- re-scoring -------------------------------------------------------------


async def test_rescoring_picks_up_a_kev_listing_without_a_rescan(
    session_factory: Factory, tenant_org: Any
) -> None:
    """The scenario: the mirror learns overnight that a CVE is being exploited."""
    # Arrange
    org = tenant_org.org_id
    await seed_vulnerability(session_factory, org)
    await seed_asset_with_port(session_factory, org)
    await run_enrichment(session_factory, org)
    (existing,) = await load_findings(session_factory, org)
    before = existing.business_risk_score

    # Act — KEV lands, then re-score with no new scan data.
    async with scoped_session(session_factory, scope_for(org)) as session:
        await sync_kev(session, StaticFeed(kev_items=(KEV_ENTRY,)))
    async with scoped_session(session_factory, scope_for(org)) as session:
        updated = await rescore_findings(session, scope_for(org))

    # Assert
    assert updated == 1
    (finding,) = await load_findings(session_factory, org)
    assert finding.business_risk_score > before
    assert finding.score_factors["exploit_maturity"]["value"] == "kev_listed"


async def test_rescoring_picks_up_a_newly_mapped_business_service(
    session_factory: Factory, tenant_org: Any
) -> None:
    org = tenant_org.org_id
    await seed_vulnerability(session_factory, org)
    seeded = await seed_asset_with_port(session_factory, org)
    await run_enrichment(session_factory, org)
    (before,) = await load_findings(session_factory, org)
    assert before.score_factors["asset_criticality"]["value"] == "unmapped"
    previous = before.business_risk_score

    service_id = await seed_business_service(session_factory, org)
    await map_asset_to_service(session_factory, org, seeded.asset_id, service_id)
    async with scoped_session(session_factory, scope_for(org)) as session:
        await rescore_findings(session, scope_for(org), asset_ids=[seeded.asset_id])

    (after,) = await load_findings(session_factory, org)
    assert after.business_risk_score > previous
    assert after.score_factors["services_affected"] == ["Payment processing"]


async def test_rescoring_is_idempotent(session_factory: Factory, tenant_org: Any) -> None:
    org = tenant_org.org_id
    await seed_vulnerability(session_factory, org)
    await seed_asset_with_port(session_factory, org)
    await run_enrichment(session_factory, org)

    scores = []
    for _ in range(2):
        async with scoped_session(session_factory, scope_for(org)) as session:
            await rescore_findings(session, scope_for(org))
        (current,) = await load_findings(session_factory, org)
        scores.append(current.business_risk_score)

    assert scores[0] == scores[1]


# --- tenancy ----------------------------------------------------------------


async def test_enrichment_never_crosses_a_tenant_boundary(
    client: AsyncClient, session_factory: Factory
) -> None:
    # Arrange — two orgs, identical inventory.
    alpha = await register_tenant(client, "enrich-alpha")
    beta = await register_tenant(client, "enrich-beta")
    await seed_vulnerability(session_factory, alpha.org_id)
    await seed_asset_with_port(session_factory, alpha.org_id, ip="10.0.4.12")
    await seed_asset_with_port(session_factory, beta.org_id, ip="10.0.4.12")

    # Act — enrich only alpha.
    await run_enrichment(session_factory, alpha.org_id)

    # Assert — beta has an identical vulnerable host and no findings.
    assert await load_findings(session_factory, beta.org_id) == ()
    assert len(await load_findings(session_factory, alpha.org_id)) == 1


async def test_rescoring_one_org_leaves_another_untouched(
    client: AsyncClient, session_factory: Factory
) -> None:
    alpha = await register_tenant(client, "rescore-alpha")
    beta = await register_tenant(client, "rescore-beta")
    for org in (alpha.org_id, beta.org_id):
        await seed_vulnerability(session_factory, org)
        await seed_asset_with_port(session_factory, org)
        await run_enrichment(session_factory, org)

    (beta_finding,) = await load_findings(session_factory, beta.org_id)
    beta_before = beta_finding.business_risk_score

    async with scoped_session(session_factory, scope_for(alpha.org_id)) as session:
        await sync_kev(session, StaticFeed(kev_items=(KEV_ENTRY,)))
        updated = await rescore_findings(session, scope_for(alpha.org_id))

    assert updated == 1  # alpha's finding only, never beta's
    (beta_after,) = await load_findings(session_factory, beta.org_id)
    assert beta_after.business_risk_score == beta_before
