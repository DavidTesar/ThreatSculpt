"""Feed parsing at the boundary.

Upstream payloads are external data. These tests are mostly about what happens
when a feed misbehaves — an outage that returns an HTML error page, a truncated
record, a CVE id that is not a CVE id — because a sync that raises on the first
odd entry syncs nothing, and a sync that trusts everything writes rubbish into
the table every tenant reads.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import date
from decimal import Decimal
from typing import Any

import pytest

from threatsculpt.enrichment.feeds import (
    KEV_CATALOG_URL,
    NVD_CVE_API_URL,
    RemoteFeed,
    StaticFeed,
    parse_cve_entry,
    parse_kev_entry,
)
from threatsculpt.enrichment.records import severity_for


class FakeFetcher:
    """A ``JsonFetcher`` that replays canned payloads and records its calls."""

    def __init__(self, payloads: dict[str, Any]) -> None:
        self.payloads = payloads
        self.calls: list[str] = []

    async def get_json(self, url: str, params: Mapping[str, str] | None = None) -> Any:
        self.calls.append(url)
        return self.payloads.get(url)


# --- the feed seam ----------------------------------------------------------


async def collect_cves(feed: RemoteFeed | StaticFeed) -> tuple[Mapping[str, Any], ...]:
    """Every entry the feed pages out, flattened."""
    entries: list[Mapping[str, Any]] = []
    async for page in feed.iter_cve_pages():
        entries.extend(page.entries)
    return tuple(entries)


async def test_remote_feed_reads_the_documented_urls() -> None:
    fetcher = FakeFetcher(
        {
            KEV_CATALOG_URL: {"vulnerabilities": [{"cveID": "CVE-2021-44228"}]},
            NVD_CVE_API_URL: {"vulnerabilities": [{"cve": {"id": "CVE-2021-44228"}}]},
        }
    )
    feed = RemoteFeed(fetcher=fetcher)

    assert len(await feed.fetch_kev()) == 1
    assert len(await collect_cves(feed)) == 1
    assert fetcher.calls == [KEV_CATALOG_URL, NVD_CVE_API_URL]


@pytest.mark.parametrize(
    "payload",
    [
        None,
        "<html>503 Service Unavailable</html>",
        {"message": "rate limited"},
        {"vulnerabilities": "not-a-list"},
        [],
    ],
)
async def test_a_feed_outage_yields_no_items_rather_than_raising(payload: Any) -> None:
    """An NVD outage must degrade the sync, not crash the process running it."""
    feed = RemoteFeed(fetcher=FakeFetcher({NVD_CVE_API_URL: payload}))
    assert await collect_cves(feed) == ()


async def test_non_object_entries_inside_the_array_are_dropped() -> None:
    feed = RemoteFeed(
        fetcher=FakeFetcher({NVD_CVE_API_URL: {"vulnerabilities": [None, 7, {"cve": {}}]}})
    )
    assert len(await collect_cves(feed)) == 1


async def test_the_static_feed_returns_what_it_was_given() -> None:
    feed = StaticFeed(kev_items=({"cveID": "CVE-1"},), cve_items=({"cve": {"id": "CVE-2"}},))
    assert len(await feed.fetch_kev()) == 1
    assert len(await collect_cves(feed)) == 1


# --- KEV parsing ------------------------------------------------------------


def test_kev_entry_parses_due_date_and_ransomware_flag() -> None:
    record = parse_kev_entry(
        {
            "cveID": "cve-2021-44228",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
        }
    )
    assert record is not None
    assert record.cve_id == "CVE-2021-44228"  # normalised to upper case
    assert record.due_date == date(2021, 12, 24)
    assert record.known_ransomware_use is True


@pytest.mark.parametrize(
    "entry",
    [{}, {"cveID": None}, {"cveID": "not-a-cve"}, {"cveID": "CVE-" + "9" * 40}],
)
def test_malformed_kev_entries_are_dropped(entry: dict[str, Any]) -> None:
    assert parse_kev_entry(entry) is None


def test_an_unparseable_due_date_does_not_lose_the_kev_listing() -> None:
    """Being on the exploited-vulnerabilities list matters more than the date."""
    record = parse_kev_entry({"cveID": "CVE-2021-44228", "dueDate": "soon"})
    assert record is not None
    assert record.due_date is None


# --- CVE parsing ------------------------------------------------------------


def test_cve_entry_prefers_the_english_description_and_newest_metric() -> None:
    record = parse_cve_entry(
        {
            "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [
                    {"lang": "fr", "value": "francais"},
                    {"lang": "en", "value": "the english one"},
                ],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
                    "cvssMetricV2": [{"cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM"}}],
                },
            }
        }
    )
    assert record is not None
    assert record.description == "the english one"
    assert record.cvss_base == Decimal("9.8")
    assert record.severity == "critical"


def test_severity_is_derived_when_the_feed_omits_the_band() -> None:
    record = parse_cve_entry(
        {
            "cve": {
                "id": "CVE-2020-0001",
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 5.4}}]},
            }
        }
    )
    assert record is not None
    assert record.severity == "medium"


def test_an_older_metric_is_used_when_no_newer_one_exists() -> None:
    record = parse_cve_entry(
        {
            "cve": {
                "id": "CVE-2015-0001",
                "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 7.5}}]},
            }
        }
    )
    assert record is not None
    assert record.cvss_base == Decimal("7.5")


@pytest.mark.parametrize(
    "metrics",
    [{}, {"cvssMetricV31": []}, {"cvssMetricV31": [{}]}, {"cvssMetricV31": "nope"}, "nope"],
)
def test_a_cve_with_no_usable_metric_still_parses(metrics: Any) -> None:
    """A freshly disclosed CVE genuinely has no score yet; scoring handles it."""
    record = parse_cve_entry({"cve": {"id": "CVE-2026-0001", "metrics": metrics}})
    assert record is not None
    assert record.cvss_base is None
    assert record.severity is None


def test_a_non_numeric_score_is_discarded_rather_than_stored() -> None:
    record = parse_cve_entry(
        {
            "cve": {
                "id": "CVE-2026-0002",
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": "high"}}]},
            }
        }
    )
    assert record is not None
    assert record.cvss_base is None


@pytest.mark.parametrize("entry", [{}, {"cve": None}, {"cve": {"id": 42}}, {"cve": {}}])
def test_malformed_cve_entries_are_dropped(entry: dict[str, Any]) -> None:
    assert parse_cve_entry(entry) is None


def test_an_exploit_tagged_reference_raises_maturity_to_poc() -> None:
    record = parse_cve_entry(
        {
            "cve": {
                "id": "CVE-2021-0003",
                "references": [
                    {"url": "https://a.test", "tags": ["Vendor Advisory"]},
                    {"url": "https://b.test", "tags": ["Exploit"]},
                ],
            }
        }
    )
    assert record is not None
    assert record.exploit_maturity == "poc"


@pytest.mark.parametrize(
    "references", [None, "nope", [], [{"tags": None}], [{"tags": ["Patch"]}], [7]]
)
def test_without_an_exploit_reference_maturity_stays_none(references: Any) -> None:
    record = parse_cve_entry({"cve": {"id": "CVE-2021-0004", "references": references}})
    assert record is not None
    assert record.exploit_maturity == "none"


def test_configurations_are_flattened_and_deduplicated() -> None:
    criteria = "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"
    record = parse_cve_entry(
        {
            "cve": {
                "id": "CVE-2021-44228",
                "configurations": [
                    {"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": criteria}]}]},
                    {"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": criteria}]}]},
                ],
            }
        }
    )
    assert record is not None
    assert len(record.cpe_matches) == 1
    assert record.cpes == (criteria,)


def test_a_criteria_naming_no_vendor_or_product_is_refused() -> None:
    """It would otherwise attach one CVE to every host in every tenant."""
    record = parse_cve_entry(
        {
            "cve": {
                "id": "CVE-2021-0005",
                "configurations": [
                    {"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:*:*:*:*:*:*:*:*:*:*"}]}]}
                ],
            }
        }
    )
    assert record is not None
    assert record.cpe_matches == ()


@pytest.mark.parametrize(
    "configurations",
    [
        None,
        "nope",
        [],
        [{}],
        [{"nodes": None}],
        [{"nodes": [None]}],
        [{"nodes": [{"cpeMatch": 7}]}],
    ],
)
def test_malformed_configurations_yield_no_criteria(configurations: Any) -> None:
    record = parse_cve_entry({"cve": {"id": "CVE-2021-0006", "configurations": configurations}})
    assert record is not None
    assert record.cpe_matches == ()


def test_non_vulnerable_rows_are_kept_but_excluded_from_the_cpe_prefilter() -> None:
    """NVD lists the platform a product runs on; that is not an affected product."""
    record = parse_cve_entry(
        {
            "cve": {
                "id": "CVE-2021-0007",
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": False,
                                        "criteria": "cpe:2.3:o:redhat:enterprise_linux"
                                        ":8:*:*:*:*:*:*:*",
                                    }
                                ]
                            }
                        ]
                    }
                ],
            }
        }
    )
    assert record is not None
    assert len(record.cpe_matches) == 1
    assert record.cpe_matches[0].vulnerable is False
    assert record.cpes == ()


def test_a_published_timestamp_with_a_z_suffix_parses() -> None:
    record = parse_cve_entry(
        {"cve": {"id": "CVE-2021-0008", "published": "2021-12-10T10:15:09.143Z"}}
    )
    assert record is not None
    assert record.published_at is not None
    assert record.published_at.year == 2021


@pytest.mark.parametrize(
    ("score", "band"),
    [
        (Decimal("10.0"), "critical"),
        (Decimal("9.0"), "critical"),
        (Decimal("8.9"), "high"),
        (Decimal("7.0"), "high"),
        (Decimal("6.9"), "medium"),
        (Decimal("4.0"), "medium"),
        (Decimal("3.9"), "low"),
        (Decimal("0.1"), "low"),
        (Decimal("0.0"), "none"),
        (None, None),
    ],
)
def test_severity_bands(score: Decimal | None, band: str | None) -> None:
    assert severity_for(score) == band
