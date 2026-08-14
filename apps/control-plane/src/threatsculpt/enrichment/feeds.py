"""Upstream feeds and their parsers.

The HTTP client is injected as a ``JsonFetcher`` protocol rather than imported
here, which is what lets the whole enrichment path be tested without a network
call. A test supplies ``StaticFeed`` with real-shaped payloads; the only module
in ``src/`` that may import an HTTP client is ``enrichment.http``, and
``tests/test_enrichment_no_network.py`` enforces both halves of that.

**CVEs arrive a page at a time, not all at once.** NVD 2.0 serves at most 2,000
results per request against roughly 300,000 CVEs, so a single unparameterised
request mirrors under one percent of the catalogue and always the same slice.
``iter_cve_pages`` walks ``startIndex`` to ``totalResults``, and yields each page
as it arrives so the caller can commit its progress — a cold sync runs for hours
and one that cannot resume never finishes on a flaky connection.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import Any, Final, Protocol

from threatsculpt.enrichment.cpe import parse_cpe
from threatsculpt.enrichment.records import CpeMatchRecord, CveRecord, KevRecord, severity_for
from threatsculpt.enrichment.versions import VersionRange

logger = logging.getLogger(__name__)

KEV_CATALOG_URL: Final = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
NVD_CVE_API_URL: Final = "https://services.nvd.nist.gov/rest/json/cves/2.0"

#: NVD's documented maximum, and its default is 20 — leaving it unset turns a
#: 150-request sync into a 15,000-request one.
NVD_MAX_RESULTS_PER_PAGE: Final = 2000

#: NVD rejects a ``lastModStartDate``/``lastModEndDate`` pair more than 120 days
#: apart, so a long gap has to be walked as several windows rather than one.
NVD_MAX_WINDOW_DAYS: Final = 120

#: Refuse to page forever if a feed reports a ``totalResults`` it never reaches.
#: 2,000 pages is ~4M CVEs, comfortably beyond any real catalogue.
MAX_PAGES_PER_WINDOW: Final = 2000

#: NVD tags a reference that points at working exploit code. It is the only
#: exploit signal the feed carries; ``weaponized`` needs a source we do not sync
#: (Metasploit module lists, EPSS), so this mapping stops at ``poc`` rather than
#: inventing a tier the data does not support.
_EXPLOIT_REFERENCE_TAG: Final = "Exploit"

_CVSS_METRIC_KEYS: Final = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


@dataclass(frozen=True, slots=True)
class SyncWindow:
    """A ``lastModStartDate``/``lastModEndDate`` pair, half-open on the end."""

    start: datetime
    end: datetime


@dataclass(frozen=True, slots=True)
class CvePage:
    """One ``startIndex`` worth of NVD results, with the caller's resume point."""

    entries: tuple[Mapping[str, Any], ...]
    start_index: int
    total_results: int

    @property
    def next_index(self) -> int:
        return self.start_index + len(self.entries)

    @property
    def is_last(self) -> bool:
        """An empty page always ends the walk, whatever ``totalResults`` claims."""
        return not self.entries or self.next_index >= self.total_results


def windows_between(
    start: datetime, end: datetime, *, max_days: int = NVD_MAX_WINDOW_DAYS
) -> tuple[SyncWindow, ...]:
    """Split ``[start, end)`` into consecutive windows NVD will accept."""
    if max_days < 1:
        raise ValueError("max_days must be at least 1")
    span = timedelta(days=max_days)
    windows: list[SyncWindow] = []
    cursor = start
    while cursor < end:
        stop = min(cursor + span, end)
        windows.append(SyncWindow(start=cursor, end=stop))
        cursor = stop
    return tuple(windows)


class JsonFetcher(Protocol):
    """Anything that can turn a URL into decoded JSON."""

    async def get_json(self, url: str, params: Mapping[str, str] | None = None) -> Any: ...


class VulnerabilityFeed(Protocol):
    async def fetch_kev(self) -> Sequence[Mapping[str, Any]]: ...

    def iter_cve_pages(
        self, *, window: SyncWindow | None = None, start_index: int = 0
    ) -> AsyncIterator[CvePage]: ...


@dataclass(frozen=True, slots=True)
class StaticFeed:
    """A feed backed by payloads held in memory. The test double, and the seam."""

    kev_items: tuple[Mapping[str, Any], ...] = ()
    cve_items: tuple[Mapping[str, Any], ...] = ()

    async def fetch_kev(self) -> Sequence[Mapping[str, Any]]:
        return self.kev_items

    async def iter_cve_pages(
        self, *, window: SyncWindow | None = None, start_index: int = 0
    ) -> AsyncIterator[CvePage]:
        yield CvePage(
            entries=tuple(self.cve_items[start_index:]),
            start_index=start_index,
            total_results=len(self.cve_items),
        )


@dataclass(frozen=True, slots=True)
class RemoteFeed:
    """The real feeds, over an injected client."""

    fetcher: JsonFetcher
    kev_url: str = KEV_CATALOG_URL
    nvd_url: str = NVD_CVE_API_URL
    page_size: int = NVD_MAX_RESULTS_PER_PAGE

    async def fetch_kev(self) -> Sequence[Mapping[str, Any]]:
        payload = await self.fetcher.get_json(self.kev_url)
        return _items(payload, "vulnerabilities")

    async def iter_cve_pages(
        self, *, window: SyncWindow | None = None, start_index: int = 0
    ) -> AsyncIterator[CvePage]:
        """Walk ``startIndex`` to ``totalResults``, yielding each page as it lands."""
        index = start_index
        for _ in range(MAX_PAGES_PER_WINDOW):
            payload = await self.fetcher.get_json(
                self.nvd_url, page_params(index, self.page_size, window)
            )
            page = _cve_page(payload, index)
            yield page
            if page.is_last:
                return
            index = page.next_index
        logger.warning("cve paging stopped at the page cap", extra={"pages": MAX_PAGES_PER_WINDOW})


def page_params(start_index: int, page_size: int, window: SyncWindow | None) -> dict[str, str]:
    params = {"startIndex": str(start_index), "resultsPerPage": str(page_size)}
    if window is not None:
        params["lastModStartDate"] = format_feed_timestamp(window.start)
        params["lastModEndDate"] = format_feed_timestamp(window.end)
    return params


def format_feed_timestamp(value: datetime) -> str:
    """NVD's ISO-8601 form: millisecond precision and an explicit offset."""
    moment = value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def _cve_page(payload: Any, start_index: int) -> CvePage:
    entries = tuple(_items(payload, "vulnerabilities"))
    total = _as_int(payload.get("totalResults")) if isinstance(payload, Mapping) else None
    return CvePage(
        entries=entries,
        start_index=start_index,
        # A payload with no usable ``totalResults`` is treated as the last page.
        # Guessing higher would page against a feed that has stopped answering.
        total_results=total if total is not None else start_index + len(entries),
    )


def _items(payload: Any, key: str) -> Sequence[Mapping[str, Any]]:
    """Never trust the envelope: a feed outage often returns an HTML error page."""
    if not isinstance(payload, Mapping):
        logger.warning("feed payload was not an object", extra={"key": key})
        return ()
    items = payload.get(key)
    if not isinstance(items, list):
        logger.warning("feed payload had no %s array", key)
        return ()
    return [item for item in items if isinstance(item, Mapping)]


# --- parsing ---------------------------------------------------------------


def parse_kev_entry(entry: Mapping[str, Any]) -> KevRecord | None:
    cve_id = _clean_cve_id(entry.get("cveID"))
    if cve_id is None:
        return None
    return KevRecord(
        cve_id=cve_id,
        due_date=_as_date(entry.get("dueDate")),
        known_ransomware_use=str(entry.get("knownRansomwareCampaignUse", "")).lower() == "known",
    )


def parse_cve_entry(entry: Mapping[str, Any]) -> CveRecord | None:
    """Parse one NVD 2.0 ``vulnerabilities[]`` element."""
    cve = entry.get("cve") if isinstance(entry.get("cve"), Mapping) else entry
    if not isinstance(cve, Mapping):
        return None
    cve_id = _clean_cve_id(cve.get("id"))
    if cve_id is None:
        return None

    score, vector, band = _cvss(cve)
    return CveRecord(
        cve_id=cve_id,
        description=_english_description(cve),
        cvss_base=score,
        cvss_vector=vector,
        severity=band or severity_for(score),
        exploit_maturity=_exploit_maturity(cve),
        published_at=_as_datetime(cve.get("published")),
        cpe_matches=_cpe_matches(cve),
    )


def _clean_cve_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip().upper()
    # The column is String(32); a longer value is malformed, not truncatable.
    if not candidate.startswith("CVE-") or len(candidate) > 32:
        return None
    return candidate


def _english_description(cve: Mapping[str, Any]) -> str | None:
    entries = cve.get("descriptions")
    if not isinstance(entries, list):
        return None
    for item in entries:
        if isinstance(item, Mapping) and item.get("lang") == "en":
            value = item.get("value")
            if isinstance(value, str):
                return value
    return None


def _cvss(cve: Mapping[str, Any]) -> tuple[Decimal | None, str | None, str | None]:
    """First available metric, newest CVSS version first."""
    metrics = cve.get("metrics")
    if not isinstance(metrics, Mapping):
        return None, None, None
    for key in _CVSS_METRIC_KEYS:
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        first = entries[0]
        data = first.get("cvssData") if isinstance(first, Mapping) else None
        if not isinstance(data, Mapping):
            continue
        band = data.get("baseSeverity")
        return (
            _as_decimal(data.get("baseScore")),
            _as_str(data.get("vectorString"), limit=255),
            band.lower() if isinstance(band, str) else None,
        )
    return None, None, None


def _exploit_maturity(cve: Mapping[str, Any]) -> str:
    references = cve.get("references")
    if not isinstance(references, list):
        return "none"
    for reference in references:
        tags = reference.get("tags") if isinstance(reference, Mapping) else None
        if isinstance(tags, list) and _EXPLOIT_REFERENCE_TAG in tags:
            return "poc"
    return "none"


def _cpe_matches(cve: Mapping[str, Any]) -> tuple[CpeMatchRecord, ...]:
    configurations = cve.get("configurations")
    if not isinstance(configurations, list):
        return ()
    records: list[CpeMatchRecord] = []
    for configuration in configurations:
        nodes = configuration.get("nodes") if isinstance(configuration, Mapping) else None
        for node in nodes if isinstance(nodes, list) else []:
            records.extend(_node_matches(node))
    # Deduplicate on the criteria string: NVD repeats a criteria across nodes.
    return tuple({record.cpe23: record for record in records}.values())


def _node_matches(node: Any) -> list[CpeMatchRecord]:
    if not isinstance(node, Mapping):
        return []
    entries = node.get("cpeMatch")
    if not isinstance(entries, list):
        return []
    return [
        record
        for record in (_one_match(entry) for entry in entries if isinstance(entry, Mapping))
        if record is not None
    ]


def _one_match(entry: Mapping[str, Any]) -> CpeMatchRecord | None:
    criteria = entry.get("criteria")
    if not isinstance(criteria, str):
        return None
    parsed = parse_cpe(criteria)
    if parsed is None or not parsed.is_specific_enough_to_match:
        # A criteria with no vendor or product would match the whole estate.
        return None
    return CpeMatchRecord(
        cpe23=parsed.to_cpe23()[:512],
        vendor=parsed.vendor[:255],
        product=parsed.product[:255],
        version_range=VersionRange(
            start_including=_as_str(entry.get("versionStartIncluding"), limit=128),
            start_excluding=_as_str(entry.get("versionStartExcluding"), limit=128),
            end_including=_as_str(entry.get("versionEndIncluding"), limit=128),
            end_excluding=_as_str(entry.get("versionEndExcluding"), limit=128),
        ),
        vulnerable=bool(entry.get("vulnerable", True)),
    )


def _as_decimal(value: Any) -> Decimal | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return Decimal(str(value)).quantize(Decimal("0.1"))
    except (InvalidOperation, ValueError):
        return None


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if value >= 0 else None


def _as_str(value: Any, *, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip()
    return cleaned[:limit] if cleaned else None


def _as_date(value: Any) -> date | None:
    parsed = _as_datetime(value)
    return parsed.date() if parsed is not None else None


def _as_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
