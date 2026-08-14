"""Validated records parsed out of the upstream CVE feeds.

Feed payloads are external data, so nothing from them reaches a column without
passing through here first. The parsers are deliberately tolerant of missing
optional fields and intolerant of missing required ones: NVD and KEV both ship
partial records routinely, and a sync that aborts on the first odd entry syncs
nothing at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime
from decimal import Decimal
from typing import Final

from threatsculpt.enrichment.versions import VersionRange

#: CVSS v3 severity bands, used when a feed gives a score but no band.
SEVERITY_BANDS: Final[tuple[tuple[Decimal, str], ...]] = (
    (Decimal("9.0"), "critical"),
    (Decimal("7.0"), "high"),
    (Decimal("4.0"), "medium"),
    (Decimal("0.1"), "low"),
    (Decimal("0.0"), "none"),
)


def severity_for(score: Decimal | None) -> str | None:
    if score is None:
        return None
    for threshold, band in SEVERITY_BANDS:
        if score >= threshold:
            return band
    return "none"


@dataclass(frozen=True, slots=True)
class CpeMatchRecord:
    """One vulnerable-configuration entry, already split into its parts."""

    cpe23: str
    vendor: str
    product: str
    version_range: VersionRange = field(default_factory=VersionRange)
    vulnerable: bool = True


@dataclass(frozen=True, slots=True)
class CveRecord:
    """A CVE as the mirror stores it."""

    cve_id: str
    description: str | None = None
    cvss_base: Decimal | None = None
    cvss_vector: str | None = None
    severity: str | None = None
    exploit_maturity: str = "none"
    published_at: datetime | None = None
    cpe_matches: tuple[CpeMatchRecord, ...] = ()

    @property
    def cpes(self) -> tuple[str, ...]:
        """Flat CPE list for ``vulnerabilities.cpes``' GIN prefilter."""
        return tuple(dict.fromkeys(match.cpe23 for match in self.cpe_matches if match.vulnerable))


@dataclass(frozen=True, slots=True)
class KevRecord:
    """One row of the CISA Known Exploited Vulnerabilities catalogue."""

    cve_id: str
    due_date: date | None = None
    known_ransomware_use: bool = False


@dataclass(frozen=True, slots=True)
class SyncReport:
    """What a sync run did. Returned rather than logged so callers can assert on it."""

    cves_upserted: int = 0
    cpe_matches_upserted: int = 0
    kev_flagged: int = 0
    skipped: tuple[str, ...] = field(default=())

    def with_kev(self, flagged: int) -> SyncReport:
        return SyncReport(
            cves_upserted=self.cves_upserted,
            cpe_matches_upserted=self.cpe_matches_upserted,
            kev_flagged=flagged,
            skipped=self.skipped,
        )

    def merged_with(self, other: SyncReport) -> SyncReport:
        """Totals across pages. A paged sync reports one number, not one per page."""
        return SyncReport(
            cves_upserted=self.cves_upserted + other.cves_upserted,
            cpe_matches_upserted=self.cpe_matches_upserted + other.cpe_matches_upserted,
            kev_flagged=self.kev_flagged + other.kev_flagged,
            skipped=self.skipped + other.skipped,
        )
