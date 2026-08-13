"""Deciding whether an observed service is affected by a CVE — and how sure we are.

The output is deliberately not a boolean. A scanner that reports every plausible
match as fact trains its operators to distrust it, and a scanner that reports
only certainties misses the CVE that mattered. So every match carries a
confidence and a one-line rationale, both of which reach the API and the report.

Confidence ladder:

``high``    The observed CPE names the same vendor and product as the CVE's
            criteria, and the observed version is known and either equals the
            criteria version or falls inside a published range.
``medium``  Vendor and product match, but the CVE's criteria names no version
            bound at all. Probably real; possibly already fixed in the running
            build.
``low``     Either the version is unknown so containment cannot be checked, or
            the match came from nmap's free-text product name with no CPE to
            corroborate the vendor.

Nothing below ``low`` is emitted. A product-name similarity with no version
agreement is not evidence and is dropped rather than recorded.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from threatsculpt.enrichment.cpe import (
    ANY,
    Cpe,
    identity_matches,
    normalise_product_name,
    qualifiers_conflict,
)
from threatsculpt.enrichment.cpe import parse_cpe as parse_cpe_name
from threatsculpt.enrichment.versions import VersionRange, compare_versions, is_known_version


class MatchConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


#: Ordered so a stronger match for the same CVE replaces a weaker one.
CONFIDENCE_RANK: dict[str, int] = {
    MatchConfidence.LOW.value: 0,
    MatchConfidence.MEDIUM.value: 1,
    MatchConfidence.HIGH.value: 2,
}


class MatchMethod(StrEnum):
    CPE_VERSION_EXACT = "cpe_version_exact"
    CPE_VERSION_RANGE = "cpe_version_range"
    CPE_ANY_VERSION = "cpe_any_version"
    CPE_VERSION_UNKNOWN = "cpe_version_unknown"
    PRODUCT_NAME_HEURISTIC = "product_name_heuristic"


@dataclass(frozen=True, slots=True)
class ObservedSoftware:
    """What a scan actually saw on one port."""

    cpes: tuple[str, ...] = ()
    product: str | None = None
    version: str | None = None

    def parsed_cpes(self) -> tuple[Cpe, ...]:
        return tuple(cpe for cpe in (parse_cpe_name(raw) for raw in self.cpes) if cpe is not None)

    def version_for(self, cpe: Cpe) -> str:
        """The version to test: the CPE's own, or the separately reported one."""
        if is_known_version(cpe.version):
            return cpe.version
        return self.version or ANY


@dataclass(frozen=True, slots=True)
class CpeCriteria:
    """One vulnerable-configuration row from the CVE mirror."""

    cve_id: str
    cpe: Cpe
    version_range: VersionRange = field(default_factory=VersionRange)
    vulnerable: bool = True


@dataclass(frozen=True, slots=True)
class Match:
    cve_id: str
    confidence: MatchConfidence
    method: MatchMethod
    rationale: str

    @property
    def rank(self) -> int:
        return CONFIDENCE_RANK[self.confidence.value]


def match_all(observed: ObservedSoftware, criteria: tuple[CpeCriteria, ...]) -> tuple[Match, ...]:
    """Best match per CVE, strongest confidence first."""
    best: dict[str, Match] = {}
    for candidate in criteria:
        match = match_one(observed, candidate)
        if match is None:
            continue
        existing = best.get(match.cve_id)
        if existing is None or match.rank > existing.rank:
            best[match.cve_id] = match
    return tuple(sorted(best.values(), key=lambda item: (-item.rank, item.cve_id)))


def match_one(observed: ObservedSoftware, criteria: CpeCriteria) -> Match | None:
    """Match one observation against one criteria row, or ``None`` for no match."""
    if not criteria.vulnerable or not criteria.cpe.is_specific_enough_to_match:
        return None

    strongest: Match | None = None
    for candidate in observed.parsed_cpes():
        if not identity_matches(candidate, criteria.cpe) or qualifiers_conflict(
            candidate, criteria.cpe
        ):
            continue
        match = _version_verdict(observed.version_for(candidate), criteria)
        if match is not None and (strongest is None or match.rank > strongest.rank):
            strongest = match
    if strongest is not None:
        return strongest
    return _heuristic_match(observed, criteria)


def _version_verdict(observed_version: str, criteria: CpeCriteria) -> Match | None:
    """Apply the version rule appropriate to how the criteria expresses itself."""
    if criteria.version_range.is_bounded:
        return _range_verdict(observed_version, criteria)
    if criteria.cpe.version != ANY:
        return _exact_verdict(observed_version, criteria)
    return _build(
        criteria,
        MatchConfidence.MEDIUM,
        MatchMethod.CPE_ANY_VERSION,
        f"{criteria.cpe.identity()} matches and the advisory names no fixed version; "
        "the running build may already contain a backported fix",
    )


def _range_verdict(observed_version: str, criteria: CpeCriteria) -> Match | None:
    window = criteria.version_range.describe()
    if not is_known_version(observed_version):
        return _build(
            criteria,
            MatchConfidence.LOW,
            MatchMethod.CPE_VERSION_UNKNOWN,
            f"{criteria.cpe.identity()} matches but no version was reported; "
            f"the advisory affects {window}",
        )
    if not criteria.version_range.contains(observed_version):
        return None
    return _build(
        criteria,
        MatchConfidence.HIGH,
        MatchMethod.CPE_VERSION_RANGE,
        f"{criteria.cpe.identity()} {observed_version} falls inside the affected range {window}",
    )


def _exact_verdict(observed_version: str, criteria: CpeCriteria) -> Match | None:
    if not is_known_version(observed_version):
        return _build(
            criteria,
            MatchConfidence.LOW,
            MatchMethod.CPE_VERSION_UNKNOWN,
            f"{criteria.cpe.identity()} matches but no version was reported; "
            f"the advisory names {criteria.cpe.version}",
        )
    if compare_versions(observed_version, criteria.cpe.version) != 0:
        return None
    return _build(
        criteria,
        MatchConfidence.HIGH,
        MatchMethod.CPE_VERSION_EXACT,
        f"{criteria.cpe.identity()} {observed_version} is the exact version named by the advisory",
    )


def _heuristic_match(observed: ObservedSoftware, criteria: CpeCriteria) -> Match | None:
    """Last resort: nmap gave a product string but no usable CPE.

    Requires whole-token equality of the product name *and* a version that
    demonstrably falls in the affected window. Product name alone proves
    nothing — plenty of vendors ship something called ``server`` — so a name
    agreement without version agreement produces no finding at all.
    """
    if not observed.product or not is_known_version(observed.version):
        return None
    if normalise_product_name(observed.product) != criteria.cpe.product:
        return None
    version = observed.version or ""
    if not _affects_version(criteria, version):
        return None
    return _build(
        criteria,
        MatchConfidence.LOW,
        MatchMethod.PRODUCT_NAME_HEURISTIC,
        f"product name {observed.product!r} version {version} matches "
        f"{criteria.cpe.identity()}, but the scan reported no CPE to confirm the vendor",
    )


def _affects_version(criteria: CpeCriteria, version: str) -> bool:
    if criteria.version_range.is_bounded:
        return criteria.version_range.contains(version)
    if criteria.cpe.version != ANY:
        return compare_versions(version, criteria.cpe.version) == 0
    return True


def _build(
    criteria: CpeCriteria, confidence: MatchConfidence, method: MatchMethod, rationale: str
) -> Match:
    return Match(cve_id=criteria.cve_id, confidence=confidence, method=method, rationale=rationale)
