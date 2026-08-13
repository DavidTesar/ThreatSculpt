"""CPE parsing, version ordering, and match confidence.

The false-positive tests carry as much weight as the true-positive ones. A
security product that cries wolf gets muted, and a muted product misses the
finding that mattered — so "does not match" is a behaviour under test, not an
absence of one.
"""

from __future__ import annotations

import pytest

from threatsculpt.enrichment.cpe import (
    ANY,
    Relation,
    compare_component,
    identity_matches,
    normalise_product_name,
    parse_cpe,
    qualifiers_conflict,
)
from threatsculpt.enrichment.matching import (
    CpeCriteria,
    MatchConfidence,
    MatchMethod,
    ObservedSoftware,
    match_all,
    match_one,
)
from threatsculpt.enrichment.versions import VersionRange, compare_versions, is_known_version

LOG4J = "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
HTTPD_23 = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
HTTPD_22 = "cpe:/a:apache:http_server:2.4.49"


# --- parsing ---------------------------------------------------------------


def test_parses_a_cpe_23_formatted_string() -> None:
    cpe = parse_cpe(HTTPD_23)
    assert cpe is not None
    assert (cpe.part, cpe.vendor, cpe.product) == ("a", "apache", "http_server")
    assert cpe.version == "2.4.49"


def test_parses_the_cpe_22_uri_binding_nmap_still_emits() -> None:
    """nmap reports 2.2 URIs; a matcher that only reads 2.3 silently sees nothing."""
    cpe = parse_cpe(HTTPD_22)
    assert cpe is not None
    assert (cpe.vendor, cpe.product, cpe.version) == ("apache", "http_server", "2.4.49")
    # Components 2.2 does not carry are unknown, not "not applicable".
    assert cpe.target_sw == ANY


def test_short_cpe_22_uri_pads_missing_components_with_any() -> None:
    cpe = parse_cpe("cpe:/a:openbsd:openssh")
    assert cpe is not None
    assert cpe.version == ANY and cpe.update == ANY


def test_empty_components_normalise_to_any() -> None:
    cpe = parse_cpe("cpe:/a:apache::2.4")
    assert cpe is not None
    assert cpe.product == ANY


def test_escaped_colons_do_not_shift_later_components() -> None:
    """A naive split would read the version as a product and score the wrong software."""
    cpe = parse_cpe(r"cpe:2.3:a:vendor:some\:product:1.0:*:*:*:*:*:*:*")
    assert cpe is not None
    assert cpe.product == "some:product"
    assert cpe.version == "1.0"


def test_parsing_is_case_insensitive() -> None:
    cpe = parse_cpe("CPE:2.3:A:Apache:HTTP_Server:2.4.49:*:*:*:*:*:*:*")
    assert cpe is not None
    assert cpe.vendor == "apache" and cpe.product == "http_server"


@pytest.mark.parametrize("value", ["", "not-a-cpe", "http://example.test", "cpe"])
def test_non_cpe_input_returns_none(value: str) -> None:
    assert parse_cpe(value) is None


def test_round_trips_to_a_cpe_23_string() -> None:
    cpe = parse_cpe(HTTPD_22)
    assert cpe is not None
    assert parse_cpe(cpe.to_cpe23()) == cpe


# --- component relations ---------------------------------------------------


@pytest.mark.parametrize(
    ("observed", "criteria", "expected"),
    [
        ("apache", "apache", Relation.EQUAL),
        ("apache", ANY, Relation.SUPERSET),
        (ANY, "apache", Relation.UNDETERMINED),
        ("apache", "nginx", Relation.DISJOINT),
    ],
)
def test_component_relations(observed: str, criteria: str, expected: Relation) -> None:
    assert compare_component(observed, criteria) is expected


def test_qualifier_conflict_only_when_both_sides_are_concrete() -> None:
    observed = parse_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:linux:*:*")
    windows = parse_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:windows:*:*")
    unqualified = parse_cpe(HTTPD_23)
    assert observed is not None and windows is not None and unqualified is not None
    assert qualifiers_conflict(observed, windows) is True
    assert qualifiers_conflict(observed, unqualified) is False


def test_identity_needs_the_observation_to_name_the_product() -> None:
    """Knowing the vendor is not knowing the software; an unknown is not a match."""
    vendor_only = parse_cpe("cpe:/a:apache")
    rule = parse_cpe(HTTPD_23)
    assert vendor_only is not None and rule is not None
    assert vendor_only.product == ANY
    assert identity_matches(vendor_only, rule) is False


# --- version ordering ------------------------------------------------------


@pytest.mark.parametrize(
    ("left", "right", "expected"),
    [
        ("1.9", "1.10", -1),
        ("1.10", "1.9", 1),
        ("2.4.49", "2.4.49", 0),
        ("2.4.9", "2.4.49", -1),
        ("1.0", "1.0.0", -1),
        ("1.2", "1.2-beta", 1),
        ("1.2.1", "1.2.beta", 1),
        ("01.02", "1.2", 0),
        ("3.0.0-rc1", "3.0.0", -1),
    ],
)
def test_version_ordering(left: str, right: str, expected: int) -> None:
    assert compare_versions(left, right) == expected
    assert compare_versions(right, left) == -expected


@pytest.mark.parametrize("value", ["", "*", "-", "unknown", None])
def test_unknown_version_markers(value: str | None) -> None:
    assert is_known_version(value) is False


def test_range_containment_uses_numeric_ordering() -> None:
    """The bug this guards: 1.10 sorting before 1.9 as a string."""
    window = VersionRange(start_including="1.9", end_excluding="1.11")
    assert window.contains("1.10") is True
    assert window.contains("1.8") is False
    assert window.contains("1.11") is False
    assert window.contains("1.9") is True


def test_unbounded_range_contains_everything_including_the_unknown() -> None:
    assert VersionRange().contains("anything") is True
    assert VersionRange().contains("*") is True


def test_bounded_range_refuses_to_guess_at_an_unknown_version() -> None:
    assert VersionRange(end_excluding="2.0").contains("*") is False


def test_range_describes_itself_for_the_explanation() -> None:
    assert VersionRange(start_including="1.0", end_excluding="2.0").describe() == ">= 1.0 and < 2.0"
    assert VersionRange().describe() == "all versions"


# --- matching: true positives ----------------------------------------------


def criteria(cpe: str, **kwargs: object) -> CpeCriteria:
    parsed = parse_cpe(cpe)
    assert parsed is not None
    return CpeCriteria(cve_id=str(kwargs.pop("cve_id", "CVE-2021-0001")), cpe=parsed, **kwargs)  # type: ignore[arg-type]


def test_exact_version_match_is_high_confidence() -> None:
    match = match_one(ObservedSoftware(cpes=(HTTPD_22,)), criteria(HTTPD_23))
    assert match is not None
    assert match.confidence is MatchConfidence.HIGH
    assert match.method is MatchMethod.CPE_VERSION_EXACT


def test_version_inside_a_published_range_is_high_confidence() -> None:
    rule = criteria(
        "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
        version_range=VersionRange(start_including="2.0", end_excluding="2.15.0"),
    )
    match = match_one(ObservedSoftware(cpes=(LOG4J,)), rule)
    assert match is not None
    assert match.confidence is MatchConfidence.HIGH
    assert match.method is MatchMethod.CPE_VERSION_RANGE
    assert "2.15.0" in match.rationale


def test_criteria_with_no_version_bound_is_only_medium_confidence() -> None:
    """ "All versions" may just mean the advisory never listed one."""
    match = match_one(
        ObservedSoftware(cpes=(HTTPD_22,)), criteria("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")
    )
    assert match is not None
    assert match.confidence is MatchConfidence.MEDIUM
    assert match.method is MatchMethod.CPE_ANY_VERSION


def test_unknown_version_is_recorded_as_low_confidence_not_dropped() -> None:
    match = match_one(
        ObservedSoftware(cpes=("cpe:/a:apache:http_server",)),
        criteria(
            "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
            version_range=VersionRange(end_excluding="2.4.50"),
        ),
    )
    assert match is not None
    assert match.confidence is MatchConfidence.LOW
    assert match.method is MatchMethod.CPE_VERSION_UNKNOWN
    assert "no version was reported" in match.rationale


def test_version_reported_beside_the_cpe_is_used_when_the_cpe_omits_it() -> None:
    match = match_one(
        ObservedSoftware(cpes=("cpe:/a:apache:http_server",), version="2.4.49"),
        criteria(HTTPD_23),
    )
    assert match is not None
    assert match.confidence is MatchConfidence.HIGH


# --- matching: false-positive resistance ------------------------------------


def test_version_outside_the_affected_range_does_not_match() -> None:
    rule = criteria(
        "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
        version_range=VersionRange(start_including="2.0", end_excluding="2.15.0"),
    )
    patched = ObservedSoftware(cpes=("cpe:/a:apache:log4j:2.17.1",))
    assert match_one(patched, rule) is None


def test_a_different_vendor_with_the_same_product_name_does_not_match() -> None:
    """``ftp_server`` is not a globally unique name; the vendor is what disambiguates."""
    rule = criteria("cpe:2.3:a:vendor_a:ftp_server:1.0:*:*:*:*:*:*:*")
    other = ObservedSoftware(cpes=("cpe:/a:vendor_b:ftp_server:1.0",))
    assert match_one(other, rule) is None


def test_a_product_name_that_merely_contains_the_criteria_does_not_match() -> None:
    """The substring trap: http_server_proxy is not http_server."""
    rule = criteria("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
    lookalike = ObservedSoftware(cpes=("cpe:/a:apache:http_server_proxy:2.4.49",))
    assert match_one(lookalike, rule) is None


def test_a_different_version_of_the_right_product_does_not_match() -> None:
    patched = ObservedSoftware(cpes=("cpe:/a:apache:http_server:2.4.50",))
    assert match_one(patched, criteria(HTTPD_23)) is None


def test_conflicting_target_platform_does_not_match() -> None:
    rule = criteria("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:windows:*:*")
    linux = ObservedSoftware(cpes=("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:linux:*:*",))
    assert match_one(linux, rule) is None


def test_criteria_naming_neither_vendor_nor_product_is_refused() -> None:
    """A wildcard criteria would otherwise attach one CVE to every host in the estate."""
    rule = criteria("cpe:2.3:a:*:*:*:*:*:*:*:*:*:*")
    assert match_one(ObservedSoftware(cpes=(HTTPD_22,)), rule) is None


def test_non_vulnerable_configuration_rows_never_produce_a_match() -> None:
    rule = criteria(HTTPD_23, vulnerable=False)
    assert match_one(ObservedSoftware(cpes=(HTTPD_22,)), rule) is None


# --- matching: the product-name fallback ------------------------------------


def test_product_name_fallback_requires_a_version_and_is_low_confidence() -> None:
    observed = ObservedSoftware(product="Apache httpd", version="2.4.49")
    match = match_one(observed, criteria(HTTPD_23))
    assert match is None  # "apache_httpd" is not the CPE product "http_server"

    named = ObservedSoftware(product="http server", version="2.4.49")
    match = match_one(named, criteria(HTTPD_23))
    assert match is not None
    assert match.confidence is MatchConfidence.LOW
    assert match.method is MatchMethod.PRODUCT_NAME_HEURISTIC
    assert "no CPE to confirm the vendor" in match.rationale


def test_product_name_alone_without_a_version_produces_nothing() -> None:
    assert match_one(ObservedSoftware(product="http server"), criteria(HTTPD_23)) is None


def test_product_name_with_a_version_outside_the_range_produces_nothing() -> None:
    rule = criteria(
        "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
        version_range=VersionRange(end_excluding="2.15.0"),
    )
    assert match_one(ObservedSoftware(product="log4j", version="2.17.1"), rule) is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("Apache httpd", "apache_httpd"), ("  OpenSSH  ", "openssh"), ("HTTP Server", "http_server")],
)
def test_product_name_normalisation(raw: str, expected: str) -> None:
    assert normalise_product_name(raw) == expected


# --- matching: aggregation --------------------------------------------------


def test_the_strongest_match_per_cve_wins() -> None:
    """Two configuration rows for one CVE must not produce two findings."""
    weak = criteria("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", cve_id="CVE-2021-41773")
    strong = criteria(HTTPD_23, cve_id="CVE-2021-41773")

    matches = match_all(ObservedSoftware(cpes=(HTTPD_22,)), (weak, strong))

    assert len(matches) == 1
    assert matches[0].confidence is MatchConfidence.HIGH


def test_matches_come_back_strongest_first() -> None:
    high = criteria(HTTPD_23, cve_id="CVE-2021-41773")
    medium = criteria("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", cve_id="CVE-2020-9490")

    matches = match_all(ObservedSoftware(cpes=(HTTPD_22,)), (medium, high))

    assert [item.cve_id for item in matches] == ["CVE-2021-41773", "CVE-2020-9490"]
