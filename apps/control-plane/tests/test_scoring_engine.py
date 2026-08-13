"""Unit tests for the risk scoring engine.

Pure functions, so every multiplier path is reachable without a database.
"""

from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal

import pytest

from threatsculpt.scoring import (
    CRITICALITY_MULTIPLIERS,
    EXPLOIT_MATURITY_MULTIPLIERS,
    EXPOSURE_MULTIPLIERS,
    MAX_RAW_SCORE,
    SCORE_SCALE,
    ScoreInputs,
    ServiceCriticality,
    posture_band,
    resolve_criticality,
    resolve_maturity_tier,
    score,
)
from threatsculpt.scoring.constants import (
    CRITICALITY_UNMAPPED,
    MATURITY_KEV,
    UNSCORED_CVSS_FALLBACK,
)


def inputs(**overrides: object) -> ScoreInputs:
    base: dict[str, object] = {
        "cvss_base": Decimal("10.0"),
        "exploit_maturity": "none",
        "kev_listed": False,
        "exposure": "internal",
        "services": (),
    }
    base.update(overrides)
    return ScoreInputs(**base)  # type: ignore[arg-type]


def test_worst_case_scores_the_top_of_the_scale() -> None:
    # Arrange
    worst = inputs(
        cvss_base=Decimal("10.0"),
        kev_listed=True,
        exposure="internet",
        services=(ServiceCriticality("Payment processing", "critical"),),
    )

    # Act
    result = score(worst)

    # Assert
    assert result.raw == MAX_RAW_SCORE.quantize(Decimal("0.01"))
    assert result.score == SCORE_SCALE.quantize(Decimal("0.01"))


def test_documented_example_reproduces_the_documented_factors() -> None:
    """docs/DATA-MODEL.md's worked example: weaponized 1.5, internet 1.4, critical 1.3."""
    # Arrange
    example = inputs(
        cvss_base=Decimal("10.0"),
        exploit_maturity="weaponized",
        exposure="internet",
        services=(ServiceCriticality("Payment processing", "critical"),),
    )

    # Act
    factors = score(example).score_factors()

    # Assert
    assert factors["cvss_base"] == 10.0
    assert factors["exploit_maturity"] == {"value": "weaponized", "multiplier": 1.5}
    assert factors["exposure"] == {"value": "internet", "multiplier": 1.4}
    assert factors["asset_criticality"] == {"value": "critical", "multiplier": 1.3}
    assert factors["services_affected"] == ["Payment processing"]


def test_zero_cvss_scores_zero_regardless_of_every_other_factor() -> None:
    result = score(
        inputs(
            cvss_base=Decimal("0.0"),
            kev_listed=True,
            exposure="internet",
            services=(ServiceCriticality("Payments", "critical"),),
        )
    )
    assert result.score == Decimal("0.00")


@pytest.mark.parametrize("maturity", sorted(EXPLOIT_MATURITY_MULTIPLIERS))
def test_every_maturity_multiplier_is_applied_and_explained(maturity: str) -> None:
    # Arrange — KEV is reached through the flag, not the column.
    payload = (
        inputs(kev_listed=True) if maturity == MATURITY_KEV else inputs(exploit_maturity=maturity)
    )

    # Act
    result = score(payload)

    # Assert
    expected = EXPLOIT_MATURITY_MULTIPLIERS[maturity]
    assert result.exploit_maturity == result.exploit_maturity.__class__(maturity, expected)
    assert result.raw == (Decimal("10.0") * expected).quantize(Decimal("0.01"))


@pytest.mark.parametrize("exposure", sorted(EXPOSURE_MULTIPLIERS))
def test_every_exposure_multiplier_is_applied_and_explained(exposure: str) -> None:
    result = score(inputs(exposure=exposure))
    assert result.exposure.multiplier == EXPOSURE_MULTIPLIERS[exposure]
    assert result.raw == (Decimal("10.0") * EXPOSURE_MULTIPLIERS[exposure]).quantize(
        Decimal("0.01")
    )


@pytest.mark.parametrize("criticality", ["critical", "high", "medium", "low"])
def test_every_criticality_multiplier_is_applied_and_explained(criticality: str) -> None:
    result = score(inputs(services=(ServiceCriticality("Svc", criticality),)))
    assert result.asset_criticality.multiplier == CRITICALITY_MULTIPLIERS[criticality]


def test_every_multiplier_combination_stays_inside_the_stored_column_range() -> None:
    """``business_risk_score`` is numeric(5,2): the full cross product must fit."""
    for maturity in EXPLOIT_MATURITY_MULTIPLIERS:
        for exposure in EXPOSURE_MULTIPLIERS:
            for criticality in CRITICALITY_MULTIPLIERS:
                result = score(
                    inputs(
                        exploit_maturity=maturity,
                        kev_listed=maturity == MATURITY_KEV,
                        exposure=exposure,
                        services=(
                            ()
                            if criticality == CRITICALITY_UNMAPPED
                            else (ServiceCriticality("Svc", criticality),)
                        ),
                    )
                )
                assert Decimal("0") <= result.score <= Decimal("100")
                assert result.score.as_tuple().exponent == -2


def test_highest_criticality_wins_when_an_asset_supports_several_services() -> None:
    # Arrange — deliberately unordered, with the critical service last.
    services = (
        ServiceCriticality("Internal wiki", "low"),
        ServiceCriticality("Reporting", "medium"),
        ServiceCriticality("Payment processing", "critical"),
        ServiceCriticality("Support portal", "high"),
    )

    # Act
    result = score(inputs(services=services))

    # Assert
    assert result.asset_criticality.value == "critical"
    assert result.asset_criticality.multiplier == CRITICALITY_MULTIPLIERS["critical"]
    assert result.services_affected == tuple(item.name for item in services)


def test_resolve_criticality_returns_unmapped_for_an_asset_with_no_services() -> None:
    assert resolve_criticality(()) == CRITICALITY_UNMAPPED


def test_unmapped_asset_is_neutral_and_says_so() -> None:
    result = score(inputs(services=()))
    assert result.asset_criticality.value == CRITICALITY_UNMAPPED
    assert result.asset_criticality.multiplier == Decimal("1.0")
    assert any("no business service" in note for note in result.notes)


def test_kev_listing_outranks_the_exploit_maturity_column() -> None:
    assert resolve_maturity_tier("poc", kev_listed=True) == MATURITY_KEV
    assert resolve_maturity_tier("poc", kev_listed=False) == "poc"
    kev = score(inputs(exploit_maturity="poc", kev_listed=True))
    weaponized = score(inputs(exploit_maturity="weaponized", kev_listed=False))
    assert kev.score > weaponized.score


def test_missing_cvss_falls_back_and_records_the_substitution() -> None:
    result = score(inputs(cvss_base=None))
    assert result.cvss_base == UNSCORED_CVSS_FALLBACK
    assert any("no published CVSS" in note for note in result.notes)


@pytest.mark.parametrize(
    ("supplied", "expected"),
    [(Decimal("-1.0"), Decimal("0.0")), (Decimal("11.0"), Decimal("10.0"))],
)
def test_out_of_range_cvss_is_clamped_and_recorded(supplied: Decimal, expected: Decimal) -> None:
    result = score(inputs(cvss_base=supplied))
    assert result.cvss_base == expected
    assert any("clamped" in note for note in result.notes)


def test_unrecognised_factor_values_stay_neutral_rather_than_inflating_risk() -> None:
    result = score(inputs(exploit_maturity="rumoured", exposure="orbital"))
    assert result.exploit_maturity.multiplier == Decimal("1.0")
    assert result.exposure.multiplier == Decimal("1.0")
    assert len(result.notes) >= 2


def test_score_factors_always_multiply_out_to_the_stored_score() -> None:
    """The explanation is the feature: it must reproduce the number, exactly."""
    for maturity in EXPLOIT_MATURITY_MULTIPLIERS:
        for exposure in EXPOSURE_MULTIPLIERS:
            for criticality in ("critical", "high", "medium", "low"):
                for cvss in (None, Decimal("0.0"), Decimal("4.3"), Decimal("9.8")):
                    result = score(
                        inputs(
                            cvss_base=cvss,
                            exploit_maturity=maturity,
                            kev_listed=maturity == MATURITY_KEV,
                            exposure=exposure,
                            services=(ServiceCriticality("Svc", criticality),),
                        )
                    )
                    factors = result.score_factors()
                    product = (
                        Decimal(str(factors["cvss_base"]))
                        * Decimal(str(factors["exploit_maturity"]["multiplier"]))
                        * Decimal(str(factors["exposure"]["multiplier"]))
                        * Decimal(str(factors["asset_criticality"]["multiplier"]))
                    )
                    normalization = factors["normalization"]
                    assert normalization["rounding"] == "half_up"
                    rescaled = (
                        product
                        / Decimal(str(normalization["max_raw"]))
                        * Decimal(str(normalization["scale"]))
                    )
                    assert (
                        rescaled.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP) == result.score
                    )


def test_score_factors_carry_every_key_the_data_model_documents() -> None:
    factors = score(inputs(services=(ServiceCriticality("Payments", "critical"),))).score_factors()
    assert {
        "cvss_base",
        "exploit_maturity",
        "exposure",
        "asset_criticality",
        "services_affected",
    } <= set(factors)


@pytest.mark.parametrize(
    ("value", "band"),
    [
        (Decimal("100"), "critical"),
        (Decimal("80"), "critical"),
        (Decimal("79.99"), "elevated"),
        (Decimal("72"), "elevated"),
        (Decimal("60"), "elevated"),
        (Decimal("59.99"), "moderate"),
        (Decimal("40"), "moderate"),
        (Decimal("39.99"), "low"),
        (Decimal("0"), "low"),
    ],
)
def test_posture_bands_partition_the_scale(value: Decimal, band: str) -> None:
    assert posture_band(value) == band


def test_isolated_exposure_discounts_and_internet_amplifies() -> None:
    isolated = score(inputs(exposure="isolated"))
    internal = score(inputs(exposure="internal"))
    internet = score(inputs(exposure="internet"))
    assert isolated.score < internal.score < internet.score
