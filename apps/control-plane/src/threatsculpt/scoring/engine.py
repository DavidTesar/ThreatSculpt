"""The risk scoring engine. Pure functions, no I/O.

``score(inputs)`` is total: every input combination — including values that are
not in any multiplier table, a CVE with no CVSS score, and an asset mapped to no
business service — produces a score *and* an explanation of it. There is no
input for which the honest answer is an exception, because the caller is a
scan-result pipeline that cannot stop to ask.
"""

from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal

from threatsculpt.scoring.constants import (
    CRITICALITY_MULTIPLIERS,
    CRITICALITY_RANK,
    CRITICALITY_UNMAPPED,
    EXPLOIT_MATURITY_MULTIPLIERS,
    EXPOSURE_MULTIPLIERS,
    MATURITY_KEV,
    MATURITY_NONE,
    MAX_CVSS_BASE,
    MAX_RAW_SCORE,
    MIN_CVSS_BASE,
    POSTURE_BANDS,
    SCORE_QUANTUM,
    SCORE_SCALE,
    UNKNOWN_FACTOR_MULTIPLIER,
    UNSCORED_CVSS_FALLBACK,
)
from threatsculpt.scoring.model import Factor, RiskScore, ScoreInputs, ServiceCriticality

_NOTE_NO_CVSS = "cvss_base defaulted: this CVE has no published CVSS base score"
_NOTE_CVSS_CLAMPED = "cvss_base clamped to the valid 0.0-10.0 range"
_NOTE_UNMAPPED = "asset supports no business service: criticality treated as neutral"
_NOTE_UNKNOWN_MATURITY = "unrecognised exploit maturity: multiplier left neutral"
_NOTE_UNKNOWN_EXPOSURE = "unrecognised exposure: multiplier left neutral"


def score(inputs: ScoreInputs) -> RiskScore:
    """Compute a finding's business risk score and the explanation of it."""
    notes: list[str] = []

    cvss = _resolve_cvss(inputs.cvss_base, notes)
    maturity = _maturity_factor(inputs, notes)
    exposure = _exposure_factor(inputs.exposure, notes)
    criticality, services = _criticality_factor(inputs.services, notes)

    raw = cvss * maturity.multiplier * exposure.multiplier * criticality.multiplier
    normalised = (raw / MAX_RAW_SCORE) * SCORE_SCALE

    return RiskScore(
        score=_quantise(normalised),
        raw=_quantise(raw),
        max_raw=_quantise(MAX_RAW_SCORE),
        cvss_base=cvss,
        exploit_maturity=maturity,
        exposure=exposure,
        asset_criticality=criticality,
        services_affected=services,
        notes=tuple(notes),
    )


def resolve_maturity_tier(exploit_maturity: str, *, kev_listed: bool) -> str:
    """KEV listing outranks whatever ``exploit_maturity`` says.

    A CVE in CISA's catalogue has been used against real targets; that fact
    cannot be weaker than "a proof of concept exists".
    """
    if kev_listed:
        return MATURITY_KEV
    return exploit_maturity or MATURITY_NONE


def resolve_criticality(services: tuple[ServiceCriticality, ...]) -> str:
    """Highest criticality wins when an asset supports several services.

    Averaging would let one ``low`` service dilute a ``critical`` one, which
    reverses the point: a host that payment processing depends on is a payment
    processing host regardless of what else also runs on it.
    """
    if not services:
        return CRITICALITY_UNMAPPED
    return max(services, key=lambda item: CRITICALITY_RANK.get(item.criticality, -1)).criticality


def posture_band(value: Decimal) -> str:
    """Band for a 0-100 posture score, per docs/API.md."""
    for threshold, band in POSTURE_BANDS:
        if value >= threshold:
            return band
    return POSTURE_BANDS[-1][1]


def _resolve_cvss(value: Decimal | None, notes: list[str]) -> Decimal:
    if value is None:
        notes.append(_NOTE_NO_CVSS)
        return UNSCORED_CVSS_FALLBACK
    if value < MIN_CVSS_BASE or value > MAX_CVSS_BASE:
        notes.append(_NOTE_CVSS_CLAMPED)
        return min(max(value, MIN_CVSS_BASE), MAX_CVSS_BASE)
    return value


def _maturity_factor(inputs: ScoreInputs, notes: list[str]) -> Factor:
    tier = resolve_maturity_tier(inputs.exploit_maturity, kev_listed=inputs.kev_listed)
    multiplier = EXPLOIT_MATURITY_MULTIPLIERS.get(tier)
    if multiplier is None:
        notes.append(_NOTE_UNKNOWN_MATURITY)
        return Factor(value=tier, multiplier=UNKNOWN_FACTOR_MULTIPLIER)
    return Factor(value=tier, multiplier=multiplier)


def _exposure_factor(exposure: str, notes: list[str]) -> Factor:
    multiplier = EXPOSURE_MULTIPLIERS.get(exposure)
    if multiplier is None:
        notes.append(_NOTE_UNKNOWN_EXPOSURE)
        return Factor(value=exposure, multiplier=UNKNOWN_FACTOR_MULTIPLIER)
    return Factor(value=exposure, multiplier=multiplier)


def _criticality_factor(
    services: tuple[ServiceCriticality, ...], notes: list[str]
) -> tuple[Factor, tuple[str, ...]]:
    tier = resolve_criticality(services)
    if tier == CRITICALITY_UNMAPPED:
        notes.append(_NOTE_UNMAPPED)
    multiplier = CRITICALITY_MULTIPLIERS.get(tier, UNKNOWN_FACTOR_MULTIPLIER)
    affected = tuple(item.name for item in services)
    return Factor(value=tier, multiplier=multiplier), affected


def _quantise(value: Decimal) -> Decimal:
    """Two decimal places, matching ``findings.business_risk_score``'s numeric(5,2)."""
    return value.quantize(SCORE_QUANTUM, rounding=ROUND_HALF_UP)
