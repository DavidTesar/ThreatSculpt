"""The multiplier table. One place, named constants, no magic numbers elsewhere.

    business_risk = cvss_base
                  x exploit_maturity   (KEV listed / weaponized / PoC / none)
                  x exposure           (internet / dmz / internal / isolated)
                  x asset_criticality  (from the business services the asset supports)

Why these numbers
-----------------
The three multipliers named in docs/DATA-MODEL.md's worked example are taken as
given — ``weaponized`` 1.5, ``internet`` 1.4, ``critical`` 1.3 — and the
remaining tiers are filled in around them so the whole ladder is monotonic and
the documented example still produces the documented factors.

* ``kev_listed`` sits *above* ``weaponized`` at 1.6. CISA's Known Exploited
  Vulnerabilities catalogue is not a claim that an exploit exists; it is a
  record that one has been used against real targets. It is the strongest
  signal in the input set, so it outranks every other maturity tier.
* ``isolated`` is the only multiplier below 1.0 in the exposure ladder (0.5).
  An air-gapped host with a critical CVE is genuinely half the problem an
  internal one is, and refusing to ever discount would leave every finding
  competing at the same altitude — which is the failure mode this product
  exists to fix.
* ``low`` criticality is 0.8 rather than something smaller: the customer said
  this service matters least, not that it does not matter.

Normalisation
-------------
The raw product tops out at ``10.0 x 1.6 x 1.4 x 1.3 = 29.12``, which is not a
number anybody can read. docs/API.md's dashboard payload shows scores like
``94.5`` and a posture of ``72``, i.e. a 0-100 scale, so the raw product is
rescaled by ``100 / MAX_RAW_SCORE``. The rescale is linear and lossless, and
both the raw product and the divisor are recorded in ``score_factors`` so the
UI can show the arithmetic rather than assert the result.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Final

#: CVSS v3 base scores run 0.0-10.0.
MIN_CVSS_BASE: Final = Decimal("0.0")
MAX_CVSS_BASE: Final = Decimal("10.0")

#: Used when a CVE has no published CVSS base score — a real state for a freshly
#: disclosed CVE. Scoring it 0 would hide it; scoring it 10 would drown the
#: dashboard. The NVD "medium" midpoint is the least-wrong neutral choice, and
#: the substitution is recorded in ``score_factors.notes`` rather than implied.
UNSCORED_CVSS_FALLBACK: Final = Decimal("5.0")

#: Exploit maturity tier used when a CVE appears in the CISA KEV catalogue. It
#: is not one of ``vulnerabilities.exploit_maturity``'s values — KEV listing is
#: a separate column — so scoring resolves the two into one ladder.
MATURITY_KEV: Final = "kev_listed"
MATURITY_WEAPONIZED: Final = "weaponized"
MATURITY_POC: Final = "poc"
MATURITY_NONE: Final = "none"

EXPLOIT_MATURITY_MULTIPLIERS: Final[dict[str, Decimal]] = {
    MATURITY_KEV: Decimal("1.6"),
    MATURITY_WEAPONIZED: Decimal("1.5"),
    MATURITY_POC: Decimal("1.2"),
    MATURITY_NONE: Decimal("1.0"),
}

EXPOSURE_INTERNET: Final = "internet"
EXPOSURE_DMZ: Final = "dmz"
EXPOSURE_INTERNAL: Final = "internal"
EXPOSURE_ISOLATED: Final = "isolated"

EXPOSURE_MULTIPLIERS: Final[dict[str, Decimal]] = {
    EXPOSURE_INTERNET: Decimal("1.4"),
    EXPOSURE_DMZ: Decimal("1.2"),
    EXPOSURE_INTERNAL: Decimal("1.0"),
    EXPOSURE_ISOLATED: Decimal("0.5"),
}

CRITICALITY_CRITICAL: Final = "critical"
CRITICALITY_HIGH: Final = "high"
CRITICALITY_MEDIUM: Final = "medium"
CRITICALITY_LOW: Final = "low"

#: Not a ``business_services.criticality`` value: it is what an asset that maps
#: to no business service resolves to. Recorded honestly rather than silently
#: borrowing ``medium``, because "we do not know what this host supports" and
#: "the customer told us it is medium" are different statements to an executive.
CRITICALITY_UNMAPPED: Final = "unmapped"

CRITICALITY_MULTIPLIERS: Final[dict[str, Decimal]] = {
    CRITICALITY_CRITICAL: Decimal("1.3"),
    CRITICALITY_HIGH: Decimal("1.15"),
    CRITICALITY_MEDIUM: Decimal("1.0"),
    CRITICALITY_LOW: Decimal("0.8"),
    CRITICALITY_UNMAPPED: Decimal("1.0"),
}

#: Highest criticality wins when an asset supports several services, so the
#: tiers need a total order. ``unmapped`` ranks lowest: any declared service
#: beats no declared service.
CRITICALITY_RANK: Final[dict[str, int]] = {
    CRITICALITY_UNMAPPED: 0,
    CRITICALITY_LOW: 1,
    CRITICALITY_MEDIUM: 2,
    CRITICALITY_HIGH: 3,
    CRITICALITY_CRITICAL: 4,
}

#: Applied when a factor value is not in its table. Neutral rather than
#: punitive: an unrecognised value is our bug, and inflating a customer's risk
#: score because of it is worse than leaving the factor out.
UNKNOWN_FACTOR_MULTIPLIER: Final = Decimal("1.0")

#: Largest product the formula can yield: 10.0 x 1.6 x 1.4 x 1.3.
MAX_RAW_SCORE: Final = (
    MAX_CVSS_BASE
    * max(EXPLOIT_MATURITY_MULTIPLIERS.values())
    * max(EXPOSURE_MULTIPLIERS.values())
    * max(CRITICALITY_MULTIPLIERS.values())
)

#: Target range of ``findings.business_risk_score``, per docs/API.md.
SCORE_SCALE: Final = Decimal("100")

#: ``findings.business_risk_score`` is ``numeric(5,2)``.
SCORE_QUANTUM: Final = Decimal("0.01")

FORMULA = "cvss_base x exploit_maturity x exposure x asset_criticality, rescaled to 0-100"

#: Named in ``score_factors`` because a UI that re-derives the score with
#: banker's rounding disagrees with the stored value on every exact half — a
#: one-cent discrepancy that reads as a bug in the number the report is trying
#: to defend.
ROUNDING_RULE: Final = "half_up"

#: Posture bands for the executive dashboard. Ordered high to low; the first
#: threshold a score meets wins. docs/API.md shows 72 -> "elevated".
BAND_CRITICAL: Final = "critical"
BAND_ELEVATED: Final = "elevated"
BAND_MODERATE: Final = "moderate"
BAND_LOW: Final = "low"

POSTURE_BANDS: Final[tuple[tuple[Decimal, str], ...]] = (
    (Decimal("80"), BAND_CRITICAL),
    (Decimal("60"), BAND_ELEVATED),
    (Decimal("40"), BAND_MODERATE),
    (Decimal("0"), BAND_LOW),
)
