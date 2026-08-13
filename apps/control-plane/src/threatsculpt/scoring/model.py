"""Value objects for the scoring engine. All frozen, all inert.

Nothing here touches a database, a clock, or the network — the engine is a
function of its inputs, which is what makes every multiplier path testable
without a fixture.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from typing import Any

from threatsculpt.scoring.constants import (
    EXPOSURE_INTERNAL,
    FORMULA,
    ROUNDING_RULE,
    SCORE_SCALE,
)


@dataclass(frozen=True, slots=True)
class ServiceCriticality:
    """One business service an asset supports, as scoring sees it."""

    name: str
    criticality: str


@dataclass(frozen=True, slots=True)
class ScoreInputs:
    """Everything the formula consumes.

    ``kev_listed`` is carried separately from ``exploit_maturity`` because the
    data model stores them in separate columns; the engine resolves the two into
    a single maturity tier so that precedence rule lives in exactly one place.
    """

    cvss_base: Decimal | None
    exploit_maturity: str
    kev_listed: bool = False
    exposure: str = EXPOSURE_INTERNAL
    services: tuple[ServiceCriticality, ...] = ()


@dataclass(frozen=True, slots=True)
class Factor:
    """One multiplier and the input value that selected it."""

    value: str
    multiplier: Decimal

    def as_dict(self) -> dict[str, Any]:
        return {"value": self.value, "multiplier": float(self.multiplier)}


@dataclass(frozen=True, slots=True)
class RiskScore:
    """A score plus the complete arithmetic that produced it.

    ``score_factors`` is not a debug field. A number an executive cannot
    interrogate is a number an executive ignores, so the explanation is built
    here, alongside the score, rather than reconstructed later by a caller who
    might reconstruct it differently.
    """

    score: Decimal
    raw: Decimal
    max_raw: Decimal
    cvss_base: Decimal
    exploit_maturity: Factor
    exposure: Factor
    asset_criticality: Factor
    services_affected: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    def score_factors(self) -> dict[str, Any]:
        """The ``findings.score_factors`` jsonb payload.

        The five keys docs/DATA-MODEL.md specifies appear exactly as specified.
        ``normalization`` and ``notes`` are added on top: the four documented
        factors multiply out to ``raw``, not to the stored score, so without the
        divisor a reader cannot reproduce the number the UI shows — and an
        unreproducible number is the thing this field exists to prevent.
        """
        return {
            "cvss_base": float(self.cvss_base),
            "exploit_maturity": self.exploit_maturity.as_dict(),
            "exposure": self.exposure.as_dict(),
            "asset_criticality": self.asset_criticality.as_dict(),
            "services_affected": list(self.services_affected),
            "normalization": {
                "raw": float(self.raw),
                "max_raw": float(self.max_raw),
                "scale": float(SCORE_SCALE),
                "formula": FORMULA,
                "rounding": ROUNDING_RULE,
            },
            "notes": list(self.notes),
        }
