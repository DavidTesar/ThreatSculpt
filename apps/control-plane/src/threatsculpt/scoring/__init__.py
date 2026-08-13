"""Risk scoring — the calculation that makes this a business-impact product.

Pure and dependency-free by design: ``scoring`` imports nothing from ``models``,
``db`` or ``api``. Persistence lives in ``enrichment.scoring_service``, which
loads the inputs and writes the result; this package only does arithmetic.
"""

from threatsculpt.scoring.constants import (
    CRITICALITY_MULTIPLIERS,
    CRITICALITY_RANK,
    CRITICALITY_UNMAPPED,
    EXPLOIT_MATURITY_MULTIPLIERS,
    EXPOSURE_MULTIPLIERS,
    MAX_RAW_SCORE,
    SCORE_SCALE,
)
from threatsculpt.scoring.engine import (
    posture_band,
    resolve_criticality,
    resolve_maturity_tier,
    score,
)
from threatsculpt.scoring.model import Factor, RiskScore, ScoreInputs, ServiceCriticality

__all__ = [
    "CRITICALITY_MULTIPLIERS",
    "CRITICALITY_RANK",
    "CRITICALITY_UNMAPPED",
    "EXPLOIT_MATURITY_MULTIPLIERS",
    "EXPOSURE_MULTIPLIERS",
    "MAX_RAW_SCORE",
    "SCORE_SCALE",
    "Factor",
    "RiskScore",
    "ScoreInputs",
    "ServiceCriticality",
    "posture_band",
    "resolve_criticality",
    "resolve_maturity_tier",
    "score",
]
