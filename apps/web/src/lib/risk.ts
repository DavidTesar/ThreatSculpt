/**
 * The shared vocabulary for risk: severity bands, exposure ordering, criticality tiers,
 * and the plain-English glosses the executive surfaces use instead of jargon.
 */

import {
  toCriticalityTier,
  toExposure,
  toMaturityTier,
  type Criticality,
  type CriticalityTier,
  type Exposure,
  type FindingStatus,
  type MatchConfidence,
  type MaturityTier,
  type RiskBand,
  type Severity,
} from '@/types/domain';
import type { ScoreFactors } from '@/lib/api/scoreFactors';

/* ---------------------------------------------------------------- severity */

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  none: 0,
};

export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER[severity] ?? 0;
}

/** CVSS v3 qualitative bands. */
export function severityForCvss(cvss: number): Severity {
  if (cvss >= 9.0) return 'critical';
  if (cvss >= 7.0) return 'high';
  if (cvss >= 4.0) return 'medium';
  if (cvss > 0) return 'low';
  return 'none';
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  none: 'None',
};

/**
 * Each severity gets its own glyph so severity is legible without colour perception.
 * Shape, not hue, is the primary channel; colour and the text label are the redundancy.
 */
export type SeverityShape = 'octagon' | 'triangle' | 'diamond' | 'circle' | 'ring';

export const SEVERITY_SHAPE: Record<Severity, SeverityShape> = {
  critical: 'octagon',
  high: 'triangle',
  medium: 'diamond',
  low: 'circle',
  none: 'ring',
};

/* ---------------------------------------------------------------- risk band */

/**
 * Thresholds mirror `POSTURE_BANDS` in the control plane's scoring constants. The API
 * sends the band it computed; this exists for the mock server and for tests.
 */
export function bandForScore(score: number): RiskBand {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'elevated';
  if (score >= 40) return 'moderate';
  return 'low';
}

export const BAND_LABEL: Record<RiskBand, string> = {
  critical: 'Critical',
  elevated: 'Elevated',
  moderate: 'Moderate',
  low: 'Low',
};

/** The sentence under the headline number. Written for a reader who does not know CVSS. */
export const BAND_NARRATIVE: Record<RiskBand, string> = {
  critical:
    'Business-critical services are exposed to vulnerabilities with known working exploits. This warrants attention this week.',
  elevated:
    'Several services carry exposure that a motivated attacker could reach. Work is needed, but nothing here is on fire today.',
  moderate:
    'Exposure is contained to lower-tier services. Steady remediation will keep it that way.',
  low: 'No business-critical service is currently exposed to a known-exploited vulnerability.',
};

export function bandToSeverity(band: RiskBand): Severity {
  switch (band) {
    case 'critical':
      return 'critical';
    case 'elevated':
      return 'high';
    case 'moderate':
      return 'medium';
    case 'low':
      return 'low';
  }
}

/* ---------------------------------------------------------------- exposure */

export const EXPOSURE_LABEL: Record<Exposure, string> = {
  internet: 'Internet-facing',
  dmz: 'DMZ',
  internal: 'Internal',
  isolated: 'Isolated',
};

/** Why this exposure matters, in the language of someone who does not run the network. */
export const EXPOSURE_GLOSS: Record<Exposure, string> = {
  internet: 'Reachable from the public internet by anyone.',
  dmz: 'In a perimeter network — reachable from outside through a controlled path.',
  internal: 'Reachable only from inside the corporate network.',
  isolated: 'Segmented away from general network access.',
};

/** Ordinal, most exposed first. Drives chart and legend ordering. */
export const EXPOSURE_ORDER: Exposure[] = ['internet', 'dmz', 'internal', 'isolated'];

export const EXPOSURE_COLOR_VAR: Record<Exposure, string> = {
  internet: 'var(--exp-internet)',
  dmz: 'var(--exp-dmz)',
  internal: 'var(--exp-internal)',
  isolated: 'var(--exp-isolated)',
};

/* ---------------------------------------------------------------- criticality */

export const CRITICALITY_LABEL: Record<Criticality, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

/** Filled segments out of four — a quantity readable without colour. */
export const CRITICALITY_TIER: Record<Criticality, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

export function criticalityToSeverity(criticality: Criticality): Severity {
  return criticality;
}

/**
 * `score_factors.asset_criticality.value`, which adds `unmapped` — what an asset that
 * supports no business service resolves to. Recorded honestly rather than borrowing
 * `medium`, because "we do not know what this host supports" and "the customer told us it
 * is medium" are different statements to an executive.
 */
export const CRITICALITY_TIER_LABEL: Record<CriticalityTier, string> = {
  ...CRITICALITY_LABEL,
  unmapped: 'Not mapped',
};

/* ---------------------------------------------------------------- exploit maturity */

/**
 * Keyed by the *scoring ladder*, not by `vulnerabilities.exploit_maturity`. KEV listing
 * outranks every maturity tier and the engine resolves the two into one scale, so a
 * `score_factors` payload can name a tier the CVE column never carries.
 */
export const EXPLOIT_MATURITY_LABEL: Record<MaturityTier, string> = {
  kev_listed: 'Known exploited',
  weaponized: 'Weaponized',
  poc: 'Proof of concept',
  none: 'None known',
};

export const EXPLOIT_MATURITY_GLOSS: Record<MaturityTier, string> = {
  kev_listed:
    'CISA records this flaw being used against real targets — not that an exploit exists, that one has been used.',
  weaponized: 'Reliable attack code is circulating and in active use.',
  poc: 'Demonstration code exists publicly; turning it into a real attack is plausible.',
  none: 'No public exploit code is known for this vulnerability.',
};

/* ---------------------------------------------------------------- match confidence */

/**
 * How sure the CPE matcher was. Shown on every finding rather than on request: an
 * operator deciding whether to wake someone needs to know the difference between "your
 * version is inside the affected range" and "we guessed from a banner".
 */
export const MATCH_CONFIDENCE_LABEL: Record<MatchConfidence, string> = {
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

export const MATCH_CONFIDENCE_GLOSS: Record<MatchConfidence, string> = {
  high: 'The observed version falls inside the range the advisory names.',
  medium: 'The product matches and the version is plausible, but the range is not exact.',
  low: 'Inferred from a service banner. Worth confirming before acting on it.',
};

export const MATCH_CONFIDENCE_TONE: Record<MatchConfidence, 'ok' | 'warn' | 'neutral'> = {
  high: 'ok',
  medium: 'warn',
  low: 'neutral',
};

/* ---------------------------------------------------------------- finding status */

export const FINDING_STATUS_LABEL: Record<FindingStatus, string> = {
  open: 'Open',
  accepted_risk: 'Accepted risk',
  remediated: 'Remediated',
  false_positive: 'False positive',
};

export const FINDING_STATUS_TONE: Record<FindingStatus, 'danger' | 'warn' | 'ok' | 'neutral'> = {
  open: 'danger',
  accepted_risk: 'warn',
  remediated: 'ok',
  false_positive: 'neutral',
};

/* ---------------------------------------------------------------- score explanation */

export interface ScoreStep {
  key: string;
  label: string;
  /** What the factor evaluated to, e.g. "internet". */
  value: string;
  multiplier: number;
  /** Running total after applying this multiplier. */
  runningTotal: number;
  /** Plain-English reason this factor moves the number. */
  gloss: string;
}

/**
 * The control plane's multiplier table, mirrored.
 *
 * Every value here is read from `apps/control-plane/src/threatsculpt/scoring/constants.py`.
 * Production display never uses them: the API sends the multiplier it actually applied in
 * `score_factors`, and {@link explainScore} shows that. They exist for the mock server and
 * for the tests that assert the product's central claim — that business context can
 * outrank raw CVSS.
 *
 * A copy that drifts is worse than no copy, which is what happened before: this table had
 * `poc` at 1.25 against the server's 1.2, `isolated` at 0.8 against 0.5, `low` at 0.9
 * against 0.8, and no `kev_listed` tier at all.
 */
export const EXPLOIT_MATURITY_MULTIPLIER: Record<MaturityTier, number> = {
  kev_listed: 1.6,
  weaponized: 1.5,
  poc: 1.2,
  none: 1.0,
};

export const EXPOSURE_MULTIPLIER: Record<Exposure, number> = {
  internet: 1.4,
  dmz: 1.2,
  internal: 1.0,
  isolated: 0.5,
};

export const CRITICALITY_MULTIPLIER: Record<CriticalityTier, number> = {
  critical: 1.3,
  high: 1.15,
  medium: 1.0,
  low: 0.8,
  unmapped: 1.0,
};

/**
 * cvss_base × exploit_maturity × exposure × asset_criticality tops out at
 * 10.0 × 1.6 × 1.4 × 1.3 = 29.12, and findings are reported on a 0–100 scale, so the raw
 * product is rescaled by `SCORE_RANGE / RAW_SCORE_MAX`.
 *
 * The rescale is shown as an explicit final step in the explanation rather than hidden,
 * because a chain of arithmetic that does not reconcile with the headline number is worse
 * than no explanation at all.
 */
export const RAW_SCORE_MAX = 29.12;
export const SCORE_RANGE = 100;

/**
 * Expands `score_factors` into the ordered multiplication that produced the score:
 *
 *   business_risk = cvss_base × exploit_maturity × exposure × asset_criticality
 *
 * (ARCHITECTURE.md, "Risk scoring — the actual product"). Returning the running total at
 * each step is what lets the UI show the arithmetic rather than assert a conclusion.
 *
 * The rescale divisor comes from `factors.normalization` when the server sent one. Reading
 * it beats recomputing it: the moment the control plane retunes a tier, a locally derived
 * divisor makes the explanation disagree with the very number it exists to defend.
 */
export function explainScore(factors: ScoreFactors): {
  base: number;
  steps: ScoreStep[];
  total: number;
} {
  const base = factors.cvss_base;
  let running = base;

  const steps: ScoreStep[] = [];

  const maturity = toMaturityTier(factors.exploit_maturity.value);
  running = running * factors.exploit_maturity.multiplier;
  steps.push({
    key: 'exploit_maturity',
    label: 'Exploit maturity',
    value: maturity ? EXPLOIT_MATURITY_LABEL[maturity] : factors.exploit_maturity.value,
    multiplier: factors.exploit_maturity.multiplier,
    runningTotal: running,
    gloss: maturity
      ? EXPLOIT_MATURITY_GLOSS[maturity]
      : 'How readily this vulnerability can be exploited in practice.',
  });

  const exposure = toExposure(factors.exposure.value);
  running = running * factors.exposure.multiplier;
  steps.push({
    key: 'exposure',
    label: 'Exposure',
    value: exposure ? EXPOSURE_LABEL[exposure] : factors.exposure.value,
    multiplier: factors.exposure.multiplier,
    runningTotal: running,
    gloss: exposure
      ? EXPOSURE_GLOSS[exposure]
      : 'Where the affected host sits relative to the outside world.',
  });

  const criticality = toCriticalityTier(factors.asset_criticality.value);
  const criticalityLabel = criticality
    ? CRITICALITY_TIER_LABEL[criticality]
    : factors.asset_criticality.value;
  running = running * factors.asset_criticality.multiplier;
  steps.push({
    key: 'asset_criticality',
    label: 'Business criticality',
    value: criticalityLabel,
    multiplier: factors.asset_criticality.multiplier,
    runningTotal: running,
    gloss:
      criticality === 'unmapped'
        ? 'The affected asset is not mapped to any business service, so it is scored without business context.'
        : `The affected asset supports a service rated ${criticalityLabel.toLowerCase()} to the business.`,
  });

  const maxRaw = factors.normalization?.max_raw ?? RAW_SCORE_MAX;
  const range = factors.normalization?.scale ?? SCORE_RANGE;
  const scale = maxRaw > 0 ? range / maxRaw : 1;

  running = Math.min(range, running * scale);
  steps.push({
    key: 'scale',
    label: `Rescaled to 0–${range}`,
    value: 'Reporting scale',
    multiplier: scale,
    runningTotal: running,
    gloss: `The factors above produce a value out of ${maxRaw}. It is rescaled so every finding in the product is comparable on the same 0–${range} scale.`,
  });

  return { base, steps, total: running };
}

/**
 * The reported 0–100 score from the documented factors. Mirrors the control plane's
 * `scoring.engine.score`; see the multiplier table above for why a copy exists at all.
 */
export function computeBusinessRisk(
  cvssBase: number,
  maturity: MaturityTier,
  exposure: Exposure,
  criticality: CriticalityTier,
): number {
  const raw =
    cvssBase *
    EXPLOIT_MATURITY_MULTIPLIER[maturity] *
    EXPOSURE_MULTIPLIER[exposure] *
    CRITICALITY_MULTIPLIER[criticality];
  const normalised = Math.min(SCORE_RANGE, (raw / RAW_SCORE_MAX) * SCORE_RANGE);
  return Math.round(normalised * 100) / 100;
}
