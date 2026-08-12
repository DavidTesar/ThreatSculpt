/**
 * The shared vocabulary for risk: severity bands, exposure ordering, criticality tiers,
 * and the plain-English glosses the executive surfaces use instead of jargon.
 */

import type {
  Criticality,
  Exposure,
  ExploitMaturity,
  FindingStatus,
  RiskBand,
  Severity,
} from '@/types/domain';

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

export function bandForScore(score: number): RiskBand {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'elevated';
  if (score >= 35) return 'moderate';
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

/* ---------------------------------------------------------------- exploit maturity */

export const EXPLOIT_MATURITY_LABEL: Record<ExploitMaturity, string> = {
  weaponized: 'Weaponized',
  poc: 'Proof of concept',
  none: 'None known',
};

export const EXPLOIT_MATURITY_GLOSS: Record<ExploitMaturity, string> = {
  weaponized: 'Reliable attack code is circulating and in active use.',
  poc: 'Demonstration code exists publicly; turning it into a real attack is plausible.',
  none: 'No public exploit code is known for this vulnerability.',
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
 * The multipliers in ARCHITECTURE.md are documented but their values are not, so these
 * mirror the control plane's scoring table. They are duplicated here only to explain a
 * score the server already computed — the UI never scores a finding itself.
 */
export const EXPLOIT_MATURITY_MULTIPLIER: Record<ExploitMaturity, number> = {
  weaponized: 1.5,
  poc: 1.25,
  none: 1.0,
};

export const EXPOSURE_MULTIPLIER: Record<Exposure, number> = {
  internet: 1.4,
  dmz: 1.2,
  internal: 1.0,
  isolated: 0.8,
};

export const CRITICALITY_MULTIPLIER: Record<Criticality, number> = {
  critical: 1.3,
  high: 1.15,
  medium: 1.0,
  low: 0.9,
};

/**
 * cvss_base × exploit_maturity × exposure × asset_criticality tops out at
 * 10.0 × 1.5 × 1.4 × 1.3 = 27.3. Findings are reported on a 0–100 scale (API.md shows
 * `worst_finding_score: 94.5`), so the product is rescaled by this factor.
 *
 * It is shown as an explicit final step in the explanation rather than hidden, because a
 * chain of arithmetic that does not reconcile with the headline number is worse than no
 * explanation at all.
 */
export const RAW_SCORE_MAX = 27.3;
export const SCORE_SCALE = 100 / RAW_SCORE_MAX;

/**
 * Expands `score_factors` into the ordered multiplication that produced the score:
 *
 *   business_risk = cvss_base × exploit_maturity × exposure × asset_criticality
 *
 * (ARCHITECTURE.md, "Risk scoring — the actual product"). Returning the running total at
 * each step is what lets the UI show the arithmetic rather than assert a conclusion.
 */
export function explainScore(factors: {
  cvss_base: number;
  exploit_maturity: { value: ExploitMaturity; multiplier: number };
  exposure: { value: Exposure; multiplier: number };
  asset_criticality: { value: Criticality; multiplier: number };
}): { base: number; steps: ScoreStep[]; total: number } {
  const base = factors.cvss_base;
  let running = base;

  const steps: ScoreStep[] = [];

  running = running * factors.exploit_maturity.multiplier;
  steps.push({
    key: 'exploit_maturity',
    label: 'Exploit maturity',
    value: EXPLOIT_MATURITY_LABEL[factors.exploit_maturity.value],
    multiplier: factors.exploit_maturity.multiplier,
    runningTotal: running,
    gloss: EXPLOIT_MATURITY_GLOSS[factors.exploit_maturity.value],
  });

  running = running * factors.exposure.multiplier;
  steps.push({
    key: 'exposure',
    label: 'Exposure',
    value: EXPOSURE_LABEL[factors.exposure.value],
    multiplier: factors.exposure.multiplier,
    runningTotal: running,
    gloss: EXPOSURE_GLOSS[factors.exposure.value],
  });

  running = running * factors.asset_criticality.multiplier;
  steps.push({
    key: 'asset_criticality',
    label: 'Business criticality',
    value: CRITICALITY_LABEL[factors.asset_criticality.value],
    multiplier: factors.asset_criticality.multiplier,
    runningTotal: running,
    gloss: `The affected asset supports a service rated ${CRITICALITY_LABEL[
      factors.asset_criticality.value
    ].toLowerCase()} to the business.`,
  });

  running = Math.min(100, running * SCORE_SCALE);
  steps.push({
    key: 'scale',
    label: 'Rescaled to 0–100',
    value: 'Reporting scale',
    multiplier: SCORE_SCALE,
    runningTotal: running,
    gloss:
      'The factors above produce a value out of 27.3. It is rescaled so every finding in the product is comparable on the same 0–100 scale.',
  });

  return { base, steps, total: running };
}

/** Computes the reported 0–100 score from the documented factors. */
export function computeBusinessRisk(
  cvssBase: number,
  maturity: ExploitMaturity,
  exposure: Exposure,
  criticality: Criticality,
): number {
  const raw =
    cvssBase *
    EXPLOIT_MATURITY_MULTIPLIER[maturity] *
    EXPOSURE_MULTIPLIER[exposure] *
    CRITICALITY_MULTIPLIER[criticality];
  return Math.round(Math.min(100, raw * SCORE_SCALE) * 100) / 100;
}
