import { describe, expect, it } from 'vitest';
import {
  bandForScore,
  computeBusinessRisk,
  explainScore,
  severityForCvss,
  severityRank,
  SEVERITY_SHAPE,
} from './risk';
import { SEVERITIES } from '@/types/domain';

describe('severityForCvss', () => {
  it.each([
    [10.0, 'critical'],
    [9.0, 'critical'],
    [8.9, 'high'],
    [7.0, 'high'],
    [6.9, 'medium'],
    [4.0, 'medium'],
    [3.9, 'low'],
    [0.1, 'low'],
    [0, 'none'],
  ])('maps CVSS %s to %s', (cvss, expected) => {
    expect(severityForCvss(cvss)).toBe(expected);
  });
});

describe('severity encoding', () => {
  it('gives every severity a distinct shape, so colour is never the only signal', () => {
    const shapes = SEVERITIES.map((severity) => SEVERITY_SHAPE[severity]);
    expect(new Set(shapes).size).toBe(SEVERITIES.length);
  });

  it('ranks severities in a strict order', () => {
    expect(severityRank('critical')).toBeGreaterThan(severityRank('high'));
    expect(severityRank('high')).toBeGreaterThan(severityRank('medium'));
    expect(severityRank('medium')).toBeGreaterThan(severityRank('low'));
    expect(severityRank('low')).toBeGreaterThan(severityRank('none'));
  });
});

describe('bandForScore', () => {
  it.each([
    [95, 'critical'],
    [80, 'critical'],
    [79, 'elevated'],
    [60, 'elevated'],
    [59, 'moderate'],
    [35, 'moderate'],
    [34, 'low'],
    [0, 'low'],
  ])('puts %d in the %s band', (score, expected) => {
    expect(bandForScore(score)).toBe(expected);
  });
});

describe('computeBusinessRisk', () => {
  it('reaches 100 only for the worst possible combination', () => {
    expect(computeBusinessRisk(10, 'weaponized', 'internet', 'critical')).toBe(100);
  });

  it('never exceeds 100', () => {
    expect(computeBusinessRisk(10, 'weaponized', 'internet', 'critical')).toBeLessThanOrEqual(100);
  });

  it('ranks business context above raw CVSS — the product premise', () => {
    // A merely-medium flaw on an internet-facing, business-critical, actively exploited
    // asset must outrank a critical flaw sitting on an isolated, low-value box.
    const businessCritical = computeBusinessRisk(6.5, 'weaponized', 'internet', 'critical');
    const technicallyWorse = computeBusinessRisk(9.8, 'none', 'isolated', 'low');

    expect(businessCritical).toBeGreaterThan(technicallyWorse);
  });

  it('lowers the score for an isolated asset', () => {
    const exposed = computeBusinessRisk(7.5, 'poc', 'internet', 'high');
    const isolated = computeBusinessRisk(7.5, 'poc', 'isolated', 'high');

    expect(isolated).toBeLessThan(exposed);
  });
});

describe('explainScore', () => {
  const factors = {
    cvss_base: 8.8,
    exploit_maturity: { value: 'poc', multiplier: 1.25 },
    exposure: { value: 'dmz', multiplier: 1.2 },
    asset_criticality: { value: 'high', multiplier: 1.15 },
  } as const;

  it('walks the documented factors in order, then the rescale', () => {
    const { steps } = explainScore(factors);

    expect(steps.map((step) => step.key)).toEqual([
      'exploit_maturity',
      'exposure',
      'asset_criticality',
      'scale',
    ]);
  });

  it('produces a running total that ends on the reported score', () => {
    const { total } = explainScore(factors);
    const reported = computeBusinessRisk(8.8, 'poc', 'dmz', 'high');

    // Displaying arithmetic that does not reconcile with the headline would undermine the
    // one thing this screen exists to do.
    expect(total).toBeCloseTo(reported, 1);
  });

  it('multiplies cumulatively rather than restating the base each time', () => {
    const { base, steps } = explainScore(factors);

    expect(base).toBe(8.8);
    expect(steps[0]?.runningTotal).toBeCloseTo(8.8 * 1.25, 5);
    expect(steps[1]?.runningTotal).toBeCloseTo(8.8 * 1.25 * 1.2, 5);
    expect(steps[2]?.runningTotal).toBeCloseTo(8.8 * 1.25 * 1.2 * 1.15, 5);
  });

  it('gives every step a plain-language gloss', () => {
    const { steps } = explainScore(factors);

    for (const step of steps) {
      expect(step.gloss.length).toBeGreaterThan(20);
      expect(step.label).toBeTruthy();
    }
  });
});
