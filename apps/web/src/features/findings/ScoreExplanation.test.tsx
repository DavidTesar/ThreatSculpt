import { describe, expect, it } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import { ScoreExplanation } from './ScoreExplanation';
import { computeBusinessRisk } from '@/lib/risk';
import type { ScoreFactors } from '@/lib/api/scoreFactors';
import { RAW_SCORE_MAX, SCORE_RANGE } from '@/lib/risk';

/** The normalisation block the control plane sends alongside the four documented factors. */
function normalization(raw: number) {
  return {
    raw,
    max_raw: RAW_SCORE_MAX,
    scale: SCORE_RANGE,
    formula: 'cvss_base x exploit_maturity x exposure x asset_criticality, rescaled to 0-100',
    rounding: 'half_up',
  };
}

const FACTORS: ScoreFactors = {
  cvss_base: 10.0,
  exploit_maturity: { value: 'weaponized', multiplier: 1.5 },
  exposure: { value: 'internet', multiplier: 1.4 },
  asset_criticality: { value: 'critical', multiplier: 1.3 },
  services_affected: ['Payment processing'],
  notes: [],
  normalization: normalization(10 * 1.5 * 1.4 * 1.3),
};

describe('ScoreExplanation', () => {
  it('shows the CVSS base as the starting point', () => {
    render(<ScoreExplanation factors={FACTORS} score="100.00" />);

    expect(screen.getByText(/cvss base score/i)).toBeInTheDocument();
    expect(screen.getByText('10.0')).toBeInTheDocument();
  });

  it('names every factor, its value, and its multiplier', () => {
    render(<ScoreExplanation factors={FACTORS} score="100.00" />);

    expect(screen.getByText(/exploit maturity/i)).toBeInTheDocument();
    expect(screen.getByText('Weaponized')).toBeInTheDocument();
    expect(screen.getByText(/↑ 1.5×/)).toBeInTheDocument();

    expect(screen.getByText(/^exposure$/i)).toBeInTheDocument();
    expect(screen.getByText('Internet-facing')).toBeInTheDocument();
    expect(screen.getByText(/↑ 1.4×/)).toBeInTheDocument();

    expect(screen.getByText(/business criticality/i)).toBeInTheDocument();
    expect(screen.getByText(/↑ 1.3×/)).toBeInTheDocument();
  });

  it('explains each factor in plain language, not jargon', () => {
    render(<ScoreExplanation factors={FACTORS} score="100.00" />);

    expect(
      screen.getByText(/reliable attack code is circulating and in active use/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/reachable from the public internet by anyone/i)).toBeInTheDocument();
  });

  it('names the business services that make this finding matter', () => {
    render(<ScoreExplanation factors={FACTORS} score="100.00" />);

    expect(screen.getByText('Payment processing')).toBeInTheDocument();
  });

  it('shows a direction for a multiplier that lowers the score', () => {
    render(
      <ScoreExplanation
        factors={{
          ...FACTORS,
          exposure: { value: 'isolated', multiplier: 0.5 },
          normalization: normalization(10 * 1.5 * 0.5 * 1.3),
        }}
        score="33.48"
      />,
    );

    expect(screen.getByText(/↓ 0.5×/)).toBeInTheDocument();
    expect(screen.getByText(/segmented away from general network access/i)).toBeInTheDocument();
  });

  it('reconciles: the arithmetic on screen ends on the headline score', () => {
    // The most important property of this component. A chain of multipliers that does not
    // add up to the number it claims to explain is worse than no explanation.
    const score = computeBusinessRisk(8.8, 'poc', 'dmz', 'high');
    const factors: ScoreFactors = {
      cvss_base: 8.8,
      exploit_maturity: { value: 'poc', multiplier: 1.2 },
      exposure: { value: 'dmz', multiplier: 1.2 },
      asset_criticality: { value: 'high', multiplier: 1.15 },
      services_affected: ['Order fulfilment'],
      notes: [],
      normalization: normalization(8.8 * 1.2 * 1.2 * 1.15),
    };

    render(<ScoreExplanation factors={factors} score={score.toFixed(2)} />);

    const total = screen.getByText(/business risk score/i).closest('.explain__row');
    expect(total).not.toBeNull();
    expect(within(total as HTMLElement).getByText(score.toFixed(1))).toBeInTheDocument();
  });

  it('says so plainly when the asset is not mapped to any service', () => {
    render(<ScoreExplanation factors={{ ...FACTORS, services_affected: [] }} score="100.00" />);

    expect(screen.getByText(/not mapped to any business service/i)).toBeInTheDocument();
    expect(screen.getByText(/mapping it will make this number more accurate/i)).toBeInTheDocument();
  });
});
