import { describe, expect, it } from 'vitest';
import {
  formatCurrency,
  formatCurrencyCompact,
  formatDelta,
  formatMultiplier,
  formatRelative,
  formatScore,
  initialsFor,
  parseMoney,
  pluralize,
} from './format';

describe('money formatting', () => {
  it('parses the numeric(14,2) string the API sends', () => {
    expect(parseMoney('4200000.00')).toBe(4200000);
    expect(parseMoney(null)).toBeNull();
    expect(parseMoney('')).toBeNull();
    expect(parseMoney('not-money')).toBeNull();
  });

  it('formats full currency without cents', () => {
    expect(formatCurrency('4200000.00')).toBe('$4,200,000');
  });

  it('compacts headline figures', () => {
    expect(formatCurrencyCompact('4200000.00')).toBe('$4.2M');
    expect(formatCurrencyCompact('980000.00')).toBe('$980K');
    expect(formatCurrencyCompact('750')).toBe('$750');
  });

  it('renders an em dash rather than $0 for a service with no figure', () => {
    // "$0 revenue at risk" would read as "this is safe", which is the opposite of
    // "nobody has costed this yet".
    expect(formatCurrency(null)).toBe('—');
    expect(formatCurrencyCompact(null)).toBe('—');
  });
});

describe('number formatting', () => {
  it('shows one decimal for risk scores', () => {
    expect(formatScore(94.456)).toBe('94.5');
    expect(formatScore(null)).toBe('—');
  });

  it('trims trailing zeros from multipliers', () => {
    expect(formatMultiplier(1.5)).toBe('1.5×');
    expect(formatMultiplier(1.0)).toBe('1×');
    expect(formatMultiplier(1.25)).toBe('1.25×');
  });

  it('signs deltas and names the zero case', () => {
    expect(formatDelta(-8)).toBe('−8');
    expect(formatDelta(3)).toBe('+3');
    expect(formatDelta(0)).toBe('no change');
  });
});

describe('formatRelative', () => {
  const now = new Date('2026-08-12T12:00:00Z').getTime();

  it('describes recent times relatively', () => {
    expect(formatRelative('2026-08-12T11:00:00Z', now)).toMatch(/hour ago/);
    expect(formatRelative('2026-08-11T12:00:00Z', now)).toMatch(/yesterday|1 day ago/i);
  });

  it('falls back to an absolute date beyond 30 days', () => {
    expect(formatRelative('2026-01-02T12:00:00Z', now)).toMatch(/Jan 2, 2026/);
  });

  it('says "never" for a null timestamp', () => {
    expect(formatRelative(null, now)).toBe('never');
  });
});

describe('initialsFor', () => {
  it('takes the first and last initial of a full name', () => {
    expect(initialsFor('Diane Whitfield')).toBe('DW');
    expect(initialsFor('Piotr Zieliński')).toBe('PZ');
  });

  it('falls back to the email local part', () => {
    expect(initialsFor(null, 'marcus.oyelaran@example.com')).toBe('MO');
  });

  it('handles a single-word name', () => {
    expect(initialsFor('Prince')).toBe('P');
  });
});

describe('pluralize', () => {
  it('handles regular and irregular plurals', () => {
    expect(pluralize(1, 'finding')).toBe('finding');
    expect(pluralize(2, 'finding')).toBe('findings');
    expect(pluralize(2, 'vulnerability', 'vulnerabilities')).toBe('vulnerabilities');
  });
});
