/**
 * Presentation formatting. Pure functions, no React, so they are cheap to unit test.
 */

/**
 * Every PostgreSQL `numeric` — money, risk scores, node weights — crosses the wire as a
 * decimal *string*, because the control plane serialises `Decimal` rather than `float`.
 *
 * Parsing to Number is safe for display at these precisions — `numeric(14,2)` exceeds
 * `Number.MAX_SAFE_INTEGER` only past 10^15, and revenue-at-risk figures are orders of
 * magnitude below that — but the parsed value is never round-tripped back to the server.
 */
export function parseDecimal(value: string | number | null | undefined): number | null {
  if (value === null || value === undefined || value === '') return null;
  const n = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(n) ? n : null;
}

/** Full currency, e.g. "$4,200,000". Cents dropped — nobody budgets an exposure to the cent. */
export function formatCurrency(value: string | number | null | undefined): string {
  const n = parseDecimal(value);
  if (n === null) return '—';
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    maximumFractionDigits: 0,
  }).format(n);
}

/**
 * Compact currency for headline figures, e.g. "$4.2M". An executive reads magnitude, not
 * digits; the exact figure stays available in the accessible label and detail views.
 */
export function formatCurrencyCompact(value: string | number | null | undefined): string {
  const n = parseDecimal(value);
  if (n === null) return '—';
  if (Math.abs(n) < 1000) {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      maximumFractionDigits: 0,
    }).format(n);
  }
  return new Intl.NumberFormat('en-US', {
    style: 'currency',
    currency: 'USD',
    notation: 'compact',
    maximumFractionDigits: 1,
  }).format(n);
}

export function formatNumber(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return new Intl.NumberFormat('en-US').format(value);
}

/**
 * Risk scores are `numeric(5,2)` and arrive as decimal strings; one decimal is the useful
 * resolution.
 */
export function formatScore(value: string | number | null | undefined): string {
  const n = parseDecimal(value);
  if (n === null) return '—';
  return n.toFixed(1);
}

export function formatMultiplier(value: number): string {
  return `${value.toFixed(2).replace(/\.?0+$/, '')}×`;
}

export function formatPercent(value: number | null | undefined, digits = 0): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  return `${value.toFixed(digits)}%`;
}

/** Signed delta, e.g. "-8" / "+3". Used for trend figures where direction is the point. */
export function formatDelta(value: number | null | undefined): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '—';
  if (value === 0) return 'no change';
  return `${value > 0 ? '+' : '−'}${Math.abs(value)}`;
}

const DATE_FMT = new Intl.DateTimeFormat('en-US', {
  year: 'numeric',
  month: 'short',
  day: 'numeric',
});

const DATETIME_FMT = new Intl.DateTimeFormat('en-US', {
  year: 'numeric',
  month: 'short',
  day: 'numeric',
  hour: 'numeric',
  minute: '2-digit',
});

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '—' : DATE_FMT.format(d);
}

export function formatDateTime(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? '—' : DATETIME_FMT.format(d);
}

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** "3 hours ago" / "in 42 minutes". Falls back to an absolute date beyond 30 days. */
export function formatRelative(iso: string | null | undefined, now: number = Date.now()): string {
  if (!iso) return 'never';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '—';

  const diff = then - now;
  const abs = Math.abs(diff);

  if (abs > 30 * DAY) return formatDate(iso);
  if (abs < MINUTE) return diff < 0 ? 'just now' : 'in a moment';

  const rtf = new Intl.RelativeTimeFormat('en-US', { numeric: 'auto' });
  if (abs < HOUR) return rtf.format(Math.round(diff / MINUTE), 'minute');
  if (abs < DAY) return rtf.format(Math.round(diff / HOUR), 'hour');
  return rtf.format(Math.round(diff / DAY), 'day');
}

/** Initials for an avatar chip. Falls back to the email local part. */
export function initialsFor(name: string | null | undefined, email?: string): string {
  const source = name?.trim() || email?.split('@')[0] || '?';
  const parts = source.split(/[\s._-]+/).filter(Boolean);
  const first = parts[0]?.[0] ?? '?';
  const second = parts.length > 1 ? (parts[parts.length - 1]?.[0] ?? '') : '';
  return (first + second).toUpperCase();
}

export function titleCase(value: string): string {
  return value
    .split(/[\s_-]+/)
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
    .join(' ');
}

export function pluralize(count: number, singular: string, plural?: string): string {
  return count === 1 ? singular : (plural ?? `${singular}s`);
}
