import type { ReactElement } from 'react';
import type { Criticality, Severity } from '@/types/domain';
import {
  CRITICALITY_LABEL,
  CRITICALITY_TIER,
  SEVERITY_LABEL,
  SEVERITY_SHAPE,
  type SeverityShape,
} from '@/lib/risk';

/**
 * Severity encoded as a *shape*.
 *
 * Red/amber/green severity coding is invisible to roughly one man in twelve. Every place
 * this product shows severity therefore carries three redundant signals: this glyph, a
 * spelled-out text label, and colour. Remove the colour and the meaning survives.
 */

const SHAPE_NODES: Record<SeverityShape, ReactElement> = {
  // Stop-sign octagon — the hardest stop.
  octagon: <path d="M5.2 1h5.6L14.8 5v5.6L10.8 15H5.2L1.2 10.6V5L5.2 1Z" />,
  // Warning triangle.
  triangle: <path d="M8 1.2 15 14.4H1L8 1.2Z" />,
  diamond: <path d="M8 1 15 8l-7 7-7-7 7-7Z" />,
  circle: <circle cx="8" cy="8" r="6.4" />,
  // Hollow ring — visibly "empty", for no severity.
  ring: <circle cx="8" cy="8" r="5.6" fill="none" stroke="currentColor" strokeWidth="2" />,
};

export interface SeverityMarkProps {
  severity: Severity;
  size?: number;
  className?: string;
}

export function SeverityMark({ severity, size = 11, className }: SeverityMarkProps) {
  const shape = SEVERITY_SHAPE[severity];
  return (
    <svg
      className={className ? `sevmark ${className}` : 'sevmark'}
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="currentColor"
      aria-hidden="true"
      focusable="false"
    >
      {SHAPE_NODES[shape]}
    </svg>
  );
}

export interface SeverityBadgeProps {
  /**
   * `null` when the API sent no severity, or one this build does not recognise. Rendered
   * as an explicit "Unrated" rather than defaulting to `none`: absent evidence and
   * evidence of absence are different claims to make about a vulnerability.
   */
  severity: Severity | null;
  /** Optional trailing detail, e.g. the CVSS base score. */
  detail?: string;
  className?: string;
}

/** Shape + label + colour. The label is never hidden — it is the accessible channel. */
export function SeverityBadge({ severity, detail, className }: SeverityBadgeProps) {
  if (severity === null) {
    return (
      <span className={`sev sev--unrated${className ? ` ${className}` : ''}`}>
        Unrated
        {detail ? <span className="mono">{detail}</span> : null}
      </span>
    );
  }

  return (
    <span className={`sev sev--${severity}${className ? ` ${className}` : ''}`}>
      <SeverityMark severity={severity} />
      {SEVERITY_LABEL[severity]}
      {detail ? <span className="mono">{detail}</span> : null}
    </span>
  );
}

export interface CriticalityMeterProps {
  /** `null` when the API sent a tier this build does not know — shown as "Unrated". */
  criticality: Criticality | null;
  /** When false, renders the meter alone (for dense table cells). */
  showLabel?: boolean;
}

/**
 * Business criticality as filled segments out of four. A quantity read by counting, so it
 * works in greyscale and for a reader who does not know the tier vocabulary.
 */
export function CriticalityMeter({ criticality, showLabel = true }: CriticalityMeterProps) {
  const filled = criticality ? CRITICALITY_TIER[criticality] : 0;
  const text = criticality ? CRITICALITY_LABEL[criticality] : 'Unrated';
  const label = `${text} business criticality, ${filled} of 4`;

  return (
    <span
      className="row"
      style={{
        gap: 'var(--space-2xs)',
        color: criticality ? `var(--sev-${criticality})` : undefined,
      }}
    >
      <span className="tiermeter" role="img" aria-label={label}>
        {[1, 2, 3, 4].map((step) => (
          <span
            key={step}
            className={`tiermeter__seg${step <= filled ? ' tiermeter__seg--on' : ''}`}
          />
        ))}
      </span>
      {showLabel ? (
        <span
          style={{
            fontSize: 'var(--text-xs)',
            fontWeight: 'var(--weight-semibold)',
            color: 'var(--ink)',
          }}
        >
          {text}
        </span>
      ) : null}
    </span>
  );
}
