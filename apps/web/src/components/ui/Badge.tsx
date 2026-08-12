import type { ReactNode } from 'react';
import { Icon } from './Icon';
import type { Exposure, FindingStatus, ScanStatus } from '@/types/domain';
import { EXPOSURE_LABEL, FINDING_STATUS_LABEL, FINDING_STATUS_TONE } from '@/lib/risk';

export type BadgeTone = 'neutral' | 'ok' | 'warn' | 'danger' | 'info' | 'brand';

export function Badge({
  tone = 'neutral',
  children,
  className,
}: {
  tone?: BadgeTone;
  children: ReactNode;
  className?: string;
}) {
  const classes = ['badge', tone !== 'neutral' ? `badge--${tone}` : '', className ?? '']
    .filter(Boolean)
    .join(' ');
  return <span className={classes}>{children}</span>;
}

/**
 * The KEV marker. CISA's Known Exploited Vulnerabilities catalogue means "this is being
 * used against real organisations right now", which is the single most actionable fact
 * about a finding — so it gets its own always-labelled badge rather than a colour hint.
 */
export function KevBadge({ dueDate }: { dueDate?: string | null }) {
  return (
    <Badge tone="danger">
      <Icon name="alert" size={11} />
      KEV
      {dueDate ? <span className="mono">{dueDate}</span> : null}
    </Badge>
  );
}

export function ExposureBadge({ exposure }: { exposure: Exposure }) {
  return (
    <span className="chip" style={{ color: `var(--exp-${exposure})`, borderColor: 'currentColor' }}>
      <Icon name={exposure === 'internet' ? 'unlock' : 'lock'} size={11} />
      {EXPOSURE_LABEL[exposure]}
    </span>
  );
}

const FINDING_TONE_TO_BADGE: Record<'danger' | 'warn' | 'ok' | 'neutral', BadgeTone> = {
  danger: 'danger',
  warn: 'warn',
  ok: 'ok',
  neutral: 'neutral',
};

export function FindingStatusBadge({ status }: { status: FindingStatus }) {
  return (
    <Badge tone={FINDING_TONE_TO_BADGE[FINDING_STATUS_TONE[status]]}>
      {FINDING_STATUS_LABEL[status]}
    </Badge>
  );
}

const SCAN_STATUS_TONE: Record<ScanStatus, BadgeTone> = {
  queued: 'neutral',
  claimed: 'info',
  running: 'info',
  completed: 'ok',
  failed: 'danger',
  cancelled: 'neutral',
};

const SCAN_STATUS_LABEL: Record<ScanStatus, string> = {
  queued: 'Queued',
  claimed: 'Claimed',
  running: 'Running',
  completed: 'Completed',
  failed: 'Failed',
  cancelled: 'Cancelled',
};

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  const isLive = status === 'running' || status === 'claimed';
  return (
    <Badge tone={SCAN_STATUS_TONE[status]}>
      {isLive ? (
        <span className="btn__spinner" style={{ width: 9, height: 9 }} aria-hidden />
      ) : null}
      {SCAN_STATUS_LABEL[status]}
    </Badge>
  );
}

/**
 * Authorization state for a network. Scanning an unauthorized network is refused by the
 * API (`network_not_authorized`), so the UI states the consequence, not just the flag.
 */
export function AuthorizedBadge({ authorized }: { authorized: boolean }) {
  return authorized ? (
    <Badge tone="ok">
      <Icon name="check" size={11} />
      Authorized
    </Badge>
  ) : (
    <Badge tone="warn">
      <Icon name="lock" size={11} />
      Not authorized
    </Badge>
  );
}
