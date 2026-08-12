import type { ReactNode } from 'react';
import { Icon, type IconName } from './Icon';
import { Button } from './Button';
import { isApiError, messageFor } from '@/lib/api/ApiError';

/**
 * Loading, empty, and error states.
 *
 * An empty state is a design problem, not a fallback: it is the first thing a new customer
 * sees on every screen, and "No data" tells them nothing about what to do next. Each empty
 * state here names the thing that is missing and offers the action that fixes it.
 */

export interface EmptyStateProps {
  icon?: IconName;
  title: string;
  body?: ReactNode;
  action?: ReactNode;
  compact?: boolean;
}

export function EmptyState({ icon = 'inbox', title, body, action, compact }: EmptyStateProps) {
  return (
    <div className={`state${compact ? ' state--compact' : ''}`}>
      <Icon name={icon} size={compact ? 24 : 32} className="state__icon" />
      <p className="state__title">{title}</p>
      {body ? <div className="state__body">{body}</div> : null}
      {action ? <div className="state__actions">{action}</div> : null}
    </div>
  );
}

export interface ErrorStateProps {
  error: unknown;
  onRetry?: () => void;
  title?: string;
  compact?: boolean;
}

/**
 * Surfaces the machine-readable code alongside the message. The code is what a customer
 * quotes to support, and it is stable in a way the message text is not.
 */
export function ErrorState({ error, onRetry, title, compact }: ErrorStateProps) {
  const code = isApiError(error) ? error.code : null;
  const heading = title ?? (isApiError(error) && error.isNotFound ? 'Not found' : 'Unable to load');

  return (
    <div className={`state state--error${compact ? ' state--compact' : ''}`} role="alert">
      <Icon name="alert" size={compact ? 24 : 32} className="state__icon" />
      <p className="state__title">{heading}</p>
      <div className="state__body">{messageFor(error)}</div>
      {code ? <span className="state__code">{code}</span> : null}
      {onRetry ? (
        <div className="state__actions">
          <Button variant="secondary" onClick={onRetry}>
            <Icon name="refresh" size={14} />
            Try again
          </Button>
        </div>
      ) : null}
    </div>
  );
}

export function Skeleton({
  height = 16,
  width = '100%',
  radius,
}: {
  height?: number | string;
  width?: number | string;
  radius?: string;
}) {
  return (
    <span
      className="skeleton"
      style={{ display: 'block', height, width, borderRadius: radius }}
      aria-hidden="true"
    />
  );
}

/**
 * A loading placeholder that announces itself once, politely. Individual skeleton bars are
 * `aria-hidden` so a screen reader hears "Loading findings", not eleven empty shapes.
 */
export function LoadingState({ label = 'Loading', rows = 5 }: { label?: string; rows?: number }) {
  return (
    <div className="card__body" aria-busy="true" aria-live="polite">
      <span className="visually-hidden">{label}…</span>
      <div className="skeleton__stack">
        {Array.from({ length: rows }, (_, i) => (
          <Skeleton key={i} height={i === 0 ? 22 : 16} width={i === 0 ? '40%' : '100%'} />
        ))}
      </div>
    </div>
  );
}

export interface AsyncBoundaryProps<T> {
  isLoading: boolean;
  error: unknown;
  data: T | undefined;
  onRetry?: () => void;
  loadingLabel?: string;
  /** Rendered when the request succeeded but returned nothing. */
  empty?: ReactNode;
  isEmpty?: (data: T) => boolean;
  children: (data: T) => ReactNode;
}

/**
 * The four states every data view owes the user — loading, error, empty, and content —
 * in one place, so no screen can quietly forget one.
 */
export function AsyncBoundary<T>({
  isLoading,
  error,
  data,
  onRetry,
  loadingLabel,
  empty,
  isEmpty,
  children,
}: AsyncBoundaryProps<T>) {
  if (isLoading) return <LoadingState label={loadingLabel} />;
  if (error) return <ErrorState error={error} onRetry={onRetry} />;
  if (data === undefined)
    return <ErrorState error={new Error('No data returned.')} onRetry={onRetry} />;
  if (empty && isEmpty?.(data)) return <>{empty}</>;
  return <>{children(data)}</>;
}
