import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from './useAuth';
import { hasRole } from './roles';
import { EmptyState } from '@/components/ui/States';
import { ButtonLink } from '@/components/ui/Button';
import type { Role } from '@/types/domain';

/** Full-page hold while the session bootstrap is in flight. */
function SessionLoading() {
  return (
    <div
      style={{ minHeight: '100dvh', display: 'grid', placeItems: 'center' }}
      aria-busy="true"
      aria-live="polite"
    >
      <span className="visually-hidden">Restoring your session…</span>
      <span className="btn__spinner" style={{ width: 26, height: 26, color: 'var(--brand)' }} />
    </div>
  );
}

/**
 * Gate for authenticated routes. Redirects to login carrying the attempted location, so a
 * user who followed a deep link lands back on it after signing in instead of on the
 * dashboard having lost their place.
 */
export function RequireAuth() {
  const { status } = useAuth();
  const location = useLocation();

  if (status === 'loading') return <SessionLoading />;
  if (status === 'unauthenticated') {
    return <Navigate to="/login" replace state={{ from: location }} />;
  }
  return <Outlet />;
}

/**
 * Gate for a minimum role. This is a courtesy that keeps users out of screens whose
 * actions would fail — the control plane enforces the same rule at the route layer, and
 * that is the enforcement that counts.
 */
export function RequireRole({ minimum }: { minimum: Role }) {
  const { role } = useAuth();

  if (!hasRole(role ?? undefined, minimum)) {
    return (
      <main className="main" id="main">
        <EmptyState
          icon="lock"
          title="You do not have access to this area"
          body={`This screen requires the ${minimum} role or higher. Your account is currently ${
            role ?? 'unassigned'
          }. An organisation admin can change this in Settings.`}
          action={
            <ButtonLink to="/" variant="primary">
              Back to dashboard
            </ButtonLink>
          }
        />
      </main>
    );
  }
  return <Outlet />;
}
