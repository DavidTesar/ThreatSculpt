import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { AuthContext, type AuthContextValue, type AuthStatus } from './authContext';
import { hasRole } from './roles';
import { authApi, type LoginRequest, type RegisterRequest } from '@/lib/api/endpoints';
import { setSessionExpiredHandler } from '@/lib/api/client';
import { isApiError } from '@/lib/api/ApiError';
import { toRole, type CurrentPrincipal, type Role } from '@/types/domain';

/**
 * Owns the session.
 *
 * Cold load carries no access token — it lives only in memory and a reload clears it. The
 * bootstrap call to `/auth/me` therefore goes out unauthenticated, gets a 401, and the API
 * client transparently redeems the HttpOnly refresh cookie for a fresh access token and
 * replays the request. A returning user with a live cookie is signed in without ever
 * seeing the login screen; one without it lands on login. Both paths are the same code.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [status, setStatus] = useState<AuthStatus>('loading');
  const [principal, setPrincipal] = useState<CurrentPrincipal | null>(null);

  const clearSession = useCallback(() => {
    setPrincipal(null);
    setStatus('unauthenticated');
    // Drop every cached tenant-scoped response. Leaving it would let the next user of
    // this browser see the previous session's data before the first refetch lands.
    queryClient.clear();
  }, [queryClient]);

  // The client calls this when a refresh fails, i.e. the session is genuinely over.
  useEffect(() => setSessionExpiredHandler(clearSession), [clearSession]);

  useEffect(() => {
    let cancelled = false;

    authApi
      .me()
      .then((me) => {
        if (cancelled) return;
        setPrincipal(me);
        setStatus('authenticated');
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        // An auth failure here is the expected "not signed in" case, not an error worth
        // reporting. Anything else still leaves the user at the login screen, but is
        // worth a console warning so a broken backend is not silently indistinguishable.
        if (!isApiError(err) || !err.isAuthFailure) {
          console.warn('Session bootstrap failed:', err);
        }
        setPrincipal(null);
        setStatus('unauthenticated');
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(async (credentials: LoginRequest) => {
    await authApi.login(credentials);
    const me = await authApi.me();
    setPrincipal(me);
    setStatus('authenticated');
  }, []);

  const register = useCallback(async (details: RegisterRequest) => {
    await authApi.register(details);
    const me = await authApi.me();
    setPrincipal(me);
    setStatus('authenticated');
  }, []);

  const logout = useCallback(async () => {
    try {
      await authApi.logout();
    } finally {
      clearSession();
    }
  }, [clearSession]);

  // `GET /auth/me` carries the role on the user, not beside it, and types it as a bare
  // string — so it is narrowed rather than asserted. An unrecognised role resolves to
  // `null`, which `hasRole` treats as "no permissions": the safe direction to fail.
  const role: Role | null = toRole(principal?.user.role);

  const can = useCallback((minimum: Role) => hasRole(role ?? undefined, minimum), [role]);

  const value = useMemo<AuthContextValue>(
    () => ({ status, principal, role, login, register, logout, can }),
    [status, principal, role, login, register, logout, can],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
