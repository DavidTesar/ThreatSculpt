import { QueryClient } from '@tanstack/react-query';
import { isApiError } from './api/ApiError';

/**
 * Retrying a 401/403/404 is pointless — the outcome is deterministic — and retrying a 401
 * in particular would multiply requests against the refresh path. Transient failures
 * (network, 5xx) still get two attempts.
 */
export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 30_000,
        gcTime: 5 * 60_000,
        refetchOnWindowFocus: false,
        retry: (failureCount, error) => {
          if (isApiError(error) && error.isTerminal) return false;
          return failureCount < 2;
        },
      },
      mutations: { retry: false },
    },
  });
}
