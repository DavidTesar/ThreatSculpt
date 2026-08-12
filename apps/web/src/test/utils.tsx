import type { ReactElement, ReactNode } from 'react';
import { render, type RenderOptions } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MemoryRouter } from 'react-router-dom';
import userEvent from '@testing-library/user-event';
import { AuthProvider } from '@/auth/AuthProvider';
import { ToastProvider } from '@/components/ui/Toast';
import { startSession } from '@/mocks/session';
import { tokenStore } from '@/lib/api/tokenStore';

/**
 * Puts the client into the signed-in state the authenticated screens assume, without
 * driving the login form in every test.
 */
export function signIn(): void {
  tokenStore.set(startSession());
}

/** Retries off and no caching between cases, so tests are deterministic and fast. */
export function createTestQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0, staleTime: 0 },
      mutations: { retry: false },
    },
  });
}

interface RenderAppOptions extends Omit<RenderOptions, 'wrapper'> {
  route?: string;
  queryClient?: QueryClient;
  /** Set false to test a component that must not be inside an AuthProvider. */
  withAuth?: boolean;
}

export function renderApp(ui: ReactElement, options: RenderAppOptions = {}) {
  const { route = '/', queryClient = createTestQueryClient(), withAuth = true, ...rest } = options;

  function Wrapper({ children }: { children: ReactNode }) {
    const inner = <ToastProvider>{children}</ToastProvider>;
    return (
      <QueryClientProvider client={queryClient}>
        <MemoryRouter
          initialEntries={[route]}
          future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
        >
          {withAuth ? <AuthProvider>{inner}</AuthProvider> : inner}
        </MemoryRouter>
      </QueryClientProvider>
    );
  }

  return {
    user: userEvent.setup(),
    queryClient,
    ...render(ui, { wrapper: Wrapper, ...rest }),
  };
}
