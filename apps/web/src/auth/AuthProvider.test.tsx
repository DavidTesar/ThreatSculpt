import { describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { screen, waitFor } from '@testing-library/react';
import { renderApp } from '@/test/utils';
import { server } from '@/mocks/server';
import { useAuth } from './useAuth';
import { tokenStore } from '@/lib/api/tokenStore';

const BASE = '*/api/v1';

function AuthProbe() {
  const { status, principal, role } = useAuth();
  return (
    <div>
      <span data-testid="status">{status}</span>
      <span data-testid="email">{principal?.user.email ?? 'none'}</span>
      <span data-testid="role">{role ?? 'none'}</span>
    </div>
  );
}

describe('AuthProvider session bootstrap', () => {
  it('lands on unauthenticated when there is no refresh cookie', async () => {
    renderApp(<AuthProbe />);

    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('unauthenticated'));
    expect(screen.getByTestId('email')).toHaveTextContent('none');
  });

  it('recovers a session from the refresh cookie without a login screen', async () => {
    // Stands in for a page reload: the access token is gone (it only ever lived in
    // memory) but the HttpOnly refresh cookie survived.
    let refreshed = false;
    server.use(
      http.post(`${BASE}/auth/refresh`, () => {
        refreshed = true;
        return HttpResponse.json({ data: { access_token: 'restored-token' }, error: null });
      }),
      http.get(`${BASE}/auth/me`, ({ request }) => {
        if (request.headers.get('Authorization') !== 'Bearer restored-token') {
          return HttpResponse.json(
            { data: null, error: { code: 'unauthenticated', message: 'No.' } },
            { status: 401 },
          );
        }
        return HttpResponse.json({
          data: {
            user: {
              id: 'u1',
              email: 'diane.whitfield@northwind-logistics.com',
              full_name: 'Diane Whitfield',
              role: 'owner',
              status: 'active',
              last_login_at: null,
              created_at: '2026-01-01T00:00:00Z',
            },
            org: {
              id: 'o1',
              name: 'Northwind Logistics',
              slug: 'northwind-logistics',
              plan: 'standard',
              status: 'active',
            },
            role: 'owner',
          },
          error: null,
        });
      }),
    );

    renderApp(<AuthProbe />);

    await waitFor(() => expect(screen.getByTestId('status')).toHaveTextContent('authenticated'));
    expect(refreshed).toBe(true);
    expect(screen.getByTestId('email')).toHaveTextContent(
      'diane.whitfield@northwind-logistics.com',
    );
    expect(screen.getByTestId('role')).toHaveTextContent('owner');
    expect(tokenStore.get()).toBe('restored-token');
  });
});
