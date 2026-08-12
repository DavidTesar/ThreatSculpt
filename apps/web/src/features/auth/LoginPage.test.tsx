import { describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { screen, waitFor } from '@testing-library/react';
import { renderApp } from '@/test/utils';
import { server } from '@/mocks/server';
import { LoginPage } from './LoginPage';
import { tokenStore } from '@/lib/api/tokenStore';

const BASE = '*/api/v1';

describe('LoginPage', () => {
  it('blocks submission and reports both fields when empty', async () => {
    const { user } = renderApp(<LoginPage />);

    await user.click(await screen.findByRole('button', { name: /sign in/i }));

    expect(await screen.findByText(/enter your email address/i)).toBeInTheDocument();
    expect(screen.getByText(/enter your password/i)).toBeInTheDocument();
    expect(tokenStore.get()).toBeNull();
  });

  it('rejects a malformed email before contacting the server', async () => {
    const { user } = renderApp(<LoginPage />);

    await user.type(await screen.findByLabelText(/email/i), 'not-an-email');
    await user.type(screen.getByLabelText(/password/i), 'correct-horse-battery');
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    expect(await screen.findByText(/valid email address/i)).toBeInTheDocument();
  });

  it('stores the access token in memory on a successful sign-in', async () => {
    const { user } = renderApp(<LoginPage />);

    await user.type(
      await screen.findByLabelText(/email/i),
      'diane.whitfield@northwind-logistics.com',
    );
    await user.type(screen.getByLabelText(/password/i), 'correct-horse-battery');
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => expect(tokenStore.get()).toBeTruthy());

    // Never in web storage — an XSS that can read localStorage would inherit the session.
    expect(window.localStorage.getItem('ts.token')).toBeNull();
    expect(JSON.stringify(window.localStorage)).not.toContain(tokenStore.get());
  });

  it('surfaces the server error message when credentials are rejected', async () => {
    const { user } = renderApp(<LoginPage />);

    await user.type(await screen.findByLabelText(/email/i), 'nobody@northwind-logistics.com');
    await user.type(screen.getByLabelText(/password/i), 'wrong-password-here');
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/email or password is incorrect/i);
    expect(tokenStore.get()).toBeNull();
  });

  it('gives rate limiting its own message rather than blaming the password', async () => {
    server.use(
      http.post(`${BASE}/auth/login`, () =>
        HttpResponse.json(
          { data: null, error: { code: 'rate_limited', message: 'Slow down.' } },
          { status: 429 },
        ),
      ),
    );

    const { user } = renderApp(<LoginPage />);

    await user.type(
      await screen.findByLabelText(/email/i),
      'diane.whitfield@northwind-logistics.com',
    );
    await user.type(screen.getByLabelText(/password/i), 'correct-horse-battery');
    await user.click(screen.getByRole('button', { name: /sign in/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/too many attempts/i);
  });
});
