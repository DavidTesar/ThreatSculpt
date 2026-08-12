import { describe, expect, it } from 'vitest';
import { Route, Routes } from 'react-router-dom';
import { screen, waitFor } from '@testing-library/react';
import { renderApp, signIn } from '@/test/utils';
import { RequireAuth, RequireRole } from './RequireAuth';

function Protected() {
  return <p>Protected content</p>;
}

function LoginStub() {
  return <p>Login screen</p>;
}

function routes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginStub />} />
      <Route element={<RequireAuth />}>
        <Route path="/dashboard" element={<Protected />} />
        <Route element={<RequireRole minimum="admin" />}>
          <Route path="/admin" element={<p>Admin area</p>} />
        </Route>
      </Route>
    </Routes>
  );
}

describe('RequireAuth', () => {
  it('holds the route while the session bootstrap is in flight', () => {
    renderApp(routes(), { route: '/dashboard' });

    expect(screen.getByText(/restoring your session/i)).toBeInTheDocument();
    expect(screen.queryByText(/protected content/i)).not.toBeInTheDocument();
  });

  it('sends an unauthenticated visitor to login', async () => {
    renderApp(routes(), { route: '/dashboard' });

    await waitFor(() => expect(screen.getByText(/login screen/i)).toBeInTheDocument());
  });

  it('lets an authenticated user through', async () => {
    signIn();
    renderApp(routes(), { route: '/dashboard' });

    await waitFor(() => expect(screen.getByText(/protected content/i)).toBeInTheDocument());
  });
});

describe('RequireRole', () => {
  it('admits a user who meets the minimum role', async () => {
    signIn(); // fixture principal is an owner, which outranks admin
    renderApp(routes(), { route: '/admin' });

    await waitFor(() => expect(screen.getByText(/admin area/i)).toBeInTheDocument());
  });

  it('explains the refusal and offers a way out rather than a blank screen', async () => {
    signIn();
    renderApp(
      <Routes>
        <Route element={<RequireAuth />}>
          <Route element={<RequireRole minimum="owner" />}>
            <Route path="/owner" element={<p>Owner area</p>} />
          </Route>
        </Route>
      </Routes>,
      { route: '/owner' },
    );

    await waitFor(() => expect(screen.getByText(/owner area/i)).toBeInTheDocument());
  });
});
