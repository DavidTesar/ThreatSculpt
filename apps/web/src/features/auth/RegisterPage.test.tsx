import { describe, expect, it } from 'vitest';
import { screen, waitFor } from '@testing-library/react';
import { renderApp } from '@/test/utils';
import { RegisterPage } from './RegisterPage';
import { tokenStore } from '@/lib/api/tokenStore';

describe('RegisterPage validation', () => {
  it('requires every field before submitting', async () => {
    const { user } = renderApp(<RegisterPage />);

    await user.click(await screen.findByRole('button', { name: /create organisation/i }));

    expect(await screen.findByText(/enter your organisation name/i)).toBeInTheDocument();
    expect(screen.getByText(/enter your full name/i)).toBeInTheDocument();
    expect(screen.getByText(/enter your email address/i)).toBeInTheDocument();
    expect(tokenStore.get()).toBeNull();
  });

  it('states the password rules up front rather than only on failure', async () => {
    renderApp(<RegisterPage />);

    expect(
      await screen.findByText(/at least 12 characters, with upper and lower case letters/i),
    ).toBeInTheDocument();
  });

  it.each([
    ['short1A', /at least 12 characters/i],
    ['alllowercase123', /include an uppercase letter/i],
    ['ALLUPPERCASE123', /include a lowercase letter/i],
    ['NoDigitsInHereAtAll', /include a number/i],
  ])('rejects %s', async (password, expected) => {
    const { user } = renderApp(<RegisterPage />);

    await user.type(await screen.findByLabelText(/organisation name/i), 'Northwind');
    await user.type(screen.getByLabelText(/your name/i), 'Diane Whitfield');
    await user.type(screen.getByLabelText(/work email/i), 'diane@northwind.test');
    await user.type(screen.getByLabelText(/^password/i), password);
    await user.type(screen.getByLabelText(/confirm password/i), password);
    await user.click(screen.getByRole('button', { name: /create organisation/i }));

    // Scoped to the field error: the always-visible hint uses the same wording.
    await waitFor(() => {
      const alerts = screen.getAllByRole('alert').map((el) => el.textContent ?? '');
      expect(alerts.some((text) => expected.test(text))).toBe(true);
    });
  });

  it('catches a mismatched confirmation without a round trip', async () => {
    const { user } = renderApp(<RegisterPage />);

    await user.type(await screen.findByLabelText(/organisation name/i), 'Northwind');
    await user.type(screen.getByLabelText(/your name/i), 'Diane Whitfield');
    await user.type(screen.getByLabelText(/work email/i), 'diane@northwind.test');
    await user.type(screen.getByLabelText(/^password/i), 'CorrectHorse1Battery');
    await user.type(screen.getByLabelText(/confirm password/i), 'CorrectHorse1Batteryy');
    await user.click(screen.getByRole('button', { name: /create organisation/i }));

    expect(await screen.findByText(/passwords do not match/i)).toBeInTheDocument();
    expect(tokenStore.get()).toBeNull();
  });

  it('creates the organisation and signs the owner in', async () => {
    const { user } = renderApp(<RegisterPage />);

    await user.type(await screen.findByLabelText(/organisation name/i), 'Fabrikam Freight');
    await user.type(screen.getByLabelText(/your name/i), 'Ada Okafor');
    await user.type(screen.getByLabelText(/work email/i), 'ada.okafor@fabrikam.test');
    await user.type(screen.getByLabelText(/^password/i), 'CorrectHorse1Battery');
    await user.type(screen.getByLabelText(/confirm password/i), 'CorrectHorse1Battery');
    await user.click(screen.getByRole('button', { name: /create organisation/i }));

    await waitFor(() => expect(tokenStore.get()).toBeTruthy());
  });

  it('reports a duplicate email from the server', async () => {
    const { user } = renderApp(<RegisterPage />);

    await user.type(await screen.findByLabelText(/organisation name/i), 'Northwind Again');
    await user.type(screen.getByLabelText(/your name/i), 'Diane Whitfield');
    await user.type(
      screen.getByLabelText(/work email/i),
      'diane.whitfield@northwind-logistics.com',
    );
    await user.type(screen.getByLabelText(/^password/i), 'CorrectHorse1Battery');
    await user.type(screen.getByLabelText(/confirm password/i), 'CorrectHorse1Battery');
    await user.click(screen.getByRole('button', { name: /create organisation/i }));

    expect(await screen.findByRole('alert')).toHaveTextContent(/already exists/i);
  });
});
