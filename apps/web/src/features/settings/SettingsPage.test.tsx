import { describe, expect, it } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import { renderApp, signIn } from '@/test/utils';
import { SettingsPage } from './SettingsPage';

describe('SettingsPage', () => {
  it('lists users with their roles', async () => {
    signIn();
    renderApp(<SettingsPage />);

    expect(await screen.findByText('Diane Whitfield')).toBeInTheDocument();
    expect(screen.getByText('Marcus Oyelaran')).toBeInTheDocument();
    expect(screen.getByLabelText(/role for diane whitfield/i)).toHaveValue('owner');
  });

  it('locks the last owner so the organisation cannot be orphaned', async () => {
    signIn();
    renderApp(<SettingsPage />);

    const select = await screen.findByLabelText(/role for diane whitfield/i);
    expect(select).toBeDisabled();
    expect(screen.getByText(/last owner cannot be demoted/i)).toBeInTheDocument();
  });

  it('changes a role and confirms it', async () => {
    signIn();
    const { user } = renderApp(<SettingsPage />);

    const select = await screen.findByLabelText(/role for helen abara/i);
    await user.selectOptions(select, 'analyst');

    await waitFor(() => expect(screen.getByText(/is now analyst/i)).toBeInTheDocument());
  });

  it('rejects a new account for an email that already exists', async () => {
    signIn();
    const { user } = renderApp(<SettingsPage />);

    await user.click(await screen.findByRole('button', { name: /add user/i }));
    const dialog = await screen.findByRole('dialog', { name: /add a user/i });

    await user.type(within(dialog).getByLabelText(/full name/i), 'Diane Again');
    await user.type(
      within(dialog).getByLabelText(/work email/i),
      'diane.whitfield@northwind-logistics.com',
    );
    await user.type(within(dialog).getByLabelText(/initial password/i), 'correct-horse-battery');
    await user.click(within(dialog).getByRole('button', { name: /create account/i }));

    expect(await screen.findByText(/already exists/i)).toBeInTheDocument();
  });

  it('validates the new-account form before sending', async () => {
    signIn();
    const { user } = renderApp(<SettingsPage />);

    await user.click(await screen.findByRole('button', { name: /add user/i }));
    const dialog = await screen.findByRole('dialog', { name: /add a user/i });

    await user.click(within(dialog).getByRole('button', { name: /create account/i }));

    expect(await screen.findByText(/enter their full name/i)).toBeInTheDocument();
    expect(screen.getByText(/enter their email address/i)).toBeInTheDocument();
    // The API requires an initial password; omitting it used to fail only at the server.
    expect(screen.getByText(/use at least 12 characters/i)).toBeInTheDocument();
  });

  it('explains what each role can do, so least privilege is an informed choice', async () => {
    signIn();
    renderApp(<SettingsPage />);

    expect(await screen.findByText(/read-only access to dashboards/i)).toBeInTheDocument();
    expect(screen.getByText(/runs scans, triages findings/i)).toBeInTheDocument();
  });
});
