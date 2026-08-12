import { describe, expect, it } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import { renderApp, signIn } from '@/test/utils';
import { AgentsPage } from './AgentsPage';

describe('AgentsPage', () => {
  it('lists enrolled agents with their health', async () => {
    signIn();
    renderApp(<AgentsPage />);

    expect(await screen.findByText('hq-dc-scanner-01')).toBeInTheDocument();
    expect(screen.getByText('lab-scanner-decommissioned')).toBeInTheDocument();
    expect(screen.getAllByText('Healthy').length).toBeGreaterThan(0);
    // An agent that has not checked in recently must be called out, not shown as fine.
    expect(screen.getByText('Not responding')).toBeInTheDocument();
    expect(screen.getByText('Revoked')).toBeInTheDocument();
  });

  it('validates the agent name before issuing a token', async () => {
    signIn();
    const { user } = renderApp(<AgentsPage />);

    await user.click(await screen.findByRole('button', { name: /enroll agent/i }));
    await user.type(screen.getByLabelText(/agent name/i), 'has spaces!');
    await user.click(screen.getByRole('button', { name: /issue enrollment token/i }));

    expect(await screen.findByText(/letters, numbers, dots, dashes/i)).toBeInTheDocument();
  });

  it('shows the enrollment token once, with an unmissable warning', async () => {
    signIn();
    const { user } = renderApp(<AgentsPage />);

    await user.click(await screen.findByRole('button', { name: /enroll agent/i }));
    await user.type(screen.getByLabelText(/agent name/i), 'new-scanner-01');
    await user.click(screen.getByRole('button', { name: /issue enrollment token/i }));

    const dialog = await screen.findByRole('dialog', { name: /copy this enrollment token now/i });

    expect(within(dialog).getByText(/you will not see this again/i)).toBeInTheDocument();
    // The token appears twice: once to copy, once inside the example enroll command.
    expect(within(dialog).getAllByText(/tse_/).length).toBeGreaterThan(0);
    expect(within(dialog).getByText(/only a hash of this token/i)).toBeInTheDocument();
  });

  it('requires an explicit acknowledgement before the token can be dismissed', async () => {
    signIn();
    const { user } = renderApp(<AgentsPage />);

    await user.click(await screen.findByRole('button', { name: /enroll agent/i }));
    await user.type(screen.getByLabelText(/agent name/i), 'new-scanner-02');
    await user.click(screen.getByRole('button', { name: /issue enrollment token/i }));

    const dialog = await screen.findByRole('dialog', { name: /copy this enrollment token/i });
    const confirm = within(dialog).getByRole('button', { name: /i have saved the token/i });

    // Closing by reflex would lose the only copy of the token.
    expect(confirm).toBeDisabled();

    await user.click(within(dialog).getByLabelText(/copied the token somewhere safe/i));
    expect(confirm).toBeEnabled();
  });

  it('spells out what revoking an agent does before confirming', async () => {
    signIn();
    const { user } = renderApp(<AgentsPage />);

    const rows = await screen.findAllByRole('row');
    const target = rows.find((row) => row.textContent?.includes('hq-dc-scanner-01'));
    await user.click(within(target as HTMLElement).getByRole('button', { name: /revoke/i }));

    const dialog = await screen.findByRole('dialog', { name: /revoke this agent/i });
    expect(within(dialog).getByText(/delete its stored key/i)).toBeInTheDocument();
    expect(within(dialog).getByText(/cannot be undone/i)).toBeInTheDocument();
  });

  it('marks the agent revoked once confirmed', async () => {
    signIn();
    const { user } = renderApp(<AgentsPage />);

    const rows = await screen.findAllByRole('row');
    const target = rows.find((row) => row.textContent?.includes('eu-branch-scanner-01'));
    await user.click(within(target as HTMLElement).getByRole('button', { name: /revoke/i }));

    const dialog = await screen.findByRole('dialog', { name: /revoke this agent/i });
    await user.click(within(dialog).getByRole('button', { name: /revoke agent/i }));

    await waitFor(() => {
      const updated = screen
        .getAllByRole('row')
        .find((row) => row.textContent?.includes('eu-branch-scanner-01'));
      expect(within(updated as HTMLElement).getByText('Revoked')).toBeInTheDocument();
    });
  });
});
