import { describe, expect, it } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import { renderApp, signIn } from '@/test/utils';
import { NetworksPage } from './NetworksPage';

describe('NetworksPage', () => {
  it('makes the unauthorized state obvious rather than a quiet flag', async () => {
    signIn();
    renderApp(<NetworksPage />);

    // A banner above the table, not just a column value.
    expect(await screen.findByText(/not authorized for scanning/i)).toBeInTheDocument();
    expect(screen.getByText(/any scan targeting them is refused/i)).toBeInTheDocument();

    const rows = await screen.findAllByRole('row');
    const otRow = rows.find((row) => row.textContent?.includes('Warehouse OT segment'));
    expect(within(otRow as HTMLElement).getByText('Not authorized')).toBeInTheDocument();

    const hqRow = rows.find((row) => row.textContent?.includes('HQ corporate LAN'));
    expect(within(hqRow as HTMLElement).getByText('Authorized')).toBeInTheDocument();
  });

  it('shows the authorization record so the approval is auditable', async () => {
    signIn();
    renderApp(<NetworksPage />);

    expect(await screen.findByText(/CHG-2291/)).toBeInTheDocument();
  });

  it('creates a network and shows it in the table', async () => {
    signIn();
    const { user } = renderApp(<NetworksPage />);

    await user.click(await screen.findByRole('button', { name: /add network/i }));

    const dialog = await screen.findByRole('dialog', { name: /add a network/i });
    await user.type(within(dialog).getByLabelText(/name/i), 'Lab segment');
    await user.type(within(dialog).getByLabelText(/cidr block/i), '10.77.0.0/24');
    await user.click(within(dialog).getByRole('button', { name: /add network/i }));

    await waitFor(() => expect(screen.getByText('Lab segment')).toBeInTheDocument());
    expect(screen.getByText('10.77.0.0/24')).toBeInTheDocument();
  });

  it('surfaces the server conflict when a CIDR is already registered', async () => {
    signIn();
    const { user } = renderApp(<NetworksPage />);

    await user.click(await screen.findByRole('button', { name: /add network/i }));

    const dialog = await screen.findByRole('dialog', { name: /add a network/i });
    await user.type(within(dialog).getByLabelText(/name/i), 'Duplicate');
    await user.type(within(dialog).getByLabelText(/cidr block/i), '10.0.0.0/16');
    await user.click(within(dialog).getByRole('button', { name: /add network/i }));

    expect(await screen.findByText(/already registered/i)).toBeInTheDocument();
  });

  it('refuses to delete a network that still holds assets, and explains why', async () => {
    signIn();
    const { user } = renderApp(<NetworksPage />);

    const rows = await screen.findAllByRole('row');
    const target = rows.find((row) => row.textContent?.includes('HQ corporate LAN'));
    await user.click(
      within(target as HTMLElement).getByRole('button', { name: /delete hq corporate lan/i }),
    );

    const dialog = await screen.findByRole('dialog', { name: /remove this network/i });
    await user.click(within(dialog).getByRole('button', { name: /remove network/i }));

    expect(await screen.findByText(/still has \d+ assets/i)).toBeInTheDocument();
  });
});
