import { describe, expect, it } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import { renderApp, signIn } from '@/test/utils';
import { AssetsPage } from './AssetsPage';

describe('AssetsPage', () => {
  it('lists assets with their network position', async () => {
    signIn();
    renderApp(<AssetsPage />);

    const table = await screen.findByRole('table');
    expect(within(table).getAllByRole('row').length).toBeGreaterThan(1);
    expect(screen.getAllByText('Internal').length).toBeGreaterThan(0);
  });

  it('flags assets that are not mapped to any business service', async () => {
    signIn();
    renderApp(<AssetsPage />);

    await screen.findByRole('table');
    // An unmapped asset is scored at the lowest criticality, so it understates risk —
    // the list has to make that visible rather than leaving a blank cell.
    expect(screen.getAllByText(/not mapped/i).length).toBeGreaterThan(0);
  });

  it('filters by network position from the URL', async () => {
    signIn();
    renderApp(<AssetsPage />, { route: '/assets?exposure=internet' });

    await waitFor(() => {
      expect(screen.getByLabelText(/network position/i)).toHaveValue('internet');
    });

    const table = await screen.findByRole('table');
    for (const row of within(table).getAllByRole('row').slice(1)) {
      expect(within(row).getByText('Internet-facing')).toBeInTheDocument();
    }
  });

  it('searches by hostname', async () => {
    signIn();
    const { user } = renderApp(<AssetsPage />);

    await screen.findByRole('table');
    await user.type(screen.getByLabelText(/search/i), 'web01');

    await waitFor(() => {
      const table = screen.getByRole('table');
      const rows = within(table).getAllByRole('row').slice(1);
      expect(rows.length).toBeGreaterThan(0);
      for (const row of rows) {
        expect(row.textContent?.toLowerCase()).toContain('web01');
      }
    });
  });

  it('explains an empty filter result and offers a way back', async () => {
    signIn();
    const { user } = renderApp(<AssetsPage />, { route: '/assets?q=zzzz-no-such-host' });

    expect(await screen.findByText(/no assets match these filters/i)).toBeInTheDocument();

    await user.click(screen.getByRole('button', { name: /clear filters/i }));

    await waitFor(() => expect(screen.getByRole('table')).toBeInTheDocument());
  });
});
