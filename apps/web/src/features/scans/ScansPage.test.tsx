import { describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { renderApp, signIn } from '@/test/utils';
import { server } from '@/mocks/server';
import { ScansPage } from './ScansPage';

const BASE = '*/api/v1';

describe('ScansPage', () => {
  it('shows scan history with live progress for a running job', async () => {
    signIn();
    renderApp(<ScansPage />);

    expect(await screen.findByText('Running')).toBeInTheDocument();
    const progressbars = screen.getAllByRole('progressbar', { name: /scan progress/i });
    expect(progressbars[0]).toHaveAttribute('aria-valuenow', '62');
  });

  it('offers only authorized networks as scan targets', async () => {
    signIn();
    const { user } = renderApp(<ScansPage />);

    await user.click(await screen.findByRole('button', { name: /new scan/i }));

    const dialog = await screen.findByRole('dialog', { name: /queue a scan/i });
    const select = within(dialog).getByRole('combobox', { name: /network/i });
    const optionText = within(select)
      .getAllByRole('option')
      .map((o) => o.textContent ?? '');

    expect(optionText.join(' ')).toContain('HQ corporate LAN');
    // Unauthorized ranges must not even be offered.
    expect(optionText.join(' ')).not.toContain('Warehouse OT segment');
    expect(optionText.join(' ')).not.toContain('Guest wireless');

    expect(within(dialog).getByText(/cannot be scanned/i)).toBeInTheDocument();
  });

  it('describes each scan profile instead of showing bare names', async () => {
    signIn();
    const { user } = renderApp(<ScansPage />);

    await user.click(await screen.findByRole('button', { name: /new scan/i }));
    const dialog = await screen.findByRole('dialog', { name: /queue a scan/i });

    expect(within(dialog).getByText(/finds which hosts are alive/i)).toBeInTheDocument();
    expect(within(dialog).getByText(/produces findings/i)).toBeInTheDocument();
    expect(within(dialog).getByText(/noticeably heavier on the network/i)).toBeInTheDocument();
  });

  it('prefills the target from the chosen network and queues the scan', async () => {
    signIn();
    const { user } = renderApp(<ScansPage />);

    await user.click(await screen.findByRole('button', { name: /new scan/i }));
    const dialog = await screen.findByRole('dialog', { name: /queue a scan/i });

    const select = within(dialog).getByRole('combobox', { name: /network/i });
    const option = within(select)
      .getAllByRole('option')
      .find((o) => o.textContent?.includes('DMZ')) as HTMLOptionElement;
    await user.selectOptions(select, option.value);

    await waitFor(() =>
      expect(within(dialog).getByLabelText(/target range/i)).toHaveValue('192.168.70.0/24'),
    );

    await user.click(within(dialog).getByRole('button', { name: /queue scan/i }));

    await waitFor(() => expect(screen.getAllByText('Queued').length).toBeGreaterThan(1));
  });

  it('reports the API refusal when the network is not authorized', async () => {
    signIn();
    // The UI hides unauthorized networks, but the server is the real enforcement — if it
    // refuses, the reason has to reach the user rather than failing silently.
    server.use(
      http.post(`${BASE}/scans`, () =>
        HttpResponse.json(
          {
            data: null,
            error: {
              code: 'network_not_authorized',
              message: 'Scans require the network to be marked authorized.',
              field: 'network_id',
            },
          },
          { status: 422 },
        ),
      ),
    );

    const { user } = renderApp(<ScansPage />);

    await user.click(await screen.findByRole('button', { name: /new scan/i }));
    const dialog = await screen.findByRole('dialog', { name: /queue a scan/i });

    const select = within(dialog).getByRole('combobox', { name: /network/i });
    const option = within(select).getAllByRole('option')[1] as HTMLOptionElement;
    await user.selectOptions(select, option.value);
    await user.click(within(dialog).getByRole('button', { name: /queue scan/i }));

    expect(
      await screen.findByText(/require the network to be marked authorized/i),
    ).toBeInTheDocument();
  });
});
