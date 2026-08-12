import { describe, expect, it } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import { renderApp, signIn } from '@/test/utils';
import { BusinessServicesPage } from './BusinessServicesPage';

describe('BusinessServicesPage', () => {
  it('lists services with their criticality and revenue at risk', async () => {
    signIn();
    renderApp(<BusinessServicesPage />);

    expect(await screen.findByText('Payment processing')).toBeInTheDocument();
    expect(screen.getByText('$4,200,000')).toBeInTheDocument();
    // Criticality is a counted meter, not a colour swatch.
    expect(
      screen.getAllByRole('img', { name: /critical business criticality, 4 of 4/i }).length,
    ).toBeGreaterThan(0);
  });

  it('says "Not costed" rather than $0 for a service with no figure', async () => {
    signIn();
    renderApp(<BusinessServicesPage />);

    // "$0 at risk" would read as "this is safe" — the opposite of "nobody costed it".
    expect(await screen.findAllByText(/not costed/i)).not.toHaveLength(0);
  });

  it('requires a name and rejects a non-numeric revenue figure', async () => {
    signIn();
    const { user } = renderApp(<BusinessServicesPage />);

    await user.click(await screen.findByRole('button', { name: /new service/i }));
    const dialog = await screen.findByRole('dialog', { name: /new business service/i });

    await user.type(within(dialog).getByLabelText(/annual revenue at risk/i), 'four million');
    await user.click(within(dialog).getByRole('button', { name: /create service/i }));

    expect(
      await screen.findByText(/name this service the way the business refers/i),
    ).toBeInTheDocument();
    expect(screen.getByText(/enter an amount in digits/i)).toBeInTheDocument();
  });

  it('creates a service and shows it in the table', async () => {
    signIn();
    const { user } = renderApp(<BusinessServicesPage />);

    await user.click(await screen.findByRole('button', { name: /new service/i }));
    const dialog = await screen.findByRole('dialog', { name: /new business service/i });

    await user.type(within(dialog).getByLabelText(/service name/i), 'Supplier portal');
    await user.selectOptions(within(dialog).getByLabelText(/business criticality/i), 'high');
    await user.type(within(dialog).getByLabelText(/annual revenue at risk/i), '1250000');
    await user.click(within(dialog).getByRole('button', { name: /create service/i }));

    await waitFor(() => expect(screen.getByText('Supplier portal')).toBeInTheDocument());
    expect(screen.getByText('$1,250,000')).toBeInTheDocument();
  });

  it('warns that deleting a service lowers reported risk without improving anything', async () => {
    signIn();
    const { user } = renderApp(<BusinessServicesPage />);

    const rows = await screen.findAllByRole('row');
    const target = rows.find((row) => row.textContent?.includes('Internal analytics'));
    await user.click(
      within(target as HTMLElement).getByRole('button', { name: /delete internal analytics/i }),
    );

    const dialog = await screen.findByRole('dialog', { name: /remove this business service/i });
    expect(
      within(dialog).getByText(/lower your reported risk without anything actually improving/i),
    ).toBeInTheDocument();
  });
});
