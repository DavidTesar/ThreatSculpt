import { describe, expect, it } from 'vitest';
import { screen, waitFor, within } from '@testing-library/react';
import { renderApp } from '@/test/utils';
import { FindingsPage } from './FindingsPage';
import { startSession } from '@/mocks/session';
import { tokenStore } from '@/lib/api/tokenStore';

function signIn() {
  tokenStore.set(startSession());
}

/** The risk column is first; reading it down gives the current sort order. */
function readRiskColumn(): number[] {
  const table = screen.getByRole('table');
  return within(table)
    .getAllByRole('row')
    .slice(1)
    .map((row) => Number(within(row).getAllByRole('cell')[0]?.textContent ?? 'NaN'))
    .filter((value) => !Number.isNaN(value));
}

async function riskColumn(): Promise<number[]> {
  await screen.findByRole('table');
  return readRiskColumn();
}

/** Reads the "1–50 of 213 findings" summary the pagination control renders. */
function totalFromPagination(): number {
  const nav = screen.getByRole('navigation', { name: /pagination/i });
  const match = /of ([\d,]+) findings/.exec(nav.textContent ?? '');
  return Number((match?.[1] ?? '0').replace(/,/g, ''));
}

describe('FindingsPage', () => {
  it('defaults to business risk score, highest first', async () => {
    signIn();
    renderApp(<FindingsPage />);

    const scores = await riskColumn();

    expect(scores.length).toBeGreaterThan(1);
    // "sort by business_risk_score desc default" (API.md).
    expect([...scores]).toEqual([...scores].sort((a, b) => b - a));
  });

  // `/findings` accepts no `sort` or `order` parameter and always returns business risk
  // descending, so there are no sortable headers to announce. The client used to send
  // both on every request and render clickable headers that reordered nothing.
  it('narrows to a single match confidence', async () => {
    signIn();
    const { user } = renderApp(<FindingsPage />);

    await riskColumn();
    const totalBefore = totalFromPagination();

    await user.selectOptions(screen.getByLabelText(/match confidence/i), 'high');

    await waitFor(() => {
      expect(totalFromPagination()).toBeLessThanOrEqual(totalBefore);
    });

    // Column 5 is Match. Severity is column 2 and also reads "High", so the assertion
    // has to name the cell rather than search the whole row.
    const table = await screen.findByRole('table');
    for (const row of within(table).getAllByRole('row').slice(1)) {
      expect(within(row).getAllByRole('cell')[4]).toHaveTextContent('High');
    }
  });

  it('filters to known-exploited findings only', async () => {
    signIn();
    const { user } = renderApp(<FindingsPage />);

    await riskColumn();
    // Row count alone proves nothing here — the list paginates at 50, so a filtered page
    // is still full. The reported total is what actually narrows.
    const totalBefore = totalFromPagination();

    await user.click(screen.getByLabelText(/known exploited only/i));

    await waitFor(() => {
      expect(totalFromPagination()).toBeLessThan(totalBefore);
    });

    const table = await screen.findByRole('table');
    for (const row of within(table).getAllByRole('row').slice(1)) {
      expect(within(row).getByText('KEV')).toBeInTheDocument();
    }
  });

  it('filters by severity', async () => {
    signIn();
    const { user } = renderApp(<FindingsPage />);

    await riskColumn();
    await user.selectOptions(screen.getByLabelText(/severity/i), 'critical');

    await waitFor(async () => {
      const table = await screen.findByRole('table');
      const rows = within(table).getAllByRole('row').slice(1);
      expect(rows.length).toBeGreaterThan(0);
      for (const row of rows) {
        expect(within(row).getByText('Critical')).toBeInTheDocument();
      }
    });
  });

  it('offers a way back when a filter combination matches nothing', async () => {
    signIn();
    const { user } = renderApp(<FindingsPage />, {
      // Remediated criticals that are also KEV-listed: an empty intersection in fixtures.
      route: '/findings?status=false_positive&severity=low&kev_only=true',
    });

    expect(await screen.findByText(/no findings match these filters/i)).toBeInTheDocument();

    // The empty state offers its own escape hatch, alongside the one in the toolbar.
    const clearButtons = screen.getAllByRole('button', { name: /clear filters/i });
    expect(clearButtons.length).toBeGreaterThan(0);
    await user.click(clearButtons[clearButtons.length - 1] as HTMLElement);

    await waitFor(() => expect(screen.getByRole('table')).toBeInTheDocument());
  });

  it('keeps filter state in the URL so a view can be shared', async () => {
    signIn();
    renderApp(<FindingsPage />, { route: '/findings?severity=critical&status=open' });

    await waitFor(() => {
      expect(screen.getByLabelText(/severity/i)).toHaveValue('critical');
      expect(screen.getByLabelText(/status/i)).toHaveValue('open');
    });
  });
});
