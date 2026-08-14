import { describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { renderApp } from '@/test/utils';
import { server } from '@/mocks/server';
import { ExecutiveDashboardPage } from './ExecutiveDashboardPage';
import { buildExecutiveDashboard } from '@/mocks/derive';
import { getDb } from '@/mocks/handlers';
import { startSession } from '@/mocks/session';
import { tokenStore } from '@/lib/api/tokenStore';

const BASE = '*/api/v1';

/** Puts the client in the signed-in state the dashboard assumes. */
function signIn() {
  tokenStore.set(startSession());
}

describe('ExecutiveDashboardPage', () => {
  it('shows a loading state before the data arrives', () => {
    signIn();
    renderApp(<ExecutiveDashboardPage />);

    expect(screen.getByText(/loading your risk posture/i)).toBeInTheDocument();
  });

  it('renders the posture score, band, and trend from fixtures', async () => {
    signIn();
    const expected = buildExecutiveDashboard(getDb());

    renderApp(<ExecutiveDashboardPage />);

    const posture = await screen.findByRole('region', { name: /overall risk posture/i });

    expect(within(posture).getByText('/ 100')).toBeInTheDocument();
    expect(
      within(posture).getByText(String(expected.risk_posture.score), { selector: '.hero__score' }),
    ).toBeInTheDocument();

    // A falling score is an improvement — the copy must not read as a warning.
    const trendWord = expected.risk_posture.trend_30d < 0 ? /improving/i : /worsening|holding/i;
    expect(within(posture).getByText(trendWord)).toBeInTheDocument();
  });

  it('ranks services by revenue at risk, not by technical score', async () => {
    signIn();
    server.use(
      http.get(`${BASE}/dashboard/executive`, () =>
        HttpResponse.json({
          data: {
            risk_posture: { score: 61, trend_30d: -4, band: 'elevated', history: [] },
            services_at_risk: [
              {
                service_id: 's1',
                name: 'Payment processing',
                criticality: 'critical',
                revenue_at_risk: '4200000.00',
                open_findings: 12,
                worst_finding_score: 71.0,
                assets_affected: 4,
              },
              {
                service_id: 's2',
                name: 'Internal analytics',
                criticality: 'low',
                revenue_at_risk: '15000.00',
                open_findings: 3,
                // Higher CVSS-derived score, far lower business impact. A CVE-ordered
                // list would put this first; this product must not.
                worst_finding_score: 98.4,
                assets_affected: 2,
              },
            ],
            exposure_summary: { internet: 3, dmz: 11, internal: 84, isolated: 6 },
            kev_findings: 2,
            remediation_progress: { opened_30d: 31, resolved_30d: 47 },
            generated_at: '2026-08-12T09:00:00Z',
          },
          error: null,
        }),
      ),
    );

    renderApp(<ExecutiveDashboardPage />);

    const items = await screen.findAllByRole('listitem');
    const ranked = items.filter((item) => item.textContent?.includes('revenue at risk'));

    expect(ranked[0]).toHaveTextContent('Payment processing');
    expect(ranked[1]).toHaveTextContent('Internal analytics');
    expect(ranked[0]).toHaveTextContent('$4.2M');
  });

  it('calls out known-exploited vulnerabilities separately from severity', async () => {
    signIn();
    renderApp(<ExecutiveDashboardPage />);

    const kev = await screen.findByText(/known-exploited/i);
    expect(kev).toBeInTheDocument();
  });

  // There is no trend chart, and no accessible table behind one: `GET
  // /dashboard/executive` returns `score`, `trend_30d` and `band` — never a daily series.
  // The direction of travel is stated in words instead, which needs no chart to read.
  it('states the direction of travel in words, not only as a signed number', async () => {
    signIn();
    renderApp(<ExecutiveDashboardPage />);

    const posture = await screen.findByRole('region', { name: /overall risk posture/i });

    expect(within(posture).getByText(/improving|worsening|holding steady/i)).toBeInTheDocument();
    expect(within(posture).getByText(/30 days/i)).toBeInTheDocument();
  });

  it('shows an actionable error state and can retry', async () => {
    signIn();
    server.use(
      http.get(`${BASE}/dashboard/executive`, () =>
        HttpResponse.json(
          { data: null, error: { code: 'server_error', message: 'Upstream unavailable.' } },
          { status: 500 },
        ),
      ),
    );

    renderApp(<ExecutiveDashboardPage />);

    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument());
    expect(screen.getByText(/upstream unavailable/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /try again/i })).toBeInTheDocument();
  });

  it('never puts a CVE identifier on the executive screen', async () => {
    signIn();
    const { container } = renderApp(<ExecutiveDashboardPage />);

    await screen.findByText('/ 100');

    // The whole premise: this page speaks business, not CVE.
    expect(container.textContent).not.toMatch(/CVE-\d{4}-\d+/);
  });
});
