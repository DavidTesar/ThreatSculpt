import { describe, expect, it } from 'vitest';
import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { renderApp, signIn } from '@/test/utils';
import { server } from '@/mocks/server';
import { AttackSurfacePage } from './AttackSurfacePage';

const BASE = '*/api/v1';

function graphResponse(overrides: Record<string, unknown> = {}) {
  return {
    nodes: [
      {
        id: 's1',
        kind: 'service',
        label: 'Payment processing',
        weight: 80,
        exposure: null,
        criticality: 'critical',
        open_findings: 12,
        represents: null,
      },
      {
        id: 'a1',
        kind: 'asset',
        label: 'web01.corp.local',
        weight: 94.5,
        exposure: 'internet',
        criticality: null,
        open_findings: 5,
        represents: null,
      },
    ],
    edges: [{ source: 'a1', target: 's1', kind: 'exposes' }],
    aggregated: false,
    node_cap: 500,
    total_nodes: 2,
    ...overrides,
  };
}

describe('AttackSurfacePage', () => {
  it('pairs the canvas with a keyboard-navigable node list', async () => {
    signIn();
    server.use(
      http.get(`${BASE}/dashboard/attack-surface`, () =>
        HttpResponse.json({ data: graphResponse(), error: null }),
      ),
    );

    renderApp(<AttackSurfacePage />);

    // Canvas pixels cannot be focused or announced, so the same data must exist as DOM.
    const list = await screen.findByRole('region', { name: /nodes by risk/i });
    expect(within(list).getByRole('button', { name: /web01.corp.local/i })).toBeInTheDocument();
    expect(within(list).getByRole('button', { name: /payment processing/i })).toBeInTheDocument();
  });

  it('explains the aggregated view when the estate exceeds the node cap', async () => {
    signIn();
    server.use(
      http.get(`${BASE}/dashboard/attack-surface`, () =>
        HttpResponse.json({
          data: graphResponse({
            aggregated: true,
            total_nodes: 1840,
            nodes: [
              {
                id: 's1',
                kind: 'service',
                label: 'Payment processing',
                weight: 80,
                exposure: null,
                criticality: 'critical',
                open_findings: 12,
                represents: null,
              },
              {
                id: 'agg-1',
                kind: 'aggregate',
                label: '312 internal assets',
                weight: 61,
                exposure: 'internal',
                criticality: null,
                open_findings: 140,
                represents: 312,
              },
            ],
          }),
          error: null,
        }),
      ),
    );

    renderApp(<AttackSurfacePage />);

    expect(await screen.findByText(/showing an aggregated view/i)).toBeInTheDocument();
    expect(screen.getByText(/1,840 nodes/)).toBeInTheDocument();
    expect(screen.getByText(/500-node limit/)).toBeInTheDocument();
  });

  it('shows details for a node selected from the list', async () => {
    signIn();
    server.use(
      http.get(`${BASE}/dashboard/attack-surface`, () =>
        HttpResponse.json({ data: graphResponse(), error: null }),
      ),
    );

    const { user } = renderApp(<AttackSurfacePage />);

    const list = await screen.findByRole('region', { name: /nodes by risk/i });
    await user.click(within(list).getByRole('button', { name: /web01.corp.local/i }));

    const detail = await screen.findByRole('region', { name: /web01.corp.local/i });
    expect(within(detail).getByText('Internet-facing')).toBeInTheDocument();
    expect(within(detail).getByText('94.5')).toBeInTheDocument();
  });

  it('filters the node list', async () => {
    signIn();
    server.use(
      http.get(`${BASE}/dashboard/attack-surface`, () =>
        HttpResponse.json({ data: graphResponse(), error: null }),
      ),
    );

    const { user } = renderApp(<AttackSurfacePage />);

    const list = await screen.findByRole('region', { name: /nodes by risk/i });
    await user.type(within(list).getByLabelText(/filter nodes/i), 'web01');

    await waitFor(() => {
      expect(within(list).queryByRole('button', { name: /payment processing/i })).toBeNull();
    });
    expect(within(list).getByRole('button', { name: /web01/i })).toBeInTheDocument();
  });

  it('offers a real next step when there is nothing to map', async () => {
    signIn();
    server.use(
      http.get(`${BASE}/dashboard/attack-surface`, () =>
        HttpResponse.json({
          data: { nodes: [], edges: [], aggregated: false, node_cap: 500, total_nodes: 0 },
          error: null,
        }),
      ),
    );

    renderApp(<AttackSurfacePage />);

    expect(await screen.findByText(/nothing to map yet/i)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /run a discovery scan/i })).toBeInTheDocument();
  });
});
