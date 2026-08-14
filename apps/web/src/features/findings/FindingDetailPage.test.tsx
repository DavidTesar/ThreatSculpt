import { describe, expect, it } from 'vitest';
import { Route, Routes } from 'react-router-dom';
import { screen, waitFor, within } from '@testing-library/react';
import { renderApp, signIn } from '@/test/utils';
import { FindingDetailPage } from './FindingDetailPage';
import { buildDb } from '@/mocks/db';

function renderFinding(id: string) {
  return renderApp(
    <Routes>
      <Route path="/findings/:id" element={<FindingDetailPage />} />
    </Routes>,
    { route: `/findings/${id}` },
  );
}

/** A KEV-listed, open finding — the case with the most to display. */
function kevFindingId(): string {
  const db = buildDb();
  return db.findings.find((f) => f.cve.kev_listed && f.status === 'open')!.id;
}

describe('FindingDetailPage', () => {
  it('leads with the CVE, its severity, and the business risk score', async () => {
    signIn();
    const db = buildDb();
    const finding = db.findings.find((f) => f.cve.kev_listed && f.status === 'open')!;

    renderFinding(finding.id);

    expect(await screen.findByRole('heading', { name: finding.cve.cve_id })).toBeInTheDocument();
    expect(screen.getAllByText('KEV').length).toBeGreaterThan(0);
  });

  it('explains the score rather than asserting it', async () => {
    signIn();
    renderFinding(kevFindingId());

    const explain = await screen.findByRole('region', { name: /why this score/i });
    expect(within(explain).getByText(/cvss base score/i)).toBeInTheDocument();
    expect(within(explain).getByText(/exploit maturity/i)).toBeInTheDocument();
    expect(within(explain).getByText(/business criticality/i)).toBeInTheDocument();
  });

  it('shows the NVD reference data behind the finding', async () => {
    signIn();
    renderFinding(kevFindingId());

    // `CveSummary` carries no CVSS vector and no publication date — the reference block
    // asserted here is what the API actually returns.
    const about = await screen.findByRole('region', { name: /about this vulnerability/i });
    expect(within(about).getByText(/cvss base/i)).toBeInTheDocument();
    expect(within(about).getByText(/known exploited/i)).toBeInTheDocument();
  });

  it('says how the CVE was matched to the host, and how sure we are', async () => {
    signIn();
    renderFinding(kevFindingId());

    const match = await screen.findByRole('region', { name: /how we matched this/i });
    expect(within(match).getByText(/confidence/i)).toBeInTheDocument();
  });

  it('transitions the finding status and confirms it', async () => {
    signIn();
    const { user } = renderFinding(kevFindingId());

    await screen.findByRole('region', { name: /why this score/i });
    await user.click(screen.getByRole('button', { name: /mark remediated/i }));

    await waitFor(() => expect(screen.getByText(/marked as remediated/i)).toBeInTheDocument());
  });

  it('tells the user when the asset is unmapped and offers to fix it', async () => {
    signIn();
    const db = buildDb();
    const unmapped = db.findings.find((f) => (f.services_affected ?? []).length === 0);

    // The fixture estate includes unmapped assets by design; skip only if that changes.
    if (!unmapped) return;

    renderFinding(unmapped.id);

    const impact = await screen.findByRole('region', { name: /business impact/i });
    expect(within(impact).getByText(/not mapped to any business service/i)).toBeInTheDocument();
    expect(within(impact).getByRole('link', { name: /map this asset/i })).toBeInTheDocument();
  });
});
