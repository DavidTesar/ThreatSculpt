import { describe, expect, it } from 'vitest';
import { Route, Routes } from 'react-router-dom';
import { screen, waitFor, within } from '@testing-library/react';
import { renderApp, signIn } from '@/test/utils';
import { AssetDetailPage } from './AssetDetailPage';
import { buildDb } from '@/mocks/db';

function renderAsset(assetId: string) {
  return renderApp(
    <Routes>
      <Route path="/assets/:id" element={<AssetDetailPage />} />
    </Routes>,
    { route: `/assets/${assetId}` },
  );
}

/** Picks a fixture asset that is already mapped, so the editor has a starting state. */
function mappedAssetId(): string {
  const db = buildDb();
  return db.assets.find((asset) => asset.services.length > 0)!.id;
}

describe('AssetDetailPage', () => {
  it('shows the observed ports the agent reported', async () => {
    signIn();
    renderAsset(mappedAssetId());

    expect(await screen.findByText(/observed services/i)).toBeInTheDocument();
    expect(screen.getByText(/what the scan agent found listening/i)).toBeInTheDocument();
  });

  it('pre-selects the services this asset already supports', async () => {
    signIn();
    const db = buildDb();
    const asset = db.assets.find((a) => a.services.length > 0)!;

    renderAsset(asset.id);

    const mapping = await screen.findByRole('region', { name: /business services/i });
    const checked = within(mapping)
      .getAllByRole('checkbox')
      .filter((box) => (box as HTMLInputElement).checked);

    expect(checked).toHaveLength(asset.services.length);
  });

  it('keeps the save button inert until the mapping actually changes', async () => {
    signIn();
    const { user } = renderApp(
      <Routes>
        <Route path="/assets/:id" element={<AssetDetailPage />} />
      </Routes>,
      { route: `/assets/${mappedAssetId()}` },
    );

    const mapping = await screen.findByRole('region', { name: /business services/i });
    const save = within(mapping).getByRole('button', { name: /mapping saved/i });
    expect(save).toBeDisabled();

    const boxes = within(mapping).getAllByRole('checkbox');
    const toToggle = boxes.find((b) => !(b as HTMLInputElement).checked)!;
    await user.click(toToggle);

    expect(within(mapping).getByRole('button', { name: /save mapping/i })).toBeEnabled();
  });

  it('saves a changed mapping and confirms it', async () => {
    signIn();
    const { user } = renderApp(
      <Routes>
        <Route path="/assets/:id" element={<AssetDetailPage />} />
      </Routes>,
      { route: `/assets/${mappedAssetId()}` },
    );

    const mapping = await screen.findByRole('region', { name: /business services/i });
    const boxes = within(mapping).getAllByRole('checkbox');
    await user.click(boxes.find((b) => !(b as HTMLInputElement).checked)!);
    await user.click(within(mapping).getByRole('button', { name: /save mapping/i }));

    await waitFor(() => expect(screen.getByText(/service mapping updated/i)).toBeInTheDocument());
  });

  it('reports a 404 for an asset that is not in this organisation', async () => {
    signIn();
    // A cross-tenant id and a genuinely missing id are indistinguishable by design.
    renderAsset('a9999-0000-4000-8000-000000000000');

    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent(/not found/i);
  });
});
