import { describe, expect, it, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, rmSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';

/**
 * Regression guard for the worst failure this frontend can have: shipping Mock Service
 * Worker to production and rendering fabricated vulnerability findings as real ones.
 *
 * The defence is that `startMocks()` is gated on `import.meta.env.DEV`, which Vite
 * replaces with the literal `false` in a production build, letting Rollup drop the branch
 * and the dynamic `import('./mocks/browser')` with it. That is a property of the emitted
 * bundle, so the only honest way to assert it is to build and inspect the output.
 *
 * A unit test on the source could not catch this — the source looks the same either way.
 */

const WEB_ROOT = resolve(__dirname, '../..');
// Inside node_modules so it is git-ignored and never mistaken for a real artifact.
const OUT_DIR = join(WEB_ROOT, 'node_modules', '.tmp-bundle-guard');

/** Strings that only appear if MSW made it into the bundle. */
const MSW_MARKERS = ['setupWorker', 'mockServiceWorker', 'msw/browser'];

/**
 * Fixture giveaways — a real customer must never see Northwind's invented estate, nor the
 * demo credentials. Deliberately not matching every example hostname: `hq-dc-scanner-01`
 * also appears as a legitimate placeholder in the agent-name field, which is real UI copy
 * rather than leaked fixture data.
 */
const FIXTURE_MARKERS = [
  'northwind-logistics',
  'Northwind Logistics',
  'diane.whitfield',
  'Demo build',
];

function readBundledJs(): string {
  const assets = join(OUT_DIR, 'assets');
  return readdirSync(assets)
    .filter((file) => file.endsWith('.js'))
    .map((file) => readFileSync(join(assets, file), 'utf8'))
    .join('\n');
}

describe('production bundle', () => {
  let bundle = '';

  beforeAll(() => {
    execFileSync(
      'npx',
      ['vite', 'build', '--mode', 'production', '--outDir', OUT_DIR, '--emptyOutDir'],
      { cwd: WEB_ROOT, stdio: 'pipe', env: { ...process.env, NODE_ENV: 'production' } },
    );
    bundle = readBundledJs();
  }, 180_000);

  afterAll(() => {
    if (existsSync(OUT_DIR)) rmSync(OUT_DIR, { recursive: true, force: true });
  });

  it('produces a non-empty bundle to inspect', () => {
    expect(bundle.length).toBeGreaterThan(10_000);
  });

  it.each(MSW_MARKERS)('contains no MSW marker: %s', (marker) => {
    expect(bundle).not.toContain(marker);
  });

  it.each(FIXTURE_MARKERS)('contains no fixture data marker: %s', (marker) => {
    expect(bundle).not.toContain(marker);
  });

  it('ships no mock handler code at all', () => {
    // A phrase unique to the fixture handlers. Its absence means the whole mock module
    // graph was eliminated, not just the worker entry point.
    expect(bundle).not.toContain('Scans require the network to be marked authorized');
    expect(bundle).not.toContain('Every finding on screen is fabricated');
  });

  it('keeps the charting library out of the entry chunk', () => {
    // Recharts is ~106 kB gzipped. A signed-out visitor looking at a login form must not
    // download it, so it has to sit behind a lazily-loaded route chunk.
    const html = readFileSync(join(OUT_DIR, 'index.html'), 'utf8');
    const preloaded = [...html.matchAll(/(?:src|href)="([^"]+\.js)"/g)].map((m) => m[1] ?? '');

    expect(preloaded.length).toBeGreaterThan(0);
    for (const asset of preloaded) {
      expect(asset).not.toMatch(/charts/);
    }
  });
});
