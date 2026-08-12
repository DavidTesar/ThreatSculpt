import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';

import './styles/tokens.css';
import './styles/base.css';
import './styles/layout.css';
import './styles/components.css';
import './styles/features.css';

/**
 * Starts Mock Service Worker — development only, enforced at build time.
 *
 * `import.meta.env.DEV` is replaced by Vite with the literal `false` in a production
 * build, so this entire branch — including the dynamic import of ./mocks/browser — is
 * dead code that Rollup eliminates. MSW is therefore *absent from the production bundle*,
 * not merely switched off inside it.
 *
 * That distinction is the whole point. This app renders vulnerability findings that
 * someone will use to decide what to patch. A build that could serve fabricated findings
 * because an environment variable was unset would be worse than a build that fails to
 * load at all: a blank screen is obviously broken, whereas a confident "0 critical
 * findings" for a real network is plausible fiction, and acted upon.
 *
 * VITE_USE_MOCKS can only ever *disable* mocks (for pointing a dev server at a real
 * control plane). It cannot enable them. There is no value of any environment variable
 * that puts MSW into a production build.
 */
async function startMocks(): Promise<void> {
  if (!import.meta.env.DEV) return;
  if (import.meta.env.VITE_USE_MOCKS === 'false') return;

  const { worker } = await import('./mocks/browser');

  // Defence in depth: if this ever executes outside a dev build, refuse to render rather
  // than serve fabricated security data.
  if (!import.meta.env.DEV) {
    throw new Error(
      'Refusing to start: mock data was activated outside a development build. ' +
        'ThreatSculpt will not render fabricated vulnerability findings.',
    );
  }

  await worker.start({
    // Not quiet, and not bypassing: in development an unmocked request should be visible
    // in the console, not silently escaping to the network.
    onUnhandledRequest: 'warn',
    serviceWorker: { url: `${import.meta.env.BASE_URL}mockServiceWorker.js` },
  });

  console.warn('[ThreatSculpt] Running against MOCK data. Every finding on screen is fabricated.');
}

async function bootstrap() {
  await startMocks();

  const container = document.getElementById('root');
  if (!container) throw new Error('Root container #root is missing from index.html');

  createRoot(container).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}

void bootstrap();
