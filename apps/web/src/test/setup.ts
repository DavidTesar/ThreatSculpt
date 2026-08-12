import '@testing-library/jest-dom/vitest';
import { afterAll, afterEach, beforeAll } from 'vitest';
import { cleanup } from '@testing-library/react';
import { server } from '@/mocks/server';
import { resetDb } from '@/mocks/handlers';
import { resetSession } from '@/mocks/session';
import { tokenStore } from '@/lib/api/tokenStore';
import { __resetRefreshState } from '@/lib/api/client';

beforeAll(() => {
  // An unhandled request is a test asking for something the contract does not define —
  // fail rather than let it silently hit the network.
  server.listen({ onUnhandledRequest: 'error' });
  // Must come after MSW installs its interceptor, so this wraps the outermost fetch.
  stripAbortSignals();
});

afterEach(() => {
  cleanup();
  server.resetHandlers();
  resetDb();
  resetSession();
  tokenStore.clear();
  __resetRefreshState();
});

afterAll(() => server.close());

/* ------------------------------------------------------------ jsdom gaps */

// jsdom implements neither of these; Recharts' ResponsiveContainer needs the first and
// the native <dialog> element needs the second.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
};

if (typeof HTMLDialogElement !== 'undefined') {
  if (!HTMLDialogElement.prototype.showModal) {
    HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
      this.setAttribute('open', '');
    };
  }
  if (!HTMLDialogElement.prototype.close) {
    HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
      this.removeAttribute('open');
      this.dispatchEvent(new Event('close'));
    };
  }
}

/**
 * jsdom + undici realm mismatch.
 *
 * Vitest's jsdom environment supplies jsdom's `AbortSignal`, while `fetch` is Node's
 * undici, which brand-checks the signal against its own privately-held `AbortSignal`
 * reference. The two are not the same class, so passing a TanStack Query abort signal to
 * fetch throws `Expected signal to be an instance of AbortSignal` — in the test
 * environment only. In a browser there is one realm and one class, so this cannot happen.
 *
 * Rather than remove signals from production code to suit the test runner, the signal is
 * dropped here at the boundary. Nothing under test asserts cancellation behaviour; that
 * belongs to TanStack Query, not to this application's code.
 */
function stripAbortSignals(): void {
  const inner = globalThis.fetch;
  globalThis.fetch = function patchedFetch(input: RequestInfo | URL, init?: RequestInit) {
    if (init?.signal) {
      const { signal: _signal, ...rest } = init;
      return inner(input, rest);
    }
    return inner(input, init);
  } as typeof fetch;
}

/**
 * A plain function, not a `vi.fn()`: `restoreMocks: true` resets spy implementations
 * after every test, which would leave this returning undefined for every case after the
 * first — a confusing failure a long way from its cause.
 */
if (!window.matchMedia) {
  window.matchMedia = (query: string): MediaQueryList =>
    ({
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false,
    }) as unknown as MediaQueryList;
}
