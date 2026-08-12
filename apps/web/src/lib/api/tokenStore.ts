/**
 * The access token lives in a module closure — never in localStorage or sessionStorage.
 *
 * A token in web storage is readable by any script that achieves execution on the page,
 * which turns one XSS into a stolen session that outlives the tab. Holding it in memory
 * means a page reload drops it, and the app re-derives a new one from the HttpOnly
 * refresh cookie, which script cannot read at all.
 */

type Listener = (token: string | null) => void;

let accessToken: string | null = null;
const listeners = new Set<Listener>();

function emit(): void {
  for (const listener of listeners) listener(accessToken);
}

export const tokenStore = {
  get(): string | null {
    return accessToken;
  },

  set(token: string | null): void {
    accessToken = token;
    emit();
  },

  clear(): void {
    accessToken = null;
    emit();
  },

  subscribe(listener: Listener): () => void {
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  },
};
