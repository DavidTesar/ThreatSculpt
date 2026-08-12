import { ApiError } from './ApiError';
import {
  codeForStatus,
  isErrorEnvelope,
  type ApiResponse,
  type Paginated,
  type PaginationMeta,
} from './envelope';
import { tokenStore } from './tokenStore';
import { assertNoTenantParams, assertNoTenantSearchParams } from './tenantGuard';

// Dot access, not bracket: Vite statically replaces `import.meta.env.FOO`, but a bracket
// lookup defeats that substitution and becomes a runtime property read.
export const API_BASE = import.meta.env.VITE_API_BASE ?? '/api/v1';

/** Endpoints that must never trigger the refresh dance — refreshing on them would loop. */
const NO_REFRESH_PATHS = ['/auth/login', '/auth/register', '/auth/refresh', '/auth/logout'];

export type QueryValue = string | number | boolean | null | undefined;
export type QueryParams = Record<string, QueryValue | QueryValue[]>;

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';
  body?: unknown;
  params?: QueryParams;
  signal?: AbortSignal;
}

/* ------------------------------------------------------------ session expiry hook */

type SessionExpiredHandler = () => void;
let onSessionExpired: SessionExpiredHandler = () => {};

/**
 * Registered by the auth provider so a dead session can clear app state and route to
 * login. Kept as a hook rather than an import so this module stays router-agnostic.
 */
export function setSessionExpiredHandler(handler: SessionExpiredHandler): () => void {
  onSessionExpired = handler;
  return () => {
    onSessionExpired = () => {};
  };
}

/* ------------------------------------------------------------ url + body helpers */

function buildUrl(path: string, params?: QueryParams): string {
  const search = new URLSearchParams();
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value === undefined || value === null || value === '') continue;
      if (Array.isArray(value)) {
        for (const entry of value) {
          if (entry === undefined || entry === null || entry === '') continue;
          search.append(key, String(entry));
        }
      } else {
        search.append(key, String(value));
      }
    }
  }
  assertNoTenantSearchParams(search);
  const qs = search.toString();
  return `${API_BASE}${path}${qs ? `?${qs}` : ''}`;
}

async function parseEnvelope<T>(res: Response): Promise<ApiResponse<T>> {
  if (res.status === 204) return { data: null as T, error: null };

  const text = await res.text();
  if (!text) {
    if (res.ok) return { data: null as T, error: null };
    throw new ApiError(codeForStatus(res.status), `Request failed (${res.status}).`, res.status);
  }

  try {
    return JSON.parse(text) as ApiResponse<T>;
  } catch {
    throw new ApiError(
      'malformed_response',
      'The server returned a response this application could not read.',
      res.status,
    );
  }
}

/* ------------------------------------------------------------ single-flight refresh */

/**
 * Holds the one in-flight refresh. Every 401 that arrives while a refresh is running
 * awaits this same promise instead of firing its own — without it, a dashboard that
 * fires six parallel queries on mount would send six refreshes, and because refresh
 * tokens rotate, five of them would present an already-spent token and the server would
 * revoke the whole family as a reuse attack. The thundering herd would log the user out.
 */
let refreshInFlight: Promise<string> | null = null;

async function performRefresh(): Promise<string> {
  let res: Response;
  try {
    res = await fetch(buildUrl('/auth/refresh'), {
      method: 'POST',
      credentials: 'include', // sends the HttpOnly refresh cookie
      headers: { Accept: 'application/json' },
    });
  } catch {
    throw new ApiError('network_error', 'Could not reach the server.', 0);
  }

  if (!res.ok) {
    throw new ApiError(
      'session_expired',
      'Your session has expired. Please sign in again.',
      res.status,
    );
  }

  const body = await parseEnvelope<{ access_token: string }>(res);
  if (isErrorEnvelope(body) || !body.data?.access_token) {
    throw new ApiError(
      'session_expired',
      'Your session has expired. Please sign in again.',
      res.status,
    );
  }
  return body.data.access_token;
}

export function refreshAccessToken(): Promise<string> {
  if (refreshInFlight) return refreshInFlight;

  refreshInFlight = performRefresh()
    .then((token) => {
      tokenStore.set(token);
      return token;
    })
    .catch((err: unknown) => {
      tokenStore.clear();
      onSessionExpired();
      throw err;
    })
    .finally(() => {
      refreshInFlight = null;
    });

  return refreshInFlight;
}

/** Test seam: drops any in-flight refresh so cases do not leak into each other. */
export function __resetRefreshState(): void {
  refreshInFlight = null;
}

/* ------------------------------------------------------------ the request itself */

async function send(url: string, options: RequestOptions, token: string | null): Promise<Response> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const init: RequestInit = {
    method: options.method ?? 'GET',
    headers,
    credentials: 'include',
  };
  if (options.signal) init.signal = options.signal;

  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(options.body);
  }

  try {
    return await fetch(url, init);
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') throw err;
    throw new ApiError('network_error', 'Could not reach the server. Check your connection.', 0);
  }
}

async function requestEnvelope<T>(
  path: string,
  options: RequestOptions = {},
): Promise<ApiResponse<T>> {
  if (options.body !== undefined) assertNoTenantParams(options.body, 'request body');

  const url = buildUrl(path, options.params);
  const allowRefresh = !NO_REFRESH_PATHS.some((p) => path.startsWith(p));

  let res = await send(url, options, tokenStore.get());

  if (res.status === 401 && allowRefresh) {
    // Joins the in-flight refresh if one exists; starts exactly one otherwise.
    const token = await refreshAccessToken();
    res = await send(url, options, token);
  }

  const body = await parseEnvelope<T>(res);

  if (isErrorEnvelope(body)) throw ApiError.fromBody(body.error, res.status);
  if (!res.ok) {
    throw new ApiError(codeForStatus(res.status), `Request failed (${res.status}).`, res.status);
  }
  return body;
}

/** Unwraps to the payload. Use for single resources and non-paginated views. */
export async function apiRequest<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const body = await requestEnvelope<T>(path, options);
  return (body as { data: T }).data;
}

/** Keeps `meta` alongside the items. Use for every paginated collection. */
export async function apiRequestPaginated<T>(
  path: string,
  options: RequestOptions = {},
): Promise<Paginated<T>> {
  const body = await requestEnvelope<T[]>(path, options);
  const items = (body as { data: T[] }).data ?? [];
  const meta: PaginationMeta = (body as { meta?: PaginationMeta }).meta ?? {
    page: 1,
    per_page: items.length,
    total: items.length,
  };
  return { items, meta };
}

export const api = {
  get: <T>(path: string, params?: QueryParams, signal?: AbortSignal) =>
    apiRequest<T>(path, { method: 'GET', params, signal }),
  list: <T>(path: string, params?: QueryParams, signal?: AbortSignal) =>
    apiRequestPaginated<T>(path, { method: 'GET', params, signal }),
  post: <T>(path: string, body?: unknown) => apiRequest<T>(path, { method: 'POST', body }),
  patch: <T>(path: string, body?: unknown) => apiRequest<T>(path, { method: 'PATCH', body }),
  put: <T>(path: string, body?: unknown) => apiRequest<T>(path, { method: 'PUT', body }),
  delete: <T = null>(path: string) => apiRequest<T>(path, { method: 'DELETE' }),
};
