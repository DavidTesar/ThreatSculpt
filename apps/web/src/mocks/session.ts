import { HttpResponse } from 'msw';
import type { ApiErrorCode } from '@/lib/api/envelope';

/**
 * Mock-side session state, standing in for the control plane's token store.
 *
 * The access token here has a real (short) lifetime and requests carrying an expired one
 * get a genuine 401. That is deliberate: it means the app's refresh-on-401 path is
 * exercised by simply using the demo, rather than being a code path nothing ever runs.
 */

/** Mock-only. The real refresh token is an HttpOnly cookie that script cannot read. */
const SESSION_MARKER = 'ts.mock.session';
const ACCESS_TTL_MS = 15 * 60_000;

interface MockSession {
  refreshValid: boolean;
  accessToken: string | null;
  accessExpiresAt: number;
  /** Bumped on every rotation so a replayed refresh can be detected. */
  family: number;
}

function readMarker(): boolean {
  try {
    return globalThis.sessionStorage?.getItem(SESSION_MARKER) === '1';
  } catch {
    return false;
  }
}

function writeMarker(active: boolean): void {
  try {
    if (active) globalThis.sessionStorage?.setItem(SESSION_MARKER, '1');
    else globalThis.sessionStorage?.removeItem(SESSION_MARKER);
  } catch {
    /* storage unavailable (tests, private mode) — session simply does not survive reload */
  }
}

let session: MockSession = {
  refreshValid: readMarker(),
  accessToken: null,
  accessExpiresAt: 0,
  family: 1,
};

export function issueAccessToken(now = Date.now()): string {
  const token = `tsk_${session.family}_${now.toString(36)}`;
  session = { ...session, accessToken: token, accessExpiresAt: now + ACCESS_TTL_MS };
  return token;
}

export function startSession(): string {
  session = { ...session, refreshValid: true, family: session.family + 1 };
  writeMarker(true);
  return issueAccessToken();
}

export function endSession(): void {
  session = { refreshValid: false, accessToken: null, accessExpiresAt: 0, family: session.family };
  writeMarker(false);
}

export function hasRefresh(): boolean {
  return session.refreshValid;
}

export function expireAccessToken(): void {
  session = { ...session, accessExpiresAt: 0 };
}

/** Test seam: resets everything between cases. */
export function resetSession(): void {
  session = { refreshValid: false, accessToken: null, accessExpiresAt: 0, family: 1 };
  writeMarker(false);
}

function bearerFrom(request: Request): string | null {
  const header = request.headers.get('Authorization');
  if (!header?.startsWith('Bearer ')) return null;
  return header.slice(7);
}

export function isAuthorized(request: Request, now = Date.now()): boolean {
  const token = bearerFrom(request);
  if (!token || !session.accessToken) return false;
  if (token !== session.accessToken) return false;
  return now < session.accessExpiresAt;
}

/* ------------------------------------------------------------------ responses */

export function envelope<T>(data: T, meta?: { page: number; per_page: number; total: number }) {
  return HttpResponse.json(meta ? { data, error: null, meta } : { data, error: null });
}

export function errorResponse(status: number, code: ApiErrorCode, message: string, field?: string) {
  return HttpResponse.json(
    { data: null, error: { code, message, field: field ?? null } },
    { status },
  );
}

export const unauthorized = () =>
  errorResponse(401, 'unauthenticated', 'Your session is no longer valid.');

/** A cross-tenant or missing resource is a 404 either way — indistinguishable by design. */
export const notFound = (what = 'Resource') =>
  errorResponse(404, 'not_found', `${what} not found.`);

/**
 * Wraps a handler so every tenant-scoped route enforces authentication the same way,
 * rather than each one remembering to check.
 */
export function guarded<T>(request: Request, handle: () => T) {
  if (!isAuthorized(request)) return unauthorized();
  return handle();
}
