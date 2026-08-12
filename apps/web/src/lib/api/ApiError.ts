import type { ApiErrorBody, ApiErrorCode } from './envelope';

/**
 * A failed API call. Always carries a machine-readable `code` so UI can branch on the
 * condition rather than on message text, and a `message` safe to show a user.
 */
export class ApiError extends Error {
  readonly code: ApiErrorCode;
  readonly status: number;
  readonly field: string | null;

  constructor(code: ApiErrorCode, message: string, status = 0, field: string | null = null) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    this.field = field;
    Object.setPrototypeOf(this, ApiError.prototype);
  }

  static fromBody(body: ApiErrorBody, status: number): ApiError {
    return new ApiError(body.code, body.message, status, body.field ?? null);
  }

  /** A 404 is also how the API reports "not in your org" — indistinguishable by design. */
  get isNotFound(): boolean {
    return this.status === 404 || this.code === 'not_found';
  }

  get isAuthFailure(): boolean {
    return (
      this.status === 401 || this.code === 'unauthenticated' || this.code === 'session_expired'
    );
  }

  get isPermissionDenied(): boolean {
    return this.status === 403 || this.code === 'forbidden';
  }

  get isRateLimited(): boolean {
    return this.status === 429 || this.code === 'rate_limited';
  }

  /** Retrying will not change the outcome — used to stop TanStack Query retrying. */
  get isTerminal(): boolean {
    return this.isAuthFailure || this.isPermissionDenied || this.isNotFound || this.status === 400;
  }
}

export function isApiError(err: unknown): err is ApiError {
  return err instanceof ApiError;
}

/** Human-readable fallback for an unknown throwable, for use in error UI. */
export function messageFor(err: unknown): string {
  if (isApiError(err)) return err.message;
  if (err instanceof Error) return err.message;
  return 'Something went wrong.';
}
