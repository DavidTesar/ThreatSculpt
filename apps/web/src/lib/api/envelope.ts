/**
 * The response envelope every endpoint returns (docs/API.md, rule 2).
 *
 *   { "data": <payload>, "error": null, "meta": { page, per_page, total } }
 *
 * `meta` is present only on paginated collections.
 */

export interface PaginationMeta {
  page: number;
  per_page: number;
  total: number;
}

/** Error body — a stable machine-readable code, never a stack trace (API.md, rule 3). */
export interface ApiErrorBody {
  code: ApiErrorCode;
  message: string;
  /** Set when the error is attributable to one input field. */
  field?: string | null;
}

export interface ApiEnvelope<T> {
  data: T;
  error: null;
  meta?: PaginationMeta;
}

export interface ApiErrorEnvelope {
  data: null;
  error: ApiErrorBody;
}

export type ApiResponse<T> = ApiEnvelope<T> | ApiErrorEnvelope;

/**
 * Codes documented in API.md, plus the client-side codes this layer synthesises for
 * conditions that never reach the server (transport failure, unparseable body, an
 * expired session after a failed refresh). The `(string & {})` arm keeps the union open
 * — the server may add codes without breaking the build — while preserving autocomplete.
 */
export type ApiErrorCode =
  | 'validation_error'
  | 'semantic_validation_error'
  | 'unauthenticated'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'rate_limited'
  | 'network_not_authorized'
  | 'last_owner'
  | 'invalid_credentials'
  | 'session_expired'
  | 'network_error'
  | 'malformed_response'
  | (string & {});

/** Maps a bare HTTP status to a code, for servers that return an unenveloped error. */
export function codeForStatus(status: number): ApiErrorCode {
  switch (status) {
    case 400:
      return 'validation_error';
    case 401:
      return 'unauthenticated';
    case 403:
      return 'forbidden';
    case 404:
      return 'not_found';
    case 409:
      return 'conflict';
    case 422:
      return 'semantic_validation_error';
    case 429:
      return 'rate_limited';
    default:
      return status >= 500 ? 'server_error' : 'request_failed';
  }
}

export function isErrorEnvelope<T>(body: ApiResponse<T>): body is ApiErrorEnvelope {
  return body.error !== null;
}

export interface Paginated<T> {
  items: T[];
  meta: PaginationMeta;
}
