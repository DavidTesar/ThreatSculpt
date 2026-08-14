import { api, apiRequest } from './client';
import { tokenStore } from './tokenStore';
import type { Paginated } from './envelope';
import type { components, paths } from './schema.gen';
import type {
  Agent,
  AdminUser,
  Asset,
  AttackSurfaceGraph,
  BusinessService,
  CurrentPrincipal,
  EnrollmentToken,
  ExecutiveDashboard,
  Finding,
  FindingDetail,
  FindingStatus,
  Network,
  PasswordReset,
  ScanJob,
  Uuid,
  VerificationState,
} from '@/types/domain';

type Schemas = components['schemas'];

/**
 * The query parameters of a GET, taken from the schema rather than described here.
 *
 * A filter the backend does not accept therefore fails to compile instead of being
 * appended to the URL and ignored — which is how `sort`, `order` and a free-text `q`
 * came to be sent to `/findings`, an endpoint that has never read any of them.
 */
type GetQuery<TPath extends keyof paths> = paths[TPath] extends {
  get: { parameters: { query?: infer TQuery } };
}
  ? TQuery
  : never;

/** Page controls, shared by every collection. */
export type PageParams = Pick<NonNullable<GetQuery<'/api/v1/networks'>>, 'page' | 'per_page'>;

/* ------------------------------------------------------------------ auth */

export type LoginRequest = Schemas['LoginRequest'];
export type RegisterRequest = Schemas['RegisterRequest'];

/**
 * `POST /auth/login`. The refresh token is deliberately absent — it goes out as an
 * `HttpOnly` cookie only. Note `expires_at` (an instant), not `expires_in`.
 */
export type AuthTokenResponse = Schemas['TokenResponse'];

/** `POST /auth/register` returns the new principal alongside its first token. */
export type RegisterResponse = Schemas['RegisterResponse'];

export const authApi = {
  async login(body: LoginRequest): Promise<AuthTokenResponse> {
    const res = await apiRequest<AuthTokenResponse>('/auth/login', { method: 'POST', body });
    tokenStore.set(res.access_token);
    return res;
  },

  async register(body: RegisterRequest): Promise<RegisterResponse> {
    const res = await apiRequest<RegisterResponse>('/auth/register', { method: 'POST', body });
    tokenStore.set(res.access_token);
    return res;
  },

  async logout(): Promise<void> {
    try {
      await apiRequest<Schemas['LogoutResponse']>('/auth/logout', { method: 'POST' });
    } finally {
      // The local session is gone regardless of whether the server acknowledged.
      tokenStore.clear();
    }
  },

  me: () => api.get<CurrentPrincipal>('/auth/me'),

  /** Proves control of the address. Unauthenticated; the token identifies the account. */
  verifyEmail: (token: string) =>
    api.post<VerificationState>('/auth/verify-email', {
      token,
    } satisfies Schemas['VerifyEmailRequest']),

  /** Re-issues the caller's own token. Never accepts an address. */
  resendVerification: () => api.post<VerificationState>('/auth/verify-email/resend'),
};

/* ------------------------------------------------------------------ dashboards */

export const dashboardApi = {
  executive: (signal?: AbortSignal) =>
    api.get<ExecutiveDashboard>('/dashboard/executive', undefined, signal),
  attackSurface: (signal?: AbortSignal) =>
    api.get<AttackSurfaceGraph>('/dashboard/attack-surface', undefined, signal),
};

/* ------------------------------------------------------------------ findings */

export type FindingFilters = NonNullable<GetQuery<'/api/v1/findings'>>;

export const findingsApi = {
  list: (filters: FindingFilters, signal?: AbortSignal): Promise<Paginated<Finding>> =>
    api.list<Finding>('/findings', { ...filters }, signal),
  get: (id: Uuid, signal?: AbortSignal) =>
    api.get<FindingDetail>(`/findings/${id}`, undefined, signal),
  /** PATCH /findings/{id} — "status transitions only" (API.md). */
  updateStatus: (id: Uuid, status: FindingStatus, note?: string) =>
    api.patch<FindingDetail>(`/findings/${id}`, {
      status,
      note,
    } satisfies Schemas['FindingStatusUpdate']),
};

/* ------------------------------------------------------------------ assets */

export type AssetFilters = NonNullable<GetQuery<'/api/v1/assets'>>;
export type AssetUpdate = Schemas['AssetUpdate'];

export const assetsApi = {
  list: (filters: AssetFilters, signal?: AbortSignal): Promise<Paginated<Asset>> =>
    api.list<Asset>('/assets', { ...filters }, signal),
  get: (id: Uuid, signal?: AbortSignal) => api.get<Asset>(`/assets/${id}`, undefined, signal),
  update: (id: Uuid, body: AssetUpdate) => api.patch<Asset>(`/assets/${id}`, body),
  /** PUT /assets/{id}/services — replaces the mapping wholesale. */
  setServices: (id: Uuid, serviceIds: readonly Uuid[]) =>
    api.put<Asset>(`/assets/${id}/services`, {
      service_ids: [...serviceIds],
    } satisfies Schemas['AssetServicesUpdate']),
};

/* ------------------------------------------------------------------ networks */

export type NetworkCreate = Schemas['NetworkCreate'];
export type NetworkUpdate = Schemas['NetworkUpdate'];

export const networksApi = {
  list: (params?: PageParams, signal?: AbortSignal) =>
    api.list<Network>('/networks', { ...params }, signal),
  get: (id: Uuid, signal?: AbortSignal) => api.get<Network>(`/networks/${id}`, undefined, signal),
  create: (body: NetworkCreate) => api.post<Network>('/networks', body),
  update: (id: Uuid, body: NetworkUpdate) => api.patch<Network>(`/networks/${id}`, body),
  remove: (id: Uuid) => api.delete(`/networks/${id}`),
};

/* ------------------------------------------------------------------ business services */

export type BusinessServiceCreate = Schemas['BusinessServiceCreate'];
export type BusinessServiceUpdate = Schemas['BusinessServiceUpdate'];

export const businessServicesApi = {
  list: (params?: PageParams, signal?: AbortSignal) =>
    api.list<BusinessService>('/business-services', { ...params }, signal),
  get: (id: Uuid, signal?: AbortSignal) =>
    api.get<BusinessService>(`/business-services/${id}`, undefined, signal),
  create: (body: BusinessServiceCreate) => api.post<BusinessService>('/business-services', body),
  update: (id: Uuid, body: BusinessServiceUpdate) =>
    api.patch<BusinessService>(`/business-services/${id}`, body),
  remove: (id: Uuid) => api.delete(`/business-services/${id}`),
};

/* ------------------------------------------------------------------ scans */

export type ScanFilters = NonNullable<GetQuery<'/api/v1/scans'>>;
export type ScanCreate = Schemas['ScanJobCreate'];

export const scansApi = {
  list: (params?: ScanFilters, signal?: AbortSignal) =>
    api.list<ScanJob>('/scans', { ...params }, signal),
  get: (id: Uuid, signal?: AbortSignal) => api.get<ScanJob>(`/scans/${id}`, undefined, signal),
  create: (body: ScanCreate) => api.post<ScanJob>('/scans', body),
  cancel: (id: Uuid) => api.post<ScanJob>(`/scans/${id}/cancel`),
};

/* ------------------------------------------------------------------ agents */

export type EnrollmentTokenCreate = Schemas['EnrollmentTokenCreate'];

export const agentsApi = {
  list: (params?: PageParams, signal?: AbortSignal) =>
    api.list<Agent>('/agents', { ...params }, signal),
  get: (id: Uuid, signal?: AbortSignal) => api.get<Agent>(`/agents/${id}`, undefined, signal),
  /** POST /agents issues a one-time enrollment token; the agent row appears when it enrols. */
  issueEnrollmentToken: (body: EnrollmentTokenCreate = {}) =>
    api.post<EnrollmentToken>('/agents', body),
  /** The ranges this agent will accept jobs for. Set on the agent, not on the token. */
  updateAllowlist: (id: Uuid, cidrs: readonly string[]) =>
    api.patch<Agent>(`/agents/${id}/allowlist`, {
      allowlist: [...cidrs],
    } satisfies Schemas['AgentAllowlistUpdate']),
  /** Revocation returns the agent in its revoked state, not an empty body. */
  revoke: (id: Uuid) => api.delete<Agent>(`/agents/${id}`),
};

/* ------------------------------------------------------------------ users */

export type UserCreate = Schemas['UserCreate'];
export type UserUpdate = Schemas['UserUpdate'];

export const usersApi = {
  list: (params?: PageParams, signal?: AbortSignal) =>
    api.list<AdminUser>('/users', { ...params }, signal),
  create: (body: UserCreate) => api.post<AdminUser>('/users', body),
  update: (id: Uuid, body: UserUpdate) => api.patch<AdminUser>(`/users/${id}`, body),
  /** DELETE deactivates rather than deleting, so the audit trail keeps naming the user. */
  remove: (id: Uuid) => api.delete<AdminUser>(`/users/${id}`),
  changeOwnPassword: (body: Schemas['PasswordChangeRequest']) =>
    api.post<AdminUser>('/users/me/password', body),
  /** Returns a temporary password, shown exactly once. */
  resetPassword: (id: Uuid) => api.post<PasswordReset>(`/users/${id}/password-reset`),
  unlock: (id: Uuid) => api.post<AdminUser>(`/users/${id}/unlock`),
};
