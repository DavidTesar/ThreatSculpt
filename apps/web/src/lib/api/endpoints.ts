import { api, apiRequest } from './client';
import { tokenStore } from './tokenStore';
import type { Paginated } from './envelope';
import type {
  Agent,
  Asset,
  AssetDetail,
  AttackSurfaceGraph,
  BusinessService,
  CurrentPrincipal,
  Criticality,
  EnrollmentToken,
  ExecutiveDashboard,
  Exposure,
  Finding,
  FindingDetail,
  FindingStatus,
  Network,
  Role,
  ScanJob,
  ScanProfile,
  Severity,
  User,
  Uuid,
} from '@/types/domain';

/* ------------------------------------------------------------------ auth */

export interface LoginRequest {
  email: string;
  password: string;
}

export interface RegisterRequest {
  org_name: string;
  full_name: string;
  email: string;
  password: string;
}

/** The refresh token is set as an HttpOnly cookie; it never appears in this body. */
export interface AuthTokenResponse {
  access_token: string;
  token_type: 'bearer';
  expires_in: number;
}

export const authApi = {
  async login(body: LoginRequest): Promise<AuthTokenResponse> {
    const res = await apiRequest<AuthTokenResponse>('/auth/login', { method: 'POST', body });
    tokenStore.set(res.access_token);
    return res;
  },

  async register(body: RegisterRequest): Promise<AuthTokenResponse> {
    const res = await apiRequest<AuthTokenResponse>('/auth/register', { method: 'POST', body });
    tokenStore.set(res.access_token);
    return res;
  },

  async logout(): Promise<void> {
    try {
      await apiRequest<null>('/auth/logout', { method: 'POST' });
    } finally {
      // The local session is gone regardless of whether the server acknowledged.
      tokenStore.clear();
    }
  },

  me: () => api.get<CurrentPrincipal>('/auth/me'),
};

/* ------------------------------------------------------------------ dashboards */

export const dashboardApi = {
  executive: (signal?: AbortSignal) =>
    api.get<ExecutiveDashboard>('/dashboard/executive', undefined, signal),
  attackSurface: (signal?: AbortSignal) =>
    api.get<AttackSurfaceGraph>('/dashboard/attack-surface', undefined, signal),
};

/* ------------------------------------------------------------------ findings */

export interface FindingFilters {
  status?: FindingStatus | '';
  severity?: Severity | '';
  service_id?: Uuid | '';
  asset_id?: Uuid | '';
  kev_only?: boolean;
  sort?: string;
  order?: 'asc' | 'desc';
  page?: number;
  per_page?: number;
}

export const findingsApi = {
  list: (filters: FindingFilters, signal?: AbortSignal): Promise<Paginated<Finding>> =>
    api.list<Finding>('/findings', { ...filters }, signal),
  get: (id: Uuid, signal?: AbortSignal) =>
    api.get<FindingDetail>(`/findings/${id}`, undefined, signal),
  /** PATCH /findings/{id} — "status transitions only" (API.md). */
  updateStatus: (id: Uuid, status: FindingStatus) =>
    api.patch<FindingDetail>(`/findings/${id}`, { status }),
};

/* ------------------------------------------------------------------ assets */

export interface AssetFilters {
  network_id?: Uuid | '';
  exposure?: Exposure | '';
  service_id?: Uuid | '';
  q?: string;
  page?: number;
  per_page?: number;
}

export const assetsApi = {
  list: (filters: AssetFilters, signal?: AbortSignal): Promise<Paginated<Asset>> =>
    api.list<Asset>('/assets', { ...filters }, signal),
  get: (id: Uuid, signal?: AbortSignal) => api.get<AssetDetail>(`/assets/${id}`, undefined, signal),
  update: (id: Uuid, body: { hostname?: string | null; exposure?: Exposure }) =>
    api.patch<AssetDetail>(`/assets/${id}`, body),
  /** PUT /assets/{id}/services — replaces the mapping wholesale. */
  setServices: (id: Uuid, serviceIds: Uuid[]) =>
    api.put<AssetDetail>(`/assets/${id}/services`, { business_service_ids: serviceIds }),
};

/* ------------------------------------------------------------------ networks */

export interface NetworkInput {
  name: string;
  cidr: string;
  authorized: boolean;
  authorization_note?: string | null;
}

export const networksApi = {
  list: (params?: { page?: number; per_page?: number }, signal?: AbortSignal) =>
    api.list<Network>('/networks', { ...params }, signal),
  get: (id: Uuid, signal?: AbortSignal) => api.get<Network>(`/networks/${id}`, undefined, signal),
  create: (body: NetworkInput) => api.post<Network>('/networks', body),
  update: (id: Uuid, body: Partial<NetworkInput>) => api.patch<Network>(`/networks/${id}`, body),
  remove: (id: Uuid) => api.delete(`/networks/${id}`),
};

/* ------------------------------------------------------------------ business services */

export interface BusinessServiceInput {
  name: string;
  description?: string | null;
  criticality: Criticality;
  revenue_at_risk?: string | null;
  owner_name?: string | null;
  owner_email?: string | null;
}

export const businessServicesApi = {
  list: (params?: { page?: number; per_page?: number }, signal?: AbortSignal) =>
    api.list<BusinessService>('/business-services', { ...params }, signal),
  get: (id: Uuid, signal?: AbortSignal) =>
    api.get<BusinessService>(`/business-services/${id}`, undefined, signal),
  create: (body: BusinessServiceInput) => api.post<BusinessService>('/business-services', body),
  update: (id: Uuid, body: Partial<BusinessServiceInput>) =>
    api.patch<BusinessService>(`/business-services/${id}`, body),
  remove: (id: Uuid) => api.delete(`/business-services/${id}`),
};

/* ------------------------------------------------------------------ scans */

export interface ScanInput {
  network_id: Uuid;
  target: string;
  profile: ScanProfile;
}

export const scansApi = {
  list: (params?: { page?: number; per_page?: number; status?: string }, signal?: AbortSignal) =>
    api.list<ScanJob>('/scans', { ...params }, signal),
  get: (id: Uuid, signal?: AbortSignal) => api.get<ScanJob>(`/scans/${id}`, undefined, signal),
  create: (body: ScanInput) => api.post<ScanJob>('/scans', body),
  cancel: (id: Uuid) => api.post<ScanJob>(`/scans/${id}/cancel`),
};

/* ------------------------------------------------------------------ agents */

export const agentsApi = {
  list: (signal?: AbortSignal) => api.list<Agent>('/agents', undefined, signal),
  /** POST /agents issues a one-time enrollment token (API.md). */
  issueEnrollmentToken: (body: { name: string }) => api.post<EnrollmentToken>('/agents', body),
  revoke: (id: Uuid) => api.delete(`/agents/${id}`),
};

/* ------------------------------------------------------------------ users */

export interface UserInput {
  email: string;
  full_name: string;
  role: Role;
}

export const usersApi = {
  list: (signal?: AbortSignal) => api.list<User>('/users', undefined, signal),
  create: (body: UserInput) => api.post<User>('/users', body),
  update: (id: Uuid, body: Partial<Pick<UserInput, 'role' | 'full_name'>>) =>
    api.patch<User>(`/users/${id}`, body),
  remove: (id: Uuid) => api.delete(`/users/${id}`),
};
