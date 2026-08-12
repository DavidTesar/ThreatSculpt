/**
 * Domain types, transcribed from docs/DATA-MODEL.md.
 *
 * When the control plane exists these will be generated from its OpenAPI schema
 * (see ARCHITECTURE.md — "Types generated from the OpenAPI schema"). Until then this
 * module is the hand-maintained stand-in and is the single place a contract drift shows up.
 */

export type Uuid = string;
/** ISO-8601 timestamp. */
export type Timestamp = string;
/** ISO-8601 date (no time component). */
export type DateOnly = string;

/* ---------------------------------------------------------------- identity */

export const ROLES = ['owner', 'admin', 'analyst', 'viewer'] as const;
export type Role = (typeof ROLES)[number];

export type OrgPlan = 'trial' | 'standard' | 'enterprise';
export type OrgStatus = 'active' | 'suspended';
export type UserStatus = 'active' | 'disabled';

export interface Org {
  id: Uuid;
  name: string;
  slug: string;
  plan: OrgPlan;
  status: OrgStatus;
}

export interface User {
  id: Uuid;
  email: string;
  full_name: string | null;
  role: Role;
  status: UserStatus;
  last_login_at: Timestamp | null;
  created_at: Timestamp;
}

/** Payload of `GET /auth/me` — "Current user + org + role". */
export interface CurrentPrincipal {
  user: User;
  org: Org;
  role: Role;
}

/* ---------------------------------------------------------------- inventory */

export const EXPOSURES = ['internet', 'dmz', 'internal', 'isolated'] as const;
export type Exposure = (typeof EXPOSURES)[number];

export const CRITICALITIES = ['critical', 'high', 'medium', 'low'] as const;
export type Criticality = (typeof CRITICALITIES)[number];

export interface Network {
  id: Uuid;
  name: string;
  cidr: string;
  authorized: boolean;
  authorization_note: string | null;
  asset_count: number;
  created_at: Timestamp;
  updated_at: Timestamp;
}

export interface BusinessService {
  id: Uuid;
  name: string;
  description: string | null;
  criticality: Criticality;
  /** numeric(14,2). Carried as a string to avoid float rounding on money. */
  revenue_at_risk: string | null;
  owner_name: string | null;
  owner_email: string | null;
  asset_count: number;
  open_findings: number;
  created_at: Timestamp;
  updated_at: Timestamp;
}

export interface AssetServiceRef {
  id: Uuid;
  name: string;
  criticality: Criticality;
}

export interface Asset {
  id: Uuid;
  network_id: Uuid | null;
  network_name: string | null;
  ip: string;
  hostname: string | null;
  mac: string | null;
  os_family: string | null;
  os_version: string | null;
  exposure: Exposure;
  first_seen_at: Timestamp;
  last_seen_at: Timestamp;
  services: AssetServiceRef[];
  open_findings: number;
  /** Highest open business_risk_score on this asset; null when it has no open findings. */
  max_business_risk_score: number | null;
}

export interface Port {
  id: Uuid;
  port: number;
  protocol: string;
  state: string;
  service: string | null;
  product: string | null;
  version: string | null;
  cpe: string[];
}

/** `GET /assets/{id}` — the list shape plus the observed ports. */
export interface AssetDetail extends Asset {
  ports: Port[];
}

/* ---------------------------------------------------------------- scanning */

export const SCAN_PROFILES = ['discovery', 'service', 'vulnerability'] as const;
export type ScanProfile = (typeof SCAN_PROFILES)[number];

export const SCAN_STATUSES = [
  'queued',
  'claimed',
  'running',
  'completed',
  'failed',
  'cancelled',
] as const;
export type ScanStatus = (typeof SCAN_STATUSES)[number];

export interface ScanJob {
  id: Uuid;
  network_id: Uuid;
  network_name: string;
  target: string;
  profile: ScanProfile;
  status: ScanStatus;
  agent_id: Uuid | null;
  agent_name: string | null;
  progress_percent: number | null;
  attempts: number;
  lease_expires_at: Timestamp | null;
  requested_by_user_id: Uuid;
  requested_by_name: string | null;
  started_at: Timestamp | null;
  finished_at: Timestamp | null;
  error: string | null;
  hosts_discovered: number;
  findings_created: number;
  created_at: Timestamp;
}

/* ---------------------------------------------------------------- agents */

export type AgentStatus = 'active' | 'revoked';

export interface Agent {
  id: Uuid;
  name: string;
  key_prefix: string;
  status: AgentStatus;
  version: string | null;
  allowlist: string[];
  last_seen_at: Timestamp | null;
  created_at: Timestamp;
}

/**
 * `POST /agents` — the enrollment token. `token` is present exactly once, in this
 * response, and is never retrievable again (DATA-MODEL.md, `enrollment_tokens`).
 */
export interface EnrollmentToken {
  id: Uuid;
  token: string;
  expires_at: Timestamp;
  created_at: Timestamp;
}

/* ---------------------------------------------------------------- findings */

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'none'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const FINDING_STATUSES = ['open', 'accepted_risk', 'remediated', 'false_positive'] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

export type ExploitMaturity = 'weaponized' | 'poc' | 'none';

export interface Vulnerability {
  cve_id: string;
  description: string;
  cvss_base: number;
  cvss_vector: string | null;
  severity: Severity;
  kev_listed: boolean;
  kev_due_date: DateOnly | null;
  exploit_maturity: ExploitMaturity;
  published_at: Timestamp | null;
}

/** One multiplier in `findings.score_factors`. */
export interface ScoreFactor<TValue extends string = string> {
  value: TValue;
  multiplier: number;
}

/** `findings.score_factors` — the inputs, so the UI can explain the number. */
export interface ScoreFactors {
  cvss_base: number;
  exploit_maturity: ScoreFactor<ExploitMaturity>;
  exposure: ScoreFactor<Exposure>;
  asset_criticality: ScoreFactor<Criticality>;
  services_affected: string[];
}

export interface Finding {
  id: Uuid;
  asset_id: Uuid;
  asset_ip: string;
  asset_hostname: string | null;
  port_id: Uuid | null;
  port: number | null;
  protocol: string | null;
  service: string | null;
  product: string | null;
  version: string | null;
  scan_job_id: Uuid | null;
  cve_id: string;
  status: FindingStatus;
  business_risk_score: number;
  score_factors: ScoreFactors;
  severity: Severity;
  kev_listed: boolean;
  exposure: Exposure;
  services_affected: string[];
  first_seen_at: Timestamp;
  last_seen_at: Timestamp;
  resolved_at: Timestamp | null;
}

export interface FindingDetail extends Finding {
  vulnerability: Vulnerability;
}

/* ---------------------------------------------------------------- dashboards */

export type RiskBand = 'critical' | 'elevated' | 'moderate' | 'low';

export interface RiskPosture {
  score: number;
  /** Change over the trailing 30 days. Negative is an improvement. */
  trend_30d: number;
  band: RiskBand;
  /** Daily samples for the sparkline/trend chart, oldest first. */
  history: { date: DateOnly; score: number }[];
}

export interface ServiceAtRisk {
  service_id: Uuid;
  name: string;
  criticality: Criticality;
  /** numeric(14,2) as a string — see BusinessService.revenue_at_risk. */
  revenue_at_risk: string | null;
  open_findings: number;
  worst_finding_score: number;
  assets_affected: number;
}

export type ExposureSummary = Record<Exposure, number>;

export interface RemediationProgress {
  opened_30d: number;
  resolved_30d: number;
}

/** `GET /dashboard/executive`. */
export interface ExecutiveDashboard {
  risk_posture: RiskPosture;
  services_at_risk: ServiceAtRisk[];
  exposure_summary: ExposureSummary;
  kev_findings: number;
  remediation_progress: RemediationProgress;
  generated_at: Timestamp;
}

export type GraphNodeKind = 'asset' | 'service' | 'aggregate';

export interface GraphNode {
  id: Uuid;
  kind: GraphNodeKind;
  label: string;
  /** Node weight — `business_risk_score` (API.md). */
  weight: number;
  exposure: Exposure | null;
  criticality: Criticality | null;
  open_findings: number;
  /** Set on `kind: 'aggregate'` — how many real nodes this one stands in for. */
  represents: number | null;
}

export type GraphEdgeKind = 'supports' | 'exposes';

export interface GraphEdge {
  source: Uuid;
  target: Uuid;
  kind: GraphEdgeKind;
}

/** `GET /dashboard/attack-surface`. */
export interface AttackSurfaceGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  /** True when the org exceeded the 500-node cap and nodes were rolled up. */
  aggregated: boolean;
  node_cap: number;
  total_nodes: number;
}
