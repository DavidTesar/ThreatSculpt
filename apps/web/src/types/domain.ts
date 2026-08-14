/**
 * The domain vocabulary, derived from the control plane's OpenAPI schema.
 *
 * Nothing here restates a response shape. Every object type is an alias for a
 * generated one in `@/lib/api/schema.gen`, so a field the backend renames, drops,
 * or retypes breaks this build instead of arriving as `undefined` in front of a
 * customer. Aliases exist only to give the generated names the vocabulary the UI
 * speaks in (`Asset`, not `AssetOut`) and to keep feature code out of
 * `components['schemas']`.
 *
 * Regenerate with `npm run openapi` after any control-plane change. CI fails when
 * the committed schema or the generated types differ from what regeneration
 * produces — see .github/workflows/ci.yml, "API contract".
 */

import type { components } from '@/lib/api/schema.gen';

type Schemas = components['schemas'];

/* ---------------------------------------------------------------- primitives */

export type Uuid = string;
/** ISO-8601 timestamp. */
export type Timestamp = string;
/** ISO-8601 date (no time component). */
export type DateOnly = string;

/**
 * A PostgreSQL `numeric` as it actually crosses the wire: a decimal *string*.
 *
 * The control plane serialises `Decimal` rather than `float`, so scores and money
 * arrive as `"94.50"`, not `94.5`. Parse for display (`parseDecimal` in
 * `@/lib/format`); never assume arithmetic works on one directly.
 */
export type DecimalString = string;

/**
 * Compile-time proof that a runtime list enumerates its whole union.
 *
 * `ListCovers<Exposure, (typeof EXPOSURES)[number]>` fails to resolve when the
 * backend enum gains a value the list omits, so a new `Exposure` breaks the build
 * rather than quietly disappearing from a filter dropdown.
 */
export type ListCovers<TUnion extends TListed, TListed extends string> = Extract<TListed, TUnion>;

/* ---------------------------------------------------------------- enumerations */

/*
 * These five are declared as enums in the backend schema, so the generated type is
 * the exact literal union. The unions further down are not: the control plane types
 * those fields as bare `str`, and the narrowing helpers at the end of this file are
 * how that imprecision is handled rather than assumed away.
 */

export type Exposure = Schemas['Exposure'];
export type Criticality = Schemas['Criticality'];
export type FindingStatus = Schemas['FindingStatus'];
export type ScanProfile = Schemas['ScanProfile'];
export type ScanStatus = Schemas['ScanStatus'];
/** How sure the CPE matcher was that a CVE applies to an observed service. */
export type MatchConfidence = Schemas['MatchConfidence'];

/** Most exposed first — drives filter, chart and legend ordering. */
export const EXPOSURES = [
  'internet',
  'dmz',
  'internal',
  'isolated',
] as const satisfies readonly Exposure[];
export type ExposureListIsComplete = ListCovers<Exposure, (typeof EXPOSURES)[number]>;

export const CRITICALITIES = [
  'critical',
  'high',
  'medium',
  'low',
] as const satisfies readonly Criticality[];
export type CriticalityListIsComplete = ListCovers<Criticality, (typeof CRITICALITIES)[number]>;

export const FINDING_STATUSES = [
  'open',
  'accepted_risk',
  'remediated',
  'false_positive',
] as const satisfies readonly FindingStatus[];
export type FindingStatusListIsComplete = ListCovers<
  FindingStatus,
  (typeof FINDING_STATUSES)[number]
>;

export const SCAN_PROFILES = [
  'discovery',
  'service',
  'vulnerability',
] as const satisfies readonly ScanProfile[];
export type ScanProfileListIsComplete = ListCovers<ScanProfile, (typeof SCAN_PROFILES)[number]>;

export const SCAN_STATUSES = [
  'queued',
  'claimed',
  'running',
  'completed',
  'failed',
  'cancelled',
] as const satisfies readonly ScanStatus[];
export type ScanStatusListIsComplete = ListCovers<ScanStatus, (typeof SCAN_STATUSES)[number]>;

/* ------------------------------------------------ unions the backend types as `str` */

/*
 * Each of these is a *client-side refinement* of a field the schema declares as a
 * plain string. They are narrower than the contract on purpose — the UI has to
 * switch on them to pick a label, a glyph or a colour — so every one of them is
 * reached through a `to…()` helper below, which returns `null` for a value the
 * backend adds without telling us. Widening a union here would be a lie; assuming
 * one would be the runtime bug this module exists to prevent.
 */

export const ROLES = ['owner', 'admin', 'analyst', 'viewer'] as const;
export type Role = (typeof ROLES)[number];

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'none'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const RISK_BANDS = ['critical', 'elevated', 'moderate', 'low'] as const;
export type RiskBand = (typeof RISK_BANDS)[number];

/** `vulnerabilities.exploit_maturity`. */
export const EXPLOIT_MATURITIES = ['weaponized', 'poc', 'none'] as const;
export type ExploitMaturity = (typeof EXPLOIT_MATURITIES)[number];

/**
 * `score_factors.exploit_maturity.value` — the scoring ladder, not the CVE column.
 * KEV listing outranks every maturity tier, so scoring resolves the two into one
 * scale with an extra rung the CVE record itself never carries.
 */
export const MATURITY_TIERS = ['kev_listed', 'weaponized', 'poc', 'none'] as const;
export type MaturityTier = (typeof MATURITY_TIERS)[number];

/**
 * `score_factors.asset_criticality.value`. `unmapped` is not a business-service
 * criticality: it is what an asset supporting no service resolves to, recorded
 * honestly rather than borrowed from `medium`.
 */
export const CRITICALITY_TIERS = ['critical', 'high', 'medium', 'low', 'unmapped'] as const;
export type CriticalityTier = (typeof CRITICALITY_TIERS)[number];

export const ORG_PLANS = ['trial', 'standard', 'enterprise'] as const;
export type OrgPlan = (typeof ORG_PLANS)[number];

export const USER_STATUSES = ['active', 'disabled'] as const;
export type UserStatus = (typeof USER_STATUSES)[number];

export const AGENT_STATUSES = ['active', 'revoked'] as const;
export type AgentStatus = (typeof AGENT_STATUSES)[number];

/** Node kinds in the attack-surface graph, as the control plane emits them. */
export const GRAPH_NODE_KINDS = [
  'asset',
  'business_service',
  'exposure',
  'aggregated_assets',
] as const;
export type GraphNodeKind = (typeof GRAPH_NODE_KINDS)[number];

export const GRAPH_EDGE_KINDS = ['supports', 'exposes'] as const;
export type GraphEdgeKind = (typeof GRAPH_EDGE_KINDS)[number];

/* ---------------------------------------------------------------- identity */

export type Org = Schemas['OrgSummary'];
export type User = Schemas['UserSummary'];
/** The user directory row — adds the lockout and verification state an admin needs. */
export type AdminUser = Schemas['UserAdminSummary'];
/** Payload of `GET /auth/me`. The role lives on `user`, not beside it. */
export type CurrentPrincipal = Schemas['MeResponse'];
export type VerificationState = Schemas['VerificationStateResponse'];
export type PasswordReset = Schemas['PasswordResetResponse'];

/* ---------------------------------------------------------------- inventory */

export type Network = Schemas['NetworkOut'];
export type BusinessService = Schemas['BusinessServiceOut'];
/** A business service as it appears on an asset — id, name, criticality only. */
export type AssetServiceRef = Schemas['ServiceLink'];
export type Asset = Schemas['AssetOut'];
/**
 * `GET /assets/{id}` returns the same shape as the list. There is no detail
 * variant and no port inventory in the API.
 */
export type AssetDetail = Asset;
/** The asset as embedded in a finding: identity only, no inventory detail. */
export type AssetRef = Schemas['AssetSummary'];

/* ---------------------------------------------------------------- scanning */

export type ScanJob = Schemas['ScanJobOut'];

/* ---------------------------------------------------------------- agents */

export type Agent = Schemas['AgentOut'];
/**
 * `POST /agents` — the enrollment token. The secret is `enrollment_token`, is
 * present exactly once, in this response, and is never retrievable again.
 */
export type EnrollmentToken = Schemas['EnrollmentTokenOut'];

/* ---------------------------------------------------------------- findings */

/** The CVE reference data attached to a finding. */
export type Cve = Schemas['CveSummary'];
/** How the CVE was attached to the observed service, and how sure the matcher was. */
export type FindingMatch = Schemas['MatchSummary'];
export type Finding = Schemas['FindingOut'];
export type FindingDetail = Schemas['FindingDetail'];

/* ---------------------------------------------------------------- dashboards */

export type RiskPosture = Schemas['RiskPosture'];
export type ServiceAtRisk = Schemas['ServiceAtRisk'];
export type ExposureSummary = Schemas['ExposureSummary'];
export type RemediationProgress = Schemas['RemediationProgress'];
export type ExecutiveDashboard = Schemas['ExecutiveDashboard'];
export type GraphNode = Schemas['GraphNode'];
export type GraphEdge = Schemas['GraphEdge'];
export type AttackSurfaceGraph = Schemas['AttackSurface'];

/* ---------------------------------------------------------------- narrowing */

/**
 * Builds a narrowing function for one of the refinement unions above.
 *
 * Returns `null` rather than a default for an unrecognised value: a value the
 * backend added is something the UI genuinely does not know how to render, and
 * silently showing it as "none" or "low" would understate a customer's risk.
 */
function narrowTo<TUnion extends string>(
  members: readonly TUnion[],
): (value: string | null | undefined) => TUnion | null {
  const allowed: ReadonlySet<string> = new Set(members);
  return (value) =>
    value !== null && value !== undefined && allowed.has(value) ? (value as TUnion) : null;
}

export const toRole = narrowTo(ROLES);
export const toSeverity = narrowTo(SEVERITIES);
export const toRiskBand = narrowTo(RISK_BANDS);
export const toExploitMaturity = narrowTo(EXPLOIT_MATURITIES);
export const toMaturityTier = narrowTo(MATURITY_TIERS);
export const toCriticalityTier = narrowTo(CRITICALITY_TIERS);
export const toExposure = narrowTo(EXPOSURES);
export const toCriticality = narrowTo(CRITICALITIES);
export const toScanStatus = narrowTo(SCAN_STATUSES);
export const toScanProfile = narrowTo(SCAN_PROFILES);
export const toAgentStatus = narrowTo(AGENT_STATUSES);
export const toUserStatus = narrowTo(USER_STATUSES);
export const toOrgPlan = narrowTo(ORG_PLANS);
export const toGraphNodeKind = narrowTo(GRAPH_NODE_KINDS);
export const toGraphEdgeKind = narrowTo(GRAPH_EDGE_KINDS);
