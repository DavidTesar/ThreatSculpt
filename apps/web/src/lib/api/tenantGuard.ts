/**
 * API.md rule 1: "The org is never in the request. There is no `userID`, `orgId`, or
 * `tenant` parameter in any body, path, or query string. A request that contains one is
 * a bug."
 *
 * The backend rejecting such a parameter is the real enforcement. This is a development
 * tripwire so the bug surfaces here, loudly, at the call site that introduced it, rather
 * than as a silently ignored field.
 */

const FORBIDDEN_KEYS = [
  'org_id',
  'orgid',
  'organization_id',
  'organisation_id',
  'tenant',
  'tenant_id',
  'tenantid',
  'user_id',
  'userid',
  'account_id',
];

/** Keys that legitimately name a *related resource* rather than the calling principal. */
const ALLOWED_EXACT = new Set([
  'requested_by_user_id',
  'created_by_user_id',
  'used_by_agent_id',
  'asset_id',
  'network_id',
  'service_id',
  'agent_id',
  'port_id',
  'scan_job_id',
  'business_service_id',
]);

export class TenantParameterError extends Error {
  constructor(key: string, where: string) {
    super(
      `Refusing to send "${key}" in the ${where}: the org is derived from the authenticated ` +
        `principal, never from the request (docs/API.md rule 1).`,
    );
    this.name = 'TenantParameterError';
  }
}

function checkKey(key: string, where: string): void {
  const normalized = key.toLowerCase();
  if (ALLOWED_EXACT.has(normalized)) return;
  if (FORBIDDEN_KEYS.includes(normalized)) {
    throw new TenantParameterError(key, where);
  }
}

export function assertNoTenantParams(value: unknown, where: string, depth = 0): void {
  if (depth > 6 || value === null || typeof value !== 'object') return;

  if (Array.isArray(value)) {
    for (const entry of value) assertNoTenantParams(entry, where, depth + 1);
    return;
  }

  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    checkKey(key, where);
    assertNoTenantParams(entry, where, depth + 1);
  }
}

export function assertNoTenantSearchParams(params: URLSearchParams): void {
  for (const key of params.keys()) checkKey(key, 'query string');
}
