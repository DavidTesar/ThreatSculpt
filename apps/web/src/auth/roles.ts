import type { Role } from '@/types/domain';

/** `owner` > `admin` > `analyst` > `viewer` (ARCHITECTURE.md, "Roles"). */
const RANK: Record<Role, number> = {
  owner: 4,
  admin: 3,
  analyst: 2,
  viewer: 1,
};

export function roleRank(role: Role): number {
  return RANK[role] ?? 0;
}

/** True when `role` is at least `minimum` in the hierarchy. */
export function hasRole(role: Role | undefined, minimum: Role): boolean {
  if (!role) return false;
  return roleRank(role) >= roleRank(minimum);
}

export const ROLE_LABEL: Record<Role, string> = {
  owner: 'Owner',
  admin: 'Admin',
  analyst: 'Analyst',
  viewer: 'Viewer',
};

export const ROLE_DESCRIPTION: Record<Role, string> = {
  owner: 'Full control, including billing and transferring ownership. Cannot be removed if last.',
  admin: 'Manages users, agents, and networks. Can delete resources.',
  analyst: 'Runs scans, triages findings, and maintains the business-service mapping.',
  viewer: 'Read-only access to dashboards, findings, and assets.',
};

/**
 * The UI hides what a role cannot do, but this is presentation only — the server enforces
 * the same rules at the route layer. A hidden button is a courtesy, never a control.
 */
export const ROLE_OPTIONS = (['owner', 'admin', 'analyst', 'viewer'] as const).map((role) => ({
  value: role,
  label: ROLE_LABEL[role],
}));
