import type { AssetFilters, FindingFilters } from './endpoints';
import type { Uuid } from '@/types/domain';

/**
 * Every cache key in one place. Prefixes are hierarchical so a mutation can invalidate a
 * whole family (`queryKeys.findings.all`) without enumerating every filter combination.
 */
export const queryKeys = {
  me: ['me'] as const,

  dashboard: {
    all: ['dashboard'] as const,
    executive: ['dashboard', 'executive'] as const,
    attackSurface: ['dashboard', 'attack-surface'] as const,
  },

  findings: {
    all: ['findings'] as const,
    list: (filters: FindingFilters) => ['findings', 'list', filters] as const,
    detail: (id: Uuid) => ['findings', 'detail', id] as const,
  },

  assets: {
    all: ['assets'] as const,
    list: (filters: AssetFilters) => ['assets', 'list', filters] as const,
    detail: (id: Uuid) => ['assets', 'detail', id] as const,
  },

  networks: {
    all: ['networks'] as const,
    list: () => ['networks', 'list'] as const,
  },

  businessServices: {
    all: ['business-services'] as const,
    list: () => ['business-services', 'list'] as const,
  },

  scans: {
    all: ['scans'] as const,
    list: (status?: string) => ['scans', 'list', status ?? 'all'] as const,
    detail: (id: Uuid) => ['scans', 'detail', id] as const,
  },

  agents: {
    all: ['agents'] as const,
    list: () => ['agents', 'list'] as const,
  },

  users: {
    all: ['users'] as const,
    list: () => ['users', 'list'] as const,
  },
} as const;
