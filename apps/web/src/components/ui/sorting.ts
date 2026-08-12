export type SortOrder = 'asc' | 'desc';

export interface SortState {
  key: string;
  order: SortOrder;
}

/**
 * Clicking a new column starts it at its natural order (descending for scores, so the
 * worst is on top); clicking the active column reverses it.
 */
export function toggleSort(
  current: SortState,
  key: string,
  defaultOrder: SortOrder = 'desc',
): SortState {
  if (current.key !== key) return { key, order: defaultOrder };
  return { key, order: current.order === 'asc' ? 'desc' : 'asc' };
}
