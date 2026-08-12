import type { ReactNode } from 'react';
import { Icon } from './Icon';
import { Button } from './Button';
import type { SortState } from './sorting';
import type { PaginationMeta } from '@/lib/api/envelope';

export interface SortableHeaderProps {
  label: string;
  sortKey: string;
  sort: SortState;
  onSort: (key: string) => void;
  numeric?: boolean;
  width?: string;
}

/**
 * A sortable column header.
 *
 * `aria-sort` on the `<th>` is what tells a screen reader the table is sorted and in which
 * direction; the arrow glyph alone conveys that to sighted users only.
 */
export function SortableHeader({
  label,
  sortKey,
  sort,
  onSort,
  numeric,
  width,
}: SortableHeaderProps) {
  const isActive = sort.key === sortKey;
  const ariaSort = isActive ? (sort.order === 'asc' ? 'ascending' : 'descending') : 'none';

  return (
    <th
      scope="col"
      aria-sort={ariaSort}
      className={numeric ? 'table__num' : undefined}
      style={{ width }}
    >
      <button
        type="button"
        className="table__sort"
        data-active={isActive}
        onClick={() => onSort(sortKey)}
      >
        {label}
        <Icon
          name={isActive ? (sort.order === 'asc' ? 'arrow-up' : 'arrow-down') : 'sort'}
          size={12}
          className="table__sorticon"
        />
        <span className="visually-hidden">
          {isActive
            ? `, sorted ${sort.order === 'asc' ? 'ascending' : 'descending'}. Activate to reverse.`
            : ', not sorted. Activate to sort.'}
        </span>
      </button>
    </th>
  );
}

export interface PaginationProps {
  meta: PaginationMeta;
  onPageChange: (page: number) => void;
  itemLabel?: string;
}

export function Pagination({ meta, onPageChange, itemLabel = 'results' }: PaginationProps) {
  const totalPages = Math.max(1, Math.ceil(meta.total / Math.max(1, meta.per_page)));
  const first = meta.total === 0 ? 0 : (meta.page - 1) * meta.per_page + 1;
  const last = Math.min(meta.total, meta.page * meta.per_page);

  return (
    <nav className="pagination" aria-label="Pagination">
      <span aria-live="polite">
        {meta.total === 0
          ? `No ${itemLabel}`
          : `${first.toLocaleString()}–${last.toLocaleString()} of ${meta.total.toLocaleString()} ${itemLabel}`}
      </span>
      <div className="pagination__controls">
        <Button
          size="sm"
          variant="secondary"
          onClick={() => onPageChange(meta.page - 1)}
          disabled={meta.page <= 1}
        >
          <Icon name="arrow-left" size={13} />
          Previous
        </Button>
        <span style={{ padding: '0 var(--space-xs)' }}>
          Page {meta.page} of {totalPages}
        </span>
        <Button
          size="sm"
          variant="secondary"
          onClick={() => onPageChange(meta.page + 1)}
          disabled={meta.page >= totalPages}
        >
          Next
          <Icon name="arrow-right" size={13} />
        </Button>
      </div>
    </nav>
  );
}

export function TableWrap({ children }: { children: ReactNode }) {
  return <div className="tablewrap">{children}</div>;
}
