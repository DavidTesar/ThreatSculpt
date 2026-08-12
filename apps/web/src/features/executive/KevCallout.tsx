import { Link } from 'react-router-dom';
import { Icon } from '@/components/ui/Icon';
import { formatNumber, pluralize } from '@/lib/format';

/**
 * CISA's Known Exploited Vulnerabilities catalogue lists flaws being used in real attacks
 * right now. That distinction — "exploitable in theory" versus "being exploited today" —
 * is the one an executive actually needs, so it gets a dedicated callout above the fold
 * rather than a column in a table.
 */
export function KevCallout({ count }: { count: number }) {
  if (count === 0) {
    return (
      <div className="kev kev--clear">
        <Icon name="shield" size={20} className="kev__icon" />
        <div>
          <p className="kev__title">No known-exploited vulnerabilities</p>
          <p className="kev__body">
            Nothing in your estate currently matches CISA&apos;s Known Exploited Vulnerabilities
            catalogue. This is the single best indicator that you are not exposed to attacks
            happening in the wild today.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="kev kev--alert" role="alert">
      <Icon name="alert" size={20} className="kev__icon" />
      <div>
        <p className="kev__title">
          {formatNumber(count)} known-exploited{' '}
          {pluralize(count, 'vulnerability', 'vulnerabilities')}
        </p>
        <p className="kev__body">
          These appear in CISA&apos;s catalogue of vulnerabilities being actively exploited in real
          attacks — not theoretical risk. US federal agencies are given a binding deadline to fix
          these; treat them as your shortest queue.
        </p>
        <Link to="/findings?kev_only=true&status=open" className="kev__link">
          Review them
          <Icon name="arrow-right" size={13} />
        </Link>
      </div>
    </div>
  );
}
