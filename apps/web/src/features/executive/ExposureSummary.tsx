import { Link } from 'react-router-dom';
import { Card, CardHead, CardBody } from '@/components/ui/Card';
import { ChartTable } from '@/components/charts/ChartTable';
import { EXPOSURE_GLOSS, EXPOSURE_LABEL, EXPOSURE_ORDER } from '@/lib/risk';
import { formatNumber, formatPercent } from '@/lib/format';
import type { ExposureSummary as ExposureSummaryData } from '@/types/domain';

/**
 * Where the estate sits relative to the outside world.
 *
 * A stacked proportion bar rather than a pie: the comparison that matters is "how much of
 * this is internet-facing", which is a length judgement, and lengths are read far more
 * accurately than angles. Each segment is also labelled and patterned, so the split is
 * legible without relying on the colour ramp.
 */
export function ExposureSummary({ summary }: { summary: ExposureSummaryData }) {
  const total = EXPOSURE_ORDER.reduce((sum, key) => sum + summary[key], 0);

  if (total === 0) {
    return (
      <Card as="section" aria-labelledby="exposure-heading">
        <CardHead titleId="exposure-heading" title="Exposure" subtitle="Where your assets sit." />
        <CardBody>
          <p className="muted">
            No assets have been discovered yet. Run a discovery scan to populate your inventory.
          </p>
        </CardBody>
      </Card>
    );
  }

  return (
    <Card as="section" aria-labelledby="exposure-heading">
      <CardHead
        titleId="exposure-heading"
        title="Exposure"
        subtitle={`${formatNumber(total)} assets by network position.`}
      />
      <CardBody>
        <div
          className="expbar"
          role="img"
          aria-label={EXPOSURE_ORDER.map(
            (key) =>
              `${EXPOSURE_LABEL[key]}: ${summary[key]} assets, ${formatPercent(
                (summary[key] / total) * 100,
              )}`,
          ).join('. ')}
        >
          {EXPOSURE_ORDER.filter((key) => summary[key] > 0).map((key) => (
            <span
              key={key}
              className={`expbar__seg expbar__seg--${key}`}
              style={{ flexGrow: summary[key] }}
            />
          ))}
        </div>

        <ul className="explegend">
          {EXPOSURE_ORDER.map((key) => (
            <li key={key} className="explegend__item">
              <span className={`explegend__swatch expbar__seg--${key}`} aria-hidden="true" />
              <span className="explegend__text">
                <Link to={`/assets?exposure=${key}`} className="explegend__label">
                  {EXPOSURE_LABEL[key]}
                </Link>
                <span className="explegend__gloss">{EXPOSURE_GLOSS[key]}</span>
              </span>
              <span className="explegend__count" data-numeric>
                {formatNumber(summary[key])}
              </span>
            </li>
          ))}
        </ul>

        <ChartTable
          summary="View exposure as a table"
          headers={['Position', 'Assets', 'Share']}
          rows={EXPOSURE_ORDER.map((key) => [
            EXPOSURE_LABEL[key],
            summary[key],
            formatPercent((summary[key] / total) * 100, 1),
          ])}
        />
      </CardBody>
    </Card>
  );
}
