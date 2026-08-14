import { Link } from 'react-router-dom';
import { Card, CardHead, CardBody } from '@/components/ui/Card';
import { CriticalityMeter } from '@/components/ui/SeverityMark';
import { EmptyState } from '@/components/ui/States';
import { Icon } from '@/components/ui/Icon';
import {
  formatCurrency,
  formatCurrencyCompact,
  formatNumber,
  formatScore,
  parseDecimal,
  pluralize,
} from '@/lib/format';
import { toCriticality, type ServiceAtRisk } from '@/types/domain';

/**
 * The screen that justifies the product.
 *
 * Ranked by revenue at risk, not by CVSS — "that ordering is the product" (API.md). Each
 * row leads with the money and the service name; the technical score is present but
 * subordinate, because it is the supporting evidence rather than the headline.
 *
 * Rendered as a ranked list rather than a dense table so it reads like a briefing.
 */
export function ServicesAtRisk({ services }: { services: ServiceAtRisk[] }) {
  const totalRevenue = services.reduce((sum, s) => sum + (parseDecimal(s.revenue_at_risk) ?? 0), 0);

  return (
    <Card as="section" aria-labelledby="services-at-risk-heading">
      <CardHead
        titleId="services-at-risk-heading"
        title="Services at risk"
        subtitle={
          services.length > 0
            ? `Ranked by revenue exposed. ${formatCurrency(totalRevenue)} across ${
                services.length
              } ${pluralize(services.length, 'service')}.`
            : 'Ranked by revenue exposed.'
        }
      />
      <CardBody flush>
        {services.length === 0 ? (
          <EmptyState
            icon="shield"
            title="No business service is currently exposed"
            body="Every open finding sits on an asset that is not mapped to a business service, or there are no open findings at all. If that seems wrong, check that your assets are mapped to the services they support."
            compact
          />
        ) : (
          <ol className="ranklist">
            {services.map((service, index) => (
              <li key={service.service_id} className="ranklist__item">
                <span className="ranklist__rank" aria-hidden="true">
                  {index + 1}
                </span>

                <div className="ranklist__main">
                  <Link
                    to={`/findings?service_id=${service.service_id}&status=open`}
                    className="ranklist__name"
                  >
                    {service.name}
                    <Icon name="arrow-right" size={13} />
                  </Link>
                  <div className="ranklist__meta">
                    <CriticalityMeter criticality={toCriticality(service.criticality)} />
                    <span className="subtle">·</span>
                    <span>
                      {formatNumber(service.open_findings)} open{' '}
                      {pluralize(service.open_findings, 'finding')}
                    </span>
                    <span className="subtle">·</span>
                    <span>
                      {formatNumber(service.assets_affected)}{' '}
                      {pluralize(service.assets_affected, 'asset')} affected
                    </span>
                  </div>
                </div>

                <div className="ranklist__money">
                  {service.revenue_at_risk ? (
                    <>
                      <span
                        className="ranklist__amount"
                        data-numeric
                        title={formatCurrency(service.revenue_at_risk)}
                      >
                        {formatCurrencyCompact(service.revenue_at_risk)}
                      </span>
                      <span className="ranklist__amountlabel">revenue at risk</span>
                    </>
                  ) : (
                    <>
                      <span className="ranklist__amount ranklist__amount--none">Not costed</span>
                      <span className="ranklist__amountlabel">
                        <Link to="/business-services">add a figure</Link>
                      </span>
                    </>
                  )}
                </div>

                <div className="ranklist__score">
                  <span className="ranklist__scorevalue" data-numeric>
                    {formatScore(service.worst_finding_score)}
                  </span>
                  <span className="ranklist__scorelabel">worst finding</span>
                </div>
              </li>
            ))}
          </ol>
        )}
      </CardBody>
    </Card>
  );
}
