import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { PageHeader } from '@/components/layout/PageHeader';
import { Card } from '@/components/ui/Card';
import { SelectField } from '@/components/ui/Field';
import { CheckboxField } from '@/components/ui/Field';
import { Button, ButtonLink } from '@/components/ui/Button';
import { Icon } from '@/components/ui/Icon';
import { SeverityBadge } from '@/components/ui/SeverityMark';
import { Badge, ExposureBadge, FindingStatusBadge, KevBadge } from '@/components/ui/Badge';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/States';
import { Pagination, TableWrap } from '@/components/ui/Table';
import { useFilterParams } from '@/hooks/useFilterParams';
import { findingsApi, businessServicesApi } from '@/lib/api/endpoints';
import { queryKeys } from '@/lib/api/queryKeys';
import { formatRelative, formatScore } from '@/lib/format';
import { FINDING_STATUSES, SEVERITIES } from '@/types/domain';
import {
  FINDING_STATUS_LABEL,
  MATCH_CONFIDENCE_LABEL,
  MATCH_CONFIDENCE_TONE,
  SEVERITY_LABEL,
} from '@/lib/risk';
import { toExposure, toSeverity } from '@/types/domain';
import type { FindingStatus, MatchConfidence, Severity } from '@/types/domain';

/*
 * Only filters `/findings` actually accepts.
 *
 * `q`, `sort` and `order` used to live here and were sent on every request; the endpoint
 * has never read any of them, so the search box filtered nothing and the sortable headers
 * reordered nothing. Results come back sorted by business risk, descending, which is the
 * product's whole ordering claim — see API.md, "sort by `business_risk_score` desc
 * default".
 */
const DEFAULTS = {
  status: 'open',
  severity: '',
  service_id: '',
  asset_id: '',
  kev_only: '',
  min_confidence: '',
  page: '1',
};

const STATUS_OPTIONS = [
  { value: '', label: 'Any status' },
  ...FINDING_STATUSES.map((status) => ({ value: status, label: FINDING_STATUS_LABEL[status] })),
];

const SEVERITY_OPTIONS = [
  { value: '', label: 'Any severity' },
  ...SEVERITIES.map((severity) => ({ value: severity, label: SEVERITY_LABEL[severity] })),
];

/**
 * "Show me only what you are sure about" is the first question a sceptical analyst asks,
 * and the API answers it — this filter is `min_confidence`, which the client never sent.
 */
const CONFIDENCE_OPTIONS = [
  { value: '', label: 'Any confidence' },
  { value: 'high', label: 'High only' },
  { value: 'medium', label: 'Medium and above' },
  { value: 'low', label: 'Low and above' },
];

export function FindingsPage() {
  const { values, setValue, reset, activeCount } = useFilterParams(DEFAULTS);

  const servicesQuery = useQuery({
    queryKey: queryKeys.businessServices.list(),
    queryFn: ({ signal }) => businessServicesApi.list(undefined, signal),
    staleTime: 5 * 60_000,
  });

  const filters = useMemo(
    () => ({
      status: (values.status || undefined) as FindingStatus | undefined,
      severity: (values.severity || undefined) as Severity | undefined,
      service_id: values.service_id || undefined,
      asset_id: values.asset_id || undefined,
      kev_only: values.kev_only === 'true' ? true : undefined,
      min_confidence: (values.min_confidence || undefined) as MatchConfidence | undefined,
      page: Number(values.page) || 1,
      per_page: 50,
    }),
    [values],
  );

  const query = useQuery({
    queryKey: queryKeys.findings.list(filters),
    queryFn: ({ signal }) => findingsApi.list(filters, signal),
    // Keeps the previous page visible while the next loads, so sorting a long table does
    // not flash an empty body and shift the layout.
    placeholderData: keepPreviousData,
  });

  const serviceOptions = [
    { value: '', label: 'Any service' },
    ...(servicesQuery.data?.items ?? []).map((service) => ({
      value: service.id,
      label: service.name,
    })),
  ];

  return (
    <main className="main" id="main">
      <PageHeader
        eyebrow="Investigate"
        title="Findings"
        lead="Every vulnerability observed on your estate, ranked by what it threatens rather than by severity alone."
      />

      <Card>
        <div className="toolbar">
          <SelectField
            label="Status"
            options={STATUS_OPTIONS}
            value={values.status}
            onChange={(event) => setValue('status', event.target.value)}
          />

          <SelectField
            label="Severity"
            options={SEVERITY_OPTIONS}
            value={values.severity}
            onChange={(event) => setValue('severity', event.target.value)}
          />

          <SelectField
            label="Business service"
            options={serviceOptions}
            value={values.service_id}
            onChange={(event) => setValue('service_id', event.target.value)}
          />

          <SelectField
            label="Match confidence"
            options={CONFIDENCE_OPTIONS}
            value={values.min_confidence}
            onChange={(event) => setValue('min_confidence', event.target.value)}
          />

          <div style={{ paddingBottom: 8 }}>
            <CheckboxField
              label="Known exploited only"
              checked={values.kev_only === 'true'}
              onChange={(event) => setValue('kev_only', event.target.checked ? 'true' : '')}
            />
          </div>

          {activeCount > 0 ? (
            <Button variant="ghost" size="sm" onClick={reset} style={{ marginBottom: 4 }}>
              <Icon name="close" size={13} />
              Clear filters
            </Button>
          ) : null}
        </div>

        {query.isPending ? (
          <LoadingState label="Loading findings" rows={8} />
        ) : query.error ? (
          <ErrorState error={query.error} onRetry={() => void query.refetch()} />
        ) : query.data.items.length === 0 ? (
          <EmptyState
            icon="search"
            title={activeCount > 0 ? 'No findings match these filters' : 'No findings yet'}
            body={
              activeCount > 0
                ? 'Try widening the filters — for example, setting status to “Any status” to include findings your team has already resolved.'
                : 'Once a vulnerability scan completes, anything it finds will appear here ranked by business risk.'
            }
            action={
              activeCount > 0 ? (
                <Button variant="secondary" onClick={reset}>
                  Clear filters
                </Button>
              ) : (
                <ButtonLink to="/scans" variant="primary">
                  Run a scan
                </ButtonLink>
              )
            }
          />
        ) : (
          <>
            <TableWrap>
              <table className="table table--rowlink">
                <caption className="visually-hidden">
                  Findings, highest business risk first.
                </caption>
                <thead>
                  <tr>
                    <th scope="col" className="table__num" style={{ width: '86px' }}>
                      Risk
                    </th>
                    <th scope="col" style={{ width: '130px' }}>
                      Severity
                    </th>
                    <th scope="col">CVE</th>
                    <th scope="col">Asset</th>
                    <th scope="col" style={{ width: '110px' }}>
                      Match
                    </th>
                    <th scope="col" style={{ width: '120px' }}>
                      Status
                    </th>
                    <th scope="col" style={{ width: '110px' }}>
                      Last seen
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {query.data.items.map((finding) => (
                    <tr key={finding.id}>
                      <td className="table__num">
                        <strong style={{ fontSize: 'var(--text-base)' }}>
                          {formatScore(finding.business_risk_score)}
                        </strong>
                      </td>
                      <td>
                        <SeverityBadge severity={toSeverity(finding.cve.severity)} />
                      </td>
                      <td>
                        <Link to={`/findings/${finding.id}`} className="rowlink mono">
                          {finding.cve.cve_id}
                        </Link>
                        {finding.cve.kev_listed ? (
                          <div style={{ marginTop: 4 }}>
                            <KevBadge />
                          </div>
                        ) : null}
                      </td>
                      <td>
                        <Link to={`/assets/${finding.asset.id}`} className="rowlink">
                          {finding.asset.hostname ?? finding.asset.ip}
                        </Link>
                        <div className="subtle mono" style={{ fontSize: 'var(--text-micro)' }}>
                          {finding.asset.ip}
                        </div>
                        <div style={{ marginTop: 4 }}>
                          <ExposureBadge exposure={toExposure(finding.asset.exposure)} />
                        </div>
                      </td>
                      <td>
                        <Badge tone={MATCH_CONFIDENCE_TONE[finding.match.confidence]}>
                          {MATCH_CONFIDENCE_LABEL[finding.match.confidence]}
                        </Badge>
                      </td>
                      <td>
                        <FindingStatusBadge status={finding.status} />
                      </td>
                      <td className="subtle" style={{ fontSize: 'var(--text-xs)' }}>
                        {formatRelative(finding.last_seen_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>

            <Pagination
              meta={query.data.meta}
              onPageChange={(page) => setValue('page', String(page))}
              itemLabel="findings"
            />
          </>
        )}
      </Card>
    </main>
  );
}
