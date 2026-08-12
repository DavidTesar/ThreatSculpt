import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { PageHeader } from '@/components/layout/PageHeader';
import { Card } from '@/components/ui/Card';
import { SelectField, TextField } from '@/components/ui/Field';
import { CheckboxField } from '@/components/ui/Field';
import { Button, ButtonLink } from '@/components/ui/Button';
import { Icon } from '@/components/ui/Icon';
import { SeverityBadge } from '@/components/ui/SeverityMark';
import { ExposureBadge, FindingStatusBadge, KevBadge } from '@/components/ui/Badge';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/States';
import { Pagination, SortableHeader, TableWrap } from '@/components/ui/Table';
import { toggleSort } from '@/components/ui/sorting';
import { useFilterParams } from '@/hooks/useFilterParams';
import { findingsApi, businessServicesApi } from '@/lib/api/endpoints';
import { queryKeys } from '@/lib/api/queryKeys';
import { formatRelative, formatScore } from '@/lib/format';
import { FINDING_STATUSES, SEVERITIES } from '@/types/domain';
import { FINDING_STATUS_LABEL, SEVERITY_LABEL } from '@/lib/risk';
import type { FindingStatus, Severity } from '@/types/domain';

const DEFAULTS = {
  status: 'open',
  severity: '',
  service_id: '',
  asset_id: '',
  kev_only: '',
  sort: 'business_risk_score',
  order: 'desc',
  page: '1',
  q: '',
};

const STATUS_OPTIONS = [
  { value: '', label: 'Any status' },
  ...FINDING_STATUSES.map((status) => ({ value: status, label: FINDING_STATUS_LABEL[status] })),
];

const SEVERITY_OPTIONS = [
  { value: '', label: 'Any severity' },
  ...SEVERITIES.map((severity) => ({ value: severity, label: SEVERITY_LABEL[severity] })),
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
      sort: values.sort,
      order: values.order as 'asc' | 'desc',
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

  const sort = { key: values.sort, order: values.order as 'asc' | 'desc' };

  const handleSort = (key: string) => {
    const next = toggleSort(sort, key);
    setValue('sort', next.key);
    setValue('order', next.order);
  };

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
          <div className="toolbar__grow">
            <TextField
              label="Search"
              placeholder="Filter by CVE, host, or IP"
              value={values.q}
              onChange={(event) => setValue('q', event.target.value)}
            />
          </div>

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
                  Findings, sorted by {sort.key.replace(/_/g, ' ')} {sort.order}ending.
                </caption>
                <thead>
                  <tr>
                    <SortableHeader
                      label="Risk"
                      sortKey="business_risk_score"
                      sort={sort}
                      onSort={handleSort}
                      numeric
                      width="86px"
                    />
                    <SortableHeader
                      label="Severity"
                      sortKey="severity"
                      sort={sort}
                      onSort={handleSort}
                      width="130px"
                    />
                    <SortableHeader label="CVE" sortKey="cve_id" sort={sort} onSort={handleSort} />
                    <SortableHeader
                      label="Asset"
                      sortKey="asset_ip"
                      sort={sort}
                      onSort={handleSort}
                    />
                    <th scope="col">Business services</th>
                    <SortableHeader
                      label="Status"
                      sortKey="status"
                      sort={sort}
                      onSort={handleSort}
                      width="120px"
                    />
                    <SortableHeader
                      label="Last seen"
                      sortKey="last_seen_at"
                      sort={sort}
                      onSort={handleSort}
                      width="110px"
                    />
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
                        <SeverityBadge severity={finding.severity} />
                      </td>
                      <td>
                        <Link to={`/findings/${finding.id}`} className="rowlink mono">
                          {finding.cve_id}
                        </Link>
                        {finding.kev_listed ? (
                          <div style={{ marginTop: 4 }}>
                            <KevBadge />
                          </div>
                        ) : null}
                      </td>
                      <td>
                        <Link to={`/assets/${finding.asset_id}`} className="rowlink">
                          {finding.asset_hostname ?? finding.asset_ip}
                        </Link>
                        <div className="subtle mono" style={{ fontSize: 'var(--text-micro)' }}>
                          {finding.asset_ip}
                          {finding.port ? `:${finding.port}` : ''}
                          {finding.product ? ` · ${finding.product}` : ''}
                        </div>
                        <div style={{ marginTop: 4 }}>
                          <ExposureBadge exposure={finding.exposure} />
                        </div>
                      </td>
                      <td>
                        {finding.services_affected.length === 0 ? (
                          <span className="subtle" style={{ fontSize: 'var(--text-xs)' }}>
                            Not mapped
                          </span>
                        ) : (
                          <div className="row row--wrap" style={{ gap: 'var(--space-2xs)' }}>
                            {finding.services_affected.map((name) => (
                              <span className="chip" key={name}>
                                {name}
                              </span>
                            ))}
                          </div>
                        )}
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
