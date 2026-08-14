import { useMemo } from 'react';
import { Link } from 'react-router-dom';
import { keepPreviousData, useQuery } from '@tanstack/react-query';
import { PageHeader } from '@/components/layout/PageHeader';
import { Card } from '@/components/ui/Card';
import { SelectField, TextField } from '@/components/ui/Field';
import { Button, ButtonLink } from '@/components/ui/Button';
import { Icon } from '@/components/ui/Icon';
import { ExposureBadge } from '@/components/ui/Badge';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/States';
import { Pagination, TableWrap } from '@/components/ui/Table';
import { useFilterParams } from '@/hooks/useFilterParams';
import { assetsApi, businessServicesApi, networksApi } from '@/lib/api/endpoints';
import { queryKeys } from '@/lib/api/queryKeys';
import { formatRelative, formatScore } from '@/lib/format';
import { EXPOSURE_LABEL } from '@/lib/risk';
import { EXPOSURES, type Exposure } from '@/types/domain';

const DEFAULTS = { q: '', network_id: '', exposure: '', service_id: '', page: '1' };

const EXPOSURE_OPTIONS = [
  { value: '', label: 'Any position' },
  ...EXPOSURES.map((exposure) => ({ value: exposure, label: EXPOSURE_LABEL[exposure] })),
];

export function AssetsPage() {
  const { values, setValue, reset, activeCount } = useFilterParams(DEFAULTS);

  const networksQuery = useQuery({
    queryKey: queryKeys.networks.list(),
    queryFn: ({ signal }) => networksApi.list(undefined, signal),
    staleTime: 5 * 60_000,
  });

  const servicesQuery = useQuery({
    queryKey: queryKeys.businessServices.list(),
    queryFn: ({ signal }) => businessServicesApi.list(undefined, signal),
    staleTime: 5 * 60_000,
  });

  const filters = useMemo(
    () => ({
      q: values.q || undefined,
      network_id: values.network_id || undefined,
      exposure: (values.exposure || undefined) as Exposure | undefined,
      service_id: values.service_id || undefined,
      page: Number(values.page) || 1,
      per_page: 50,
    }),
    [values],
  );

  const query = useQuery({
    queryKey: queryKeys.assets.list(filters),
    queryFn: ({ signal }) => assetsApi.list(filters, signal),
    placeholderData: keepPreviousData,
  });

  // `AssetOut` carries `network_id`, never a network name, so the name is resolved from
  // the networks this page already loads for its filter rather than invented on the row.
  const networkNames = useMemo(() => {
    const entries = (networksQuery.data?.items ?? []).map((n) => [n.id, n.name] as const);
    return new Map<string, string>(entries);
  }, [networksQuery.data]);

  return (
    <main className="main" id="main">
      <PageHeader
        eyebrow="Investigate"
        title="Assets"
        lead="Every host discovered on your networks, and the business services each one supports."
      />

      <Card>
        <div className="toolbar">
          <div className="toolbar__grow">
            <TextField
              label="Search"
              placeholder="Hostname or IP address"
              value={values.q}
              onChange={(event) => setValue('q', event.target.value)}
            />
          </div>

          <SelectField
            label="Network"
            options={[
              { value: '', label: 'Any network' },
              ...(networksQuery.data?.items ?? []).map((n) => ({ value: n.id, label: n.name })),
            ]}
            value={values.network_id}
            onChange={(event) => setValue('network_id', event.target.value)}
          />

          <SelectField
            label="Network position"
            options={EXPOSURE_OPTIONS}
            value={values.exposure}
            onChange={(event) => setValue('exposure', event.target.value)}
          />

          <SelectField
            label="Business service"
            options={[
              { value: '', label: 'Any service' },
              ...(servicesQuery.data?.items ?? []).map((s) => ({ value: s.id, label: s.name })),
            ]}
            value={values.service_id}
            onChange={(event) => setValue('service_id', event.target.value)}
          />

          {activeCount > 0 ? (
            <Button variant="ghost" size="sm" onClick={reset} style={{ marginBottom: 4 }}>
              <Icon name="close" size={13} />
              Clear
            </Button>
          ) : null}
        </div>

        {query.isPending ? (
          <LoadingState label="Loading assets" rows={8} />
        ) : query.error ? (
          <ErrorState error={query.error} onRetry={() => void query.refetch()} />
        ) : query.data.items.length === 0 ? (
          <EmptyState
            icon="assets"
            title={activeCount > 0 ? 'No assets match these filters' : 'No assets discovered yet'}
            body={
              activeCount > 0
                ? 'Nothing on your estate matches this combination of filters.'
                : 'Register a network, mark it authorized, and run a discovery scan. Anything that answers will appear here.'
            }
            action={
              activeCount > 0 ? (
                <Button variant="secondary" onClick={reset}>
                  Clear filters
                </Button>
              ) : (
                <ButtonLink to="/networks" variant="primary">
                  Register a network
                </ButtonLink>
              )
            }
          />
        ) : (
          <>
            <TableWrap>
              <table className="table table--rowlink">
                <caption className="visually-hidden">Assets, highest business risk first.</caption>
                <thead>
                  <tr>
                    <th scope="col">Host</th>
                    <th scope="col">Network</th>
                    <th scope="col">Position</th>
                    <th scope="col">Operating system</th>
                    <th scope="col">Business services</th>
                    <th scope="col" className="table__num">
                      Open findings
                    </th>
                    <th scope="col" className="table__num">
                      Top risk
                    </th>
                    <th scope="col">Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {query.data.items.map((asset) => (
                    <tr key={asset.id}>
                      <td>
                        <Link to={`/assets/${asset.id}`} className="rowlink">
                          {asset.hostname ?? asset.ip}
                        </Link>
                        <div className="subtle mono" style={{ fontSize: 'var(--text-micro)' }}>
                          {asset.ip}
                        </div>
                      </td>
                      <td className="subtle" style={{ fontSize: 'var(--text-xs)' }}>
                        {(asset.network_id ? networkNames.get(asset.network_id) : null) ?? '—'}
                      </td>
                      <td>
                        <ExposureBadge exposure={asset.exposure} />
                      </td>
                      <td className="subtle" style={{ fontSize: 'var(--text-xs)' }}>
                        {asset.os_family ? `${asset.os_family} ${asset.os_version ?? ''}` : '—'}
                      </td>
                      <td>
                        {(asset.services ?? []).length === 0 ? (
                          <span className="chip" style={{ color: 'var(--warn)' }}>
                            <Icon name="alert" size={10} />
                            Not mapped
                          </span>
                        ) : (
                          <div className="row row--wrap" style={{ gap: 'var(--space-2xs)' }}>
                            {(asset.services ?? []).map((service) => (
                              <span className="chip" key={service.id}>
                                {service.name}
                              </span>
                            ))}
                          </div>
                        )}
                      </td>
                      <td className="table__num">{asset.open_findings}</td>
                      <td className="table__num">
                        <strong>{formatScore(asset.worst_finding_score)}</strong>
                      </td>
                      <td className="subtle" style={{ fontSize: 'var(--text-xs)' }}>
                        {formatRelative(asset.last_seen_at)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>

            <Pagination
              meta={query.data.meta}
              onPageChange={(page) => setValue('page', String(page))}
              itemLabel="assets"
            />
          </>
        )}
      </Card>
    </main>
  );
}
