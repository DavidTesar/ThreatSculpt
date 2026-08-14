import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { PageHeader } from '@/components/layout/PageHeader';
import { Card, CardBody, CardHead } from '@/components/ui/Card';
import { AsyncBoundary, EmptyState } from '@/components/ui/States';
import { ExposureBadge } from '@/components/ui/Badge';
import { SeverityBadge } from '@/components/ui/SeverityMark';
import { Button } from '@/components/ui/Button';
import { CheckboxField } from '@/components/ui/Field';
import { TableWrap } from '@/components/ui/Table';
import { useToast } from '@/components/ui/useToast';
import { assetsApi, businessServicesApi, findingsApi, networksApi } from '@/lib/api/endpoints';
import { queryKeys } from '@/lib/api/queryKeys';
import { formatDateTime, formatRelative, formatScore } from '@/lib/format';
import { messageFor } from '@/lib/api/ApiError';
import { useAuth } from '@/auth/useAuth';
import { MATCH_CONFIDENCE_LABEL } from '@/lib/risk';
import { toSeverity, type AssetDetail } from '@/types/domain';

/**
 * Mapping an asset to the business services it supports.
 *
 * This is the mapping layer the whole product rests on (ARCHITECTURE.md: "This mapping is
 * what turns 'CVE-2021-44228 on 10.0.4.12' into 'Payment processing is exposed.'"), so it
 * gets a first-class editor rather than being buried in a settings screen.
 */
function ServiceMapping({ asset }: { asset: AssetDetail }) {
  const { can } = useAuth();
  const { notify } = useToast();
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<string[]>(() => (asset.services ?? []).map((s) => s.id));

  // Re-sync when the server's copy changes underneath us (e.g. after a refetch).
  useEffect(() => {
    setSelected((asset.services ?? []).map((s) => s.id));
  }, [asset.services]);

  const servicesQuery = useQuery({
    queryKey: queryKeys.businessServices.list(),
    queryFn: ({ signal }) => businessServicesApi.list(undefined, signal),
  });

  const mutation = useMutation({
    mutationFn: (ids: string[]) => assetsApi.setServices(asset.id, ids),
    onSuccess: (updated) => {
      queryClient.setQueryData(queryKeys.assets.detail(asset.id), updated);
      void queryClient.invalidateQueries({ queryKey: queryKeys.assets.all });
      void queryClient.invalidateQueries({ queryKey: queryKeys.dashboard.all });
      void queryClient.invalidateQueries({ queryKey: queryKeys.findings.all });
      notify(
        'Service mapping updated. Risk scores will reflect it on the next refresh.',
        'success',
      );
    },
    onError: (error) => notify(messageFor(error), 'error'),
  });

  const current = (asset.services ?? [])
    .map((s) => s.id)
    .sort()
    .join(',');
  const pending = [...selected].sort().join(',');
  const isDirty = current !== pending;

  const toggle = (id: string, checked: boolean) => {
    // Immutable update — never splice the existing array.
    setSelected((ids) => (checked ? [...ids, id] : ids.filter((entry) => entry !== id)));
  };

  const services = servicesQuery.data?.items ?? [];

  return (
    <Card as="section" aria-labelledby="mapping-heading">
      <CardHead
        titleId="mapping-heading"
        title="Business services"
        subtitle="What this host supports. This is what turns a CVE into a business consequence."
        as="h2"
      />
      <CardBody>
        {services.length === 0 ? (
          <EmptyState
            icon="service"
            title="No business services defined"
            body="Define the services your organisation depends on, then map assets to them."
            compact
          />
        ) : (
          <>
            <fieldset style={{ border: 'none', padding: 0, margin: 0 }}>
              <legend className="visually-hidden">Business services this asset supports</legend>
              <div className="stack stack--sm">
                {services.map((service) => (
                  <CheckboxField
                    key={service.id}
                    label={service.name}
                    description={`${service.criticality} criticality`}
                    checked={selected.includes(service.id)}
                    disabled={!can('analyst') || mutation.isPending}
                    onChange={(event) => toggle(service.id, event.target.checked)}
                  />
                ))}
              </div>
            </fieldset>

            {can('analyst') ? (
              <Button
                variant="primary"
                fullWidth
                style={{ marginTop: 'var(--space-md)' }}
                disabled={!isDirty}
                loading={mutation.isPending}
                onClick={() => mutation.mutate(selected)}
              >
                {isDirty ? 'Save mapping' : 'Mapping saved'}
              </Button>
            ) : (
              <p
                className="subtle"
                style={{ fontSize: 'var(--text-xs)', marginTop: 'var(--space-md)' }}
              >
                Analyst role or above is required to change this mapping.
              </p>
            )}
          </>
        )}
      </CardBody>
    </Card>
  );
}

export function AssetDetailPage() {
  const { id = '' } = useParams();

  const query = useQuery({
    queryKey: queryKeys.assets.detail(id),
    queryFn: ({ signal }) => assetsApi.get(id, signal),
    enabled: id !== '',
  });

  const findingsQuery = useQuery({
    queryKey: queryKeys.findings.list({ asset_id: id, per_page: 100 }),
    queryFn: ({ signal }) => findingsApi.list({ asset_id: id, per_page: 100 }, signal),
    enabled: id !== '',
  });

  // The asset carries `network_id`; the name lives on the network resource.
  const networksQuery = useQuery({
    queryKey: queryKeys.networks.list(),
    queryFn: ({ signal }) => networksApi.list(undefined, signal),
    staleTime: 5 * 60_000,
  });
  const networkId = query.data?.network_id;
  const networkName = networkId
    ? (networksQuery.data?.items.find((n) => n.id === networkId)?.name ?? null)
    : null;

  return (
    <main className="main" id="main">
      <AsyncBoundary
        isLoading={query.isPending}
        error={query.error}
        data={query.data}
        onRetry={() => void query.refetch()}
        loadingLabel="Loading asset"
      >
        {(asset) => (
          <>
            <PageHeader
              eyebrow={<Link to="/assets">← Assets</Link>}
              title={asset.hostname ?? asset.ip}
              lead={
                <span className="mono" style={{ fontSize: 'var(--text-sm)' }}>
                  {asset.ip}
                  {asset.mac ? ` · ${asset.mac}` : ''}
                </span>
              }
              actions={<ExposureBadge exposure={asset.exposure} />}
            />

            <div className="detail">
              <div className="stack stack--lg">
                <Card as="section" aria-labelledby="asset-findings-heading">
                  <CardHead
                    titleId="asset-findings-heading"
                    title="Findings on this asset"
                    subtitle={
                      findingsQuery.data ? `${findingsQuery.data.meta.total} in total.` : undefined
                    }
                  />
                  <CardBody flush>
                    {findingsQuery.isPending ? (
                      <p className="card__body muted">Loading findings…</p>
                    ) : findingsQuery.data && findingsQuery.data.items.length > 0 ? (
                      <TableWrap>
                        <table className="table table--rowlink">
                          <caption className="visually-hidden">
                            Findings on this asset, highest risk first.
                          </caption>
                          <thead>
                            <tr>
                              <th scope="col" className="table__num">
                                Risk
                              </th>
                              <th scope="col">Severity</th>
                              <th scope="col">CVE</th>
                              <th scope="col">Match</th>
                              <th scope="col">Status</th>
                            </tr>
                          </thead>
                          <tbody>
                            {findingsQuery.data.items.map((finding) => (
                              <tr key={finding.id}>
                                <td className="table__num">
                                  <strong>{formatScore(finding.business_risk_score)}</strong>
                                </td>
                                <td>
                                  <SeverityBadge severity={toSeverity(finding.cve.severity)} />
                                </td>
                                <td>
                                  <Link to={`/findings/${finding.id}`} className="rowlink mono">
                                    {finding.cve.cve_id}
                                  </Link>
                                </td>
                                <td className="subtle" style={{ fontSize: 'var(--text-xs)' }}>
                                  {MATCH_CONFIDENCE_LABEL[finding.match.confidence]}
                                </td>
                                <td className="subtle" style={{ fontSize: 'var(--text-xs)' }}>
                                  {finding.status.replace(/_/g, ' ')}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </TableWrap>
                    ) : (
                      <EmptyState
                        icon="shield"
                        title="No findings on this asset"
                        body="Nothing the enrichment step matched against this host's observed software."
                        compact
                      />
                    )}
                  </CardBody>
                </Card>
              </div>

              <div className="stack stack--lg">
                <ServiceMapping asset={asset} />

                <Card as="section" aria-labelledby="asset-facts-heading">
                  <CardHead titleId="asset-facts-heading" title="Details" as="h2" />
                  <CardBody>
                    <dl className="deflist">
                      <dt>Network</dt>
                      <dd>{networkName ?? '—'}</dd>

                      <dt>IP address</dt>
                      <dd className="mono">{asset.ip}</dd>

                      <dt>MAC</dt>
                      <dd className="mono">{asset.mac ?? '—'}</dd>

                      <dt>Operating system</dt>
                      <dd>
                        {asset.os_family
                          ? `${asset.os_family} ${asset.os_version ?? ''}`.trim()
                          : 'Not fingerprinted'}
                      </dd>

                      <dt>Position</dt>
                      <dd>
                        <ExposureBadge exposure={asset.exposure} />
                      </dd>

                      <dt>Open findings</dt>
                      <dd>{asset.open_findings}</dd>

                      <dt>First seen</dt>
                      <dd>{formatDateTime(asset.first_seen_at)}</dd>

                      <dt>Last seen</dt>
                      <dd>{formatRelative(asset.last_seen_at)}</dd>
                    </dl>
                  </CardBody>
                </Card>
              </div>
            </div>
          </>
        )}
      </AsyncBoundary>
    </main>
  );
}
