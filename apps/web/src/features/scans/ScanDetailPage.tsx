import { Link, useParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { PageHeader } from '@/components/layout/PageHeader';
import { Card, CardBody, CardHead } from '@/components/ui/Card';
import { AsyncBoundary } from '@/components/ui/States';
import { ScanStatusBadge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Icon } from '@/components/ui/Icon';
import { useToast } from '@/components/ui/useToast';
import { scansApi } from '@/lib/api/endpoints';
import { queryKeys } from '@/lib/api/queryKeys';
import { formatDateTime, formatNumber, formatRelative } from '@/lib/format';
import { messageFor } from '@/lib/api/ApiError';
import { useAuth } from '@/auth/useAuth';

const LIVE_STATUSES = ['queued', 'claimed', 'running'];

export function ScanDetailPage() {
  const { id = '' } = useParams();
  const { can } = useAuth();
  const { notify } = useToast();
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: queryKeys.scans.detail(id),
    queryFn: ({ signal }) => scansApi.get(id, signal),
    enabled: id !== '',
    refetchInterval: (q) =>
      q.state.data && LIVE_STATUSES.includes(q.state.data.status) ? 4000 : false,
  });

  const cancelMutation = useMutation({
    mutationFn: () => scansApi.cancel(id),
    onSuccess: (updated) => {
      queryClient.setQueryData(queryKeys.scans.detail(id), updated);
      void queryClient.invalidateQueries({ queryKey: queryKeys.scans.all });
      notify('Scan cancelled.', 'success');
    },
    onError: (error) => notify(messageFor(error), 'error'),
  });

  return (
    <main className="main" id="main">
      <AsyncBoundary
        isLoading={query.isPending}
        error={query.error}
        data={query.data}
        onRetry={() => void query.refetch()}
        loadingLabel="Loading scan"
      >
        {(scan) => {
          const isLive = LIVE_STATUSES.includes(scan.status);
          return (
            <>
              <PageHeader
                eyebrow={<Link to="/scans">← Scans</Link>}
                title={scan.target}
                lead={`${scan.profile} scan of ${scan.network_name}`}
                actions={
                  <div className="row">
                    <ScanStatusBadge status={scan.status} />
                    {can('analyst') && isLive ? (
                      <Button
                        variant="secondary"
                        loading={cancelMutation.isPending}
                        onClick={() => cancelMutation.mutate()}
                      >
                        Cancel scan
                      </Button>
                    ) : null}
                  </div>
                }
              />

              {scan.status === 'running' && scan.progress_percent !== null ? (
                <Card style={{ marginBottom: 'var(--space-lg)' }}>
                  <CardBody>
                    <div className="row row--between" style={{ marginBottom: 'var(--space-xs)' }}>
                      <strong>Scan in progress</strong>
                      <span data-numeric>{scan.progress_percent}%</span>
                    </div>
                    <div
                      className="progressbar"
                      role="progressbar"
                      aria-valuenow={scan.progress_percent}
                      aria-valuemin={0}
                      aria-valuemax={100}
                      aria-label="Scan progress"
                    >
                      <div
                        className="progressbar__fill"
                        style={{ width: `${scan.progress_percent}%` }}
                      />
                    </div>
                    <p className="subtle" style={{ fontSize: 'var(--text-xs)', marginTop: 8 }}>
                      This page updates automatically while the scan runs.
                    </p>
                  </CardBody>
                </Card>
              ) : null}

              {scan.error ? (
                <div className="alert alert--danger" style={{ marginBottom: 'var(--space-lg)' }}>
                  <Icon name="alert" size={16} className="alert__icon" />
                  <div>
                    <p className="alert__title">This scan failed</p>
                    <p style={{ fontSize: 'var(--text-xs)' }}>{scan.error}</p>
                  </div>
                </div>
              ) : null}

              <div className="metricgrid" style={{ marginBottom: 'var(--space-lg)' }}>
                <div className="metric">
                  <p className="metric__label">Hosts discovered</p>
                  <p className="metric__value">{formatNumber(scan.hosts_discovered)}</p>
                </div>
                <div className="metric">
                  <p className="metric__label">Findings created</p>
                  <p className="metric__value">{formatNumber(scan.findings_created)}</p>
                </div>
                <div className="metric">
                  <p className="metric__label">Attempts</p>
                  <p className="metric__value">{scan.attempts}</p>
                  <p className="metric__hint">Maximum 3 before the job is failed.</p>
                </div>
              </div>

              <Card as="section" aria-labelledby="scan-facts">
                <CardHead titleId="scan-facts" title="Job detail" />
                <CardBody>
                  <dl className="deflist">
                    <dt>Target</dt>
                    <dd className="mono">{scan.target}</dd>

                    <dt>Network</dt>
                    <dd>{scan.network_name}</dd>

                    <dt>Profile</dt>
                    <dd>{scan.profile}</dd>

                    <dt>Agent</dt>
                    <dd>{scan.agent_name ?? 'Not yet claimed'}</dd>

                    {scan.lease_expires_at ? (
                      <>
                        <dt>Lease expires</dt>
                        <dd>
                          {formatRelative(scan.lease_expires_at)}
                          <span className="subtle">
                            {' '}
                            — the job returns to the queue if the agent stops reporting.
                          </span>
                        </dd>
                      </>
                    ) : null}

                    <dt>Requested by</dt>
                    <dd>{scan.requested_by_name ?? '—'}</dd>

                    <dt>Queued</dt>
                    <dd>{formatDateTime(scan.created_at)}</dd>

                    <dt>Started</dt>
                    <dd>{scan.started_at ? formatDateTime(scan.started_at) : 'Not started'}</dd>

                    <dt>Finished</dt>
                    <dd>{scan.finished_at ? formatDateTime(scan.finished_at) : '—'}</dd>
                  </dl>
                </CardBody>
              </Card>
            </>
          );
        }}
      </AsyncBoundary>
    </main>
  );
}
