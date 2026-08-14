import { Link, useParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { PageHeader } from '@/components/layout/PageHeader';
import { Card, CardBody, CardHead } from '@/components/ui/Card';
import { AsyncBoundary } from '@/components/ui/States';
import { ScanStatusBadge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Icon } from '@/components/ui/Icon';
import { useToast } from '@/components/ui/useToast';
import { agentsApi, networksApi, scansApi } from '@/lib/api/endpoints';
import { queryKeys } from '@/lib/api/queryKeys';
import { formatDateTime, formatRelative } from '@/lib/format';
import { messageFor } from '@/lib/api/ApiError';
import { useAuth } from '@/auth/useAuth';
import { toScanStatus, type ScanStatus } from '@/types/domain';

const LIVE_STATUSES: readonly ScanStatus[] = ['queued', 'claimed', 'running'];

/** `ScanJobOut.status` is typed `str`, so it is narrowed before it is compared. */
function isLiveStatus(status: string | undefined): boolean {
  const narrowed = toScanStatus(status);
  return narrowed !== null && LIVE_STATUSES.includes(narrowed);
}

export function ScanDetailPage() {
  const { id = '' } = useParams();
  const { can } = useAuth();
  const { notify } = useToast();
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: queryKeys.scans.detail(id),
    queryFn: ({ signal }) => scansApi.get(id, signal),
    enabled: id !== '',
    refetchInterval: (q) => (isLiveStatus(q.state.data?.status) ? 4000 : false),
  });

  /*
   * `ScanJobOut` carries `network_id` and `agent_id`, never their names. Both are resolved
   * from the resources that own them rather than read off a field the API does not send.
   */
  const networksQuery = useQuery({
    queryKey: queryKeys.networks.list(),
    queryFn: ({ signal }) => networksApi.list(undefined, signal),
    staleTime: 5 * 60_000,
  });
  const agentsQuery = useQuery({
    queryKey: queryKeys.agents.list(),
    queryFn: ({ signal }) => agentsApi.list(undefined, signal),
    staleTime: 5 * 60_000,
  });

  const scan = query.data;
  const networkName = scan?.network_id
    ? (networksQuery.data?.items.find((n) => n.id === scan.network_id)?.name ?? null)
    : null;
  const agentName = scan?.agent_id
    ? (agentsQuery.data?.items.find((a) => a.id === scan.agent_id)?.name ?? null)
    : null;

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
          const status = toScanStatus(scan.status);
          const isLive = isLiveStatus(scan.status);
          return (
            <>
              <PageHeader
                eyebrow={<Link to="/scans">← Scans</Link>}
                title={scan.target}
                lead={`${scan.profile} scan${networkName ? ` of ${networkName}` : ''}`}
                actions={
                  <div className="row">
                    <ScanStatusBadge status={status} />
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
                {/*
                  `ScanJobOut` carries no result counts — no `hosts_discovered`, no
                  `findings_created`. The two metrics that used to sit here rendered "—"
                  on every scan. Progress, attempts and the lease are what the job
                  actually reports.
                */}
                <div className="metric">
                  <p className="metric__label">Progress</p>
                  <p className="metric__value">
                    {scan.progress_percent === null || scan.progress_percent === undefined
                      ? '—'
                      : `${scan.progress_percent}%`}
                  </p>
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
                    <dd>{networkName ?? '—'}</dd>

                    <dt>Profile</dt>
                    <dd>{scan.profile}</dd>

                    <dt>Agent</dt>
                    <dd className="mono">{agentName ?? 'Not yet claimed'}</dd>

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
