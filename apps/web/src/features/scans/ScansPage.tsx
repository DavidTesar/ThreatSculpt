import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { PageHeader } from '@/components/layout/PageHeader';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Icon } from '@/components/ui/Icon';
import { Dialog } from '@/components/ui/Dialog';
import { ScanStatusBadge } from '@/components/ui/Badge';
import { SelectField, TextField } from '@/components/ui/Field';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/States';
import { TableWrap } from '@/components/ui/Table';
import { useToast } from '@/components/ui/useToast';
import { agentsApi, networksApi, scansApi, type ScanCreate } from '@/lib/api/endpoints';
import { queryKeys } from '@/lib/api/queryKeys';
import { formatRelative } from '@/lib/format';
import { messageFor } from '@/lib/api/ApiError';
import { useAuth } from '@/auth/useAuth';
import { SCAN_PROFILES, toScanProfile, toScanStatus, type ScanProfile } from '@/types/domain';

/** Named constants only — "the API accepts a profile name, never raw nmap flags." */
const PROFILE_COPY: Record<ScanProfile, { label: string; blurb: string; duration: string }> = {
  discovery: {
    label: 'Discovery',
    blurb: 'Finds which hosts are alive. Fast, very light, no port detail.',
    duration: 'Minutes',
  },
  service: {
    label: 'Service detection',
    blurb:
      'Identifies what is running on the top 1,000 ports and fingerprints the operating system. This is the profile that produces findings.',
    duration: 'Tens of minutes',
  },
  vulnerability: {
    label: 'Full vulnerability sweep',
    blurb:
      'Every port, with aggressive version detection. Thorough, noticeably heavier on the network — schedule it deliberately.',
    duration: 'Hours',
  },
};

/** `ScanJobOut.profile` is typed `str`, so the copy table is looked up defensively. */
function profileLabel(profile: string): string {
  const narrowed = toScanProfile(profile);
  return narrowed ? PROFILE_COPY[narrowed].label : profile;
}

const schema = z.object({
  network_id: z.string().min(1, 'Choose a network to scan.'),
  target: z.string().min(1, 'Enter a target range.'),
  profile: z.enum(SCAN_PROFILES),
});

type ScanFormValues = z.infer<typeof schema>;

function LaunchScanForm({
  onSubmit,
  onCancel,
  isSubmitting,
}: {
  onSubmit: (values: ScanCreate) => void;
  onCancel: () => void;
  isSubmitting: boolean;
}) {
  const networksQuery = useQuery({
    queryKey: queryKeys.networks.list(),
    queryFn: ({ signal }) => networksApi.list(undefined, signal),
  });

  const networks = networksQuery.data?.items ?? [];
  const authorized = networks.filter((n) => n.authorized);

  const {
    register,
    handleSubmit,
    watch,
    setValue,
    formState: { errors },
  } = useForm<ScanFormValues>({
    resolver: zodResolver(schema),
    defaultValues: { network_id: '', target: '', profile: 'service' },
  });

  const selectedId = watch('network_id');
  const selectedProfile = watch('profile');
  const selected = networks.find((n) => n.id === selectedId);

  if (networksQuery.isPending) return <LoadingState label="Loading networks" rows={3} />;

  if (authorized.length === 0) {
    return (
      <EmptyState
        icon="lock"
        title="No authorized networks"
        body="A scan can only target a network you have registered and marked authorized. Nothing here is authorized yet."
        action={
          <Link to="/networks" className="btn btn--primary">
            Manage networks
          </Link>
        }
        compact
      />
    );
  }

  return (
    <form onSubmit={handleSubmit((values) => onSubmit(values))} noValidate className="stack">
      <SelectField
        label="Network"
        placeholder="Choose a network"
        options={authorized.map((n) => ({ value: n.id, label: `${n.name} — ${n.cidr}` }))}
        required
        hint={
          networks.length > authorized.length
            ? `${networks.length - authorized.length} unauthorized ${
                networks.length - authorized.length === 1 ? 'network is' : 'networks are'
              } hidden — they cannot be scanned.`
            : undefined
        }
        error={errors.network_id?.message}
        {...register('network_id', {
          onChange: (event: React.ChangeEvent<HTMLSelectElement>) => {
            const network = networks.find((n) => n.id === event.target.value);
            if (network) setValue('target', network.cidr, { shouldValidate: true });
          },
        })}
      />

      <TextField
        label="Target range"
        mono
        required
        hint={
          selected
            ? `Must sit inside ${selected.cidr}. The agent independently re-checks this against its own allowlist before running.`
            : 'Must sit inside the selected network.'
        }
        error={errors.target?.message}
        {...register('target')}
      />

      <fieldset style={{ border: 'none', padding: 0, margin: 0 }}>
        <legend className="field__label" style={{ marginBottom: 'var(--space-xs)' }}>
          Scan profile
        </legend>
        <div className="stack stack--sm">
          {SCAN_PROFILES.map((profile) => (
            <label
              key={profile}
              className="checkbox"
              style={{
                border: '1px solid var(--line)',
                borderColor: selectedProfile === profile ? 'var(--brand)' : 'var(--line)',
                background: selectedProfile === profile ? 'var(--brand-soft)' : 'transparent',
                borderRadius: 'var(--radius-md)',
                padding: 'var(--space-sm)',
                transition: 'border-color 140ms, background 140ms',
              }}
            >
              <input type="radio" value={profile} {...register('profile')} />
              <span className="checkbox__text">
                <strong>{PROFILE_COPY[profile].label}</strong>
                <span className="checkbox__desc">
                  {PROFILE_COPY[profile].blurb} Typically: {PROFILE_COPY[profile].duration}.
                </span>
              </span>
            </label>
          ))}
        </div>
      </fieldset>

      <div className="row" style={{ justifyContent: 'flex-end', marginTop: 'var(--space-xs)' }}>
        <Button variant="ghost" type="button" onClick={onCancel}>
          Cancel
        </Button>
        <Button variant="primary" type="submit" loading={isSubmitting}>
          <Icon name="scan" size={15} />
          Queue scan
        </Button>
      </div>
    </form>
  );
}

export function ScansPage() {
  const { can } = useAuth();
  const { notify } = useToast();
  const queryClient = useQueryClient();
  const [isLaunching, setIsLaunching] = useState(false);

  const query = useQuery({
    queryKey: queryKeys.scans.list(),
    queryFn: ({ signal }) => scansApi.list(undefined, signal),
    // A running scan changes state on its own; poll while any job is live.
    refetchInterval: (q) => {
      const items = q.state.data?.items ?? [];
      return items.some(
        (s) => s.status === 'running' || s.status === 'claimed' || s.status === 'queued',
      )
        ? 5000
        : false;
    },
  });

  /*
   * A scan job carries `network_id` and `agent_id`, never their names. Both are resolved
   * from the collections that own them rather than read off fields the API does not send.
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

  const networkNames = useMemo(
    () => new Map((networksQuery.data?.items ?? []).map((n) => [n.id, n.name] as const)),
    [networksQuery.data],
  );
  const agentNames = useMemo(
    () => new Map((agentsQuery.data?.items ?? []).map((a) => [a.id, a.name] as const)),
    [agentsQuery.data],
  );

  const createMutation = useMutation({
    mutationFn: (values: ScanCreate) => scansApi.create(values),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.scans.all });
      setIsLaunching(false);
      notify('Scan queued. An agent will claim it on its next poll.', 'success');
    },
    onError: (error) => notify(messageFor(error), 'error'),
  });

  return (
    <main className="main" id="main">
      <PageHeader
        eyebrow="Operate"
        title="Scans"
        lead="Scan jobs are queued here and claimed by your on-premise agents. The agents poll outbound — nothing connects inbound to your network."
        actions={
          can('analyst') ? (
            <Button variant="primary" onClick={() => setIsLaunching(true)}>
              <Icon name="scan" size={15} />
              New scan
            </Button>
          ) : null
        }
      />

      <Card>
        {query.isPending ? (
          <LoadingState label="Loading scans" />
        ) : query.error ? (
          <ErrorState error={query.error} onRetry={() => void query.refetch()} />
        ) : query.data.items.length === 0 ? (
          <EmptyState
            icon="scan"
            title="No scans yet"
            body="Queue a discovery scan against an authorized network to build your asset inventory. An enrolled agent will pick it up on its next poll."
            action={
              can('analyst') ? (
                <Button variant="primary" onClick={() => setIsLaunching(true)}>
                  Queue your first scan
                </Button>
              ) : null
            }
          />
        ) : (
          <TableWrap>
            <table className="table table--rowlink">
              <caption className="visually-hidden">Scan history, most recent first.</caption>
              <thead>
                <tr>
                  <th scope="col">Status</th>
                  <th scope="col">Target</th>
                  <th scope="col">Profile</th>
                  <th scope="col">Agent</th>
                  <th scope="col">Started</th>
                </tr>
              </thead>
              <tbody>
                {query.data.items.map((scan) => (
                  <tr key={scan.id}>
                    <td>
                      <ScanStatusBadge status={toScanStatus(scan.status)} />
                      {scan.status === 'running' &&
                      scan.progress_percent !== null &&
                      scan.progress_percent !== undefined ? (
                        <div style={{ marginTop: 6, width: 88 }}>
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
                        </div>
                      ) : null}
                    </td>
                    <td>
                      <Link to={`/scans/${scan.id}`} className="rowlink mono">
                        {scan.target}
                      </Link>
                      <div className="subtle" style={{ fontSize: 'var(--text-micro)' }}>
                        {(scan.network_id ? networkNames.get(scan.network_id) : null) ?? '—'}
                      </div>
                    </td>
                    <td>{profileLabel(scan.profile)}</td>
                    <td className="subtle mono" style={{ fontSize: 'var(--text-xs)' }}>
                      {(scan.agent_id ? agentNames.get(scan.agent_id) : null) ?? 'Awaiting claim'}
                    </td>
                    <td className="subtle" style={{ fontSize: 'var(--text-xs)' }}>
                      {scan.started_at ? formatRelative(scan.started_at) : 'Not started'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Card>

      <Dialog
        open={isLaunching}
        onClose={() => setIsLaunching(false)}
        title="Queue a scan"
        description="Only registered, authorized networks can be targeted."
        footer={null}
      >
        <LaunchScanForm
          onSubmit={(values) => createMutation.mutate(values)}
          onCancel={() => setIsLaunching(false)}
          isSubmitting={createMutation.isPending}
        />
      </Dialog>
    </main>
  );
}
