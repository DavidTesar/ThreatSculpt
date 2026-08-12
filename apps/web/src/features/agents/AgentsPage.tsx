import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { PageHeader } from '@/components/layout/PageHeader';
import { Card } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Icon } from '@/components/ui/Icon';
import { Dialog } from '@/components/ui/Dialog';
import { TextField } from '@/components/ui/Field';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/States';
import { TableWrap } from '@/components/ui/Table';
import { useToast } from '@/components/ui/useToast';
import { EnrollmentTokenDialog } from './EnrollmentTokenDialog';
import { agentsApi } from '@/lib/api/endpoints';
import { queryKeys } from '@/lib/api/queryKeys';
import { formatRelative } from '@/lib/format';
import { messageFor } from '@/lib/api/ApiError';
import type { Agent, EnrollmentToken } from '@/types/domain';

const schema = z.object({
  name: z
    .string()
    .min(3, 'Give the agent a name you will recognise on the host it runs on.')
    .max(80)
    .regex(/^[a-zA-Z0-9._-]+$/, 'Use letters, numbers, dots, dashes, and underscores only.'),
});

type AgentFormValues = z.infer<typeof schema>;

/** An agent that has not checked in recently is probably dead, so say so plainly. */
const STALE_AFTER_MS = 10 * 60_000;

function HealthBadge({ agent }: { agent: Agent }) {
  if (agent.status === 'revoked') return <Badge tone="neutral">Revoked</Badge>;
  if (!agent.last_seen_at) return <Badge tone="warn">Never checked in</Badge>;

  const age = Date.now() - new Date(agent.last_seen_at).getTime();
  if (age > STALE_AFTER_MS) return <Badge tone="danger">Not responding</Badge>;
  return (
    <Badge tone="ok">
      <Icon name="check" size={11} />
      Healthy
    </Badge>
  );
}

export function AgentsPage() {
  const { notify } = useToast();
  const queryClient = useQueryClient();

  const [isCreating, setIsCreating] = useState(false);
  const [issuedToken, setIssuedToken] = useState<EnrollmentToken | null>(null);
  const [issuedFor, setIssuedFor] = useState('');
  const [revoking, setRevoking] = useState<Agent | null>(null);

  const query = useQuery({
    queryKey: queryKeys.agents.list(),
    queryFn: ({ signal }) => agentsApi.list(signal),
  });

  const {
    register,
    handleSubmit,
    reset: resetForm,
    formState: { errors },
  } = useForm<AgentFormValues>({
    resolver: zodResolver(schema),
    defaultValues: { name: '' },
  });

  const createMutation = useMutation({
    mutationFn: (values: AgentFormValues) => agentsApi.issueEnrollmentToken(values),
    onSuccess: (token, values) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.agents.all });
      setIsCreating(false);
      resetForm();
      setIssuedFor(values.name);
      setIssuedToken(token);
    },
    onError: (error) => notify(messageFor(error), 'error'),
  });

  const revokeMutation = useMutation({
    mutationFn: (id: string) => agentsApi.revoke(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.agents.all });
      setRevoking(null);
      notify('Agent revoked. It will shut down on its next heartbeat.', 'success');
    },
    onError: (error) => notify(messageFor(error), 'error'),
  });

  return (
    <main className="main" id="main">
      <PageHeader
        eyebrow="Operate"
        title="Scan agents"
        lead="The daemons installed on your network that run the scans. They poll outbound only and never accept an inbound connection, so no firewall ports need opening."
        actions={
          <Button variant="primary" onClick={() => setIsCreating(true)}>
            <Icon name="plus" size={15} />
            Enroll agent
          </Button>
        }
      />

      <Card>
        {query.isPending ? (
          <LoadingState label="Loading agents" />
        ) : query.error ? (
          <ErrorState error={query.error} onRetry={() => void query.refetch()} />
        ) : query.data.items.length === 0 ? (
          <EmptyState
            icon="agent"
            title="No agents enrolled"
            body="An agent is a small service you install on a host inside your network. It claims scan jobs, runs nmap, and posts results back — all over outbound HTTPS. Nothing can be scanned until at least one is enrolled."
            action={
              <Button variant="primary" onClick={() => setIsCreating(true)}>
                Enroll your first agent
              </Button>
            }
          />
        ) : (
          <TableWrap>
            <table className="table">
              <caption className="visually-hidden">Enrolled scan agents.</caption>
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">Health</th>
                  <th scope="col">Key</th>
                  <th scope="col">Version</th>
                  <th scope="col">Allowlist</th>
                  <th scope="col">Last seen</th>
                  <th scope="col">
                    <span className="visually-hidden">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {query.data.items.map((agent) => (
                  <tr key={agent.id}>
                    <td>
                      <strong>{agent.name}</strong>
                    </td>
                    <td>
                      <HealthBadge agent={agent} />
                    </td>
                    <td className="mono subtle" style={{ fontSize: 'var(--text-xs)' }}>
                      {agent.key_prefix}…
                    </td>
                    <td className="subtle" style={{ fontSize: 'var(--text-xs)' }}>
                      {agent.version ?? '—'}
                    </td>
                    <td>
                      {agent.allowlist.length === 0 ? (
                        <span className="subtle" style={{ fontSize: 'var(--text-xs)' }}>
                          None
                        </span>
                      ) : (
                        <div className="row row--wrap" style={{ gap: 'var(--space-2xs)' }}>
                          {agent.allowlist.map((cidr) => (
                            <span className="chip mono" key={cidr}>
                              {cidr}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="subtle" style={{ fontSize: 'var(--text-xs)' }}>
                      {formatRelative(agent.last_seen_at)}
                    </td>
                    <td>
                      {agent.status === 'active' ? (
                        <div className="row" style={{ justifyContent: 'flex-end' }}>
                          <Button size="sm" variant="ghost" onClick={() => setRevoking(agent)}>
                            Revoke
                          </Button>
                        </div>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Card>

      <Dialog
        open={isCreating}
        onClose={() => setIsCreating(false)}
        title="Enroll a new agent"
        description="You will be given a one-time enrollment token to configure on the scanner host."
        footer={null}
      >
        <form
          onSubmit={handleSubmit((values) => createMutation.mutate(values))}
          noValidate
          className="stack"
        >
          <TextField
            label="Agent name"
            placeholder="hq-dc-scanner-01"
            mono
            required
            hint="Usually the hostname it will run on. Shown in scan history so you can tell which agent ran what."
            error={errors.name?.message}
            {...register('name')}
          />

          <div className="row" style={{ justifyContent: 'flex-end' }}>
            <Button variant="ghost" type="button" onClick={() => setIsCreating(false)}>
              Cancel
            </Button>
            <Button variant="primary" type="submit" loading={createMutation.isPending}>
              Issue enrollment token
            </Button>
          </div>
        </form>
      </Dialog>

      <EnrollmentTokenDialog
        token={issuedToken}
        agentName={issuedFor}
        onClose={() => setIssuedToken(null)}
      />

      <Dialog
        open={revoking !== null}
        onClose={() => setRevoking(null)}
        title="Revoke this agent?"
        description={
          revoking
            ? `${revoking.name} will be told to shut down and delete its stored key on its next heartbeat. Any scan it is running will return to the queue when its lease expires. This cannot be undone — enrolling it again means issuing a new token.`
            : undefined
        }
        footer={
          <>
            <Button variant="ghost" onClick={() => setRevoking(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              loading={revokeMutation.isPending}
              onClick={() => revoking && revokeMutation.mutate(revoking.id)}
            >
              Revoke agent
            </Button>
          </>
        }
      />
    </main>
  );
}
