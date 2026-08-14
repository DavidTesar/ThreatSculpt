import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { PageHeader } from '@/components/layout/PageHeader';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Icon } from '@/components/ui/Icon';
import { AuthorizedBadge } from '@/components/ui/Badge';
import { Dialog } from '@/components/ui/Dialog';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/States';
import { TableWrap } from '@/components/ui/Table';
import { useToast } from '@/components/ui/useToast';
import { NetworkForm } from './NetworkForm';
import { networksApi, type NetworkCreate } from '@/lib/api/endpoints';
import { queryKeys } from '@/lib/api/queryKeys';
import { messageFor } from '@/lib/api/ApiError';
import { useAuth } from '@/auth/useAuth';
import type { Network } from '@/types/domain';

export function NetworksPage() {
  const { can } = useAuth();
  const { notify } = useToast();
  const queryClient = useQueryClient();

  const [editing, setEditing] = useState<Network | null>(null);
  const [isCreating, setIsCreating] = useState(false);
  const [deleting, setDeleting] = useState<Network | null>(null);

  const query = useQuery({
    queryKey: queryKeys.networks.list(),
    queryFn: ({ signal }) => networksApi.list(undefined, signal),
  });

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: queryKeys.networks.all });
    void queryClient.invalidateQueries({ queryKey: queryKeys.dashboard.all });
  };

  const createMutation = useMutation({
    mutationFn: (values: NetworkCreate) => networksApi.create(values),
    onSuccess: () => {
      invalidate();
      setIsCreating(false);
      notify('Network added.', 'success');
    },
    onError: (error) => notify(messageFor(error), 'error'),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, values }: { id: string; values: NetworkCreate }) =>
      networksApi.update(id, values),
    onSuccess: () => {
      invalidate();
      setEditing(null);
      notify('Network updated.', 'success');
    },
    onError: (error) => notify(messageFor(error), 'error'),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => networksApi.remove(id),
    onSuccess: () => {
      invalidate();
      setDeleting(null);
      notify('Network removed.', 'success');
    },
    onError: (error) => notify(messageFor(error), 'error'),
  });

  const unauthorizedCount = (query.data?.items ?? []).filter((n) => !n.authorized).length;

  return (
    <main className="main" id="main">
      <PageHeader
        eyebrow="Operate"
        title="Networks"
        lead="The address ranges ThreatSculpt is permitted to scan. Nothing outside a registered, authorized range can be targeted."
        actions={
          can('analyst') ? (
            <Button variant="primary" onClick={() => setIsCreating(true)}>
              <Icon name="plus" size={15} />
              Add network
            </Button>
          ) : null
        }
      />

      {unauthorizedCount > 0 ? (
        <div className="alert alert--warn" style={{ marginBottom: 'var(--space-lg)' }}>
          <Icon name="lock" size={16} className="alert__icon" />
          <div>
            <p className="alert__title">
              {unauthorizedCount} {unauthorizedCount === 1 ? 'network is' : 'networks are'} not
              authorized for scanning
            </p>
            <p style={{ fontSize: 'var(--text-xs)' }}>
              Assets inside these ranges will not be scanned and any scan targeting them is refused.
              Authorize a network only once you have written permission to test it.
            </p>
          </div>
        </div>
      ) : null}

      <Card>
        {query.isPending ? (
          <LoadingState label="Loading networks" />
        ) : query.error ? (
          <ErrorState error={query.error} onRetry={() => void query.refetch()} />
        ) : query.data.items.length === 0 ? (
          <EmptyState
            icon="network"
            title="No networks registered"
            body="Register the address ranges your organisation owns. ThreatSculpt refuses to scan anything outside them, which is what keeps a misconfiguration from turning into an incident."
            action={
              can('analyst') ? (
                <Button variant="primary" onClick={() => setIsCreating(true)}>
                  <Icon name="plus" size={15} />
                  Add your first network
                </Button>
              ) : null
            }
          />
        ) : (
          <TableWrap>
            <table className="table">
              <caption className="visually-hidden">Registered networks.</caption>
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">CIDR</th>
                  <th scope="col">Scanning</th>
                  <th scope="col">Authorization record</th>
                  {can('analyst') ? (
                    <th scope="col">
                      <span className="visually-hidden">Actions</span>
                    </th>
                  ) : null}
                </tr>
              </thead>
              <tbody>
                {query.data.items.map((network) => (
                  <tr key={network.id}>
                    <td>
                      <strong>{network.name}</strong>
                    </td>
                    <td className="mono">{network.cidr}</td>
                    <td>
                      <AuthorizedBadge authorized={network.authorized} />
                    </td>
                    <td className="subtle" style={{ fontSize: 'var(--text-xs)', maxWidth: '32ch' }}>
                      {network.authorization_note ?? (
                        <em>{network.authorized ? 'No record captured' : '—'}</em>
                      )}
                    </td>
                    {can('analyst') ? (
                      <td>
                        <div className="row" style={{ justifyContent: 'flex-end' }}>
                          <Button size="sm" variant="ghost" onClick={() => setEditing(network)}>
                            Edit
                          </Button>
                          {can('admin') ? (
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => setDeleting(network)}
                              aria-label={`Delete ${network.name}`}
                            >
                              <Icon name="trash" size={14} />
                            </Button>
                          ) : null}
                        </div>
                      </td>
                    ) : null}
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
        title="Add a network"
        description="Register an address range you own or are contracted to test."
        footer={null}
      >
        <NetworkForm
          onSubmit={(values) => createMutation.mutate(values)}
          onCancel={() => setIsCreating(false)}
          isSubmitting={createMutation.isPending}
        />
      </Dialog>

      <Dialog
        open={editing !== null}
        onClose={() => setEditing(null)}
        title="Edit network"
        footer={null}
      >
        {editing ? (
          <NetworkForm
            initial={editing}
            onSubmit={(values) => updateMutation.mutate({ id: editing.id, values })}
            onCancel={() => setEditing(null)}
            isSubmitting={updateMutation.isPending}
          />
        ) : null}
      </Dialog>

      <Dialog
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        title="Remove this network?"
        description={
          deleting
            ? `${deleting.name} (${deleting.cidr}) will no longer be scannable. Assets already discovered inside it are kept.`
            : undefined
        }
        footer={
          <>
            <Button variant="ghost" onClick={() => setDeleting(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              loading={deleteMutation.isPending}
              onClick={() => deleting && deleteMutation.mutate(deleting.id)}
            >
              Remove network
            </Button>
          </>
        }
      />
    </main>
  );
}
