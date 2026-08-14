import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { PageHeader } from '@/components/layout/PageHeader';
import { Card, CardBody, CardHead } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Icon } from '@/components/ui/Icon';
import { Dialog } from '@/components/ui/Dialog';
import { SelectField, TextField } from '@/components/ui/Field';
import { ErrorState, LoadingState } from '@/components/ui/States';
import { TableWrap } from '@/components/ui/Table';
import { useToast } from '@/components/ui/useToast';
import { usersApi } from '@/lib/api/endpoints';
import { queryKeys } from '@/lib/api/queryKeys';
import { formatRelative, initialsFor } from '@/lib/format';
import { messageFor } from '@/lib/api/ApiError';
import { ROLE_DESCRIPTION, ROLE_LABEL, ROLE_OPTIONS } from '@/auth/roles';
import { useAuth } from '@/auth/useAuth';
import { ROLES, toRole, type AdminUser, type Role } from '@/types/domain';

/**
 * `POST /users` mints the account outright and **requires a password** — there is no
 * invitation-email flow behind it, and this form used to send no password at all. The
 * admin sets an initial credential and passes it on; the new account starts unverified,
 * exactly like a self-service sign-up.
 */
const schema = z.object({
  full_name: z.string().min(2, 'Enter their full name.').max(120),
  email: z.string().min(1, 'Enter their email address.').email('Enter a valid email address.'),
  role: z.enum(ROLES),
  password: z
    .string()
    .min(12, 'Use at least 12 characters.')
    .max(256, 'Use at most 256 characters.'),
});

type InviteValues = z.infer<typeof schema>;

export function SettingsPage() {
  const { principal } = useAuth();
  const { notify } = useToast();
  const queryClient = useQueryClient();

  const [isInviting, setIsInviting] = useState(false);
  const [removing, setRemoving] = useState<AdminUser | null>(null);

  const query = useQuery({
    queryKey: queryKeys.users.list(),
    queryFn: ({ signal }) => usersApi.list(undefined, signal),
  });

  const {
    register,
    handleSubmit,
    reset: resetForm,
    formState: { errors },
  } = useForm<InviteValues>({
    resolver: zodResolver(schema),
    defaultValues: { full_name: '', email: '', role: 'viewer', password: '' },
  });

  const inviteMutation = useMutation({
    mutationFn: (values: InviteValues) => usersApi.create(values),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.users.all });
      setIsInviting(false);
      resetForm();
      notify(
        'Account created. Share the password you set — they can change it after signing in.',
        'success',
      );
    },
    onError: (error) => notify(messageFor(error), 'error'),
  });

  const roleMutation = useMutation({
    mutationFn: ({ id, role }: { id: string; role: Role }) => usersApi.update(id, { role }),
    onSuccess: (updated) => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.users.all });
      const role = toRole(updated.role);
      notify(
        `${updated.full_name ?? updated.email} is now ${role ? ROLE_LABEL[role] : updated.role}.`,
        'success',
      );
    },
    onError: (error) => notify(messageFor(error), 'error'),
  });

  const removeMutation = useMutation({
    mutationFn: (id: string) => usersApi.remove(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: queryKeys.users.all });
      setRemoving(null);
      notify('User removed.', 'success');
    },
    onError: (error) => notify(messageFor(error), 'error'),
  });

  const users = query.data?.items ?? [];
  const ownerCount = users.filter((u) => u.role === 'owner').length;

  return (
    <main className="main" id="main">
      <PageHeader
        eyebrow="Operate"
        title="Settings"
        lead="Who can see and do what in your organisation."
        actions={
          <Button variant="primary" onClick={() => setIsInviting(true)}>
            <Icon name="plus" size={15} />
            Add user
          </Button>
        }
      />

      <div className="stack stack--lg">
        <Card as="section" aria-labelledby="org-heading">
          <CardHead titleId="org-heading" title="Organisation" />
          <CardBody>
            <dl className="deflist">
              <dt>Name</dt>
              <dd>{principal?.org.name ?? '—'}</dd>
              <dt>Identifier</dt>
              <dd className="mono">{principal?.org.slug ?? '—'}</dd>
              <dt>Plan</dt>
              <dd style={{ textTransform: 'capitalize' }}>{principal?.org.plan ?? '—'}</dd>
              <dt>Status</dt>
              <dd>
                {principal?.org.status === 'active' ? (
                  <Badge tone="ok">Active</Badge>
                ) : (
                  <Badge tone="danger">Suspended</Badge>
                )}
              </dd>
            </dl>
          </CardBody>
        </Card>

        <Card as="section" aria-labelledby="users-heading">
          <CardHead
            titleId="users-heading"
            title="Users and roles"
            subtitle="Roles are hierarchical: owner, then admin, then analyst, then viewer."
          />
          {query.isPending ? (
            <LoadingState label="Loading users" />
          ) : query.error ? (
            <ErrorState error={query.error} onRetry={() => void query.refetch()} />
          ) : (
            <TableWrap>
              <table className="table">
                <caption className="visually-hidden">Users in this organisation.</caption>
                <thead>
                  <tr>
                    <th scope="col">User</th>
                    <th scope="col">Role</th>
                    <th scope="col">Status</th>
                    <th scope="col">Last signed in</th>
                    <th scope="col">
                      <span className="visually-hidden">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((user) => {
                    const isSelf = user.id === principal?.user.id;
                    const isLastOwner = user.role === 'owner' && ownerCount <= 1;

                    return (
                      <tr key={user.id}>
                        <td>
                          <div className="row">
                            <span className="userchip__avatar" aria-hidden="true">
                              {initialsFor(user.full_name, user.email)}
                            </span>
                            <span>
                              <strong>{user.full_name ?? user.email}</strong>
                              {isSelf ? (
                                <span className="chip" style={{ marginLeft: 6 }}>
                                  You
                                </span>
                              ) : null}
                              <div className="subtle" style={{ fontSize: 'var(--text-xs)' }}>
                                {user.email}
                              </div>
                            </span>
                          </div>
                        </td>
                        <td style={{ minWidth: 160 }}>
                          <select
                            className="select"
                            value={user.role}
                            aria-label={`Role for ${user.full_name ?? user.email}`}
                            disabled={isLastOwner || roleMutation.isPending}
                            onChange={(event) =>
                              roleMutation.mutate({
                                id: user.id,
                                role: event.target.value as Role,
                              })
                            }
                          >
                            {ROLE_OPTIONS.map((option) => (
                              <option key={option.value} value={option.value}>
                                {option.label}
                              </option>
                            ))}
                          </select>
                          {isLastOwner ? (
                            <p className="field__hint" style={{ marginTop: 4 }}>
                              The last owner cannot be demoted.
                            </p>
                          ) : null}
                        </td>
                        <td>
                          {/*
                            `locked` and `verified` come back on every directory row, and
                            they are the two reasons a colleague cannot sign in. Showing
                            only `status` left an admin with no way to know which lever to
                            pull.
                          */}
                          <div className="row row--wrap" style={{ gap: 'var(--space-2xs)' }}>
                            {user.status === 'active' ? (
                              <Badge tone="ok">Active</Badge>
                            ) : (
                              <Badge tone="neutral">Disabled</Badge>
                            )}
                            {user.locked ? <Badge tone="danger">Locked out</Badge> : null}
                            {user.verified ? null : <Badge tone="warn">Unverified</Badge>}
                          </div>
                        </td>
                        <td className="subtle" style={{ fontSize: 'var(--text-xs)' }}>
                          {formatRelative(user.last_login_at)}
                        </td>
                        <td>
                          <div className="row" style={{ justifyContent: 'flex-end' }}>
                            <Button
                              size="sm"
                              variant="ghost"
                              disabled={isLastOwner}
                              onClick={() => setRemoving(user)}
                              aria-label={`Remove ${user.full_name ?? user.email}`}
                            >
                              <Icon name="trash" size={14} />
                            </Button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </TableWrap>
          )}
        </Card>

        <Card as="section" aria-labelledby="roles-heading" variant="sunken">
          <CardHead titleId="roles-heading" title="What each role can do" />
          <CardBody>
            <dl className="deflist">
              {ROLE_OPTIONS.map((option) => (
                <div key={option.value} style={{ display: 'contents' }}>
                  <dt>{option.label}</dt>
                  <dd>{ROLE_DESCRIPTION[option.value]}</dd>
                </div>
              ))}
            </dl>
          </CardBody>
        </Card>
      </div>

      <Dialog
        open={isInviting}
        onClose={() => setIsInviting(false)}
        title="Add a user"
        description="You set their initial password and pass it on; they can change it once signed in. Grant the least role that lets them do their job."
        footer={null}
      >
        <form
          onSubmit={handleSubmit((values) => inviteMutation.mutate(values))}
          noValidate
          className="stack"
        >
          <TextField
            label="Full name"
            required
            error={errors.full_name?.message}
            {...register('full_name')}
          />
          <TextField
            label="Work email"
            type="email"
            required
            error={errors.email?.message}
            {...register('email')}
          />
          <SelectField
            label="Role"
            options={ROLE_OPTIONS}
            required
            error={errors.role?.message}
            {...register('role')}
          />
          <TextField
            label="Initial password"
            type="password"
            autoComplete="new-password"
            required
            hint="At least 12 characters. Share it with them out of band; they can change it once signed in."
            error={errors.password?.message}
            {...register('password')}
          />

          <div className="row" style={{ justifyContent: 'flex-end' }}>
            <Button variant="ghost" type="button" onClick={() => setIsInviting(false)}>
              Cancel
            </Button>
            <Button variant="primary" type="submit" loading={inviteMutation.isPending}>
              Create account
            </Button>
          </div>
        </form>
      </Dialog>

      <Dialog
        open={removing !== null}
        onClose={() => setRemoving(null)}
        title="Remove this user?"
        description={
          removing
            ? `${removing.full_name ?? removing.email} will lose access immediately and their active sessions will be revoked.`
            : undefined
        }
        footer={
          <>
            <Button variant="ghost" onClick={() => setRemoving(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              loading={removeMutation.isPending}
              onClick={() => removing && removeMutation.mutate(removing.id)}
            >
              Remove user
            </Button>
          </>
        }
      />
    </main>
  );
}
