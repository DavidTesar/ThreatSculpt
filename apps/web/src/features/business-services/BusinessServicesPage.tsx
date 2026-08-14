import { useState } from 'react';
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
import { CriticalityMeter } from '@/components/ui/SeverityMark';
import { SelectField, TextAreaField, TextField } from '@/components/ui/Field';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/States';
import { TableWrap } from '@/components/ui/Table';
import { useToast } from '@/components/ui/useToast';
import { businessServicesApi, type BusinessServiceCreate } from '@/lib/api/endpoints';
import { queryKeys } from '@/lib/api/queryKeys';
import { formatCurrency } from '@/lib/format';
import { CRITICALITY_LABEL } from '@/lib/risk';
import { messageFor } from '@/lib/api/ApiError';
import { useAuth } from '@/auth/useAuth';
import { CRITICALITIES, toCriticality, type BusinessService } from '@/types/domain';

const schema = z.object({
  name: z.string().min(2, 'Name this service the way the business refers to it.').max(120),
  description: z.string().max(600).optional(),
  criticality: z.enum(CRITICALITIES),
  // Money is entered as digits and carried as a string, never a float.
  revenue_at_risk: z
    .string()
    .optional()
    .refine(
      (value) => !value || /^\d{1,12}(\.\d{1,2})?$/.test(value.replace(/[,\s]/g, '')),
      'Enter an amount in digits, for example 4200000.',
    ),
  owner_name: z.string().max(120).optional(),
  owner_email: z.string().email('Enter a valid email address.').or(z.literal('')).optional(),
});

type ServiceFormValues = z.infer<typeof schema>;

const CRITICALITY_OPTIONS = CRITICALITIES.map((value) => ({
  value,
  label: CRITICALITY_LABEL[value],
}));

function ServiceForm({
  initial,
  onSubmit,
  onCancel,
  isSubmitting,
}: {
  initial?: BusinessService;
  onSubmit: (values: BusinessServiceCreate) => void;
  onCancel: () => void;
  isSubmitting: boolean;
}) {
  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<ServiceFormValues>({
    resolver: zodResolver(schema),
    defaultValues: {
      name: initial?.name ?? '',
      description: initial?.description ?? '',
      criticality: toCriticality(initial?.criticality) ?? 'medium',
      revenue_at_risk: initial?.revenue_at_risk ?? '',
      owner_name: initial?.owner_name ?? '',
      owner_email: initial?.owner_email ?? '',
    },
  });

  return (
    <form
      onSubmit={handleSubmit((values) =>
        onSubmit({
          name: values.name,
          description: values.description?.trim() || null,
          criticality: values.criticality,
          revenue_at_risk: values.revenue_at_risk?.replace(/[,\s]/g, '') || null,
          owner_name: values.owner_name?.trim() || null,
          owner_email: values.owner_email?.trim() || null,
        }),
      )}
      noValidate
      className="stack"
    >
      <TextField
        label="Service name"
        placeholder="Payment processing"
        required
        error={errors.name?.message}
        {...register('name')}
      />

      <TextAreaField
        label="What it does"
        placeholder="Card authorisation and settlement for all sales channels."
        hint="Written for someone outside IT. This appears on executive reports."
        error={errors.description?.message}
        {...register('description')}
      />

      <SelectField
        label="Business criticality"
        options={CRITICALITY_OPTIONS}
        required
        hint="Drives the multiplier applied to every finding on assets supporting this service."
        error={errors.criticality?.message}
        {...register('criticality')}
      />

      <TextField
        label="Annual revenue at risk"
        placeholder="4200000"
        mono
        hint="Optional. The annual revenue that depends on this service, in whole currency units. This is the figure that appears on the executive dashboard."
        error={errors.revenue_at_risk?.message}
        {...register('revenue_at_risk')}
      />

      <TextField
        label="Business owner"
        placeholder="Diane Whitfield"
        hint="The business owner, not the IT owner."
        error={errors.owner_name?.message}
        {...register('owner_name')}
      />

      <TextField
        label="Owner email"
        type="email"
        error={errors.owner_email?.message}
        {...register('owner_email')}
      />

      <div className="row" style={{ justifyContent: 'flex-end', marginTop: 'var(--space-xs)' }}>
        <Button variant="ghost" type="button" onClick={onCancel}>
          Cancel
        </Button>
        <Button variant="primary" type="submit" loading={isSubmitting}>
          {initial ? 'Save changes' : 'Create service'}
        </Button>
      </div>
    </form>
  );
}

export function BusinessServicesPage() {
  const { can } = useAuth();
  const { notify } = useToast();
  const queryClient = useQueryClient();

  const [isCreating, setIsCreating] = useState(false);
  const [editing, setEditing] = useState<BusinessService | null>(null);
  const [deleting, setDeleting] = useState<BusinessService | null>(null);

  const query = useQuery({
    queryKey: queryKeys.businessServices.list(),
    queryFn: ({ signal }) => businessServicesApi.list(undefined, signal),
  });

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: queryKeys.businessServices.all });
    void queryClient.invalidateQueries({ queryKey: queryKeys.dashboard.all });
  };

  const createMutation = useMutation({
    mutationFn: (values: BusinessServiceCreate) => businessServicesApi.create(values),
    onSuccess: () => {
      invalidate();
      setIsCreating(false);
      notify('Business service created.', 'success');
    },
    onError: (error) => notify(messageFor(error), 'error'),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, values }: { id: string; values: BusinessServiceCreate }) =>
      businessServicesApi.update(id, values),
    onSuccess: () => {
      invalidate();
      setEditing(null);
      notify('Business service updated.', 'success');
    },
    onError: (error) => notify(messageFor(error), 'error'),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => businessServicesApi.remove(id),
    onSuccess: () => {
      invalidate();
      setDeleting(null);
      notify('Business service removed.', 'success');
    },
    onError: (error) => notify(messageFor(error), 'error'),
  });

  return (
    <main className="main" id="main">
      <PageHeader
        eyebrow="Investigate"
        title="Business services"
        lead="The things your organisation actually depends on. Mapping assets to these is what lets ThreatSculpt report exposure in money rather than in CVEs."
        actions={
          can('analyst') ? (
            <Button variant="primary" onClick={() => setIsCreating(true)}>
              <Icon name="plus" size={15} />
              New service
            </Button>
          ) : null
        }
      />

      <Card>
        {query.isPending ? (
          <LoadingState label="Loading business services" />
        ) : query.error ? (
          <ErrorState error={query.error} onRetry={() => void query.refetch()} />
        ) : query.data.items.length === 0 ? (
          <EmptyState
            icon="service"
            title="No business services defined yet"
            body="This is the step that makes ThreatSculpt different from a scanner. Define what your organisation depends on — payment processing, customer records, order fulfilment — then map your assets to them. Until you do, every finding is scored at the lowest business criticality."
            action={
              can('analyst') ? (
                <Button variant="primary" onClick={() => setIsCreating(true)}>
                  <Icon name="plus" size={15} />
                  Define your first service
                </Button>
              ) : null
            }
          />
        ) : (
          <TableWrap>
            <table className="table">
              <caption className="visually-hidden">Business services.</caption>
              <thead>
                <tr>
                  <th scope="col">Service</th>
                  <th scope="col">Criticality</th>
                  <th scope="col" className="table__num">
                    Revenue at risk
                  </th>
                  <th scope="col" className="table__num">
                    Mapped work
                  </th>
                  <th scope="col">Business owner</th>
                  {can('analyst') ? (
                    <th scope="col">
                      <span className="visually-hidden">Actions</span>
                    </th>
                  ) : null}
                </tr>
              </thead>
              <tbody>
                {query.data.items.map((service) => (
                  <tr key={service.id}>
                    <td style={{ maxWidth: '34ch' }}>
                      <strong>{service.name}</strong>
                      {service.description ? (
                        <div className="subtle" style={{ fontSize: 'var(--text-xs)' }}>
                          {service.description}
                        </div>
                      ) : null}
                    </td>
                    <td>
                      <CriticalityMeter criticality={toCriticality(service.criticality)} />
                    </td>
                    <td className="table__num">
                      {service.revenue_at_risk ? (
                        formatCurrency(service.revenue_at_risk)
                      ) : (
                        <span className="subtle">Not costed</span>
                      )}
                    </td>
                    {/*
                      `BusinessServiceOut` carries no asset or finding counts, so these are
                      links to the filtered views rather than numbers invented on the row.
                    */}
                    <td className="table__num">
                      <Link to={`/assets?service_id=${service.id}`}>Assets</Link>
                      {' · '}
                      <Link to={`/findings?service_id=${service.id}&status=open`}>Findings</Link>
                    </td>
                    <td className="subtle" style={{ fontSize: 'var(--text-xs)' }}>
                      {service.owner_name ?? '—'}
                      {service.owner_email ? (
                        <div>
                          <a href={`mailto:${service.owner_email}`}>{service.owner_email}</a>
                        </div>
                      ) : null}
                    </td>
                    {can('analyst') ? (
                      <td>
                        <div className="row" style={{ justifyContent: 'flex-end' }}>
                          <Button size="sm" variant="ghost" onClick={() => setEditing(service)}>
                            Edit
                          </Button>
                          {can('admin') ? (
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => setDeleting(service)}
                              aria-label={`Delete ${service.name}`}
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
        title="New business service"
        description="Describe it the way the business does, not the way IT does."
        footer={null}
      >
        <ServiceForm
          onSubmit={(values) => createMutation.mutate(values)}
          onCancel={() => setIsCreating(false)}
          isSubmitting={createMutation.isPending}
        />
      </Dialog>

      <Dialog
        open={editing !== null}
        onClose={() => setEditing(null)}
        title="Edit business service"
        footer={null}
      >
        {editing ? (
          <ServiceForm
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
        title="Remove this business service?"
        description={
          deleting
            ? `${deleting.name} will be unmapped from every asset that supports it. Findings on those assets will be rescored without business context, which will lower your reported risk without anything actually improving.`
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
              Remove service
            </Button>
          </>
        }
      />
    </main>
  );
}
