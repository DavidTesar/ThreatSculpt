import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { TextField, TextAreaField, CheckboxField } from '@/components/ui/Field';
import { Button } from '@/components/ui/Button';
import { Icon } from '@/components/ui/Icon';
import type { NetworkInput } from '@/lib/api/endpoints';
import type { Network } from '@/types/domain';

/**
 * IPv4 CIDR, validated properly rather than by a loose regex: each octet must be 0–255 and
 * the prefix 0–32. The control plane stores this as a native `cidr` type and will reject
 * anything malformed anyway, but catching it here saves a round trip and gives a better
 * message than a database error would.
 */
const cidrSchema = z
  .string()
  .min(1, 'Enter a CIDR block.')
  .refine((value) => {
    const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(value.trim());
    if (!match) return false;
    const octets = [match[1], match[2], match[3], match[4]].map(Number);
    const prefix = Number(match[5]);
    return octets.every((octet) => octet >= 0 && octet <= 255) && prefix >= 0 && prefix <= 32;
  }, 'Enter a valid IPv4 CIDR block, for example 10.0.0.0/16.');

const schema = z.object({
  name: z.string().min(2, 'Give this network a recognisable name.').max(120),
  cidr: cidrSchema,
  authorized: z.boolean(),
  authorization_note: z.string().max(500).optional(),
});

type NetworkFormValues = z.infer<typeof schema>;

export function NetworkForm({
  initial,
  onSubmit,
  onCancel,
  isSubmitting,
}: {
  initial?: Network;
  onSubmit: (values: NetworkInput) => void;
  onCancel: () => void;
  isSubmitting: boolean;
}) {
  const {
    register,
    handleSubmit,
    watch,
    formState: { errors },
  } = useForm<NetworkFormValues>({
    resolver: zodResolver(schema),
    defaultValues: {
      name: initial?.name ?? '',
      cidr: initial?.cidr ?? '',
      authorized: initial?.authorized ?? false,
      authorization_note: initial?.authorization_note ?? '',
    },
  });

  const authorized = watch('authorized');

  return (
    <form
      id="network-form"
      onSubmit={handleSubmit((values) =>
        onSubmit({
          name: values.name,
          cidr: values.cidr.trim(),
          authorized: values.authorized,
          authorization_note: values.authorization_note?.trim() || null,
        }),
      )}
      noValidate
      className="stack"
    >
      <TextField
        label="Name"
        placeholder="Datacentre — production"
        required
        error={errors.name?.message}
        {...register('name')}
      />

      <TextField
        label="CIDR block"
        placeholder="10.40.0.0/16"
        mono
        required
        hint="The address range this network covers. Scan targets must fall inside it."
        error={errors.cidr?.message}
        {...register('cidr')}
      />

      <div className="alert alert--warn" style={{ marginTop: 'var(--space-2xs)' }}>
        <Icon name="alert" size={16} className="alert__icon" />
        <div>
          <p className="alert__title">Only authorize ranges you own or are contracted to test</p>
          <p style={{ fontSize: 'var(--text-xs)' }}>
            Marking a network authorized permits ThreatSculpt to send scan traffic to it. Scanning
            infrastructure you do not have permission to test is unlawful in most jurisdictions. The
            agent independently re-checks its own local allowlist before running anything.
          </p>
        </div>
      </div>

      <CheckboxField
        label="This network is authorized for scanning"
        description="Scans against an unauthorized network are refused by the API."
        {...register('authorized')}
      />

      {authorized ? (
        <TextAreaField
          label="Authorization record"
          placeholder="CHG-2301 — signed off by the IT Director, 2026-01-14"
          hint="Who approved this, and the change or ticket reference. Recorded for audit."
          error={errors.authorization_note?.message}
          {...register('authorization_note')}
        />
      ) : null}

      <div className="row" style={{ justifyContent: 'flex-end', marginTop: 'var(--space-xs)' }}>
        <Button variant="ghost" onClick={onCancel} type="button">
          Cancel
        </Button>
        <Button variant="primary" type="submit" loading={isSubmitting}>
          {initial ? 'Save changes' : 'Add network'}
        </Button>
      </div>
    </form>
  );
}
