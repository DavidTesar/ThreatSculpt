import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Link, Navigate, useNavigate } from 'react-router-dom';
import { AuthLayout } from './AuthLayout';
import { TextField } from '@/components/ui/Field';
import { Button } from '@/components/ui/Button';
import { Icon } from '@/components/ui/Icon';
import { useAuth } from '@/auth/useAuth';
import { messageFor } from '@/lib/api/ApiError';

/**
 * `org_slug` is **required** by `POST /auth/register` — one address may legitimately hold
 * an account in several orgs, and the slug is what tells them apart at login. This form
 * used to omit it entirely, so every registration was rejected before it reached the
 * database. It is offered as an editable field with a sensible default rather than being
 * generated silently, because the customer has to be able to type it at sign-in.
 */
function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 63);
}

/**
 * Password rules are stated up front rather than only on failure, and the confirmation is
 * checked client-side so a typo does not cost a round trip.
 */
const schema = z
  .object({
    org_name: z.string().min(2, 'Enter your organisation name.').max(120),
    org_slug: z
      .string()
      .max(63)
      .regex(/^[a-z0-9-]*$/, 'Use lowercase letters, numbers and dashes only.')
      .optional(),
    full_name: z.string().min(2, 'Enter your full name.').max(120),
    email: z.string().min(1, 'Enter your email address.').email('Enter a valid email address.'),
    password: z
      .string()
      .min(12, 'Use at least 12 characters.')
      .regex(/[a-z]/, 'Include a lowercase letter.')
      .regex(/[A-Z]/, 'Include an uppercase letter.')
      .regex(/[0-9]/, 'Include a number.'),
    confirm: z.string().min(1, 'Re-enter your password.'),
  })
  .refine((values) => values.password === values.confirm, {
    message: 'Passwords do not match.',
    path: ['confirm'],
  })
  .refine((values) => slugify(values.org_slug || values.org_name).length >= 3, {
    message: 'Enter a workspace address of at least three characters.',
    path: ['org_slug'],
  });

type RegisterValues = z.infer<typeof schema>;

export function RegisterPage() {
  const { status, register: createAccount } = useAuth();
  const navigate = useNavigate();
  const [formError, setFormError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    watch,
    formState: { errors, isSubmitting },
  } = useForm<RegisterValues>({
    resolver: zodResolver(schema),
    defaultValues: {
      org_name: '',
      org_slug: '',
      full_name: '',
      email: '',
      password: '',
      confirm: '',
    },
  });

  const orgName = watch('org_name');

  if (status === 'authenticated') return <Navigate to="/" replace />;

  const onSubmit = handleSubmit(async (values) => {
    setFormError(null);
    try {
      await createAccount({
        org_name: values.org_name,
        org_slug: slugify(values.org_slug || values.org_name),
        full_name: values.full_name,
        email: values.email,
        password: values.password,
      });
      navigate('/', { replace: true });
    } catch (err) {
      setFormError(messageFor(err));
    }
  });

  return (
    <AuthLayout
      title="Create your organisation"
      subtitle="You will be the owner of this organisation and can invite your team afterwards."
      footer={
        <p>
          Already have an account? <Link to="/login">Sign in</Link>
        </p>
      }
    >
      <form onSubmit={onSubmit} noValidate className="stack">
        {formError ? (
          <div className="alert alert--danger" role="alert">
            <Icon name="alert" size={16} className="alert__icon" />
            <div>{formError}</div>
          </div>
        ) : null}

        <TextField
          label="Organisation name"
          autoComplete="organization"
          required
          error={errors.org_name?.message}
          {...register('org_name')}
        />

        <TextField
          label="Workspace address"
          mono
          placeholder={slugify(orgName) || 'acme-corp'}
          hint="How your organisation is identified at sign-in. Leave blank to use the name above."
          error={errors.org_slug?.message}
          {...register('org_slug')}
        />

        <TextField
          label="Your name"
          autoComplete="name"
          required
          error={errors.full_name?.message}
          {...register('full_name')}
        />

        <TextField
          label="Work email"
          type="email"
          autoComplete="username"
          required
          error={errors.email?.message}
          {...register('email')}
        />

        <TextField
          label="Password"
          type="password"
          autoComplete="new-password"
          required
          hint="At least 12 characters, with upper and lower case letters and a number."
          error={errors.password?.message}
          {...register('password')}
        />

        <TextField
          label="Confirm password"
          type="password"
          autoComplete="new-password"
          required
          error={errors.confirm?.message}
          {...register('confirm')}
        />

        <Button type="submit" variant="primary" size="lg" fullWidth loading={isSubmitting}>
          Create organisation
        </Button>
      </form>
    </AuthLayout>
  );
}
