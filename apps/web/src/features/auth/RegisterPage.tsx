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
 * Password rules are stated up front rather than only on failure, and the confirmation is
 * checked client-side so a typo does not cost a round trip.
 */
const schema = z
  .object({
    org_name: z.string().min(2, 'Enter your organisation name.').max(120),
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
  });

type RegisterValues = z.infer<typeof schema>;

export function RegisterPage() {
  const { status, register: createAccount } = useAuth();
  const navigate = useNavigate();
  const [formError, setFormError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<RegisterValues>({
    resolver: zodResolver(schema),
    defaultValues: { org_name: '', full_name: '', email: '', password: '', confirm: '' },
  });

  if (status === 'authenticated') return <Navigate to="/" replace />;

  const onSubmit = handleSubmit(async (values) => {
    setFormError(null);
    try {
      await createAccount({
        org_name: values.org_name,
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
