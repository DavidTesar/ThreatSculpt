import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom';
import { AuthLayout } from './AuthLayout';
import { TextField } from '@/components/ui/Field';
import { Button } from '@/components/ui/Button';
import { Icon } from '@/components/ui/Icon';
import { useAuth } from '@/auth/useAuth';
import { isApiError, messageFor } from '@/lib/api/ApiError';

const schema = z.object({
  email: z.string().min(1, 'Enter your email address.').email('Enter a valid email address.'),
  password: z.string().min(1, 'Enter your password.'),
});

type LoginValues = z.infer<typeof schema>;

interface LocationState {
  from?: { pathname: string };
}

export function LoginPage() {
  const { status, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [formError, setFormError] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<LoginValues>({
    resolver: zodResolver(schema),
    defaultValues: { email: '', password: '' },
  });

  // Already signed in — go straight through rather than showing a login form.
  if (status === 'authenticated') return <Navigate to="/" replace />;

  const onSubmit = handleSubmit(async (values) => {
    setFormError(null);
    try {
      await login(values);
      const from = (location.state as LocationState | null)?.from?.pathname;
      navigate(from ?? '/', { replace: true });
    } catch (err) {
      // Rate limiting deserves its own message: "incorrect password" would be a lie and
      // would send the user into a retry loop that makes the lockout worse.
      if (isApiError(err) && err.isRateLimited) {
        setFormError('Too many attempts. Wait a minute before trying again.');
      } else {
        setFormError(messageFor(err));
      }
    }
  });

  return (
    <AuthLayout
      title="Sign in"
      subtitle="Access your organisation's risk posture."
      footer={
        <p>
          No account yet? <Link to="/register">Create an organisation</Link>
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
          label="Email"
          type="email"
          autoComplete="username"
          required
          error={errors.email?.message}
          {...register('email')}
        />

        <TextField
          label="Password"
          type="password"
          autoComplete="current-password"
          required
          error={errors.password?.message}
          {...register('password')}
        />

        <Button type="submit" variant="primary" size="lg" fullWidth loading={isSubmitting}>
          Sign in
        </Button>
      </form>

      {/*
        Gated on DEV so it is compiled out of a production build along with the mocks it
        describes. Fixture credentials on a real customer's login screen would be both
        confusing and a small information leak.
      */}
      {import.meta.env.DEV ? (
        <p className="authpage__demo">
          <strong>Demo build.</strong> The control plane is not wired up yet — this runs against
          mocked fixtures. Sign in as <code>diane.whitfield@northwind-logistics.com</code> with any
          password of eight characters or more.
        </p>
      ) : null}
    </AuthLayout>
  );
}
