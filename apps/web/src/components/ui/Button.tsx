import { forwardRef, type ButtonHTMLAttributes } from 'react';
import { Link, type LinkProps } from 'react-router-dom';

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger';
type Size = 'sm' | 'md' | 'lg';

function classesFor(variant: Variant, size: Size, fullWidth: boolean, extra?: string): string {
  return [
    'btn',
    `btn--${variant}`,
    size !== 'md' ? `btn--${size}` : '',
    fullWidth ? 'btn--full' : '',
    extra ?? '',
  ]
    .filter(Boolean)
    .join(' ');
}

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  fullWidth?: boolean;
  /** Shows a spinner and blocks interaction. Width is held so the layout does not jump. */
  loading?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    variant = 'secondary',
    size = 'md',
    fullWidth = false,
    loading = false,
    disabled,
    className,
    children,
    type = 'button',
    ...rest
  },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      className={classesFor(variant, size, fullWidth, className)}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      {...rest}
    >
      {loading ? <span className="btn__spinner" aria-hidden="true" /> : null}
      {children}
    </button>
  );
});

export interface ButtonLinkProps extends LinkProps {
  variant?: Variant;
  size?: Size;
  fullWidth?: boolean;
}

/** A router link styled as a button. Stays an anchor, so it keeps link semantics. */
export function ButtonLink({
  variant = 'secondary',
  size = 'md',
  fullWidth = false,
  className,
  children,
  ...rest
}: ButtonLinkProps) {
  return (
    <Link className={classesFor(variant, size, fullWidth, className)} {...rest}>
      {children}
    </Link>
  );
}
