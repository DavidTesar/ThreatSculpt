import {
  forwardRef,
  useId,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TextareaHTMLAttributes,
} from 'react';
import { Icon } from './Icon';

/**
 * Form controls that wire up their own label, hint, and error associations.
 *
 * The error is linked with `aria-describedby` and the control is marked `aria-invalid`, so
 * a screen reader announces the problem when focus lands on the field rather than leaving
 * the user to hunt for red text they cannot see.
 */

interface FieldShellProps {
  id: string;
  label: string;
  hint?: string;
  error?: string;
  required?: boolean;
  children: ReactNode;
  hintId: string;
  errorId: string;
}

function FieldShell({
  id,
  label,
  hint,
  error,
  required,
  children,
  hintId,
  errorId,
}: FieldShellProps) {
  return (
    <div className="field">
      <label className="field__label" htmlFor={id}>
        {label}
        {required ? (
          <span className="field__required" aria-hidden="true">
            *
          </span>
        ) : null}
      </label>
      {hint ? (
        <span className="field__hint" id={hintId}>
          {hint}
        </span>
      ) : null}
      {children}
      {error ? (
        <span className="field__error" id={errorId} role="alert">
          <Icon name="alert" size={13} />
          {error}
        </span>
      ) : null}
    </div>
  );
}

function describedBy(
  hint: string | undefined,
  error: string | undefined,
  hintId: string,
  errorId: string,
) {
  const ids = [hint ? hintId : null, error ? errorId : null].filter(Boolean);
  return ids.length > 0 ? ids.join(' ') : undefined;
}

export interface TextFieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'id'> {
  label: string;
  hint?: string;
  error?: string;
  mono?: boolean;
}

export const TextField = forwardRef<HTMLInputElement, TextFieldProps>(function TextField(
  { label, hint, error, mono, required, className, ...rest },
  ref,
) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;

  return (
    <FieldShell
      id={id}
      label={label}
      hint={hint}
      error={error}
      required={required}
      hintId={hintId}
      errorId={errorId}
    >
      <input
        ref={ref}
        id={id}
        className={`input${mono ? ' input--mono' : ''}${className ? ` ${className}` : ''}`}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(hint, error, hintId, errorId)}
        required={required}
        {...rest}
      />
    </FieldShell>
  );
});

export interface SelectFieldProps extends Omit<SelectHTMLAttributes<HTMLSelectElement>, 'id'> {
  label: string;
  hint?: string;
  error?: string;
  options: { value: string; label: string }[];
  placeholder?: string;
}

export const SelectField = forwardRef<HTMLSelectElement, SelectFieldProps>(function SelectField(
  { label, hint, error, options, placeholder, required, className, ...rest },
  ref,
) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;

  return (
    <FieldShell
      id={id}
      label={label}
      hint={hint}
      error={error}
      required={required}
      hintId={hintId}
      errorId={errorId}
    >
      <select
        ref={ref}
        id={id}
        className={`select${className ? ` ${className}` : ''}`}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(hint, error, hintId, errorId)}
        required={required}
        {...rest}
      >
        {placeholder ? <option value="">{placeholder}</option> : null}
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </FieldShell>
  );
});

export interface TextAreaFieldProps extends Omit<
  TextareaHTMLAttributes<HTMLTextAreaElement>,
  'id'
> {
  label: string;
  hint?: string;
  error?: string;
}

export const TextAreaField = forwardRef<HTMLTextAreaElement, TextAreaFieldProps>(
  function TextAreaField({ label, hint, error, required, className, ...rest }, ref) {
    const id = useId();
    const hintId = `${id}-hint`;
    const errorId = `${id}-error`;

    return (
      <FieldShell
        id={id}
        label={label}
        hint={hint}
        error={error}
        required={required}
        hintId={hintId}
        errorId={errorId}
      >
        <textarea
          ref={ref}
          id={id}
          className={`textarea${className ? ` ${className}` : ''}`}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy(hint, error, hintId, errorId)}
          required={required}
          {...rest}
        />
      </FieldShell>
    );
  },
);

export interface CheckboxFieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'id'> {
  label: string;
  description?: string;
}

export const CheckboxField = forwardRef<HTMLInputElement, CheckboxFieldProps>(
  function CheckboxField({ label, description, className, ...rest }, ref) {
    const id = useId();
    const descId = `${id}-desc`;

    return (
      <label className={`checkbox${className ? ` ${className}` : ''}`} htmlFor={id}>
        <input
          ref={ref}
          id={id}
          type="checkbox"
          aria-describedby={description ? descId : undefined}
          {...rest}
        />
        <span className="checkbox__text">
          {label}
          {description ? (
            <span className="checkbox__desc" id={descId}>
              {description}
            </span>
          ) : null}
        </span>
      </label>
    );
  },
);
