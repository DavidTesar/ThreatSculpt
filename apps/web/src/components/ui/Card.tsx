import type { CSSProperties, ReactNode } from 'react';

export interface CardProps {
  children: ReactNode;
  variant?: 'default' | 'flat' | 'sunken';
  className?: string;
  as?: 'div' | 'section' | 'article';
  style?: CSSProperties;
  'aria-labelledby'?: string;
}

export function Card({
  children,
  variant = 'default',
  className,
  as: Tag = 'div',
  ...rest
}: CardProps) {
  const classes = ['card', variant !== 'default' ? `card--${variant}` : '', className ?? '']
    .filter(Boolean)
    .join(' ');
  return (
    <Tag className={classes} {...rest}>
      {children}
    </Tag>
  );
}

export interface CardHeadProps {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  titleId?: string;
  /** Renders the title as this heading level, so the page keeps a valid outline. */
  as?: 'h2' | 'h3' | 'h4';
}

export function CardHead({ title, subtitle, actions, titleId, as: Tag = 'h2' }: CardHeadProps) {
  return (
    <div className="card__head">
      <div>
        <Tag className="card__title" id={titleId}>
          {title}
        </Tag>
        {subtitle ? <p className="card__subtitle">{subtitle}</p> : null}
      </div>
      {actions ? <div className="row">{actions}</div> : null}
    </div>
  );
}

export function CardBody({
  children,
  flush = false,
  className,
}: {
  children: ReactNode;
  flush?: boolean;
  className?: string;
}) {
  const classes = ['card__body', flush ? 'card__body--flush' : '', className ?? '']
    .filter(Boolean)
    .join(' ');
  return <div className={classes}>{children}</div>;
}

export function CardFoot({ children }: { children: ReactNode }) {
  return <div className="card__foot">{children}</div>;
}
