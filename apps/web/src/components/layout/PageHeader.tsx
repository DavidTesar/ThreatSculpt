import type { ReactNode } from 'react';

export interface PageHeaderProps {
  /** Usually the section name or a breadcrumb link back to the parent list. */
  eyebrow?: ReactNode;
  title: string;
  lead?: ReactNode;
  actions?: ReactNode;
}

export function PageHeader({ eyebrow, title, lead, actions }: PageHeaderProps) {
  return (
    <div className="pagehead">
      <div className="pagehead__text">
        {eyebrow ? <div className="pagehead__eyebrow">{eyebrow}</div> : null}
        <h1 className="pagehead__title">{title}</h1>
        {lead ? <p className="pagehead__lead">{lead}</p> : null}
      </div>
      {actions ? <div className="pagehead__actions">{actions}</div> : null}
    </div>
  );
}
