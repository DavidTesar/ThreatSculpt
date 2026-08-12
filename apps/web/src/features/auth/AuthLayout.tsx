import type { ReactNode } from 'react';

/**
 * Split layout: the form on the left, the product's argument on the right. The panel is
 * not decoration — a security product bought by an executive has to state what it does in
 * business terms before anyone signs in.
 */
export function AuthLayout({
  title,
  subtitle,
  children,
  footer,
}: {
  title: string;
  subtitle: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <div className="authpage">
      <main className="authpage__form" id="main">
        <div className="authpage__inner">
          <div className="authpage__brand">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path
                d="M12 2 3 6v6c0 5.2 3.8 9.4 9 10 5.2-.6 9-4.8 9-10V6l-9-4Z"
                stroke="currentColor"
                strokeWidth="1.6"
                strokeLinejoin="round"
              />
              <path
                d="M12 7.5 8 10v3.2c0 2.3 1.7 4.2 4 4.6 2.3-.4 4-2.3 4-4.6V10l-4-2.5Z"
                fill="currentColor"
              />
            </svg>
            <span className="authpage__wordmark">ThreatSculpt</span>
          </div>

          <h1 className="authpage__title">{title}</h1>
          <p className="authpage__subtitle">{subtitle}</p>

          {children}

          {footer ? <div className="authpage__footer">{footer}</div> : null}
        </div>
      </main>

      <aside className="authpage__panel" aria-label="About ThreatSculpt">
        <div className="authpage__panelinner">
          <p className="authpage__quote">“Payment processing is exposed.”</p>
          <p className="authpage__quotesub">
            Not “CVE-2021-44228 on 10.0.4.12”. ThreatSculpt maps every scanned asset to the business
            service it supports, so the number on the board slide is the revenue at risk — not a
            CVSS score nobody in the room can act on.
          </p>

          <ul className="authpage__points">
            <li>
              <strong>Business impact first.</strong> Findings ranked by what they threaten, not by
              severity alone.
            </li>
            <li>
              <strong>Every score explained.</strong> Exposure, exploit maturity, and service
              criticality shown as the arithmetic that produced the number.
            </li>
            <li>
              <strong>No inbound firewall rules.</strong> The scan agent polls outbound only and
              never accepts a connection.
            </li>
          </ul>
        </div>
      </aside>
    </div>
  );
}
