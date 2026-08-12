import { Suspense } from 'react';
import { NavLink, Outlet } from 'react-router-dom';
import { useAuth } from '@/auth/useAuth';
import { hasRole, ROLE_LABEL } from '@/auth/roles';
import { Icon, type IconName } from '@/components/ui/Icon';
import { Button } from '@/components/ui/Button';
import { useTheme } from '@/theme/useTheme';
import { initialsFor } from '@/lib/format';
import type { Role } from '@/types/domain';

interface NavItem {
  to: string;
  label: string;
  icon: IconName;
  end?: boolean;
  minimum?: Role;
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

const NAV: NavGroup[] = [
  {
    label: 'Overview',
    items: [
      { to: '/', label: 'Risk posture', icon: 'dashboard', end: true },
      { to: '/attack-surface', label: 'Attack surface', icon: 'graph' },
    ],
  },
  {
    label: 'Investigate',
    items: [
      { to: '/findings', label: 'Findings', icon: 'findings' },
      { to: '/assets', label: 'Assets', icon: 'assets' },
      { to: '/business-services', label: 'Business services', icon: 'service' },
    ],
  },
  {
    label: 'Operate',
    items: [
      { to: '/scans', label: 'Scans', icon: 'scan' },
      { to: '/networks', label: 'Networks', icon: 'network', minimum: 'analyst' },
      { to: '/agents', label: 'Agents', icon: 'agent', minimum: 'admin' },
      { to: '/settings', label: 'Settings', icon: 'settings', minimum: 'admin' },
    ],
  },
];

function BrandMark() {
  return (
    <svg
      className="sidebar__mark"
      width="26"
      height="26"
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
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
  );
}

/** Holds the content column while a lazily-loaded route chunk arrives. */
function RouteFallback() {
  return (
    <main className="main" id="main" aria-busy="true" aria-live="polite">
      <span className="visually-hidden">Loading…</span>
      <div className="skeleton__stack">
        <span className="skeleton" style={{ display: 'block', height: 30, width: '32%' }} />
        <span className="skeleton" style={{ display: 'block', height: 16, width: '58%' }} />
        <span className="skeleton" style={{ display: 'block', height: 220, width: '100%' }} />
      </div>
    </main>
  );
}

export function AppShell() {
  const { principal, role, logout } = useAuth();
  const { theme, toggle } = useTheme();

  const user = principal?.user;

  return (
    <div className="shell">
      <a className="skip-link" href="#main">
        Skip to main content
      </a>

      <aside className="sidebar">
        <NavLink to="/" className="sidebar__brand" end>
          <BrandMark />
          <span>
            <span className="sidebar__wordmark">ThreatSculpt</span>
            <span className="sidebar__org">{principal?.org.name ?? '—'}</span>
          </span>
        </NavLink>

        <nav className="sidebar__nav" aria-label="Main navigation">
          {NAV.map((group) => {
            const visible = group.items.filter(
              (item) => !item.minimum || hasRole(role ?? undefined, item.minimum),
            );
            if (visible.length === 0) return null;

            return (
              <div className="navgroup" key={group.label}>
                <h2 className="navgroup__label">{group.label}</h2>
                <ul className="navgroup__list">
                  {visible.map((item) => (
                    <li key={item.to}>
                      <NavLink to={item.to} end={item.end} className="navlink">
                        <Icon name={item.icon} size={16} className="navlink__icon" />
                        {item.label}
                      </NavLink>
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </nav>

        <div className="sidebar__footer">
          <div className="userchip">
            <span className="userchip__avatar" aria-hidden="true">
              {initialsFor(user?.full_name, user?.email)}
            </span>
            <span className="userchip__meta">
              <span className="userchip__name">
                {user?.full_name ?? user?.email ?? 'Signed in'}
              </span>
              <span className="userchip__role">{role ? ROLE_LABEL[role] : ''}</span>
            </span>
          </div>
          <Button variant="ghost" size="sm" onClick={() => void logout()}>
            <Icon name="logout" size={14} />
            Sign out
          </Button>
        </div>
      </aside>

      <div className="content">
        <header className="topbar">
          <div className="topbar__spacer" />
          <Button
            variant="ghost"
            size="sm"
            onClick={toggle}
            aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
          >
            <Icon name={theme === 'dark' ? 'sun' : 'moon'} size={16} />
          </Button>
        </header>
        {/* Route chunks load on demand; the shell stays put while one arrives. */}
        <Suspense fallback={<RouteFallback />}>
          <Outlet />
        </Suspense>
      </div>
    </div>
  );
}
