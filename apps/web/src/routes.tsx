import { lazy } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';
import { RequireAuth, RequireRole } from './auth/RequireAuth';
import { AppShell } from './components/layout/AppShell';
// Login and register stay eager: they are the first paint for a signed-out visitor, and
// a lazy chunk there would put a spinner on the critical path for no benefit.
import { LoginPage } from './features/auth/LoginPage';
import { RegisterPage } from './features/auth/RegisterPage';

/**
 * Authenticated screens are split per route.
 *
 * Recharts alone is ~106 kB gzipped. Imported statically it lands in the entry graph and
 * every visitor downloads a charting library to look at a login form. Lazy routes keep it
 * on the two screens that actually plot anything.
 */
const ExecutiveDashboardPage = lazy(() =>
  import('./features/executive/ExecutiveDashboardPage').then((m) => ({
    default: m.ExecutiveDashboardPage,
  })),
);
const AttackSurfacePage = lazy(() =>
  import('./features/attack-surface/AttackSurfacePage').then((m) => ({
    default: m.AttackSurfacePage,
  })),
);
const FindingsPage = lazy(() =>
  import('./features/findings/FindingsPage').then((m) => ({ default: m.FindingsPage })),
);
const FindingDetailPage = lazy(() =>
  import('./features/findings/FindingDetailPage').then((m) => ({
    default: m.FindingDetailPage,
  })),
);
const AssetsPage = lazy(() =>
  import('./features/assets/AssetsPage').then((m) => ({ default: m.AssetsPage })),
);
const AssetDetailPage = lazy(() =>
  import('./features/assets/AssetDetailPage').then((m) => ({ default: m.AssetDetailPage })),
);
const NetworksPage = lazy(() =>
  import('./features/networks/NetworksPage').then((m) => ({ default: m.NetworksPage })),
);
const BusinessServicesPage = lazy(() =>
  import('./features/business-services/BusinessServicesPage').then((m) => ({
    default: m.BusinessServicesPage,
  })),
);
const ScansPage = lazy(() =>
  import('./features/scans/ScansPage').then((m) => ({ default: m.ScansPage })),
);
const ScanDetailPage = lazy(() =>
  import('./features/scans/ScanDetailPage').then((m) => ({ default: m.ScanDetailPage })),
);
const AgentsPage = lazy(() =>
  import('./features/agents/AgentsPage').then((m) => ({ default: m.AgentsPage })),
);
const SettingsPage = lazy(() =>
  import('./features/settings/SettingsPage').then((m) => ({ default: m.SettingsPage })),
);
const NotFoundPage = lazy(() =>
  import('./features/misc/NotFoundPage').then((m) => ({ default: m.NotFoundPage })),
);

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />

      <Route element={<RequireAuth />}>
        <Route element={<AppShell />}>
          <Route index element={<ExecutiveDashboardPage />} />
          <Route path="attack-surface" element={<AttackSurfacePage />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="findings/:id" element={<FindingDetailPage />} />
          <Route path="assets" element={<AssetsPage />} />
          <Route path="assets/:id" element={<AssetDetailPage />} />
          <Route path="business-services" element={<BusinessServicesPage />} />
          <Route path="scans" element={<ScansPage />} />
          <Route path="scans/:id" element={<ScanDetailPage />} />

          <Route element={<RequireRole minimum="analyst" />}>
            <Route path="networks" element={<NetworksPage />} />
          </Route>

          <Route element={<RequireRole minimum="admin" />}>
            <Route path="agents" element={<AgentsPage />} />
            <Route path="settings" element={<SettingsPage />} />
          </Route>

          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
