import { useQuery } from '@tanstack/react-query';
import { PageHeader } from '@/components/layout/PageHeader';
import { AsyncBoundary } from '@/components/ui/States';
import { ButtonLink } from '@/components/ui/Button';
import { Icon } from '@/components/ui/Icon';
import { RiskPostureHero } from './RiskPostureHero';
import { ServicesAtRisk } from './ServicesAtRisk';
import { ExposureSummary } from './ExposureSummary';
import { RemediationProgress } from './RemediationProgress';
import { KevCallout } from './KevCallout';
import { dashboardApi } from '@/lib/api/endpoints';
import { queryKeys } from '@/lib/api/queryKeys';
import { formatDateTime } from '@/lib/format';
import { useAuth } from '@/auth/useAuth';

/**
 * The flagship screen.
 *
 * Reading order is deliberate: the single posture number, then whether anything is being
 * exploited today, then which business services are exposed and for how much money, and
 * only then the supporting breakdowns. A CVE never appears on this page.
 */
export function ExecutiveDashboardPage() {
  const { principal } = useAuth();

  const query = useQuery({
    queryKey: queryKeys.dashboard.executive,
    queryFn: ({ signal }) => dashboardApi.executive(signal),
  });

  return (
    <main className="main" id="main">
      <PageHeader
        eyebrow={principal?.org.name}
        title="Risk posture"
        lead="What your organisation is exposed to right now, in business terms — which services are at risk, and what that exposure is worth."
        actions={
          <ButtonLink to="/findings" variant="secondary">
            <Icon name="findings" size={15} />
            All findings
          </ButtonLink>
        }
      />

      <AsyncBoundary
        isLoading={query.isPending}
        error={query.error}
        data={query.data}
        onRetry={() => void query.refetch()}
        loadingLabel="Loading your risk posture"
      >
        {(dashboard) => (
          <div className="exec">
            <RiskPostureHero posture={dashboard.risk_posture} />

            <KevCallout count={dashboard.kev_findings} />

            <ServicesAtRisk services={dashboard.services_at_risk} />

            <div className="exec__split">
              <ExposureSummary summary={dashboard.exposure_summary} />
              <RemediationProgress progress={dashboard.remediation_progress} />
            </div>

            <p className="exec__generated">
              Generated {formatDateTime(dashboard.generated_at)} from your most recent scan data.
            </p>
          </div>
        )}
      </AsyncBoundary>
    </main>
  );
}
