import { Link, useParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { PageHeader } from '@/components/layout/PageHeader';
import { Card, CardBody, CardHead } from '@/components/ui/Card';
import { AsyncBoundary } from '@/components/ui/States';
import { SeverityBadge } from '@/components/ui/SeverityMark';
import { ExposureBadge, FindingStatusBadge, KevBadge } from '@/components/ui/Badge';
import { Button, ButtonLink } from '@/components/ui/Button';
import { Icon } from '@/components/ui/Icon';
import { SelectField } from '@/components/ui/Field';
import { useToast } from '@/components/ui/useToast';
import { ScoreExplanation } from './ScoreExplanation';
import { findingsApi } from '@/lib/api/endpoints';
import { queryKeys } from '@/lib/api/queryKeys';
import { formatDate, formatDateTime, formatRelative, formatScore } from '@/lib/format';
import { messageFor } from '@/lib/api/ApiError';
import { EXPLOIT_MATURITY_LABEL, FINDING_STATUS_LABEL } from '@/lib/risk';
import { FINDING_STATUSES, type FindingStatus } from '@/types/domain';
import { useAuth } from '@/auth/useAuth';

const STATUS_OPTIONS = FINDING_STATUSES.map((status) => ({
  value: status,
  label: FINDING_STATUS_LABEL[status],
}));

export function FindingDetailPage() {
  const { id = '' } = useParams();
  const { can } = useAuth();
  const { notify } = useToast();
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: queryKeys.findings.detail(id),
    queryFn: ({ signal }) => findingsApi.get(id, signal),
    enabled: id !== '',
  });

  const mutation = useMutation({
    mutationFn: (status: FindingStatus) => findingsApi.updateStatus(id, status),
    onSuccess: (updated) => {
      queryClient.setQueryData(queryKeys.findings.detail(id), updated);
      // The headline posture is derived from finding status, so it must be refetched too.
      void queryClient.invalidateQueries({ queryKey: queryKeys.findings.all });
      void queryClient.invalidateQueries({ queryKey: queryKeys.dashboard.all });
      notify(`Marked as ${FINDING_STATUS_LABEL[updated.status].toLowerCase()}.`, 'success');
    },
    onError: (error) => notify(messageFor(error), 'error'),
  });

  return (
    <main className="main" id="main">
      <AsyncBoundary
        isLoading={query.isPending}
        error={query.error}
        data={query.data}
        onRetry={() => void query.refetch()}
        loadingLabel="Loading finding"
      >
        {(finding) => (
          <>
            <PageHeader
              eyebrow={<Link to="/findings">← Findings</Link>}
              title={finding.cve_id}
              lead={finding.vulnerability.description}
              actions={
                can('analyst') ? (
                  <div style={{ minWidth: 200 }}>
                    <SelectField
                      label="Status"
                      options={STATUS_OPTIONS}
                      value={finding.status}
                      disabled={mutation.isPending}
                      onChange={(event) => mutation.mutate(event.target.value as FindingStatus)}
                    />
                  </div>
                ) : (
                  <FindingStatusBadge status={finding.status} />
                )
              }
            />

            <div className="row row--wrap" style={{ marginBottom: 'var(--space-lg)' }}>
              <SeverityBadge
                severity={finding.severity}
                detail={`CVSS ${finding.vulnerability.cvss_base.toFixed(1)}`}
              />
              {finding.kev_listed ? (
                <KevBadge dueDate={finding.vulnerability.kev_due_date} />
              ) : null}
              <ExposureBadge exposure={finding.exposure} />
              <FindingStatusBadge status={finding.status} />
              <span className="chip">
                Business risk <strong>{formatScore(finding.business_risk_score)}</strong>
              </span>
            </div>

            <div className="detail">
              <div className="stack stack--lg">
                <ScoreExplanation
                  factors={finding.score_factors}
                  score={finding.business_risk_score}
                />

                <Card as="section" aria-labelledby="vuln-heading">
                  <CardHead
                    titleId="vuln-heading"
                    title="About this vulnerability"
                    subtitle="Reference data from the National Vulnerability Database and CISA."
                  />
                  <CardBody>
                    <p className="cvedesc">{finding.vulnerability.description}</p>

                    <dl className="deflist" style={{ marginTop: 'var(--space-lg)' }}>
                      <dt>CVE</dt>
                      <dd className="mono">{finding.cve_id}</dd>

                      <dt>CVSS base</dt>
                      <dd>
                        {finding.vulnerability.cvss_base.toFixed(1)}{' '}
                        <span className="subtle">({finding.vulnerability.severity})</span>
                      </dd>

                      {finding.vulnerability.cvss_vector ? (
                        <>
                          <dt>CVSS vector</dt>
                          <dd className="mono" style={{ fontSize: 'var(--text-xs)' }}>
                            {finding.vulnerability.cvss_vector}
                          </dd>
                        </>
                      ) : null}

                      <dt>Exploit maturity</dt>
                      <dd>{EXPLOIT_MATURITY_LABEL[finding.vulnerability.exploit_maturity]}</dd>

                      <dt>Known exploited</dt>
                      <dd>
                        {finding.vulnerability.kev_listed ? (
                          <>
                            Yes — listed by CISA
                            {finding.vulnerability.kev_due_date
                              ? `, federal remediation due ${formatDate(
                                  finding.vulnerability.kev_due_date,
                                )}`
                              : ''}
                          </>
                        ) : (
                          'Not listed in the CISA KEV catalogue'
                        )}
                      </dd>

                      <dt>Published</dt>
                      <dd>{formatDate(finding.vulnerability.published_at)}</dd>
                    </dl>
                  </CardBody>
                </Card>
              </div>

              <div className="stack stack--lg">
                <Card as="section" aria-labelledby="where-heading">
                  <CardHead titleId="where-heading" title="Where it was found" as="h2" />
                  <CardBody>
                    <dl className="deflist">
                      <dt>Asset</dt>
                      <dd>
                        <Link to={`/assets/${finding.asset_id}`}>
                          {finding.asset_hostname ?? finding.asset_ip}
                        </Link>
                      </dd>

                      <dt>IP address</dt>
                      <dd className="mono">{finding.asset_ip}</dd>

                      {finding.port ? (
                        <>
                          <dt>Port</dt>
                          <dd className="mono">
                            {finding.port}/{finding.protocol}
                            {finding.service ? ` (${finding.service})` : ''}
                          </dd>
                        </>
                      ) : null}

                      {finding.product ? (
                        <>
                          <dt>Software</dt>
                          <dd>
                            {finding.product}
                            {finding.version ? ` ${finding.version}` : ''}
                          </dd>
                        </>
                      ) : null}

                      <dt>Exposure</dt>
                      <dd>
                        <ExposureBadge exposure={finding.exposure} />
                      </dd>

                      <dt>First seen</dt>
                      <dd>{formatDateTime(finding.first_seen_at)}</dd>

                      <dt>Last seen</dt>
                      <dd>{formatRelative(finding.last_seen_at)}</dd>

                      {finding.resolved_at ? (
                        <>
                          <dt>Resolved</dt>
                          <dd>{formatDateTime(finding.resolved_at)}</dd>
                        </>
                      ) : null}
                    </dl>
                  </CardBody>
                </Card>

                <Card as="section" aria-labelledby="impact-heading">
                  <CardHead
                    titleId="impact-heading"
                    title="Business impact"
                    subtitle="What this asset supports."
                    as="h2"
                  />
                  <CardBody>
                    {finding.services_affected.length === 0 ? (
                      <>
                        <p className="muted" style={{ fontSize: 'var(--text-sm)' }}>
                          This asset is not mapped to any business service, so its risk score
                          assumes the lowest business criticality. That is almost certainly an
                          understatement.
                        </p>
                        <ButtonLink
                          to={`/assets/${finding.asset_id}`}
                          variant="secondary"
                          size="sm"
                          className="btn--full"
                          style={{ marginTop: 'var(--space-md)' }}
                        >
                          <Icon name="service" size={14} />
                          Map this asset
                        </ButtonLink>
                      </>
                    ) : (
                      <ul className="stack stack--sm" style={{ listStyle: 'none', padding: 0 }}>
                        {finding.services_affected.map((name) => (
                          <li key={name} className="row">
                            <Icon name="service" size={14} style={{ color: 'var(--brand)' }} />
                            <strong style={{ fontSize: 'var(--text-sm)' }}>{name}</strong>
                          </li>
                        ))}
                      </ul>
                    )}
                  </CardBody>
                </Card>

                {can('analyst') ? (
                  <Card as="section" aria-labelledby="actions-heading" variant="sunken">
                    <CardHead titleId="actions-heading" title="Triage" as="h2" />
                    <CardBody>
                      <div className="stack stack--sm">
                        <Button
                          variant="secondary"
                          fullWidth
                          disabled={finding.status === 'remediated' || mutation.isPending}
                          onClick={() => mutation.mutate('remediated')}
                        >
                          <Icon name="check" size={14} />
                          Mark remediated
                        </Button>
                        <Button
                          variant="secondary"
                          fullWidth
                          disabled={finding.status === 'accepted_risk' || mutation.isPending}
                          onClick={() => mutation.mutate('accepted_risk')}
                        >
                          Accept the risk
                        </Button>
                        <Button
                          variant="ghost"
                          fullWidth
                          disabled={finding.status === 'false_positive' || mutation.isPending}
                          onClick={() => mutation.mutate('false_positive')}
                        >
                          Flag as false positive
                        </Button>
                      </div>
                    </CardBody>
                  </Card>
                ) : null}
              </div>
            </div>
          </>
        )}
      </AsyncBoundary>
    </main>
  );
}
