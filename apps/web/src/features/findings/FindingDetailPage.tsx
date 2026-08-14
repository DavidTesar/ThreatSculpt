import { Link, useParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { PageHeader } from '@/components/layout/PageHeader';
import { Card, CardBody, CardHead } from '@/components/ui/Card';
import { AsyncBoundary } from '@/components/ui/States';
import { SeverityBadge } from '@/components/ui/SeverityMark';
import { Badge, ExposureBadge, FindingStatusBadge, KevBadge } from '@/components/ui/Badge';
import { Button, ButtonLink } from '@/components/ui/Button';
import { Icon } from '@/components/ui/Icon';
import { SelectField } from '@/components/ui/Field';
import { useToast } from '@/components/ui/useToast';
import { ScoreExplanation } from './ScoreExplanation';
import { findingsApi } from '@/lib/api/endpoints';
import { queryKeys } from '@/lib/api/queryKeys';
import {
  formatDate,
  formatDateTime,
  formatRelative,
  formatScore,
  parseDecimal,
} from '@/lib/format';
import { messageFor } from '@/lib/api/ApiError';
import {
  EXPLOIT_MATURITY_LABEL,
  FINDING_STATUS_LABEL,
  MATCH_CONFIDENCE_GLOSS,
  MATCH_CONFIDENCE_LABEL,
  MATCH_CONFIDENCE_TONE,
} from '@/lib/risk';
import {
  FINDING_STATUSES,
  toExploitMaturity,
  toExposure,
  toSeverity,
  type FindingStatus,
} from '@/types/domain';
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
        {(finding) => {
          const cvssBase = parseDecimal(finding.cve.cvss_base);
          const maturity = toExploitMaturity(finding.cve.exploit_maturity);
          // The control plane types `kev_due_date` as `Any | None`, so the schema says
          // `unknown`. It is a date string in practice; anything else is shown as nothing
          // rather than coerced into "[object Object]" next to a remediation deadline.
          const kevDueDate =
            typeof finding.cve.kev_due_date === 'string'
              ? formatDate(finding.cve.kev_due_date)
              : null;
          const servicesAffected = finding.services_affected ?? [];

          return (
            <>
              <PageHeader
                eyebrow={<Link to="/findings">← Findings</Link>}
                title={finding.cve.cve_id}
                lead={finding.description ?? 'No description is published for this CVE yet.'}
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
                  severity={toSeverity(finding.cve.severity)}
                  detail={cvssBase === null ? undefined : `CVSS ${cvssBase.toFixed(1)}`}
                />
                {finding.cve.kev_listed ? <KevBadge dueDate={kevDueDate} /> : null}
                <ExposureBadge exposure={toExposure(finding.asset.exposure)} />
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
                      <p className="cvedesc">
                        {finding.description ?? 'No description is published for this CVE yet.'}
                      </p>

                      <dl className="deflist" style={{ marginTop: 'var(--space-lg)' }}>
                        <dt>CVE</dt>
                        <dd className="mono">{finding.cve.cve_id}</dd>

                        <dt>CVSS base</dt>
                        <dd>
                          {cvssBase === null ? (
                            'Not yet scored'
                          ) : (
                            <>
                              {cvssBase.toFixed(1)}{' '}
                              <span className="subtle">({finding.cve.severity ?? 'unrated'})</span>
                            </>
                          )}
                        </dd>

                        <dt>Exploit maturity</dt>
                        <dd>
                          {maturity
                            ? EXPLOIT_MATURITY_LABEL[maturity]
                            : finding.cve.exploit_maturity}
                        </dd>

                        <dt>Known exploited</dt>
                        <dd>
                          {finding.cve.kev_listed
                            ? `Yes — listed by CISA${
                                kevDueDate ? `, federal remediation due ${kevDueDate}` : ''
                              }`
                            : 'Not listed in the CISA KEV catalogue'}
                        </dd>
                      </dl>
                    </CardBody>
                  </Card>

                  {/*
                  How the CVE came to be attached to this host. An operator deciding
                  whether to wake somebody needs the difference between "your version is
                  inside the affected range" and "we guessed from a banner".
                */}
                  <Card as="section" aria-labelledby="match-heading">
                    <CardHead
                      titleId="match-heading"
                      title="How we matched this"
                      subtitle="Why this CVE is attached to this host, and how sure we are."
                    />
                    <CardBody>
                      <dl className="deflist">
                        <dt>Confidence</dt>
                        <dd>
                          <Badge tone={MATCH_CONFIDENCE_TONE[finding.match.confidence]}>
                            {MATCH_CONFIDENCE_LABEL[finding.match.confidence]}
                          </Badge>
                          <p
                            className="subtle"
                            style={{ fontSize: 'var(--text-xs)', marginTop: 4 }}
                          >
                            {MATCH_CONFIDENCE_GLOSS[finding.match.confidence]}
                          </p>
                        </dd>

                        {finding.match.method ? (
                          <>
                            <dt>Method</dt>
                            <dd className="mono">{finding.match.method}</dd>
                          </>
                        ) : null}

                        {finding.match.rationale ? (
                          <>
                            <dt>Rationale</dt>
                            <dd>{finding.match.rationale}</dd>
                          </>
                        ) : null}
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
                          <Link to={`/assets/${finding.asset.id}`}>
                            {finding.asset.hostname ?? finding.asset.ip}
                          </Link>
                        </dd>

                        <dt>IP address</dt>
                        <dd className="mono">{finding.asset.ip}</dd>

                        <dt>Exposure</dt>
                        <dd>
                          <ExposureBadge exposure={toExposure(finding.asset.exposure)} />
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
                      {servicesAffected.length === 0 ? (
                        <>
                          <p className="muted" style={{ fontSize: 'var(--text-sm)' }}>
                            This asset is not mapped to any business service, so its risk score
                            assumes the lowest business criticality. That is almost certainly an
                            understatement.
                          </p>
                          <ButtonLink
                            to={`/assets/${finding.asset.id}`}
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
                          {servicesAffected.map((name) => (
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
          );
        }}
      </AsyncBoundary>
    </main>
  );
}
