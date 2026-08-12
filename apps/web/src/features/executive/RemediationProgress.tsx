import { Card, CardHead, CardBody } from '@/components/ui/Card';
import { Icon } from '@/components/ui/Icon';
import { formatNumber, pluralize } from '@/lib/format';
import type { RemediationProgress as RemediationProgressData } from '@/types/domain';

/**
 * Are we gaining or losing ground?
 *
 * Two raw counts do not answer that; the net is what does, so the net leads and the counts
 * support it. "Closing faster than they appear" is the sentence a board wants.
 */
export function RemediationProgress({ progress }: { progress: RemediationProgressData }) {
  const net = progress.resolved_30d - progress.opened_30d;
  const winning = net > 0;
  const level = net === 0 ? 'flat' : winning ? 'good' : 'bad';

  const headline =
    net === 0
      ? 'Breaking even'
      : winning
        ? `Net ${formatNumber(net)} fewer`
        : `Net ${formatNumber(Math.abs(net))} more`;

  const sentence =
    net === 0
      ? 'Your team closed exactly as many findings as appeared over the last 30 days.'
      : winning
        ? `Your team is closing findings faster than new ones appear. At this rate the backlog shrinks by ${formatNumber(
            net,
          )} ${pluralize(net, 'finding')} a month.`
        : `New findings are appearing faster than they are being closed. The backlog grew by ${formatNumber(
            Math.abs(net),
          )} ${pluralize(Math.abs(net), 'finding')} this month.`;

  return (
    <Card as="section" aria-labelledby="remediation-heading">
      <CardHead
        titleId="remediation-heading"
        title="Remediation progress"
        subtitle="Last 30 days."
      />
      <CardBody>
        <p className={`remed__headline remed__headline--${level}`}>
          <Icon name={net === 0 ? 'arrow-right' : winning ? 'arrow-down' : 'arrow-up'} size={20} />
          {headline}
        </p>
        <p className="remed__sentence">{sentence}</p>

        <dl className="remed__counts">
          <div className="remed__count">
            <dt>Opened</dt>
            <dd data-numeric>{formatNumber(progress.opened_30d)}</dd>
          </div>
          <div className="remed__count">
            <dt>Resolved</dt>
            <dd data-numeric>{formatNumber(progress.resolved_30d)}</dd>
          </div>
        </dl>
      </CardBody>
    </Card>
  );
}
