import { Card, CardHead, CardBody } from '@/components/ui/Card';
import { Icon } from '@/components/ui/Icon';
import { explainScore } from '@/lib/risk';
import { formatMultiplier, formatScore } from '@/lib/format';
import type { ScoreFactors } from '@/types/domain';

/**
 * Why this finding scores what it scores.
 *
 * "An unexplained number is not persuasive to the audience this product targets"
 * (ARCHITECTURE.md). So this shows the actual arithmetic — the CVSS base, each multiplier,
 * what each one evaluated to and why, and the running total after each step — ending on a
 * figure that matches the headline exactly.
 *
 * The multiplier chips are tinted by direction (above 1 raises the score, below 1 lowers
 * it) and also carry an explicit ↑/↓, so the direction survives without colour.
 */
export function ScoreExplanation({ factors, score }: { factors: ScoreFactors; score: number }) {
  const { base, steps } = explainScore(factors);

  return (
    <Card as="section" aria-labelledby="explain-heading">
      <CardHead
        titleId="explain-heading"
        title="Why this score"
        subtitle="The published CVSS severity, adjusted for what this particular asset does for your business."
      />
      <CardBody flush>
        <div className="explain">
          <div className="explain__row explain__row--base">
            <div>
              <span className="explain__label">CVSS base score</span>
              <span className="explain__value">
                The vendor-published technical severity, identical for every organisation.
              </span>
            </div>
            <span className="explain__mult">start</span>
            <span className="explain__running" data-numeric>
              {base.toFixed(1)}
            </span>
          </div>

          {steps.map((step) => {
            const direction = step.multiplier > 1 ? 'up' : step.multiplier < 1 ? 'down' : 'flat';
            return (
              <div className="explain__row" key={step.key}>
                <div>
                  <span className="explain__label">{step.label}</span>
                  <span className="explain__value">{step.value}</span>
                  <p className="explain__gloss">{step.gloss}</p>
                </div>
                <span
                  className={`explain__mult${direction !== 'flat' ? ` explain__mult--${direction}` : ''}`}
                >
                  {direction === 'up' ? '↑ ' : direction === 'down' ? '↓ ' : ''}
                  {formatMultiplier(step.multiplier)}
                </span>
                <span className="explain__running" data-numeric>
                  {step.runningTotal.toFixed(1)}
                </span>
              </div>
            );
          })}

          <div className="explain__row explain__row--total">
            <div>
              <span className="explain__label">Business risk score</span>
              {factors.services_affected.length > 0 ? (
                <>
                  <span className="explain__value">
                    Because this asset supports{' '}
                    {factors.services_affected.length === 1 ? 'a service' : 'services'} you have
                    marked as business-critical:
                  </span>
                  <div className="explain__services">
                    {factors.services_affected.map((name) => (
                      <span className="chip" key={name}>
                        <Icon name="service" size={11} />
                        {name}
                      </span>
                    ))}
                  </div>
                </>
              ) : (
                <span className="explain__value">
                  This asset is not mapped to any business service, so it is scored at the lowest
                  criticality. Mapping it will make this number more accurate.
                </span>
              )}
            </div>
            <span />
            <span className="explain__total" data-numeric>
              {formatScore(score)}
            </span>
          </div>
        </div>
      </CardBody>
    </Card>
  );
}
