import { Area, AreaChart, ResponsiveContainer, Tooltip, YAxis } from 'recharts';
import { ChartTable } from '@/components/charts/ChartTable';
import { SeverityMark } from '@/components/ui/SeverityMark';
import { Icon } from '@/components/ui/Icon';
import { BAND_LABEL, BAND_NARRATIVE, bandToSeverity } from '@/lib/risk';
import { formatDate } from '@/lib/format';
import type { RiskPosture } from '@/types/domain';

/**
 * The headline. One number, what it means in a sentence, and whether it is moving the
 * right way — in that order, because that is the order the reader cares about.
 *
 * A falling score is an improvement, so the trend is labelled "improving" / "worsening"
 * rather than shown as a bare signed number that the reader has to interpret.
 */
export function RiskPostureHero({ posture }: { posture: RiskPosture }) {
  const severity = bandToSeverity(posture.band);
  const improving = posture.trend_30d < 0;
  const flat = posture.trend_30d === 0;

  const trendLabel = flat
    ? 'Unchanged over 30 days'
    : `${Math.abs(posture.trend_30d)} points ${improving ? 'lower' : 'higher'} than 30 days ago`;

  return (
    <section className="hero" aria-labelledby="posture-heading">
      <div className="hero__primary">
        <p className="eyebrow" id="posture-heading">
          Overall risk posture
        </p>

        <div className="hero__scoreline">
          <span className="hero__score" data-numeric>
            {posture.score}
          </span>
          <span className="hero__scaleof">/ 100</span>
        </div>

        <p className={`hero__band hero__band--${severity}`}>
          <SeverityMark severity={severity} size={14} />
          {BAND_LABEL[posture.band]}
        </p>

        <p className="hero__narrative">{BAND_NARRATIVE[posture.band]}</p>

        <p className={`hero__trend hero__trend--${flat ? 'flat' : improving ? 'good' : 'bad'}`}>
          <Icon name={flat ? 'arrow-right' : improving ? 'arrow-down' : 'arrow-up'} size={15} />
          <span>
            <strong>{flat ? 'Holding steady' : improving ? 'Improving' : 'Worsening'}</strong>
            {' — '}
            {trendLabel}.
          </span>
        </p>
      </div>

      <div className="hero__chart">
        <p className="hero__chartlabel">30-day trend</p>
        <div
          className="hero__chartbox"
          role="img"
          aria-label={`Risk posture over the last 30 days. ${trendLabel}. Currently ${posture.score} out of 100.`}
        >
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={posture.history} margin={{ top: 4, right: 0, bottom: 0, left: 0 }}>
              <defs>
                <linearGradient id="postureFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--chart-area-from)" />
                  <stop offset="100%" stopColor="var(--chart-area-to)" />
                </linearGradient>
              </defs>
              <YAxis domain={[0, 100]} hide />
              <Tooltip
                contentStyle={{
                  background: 'var(--surface-raised)',
                  border: '1px solid var(--line-strong)',
                  borderRadius: 8,
                  fontSize: 12,
                  color: 'var(--ink)',
                }}
                labelStyle={{ color: 'var(--ink-muted)' }}
                formatter={(value: number) => [`${value} / 100`, 'Risk posture']}
              />
              <Area
                type="monotone"
                dataKey="score"
                stroke="var(--chart-line)"
                strokeWidth={2}
                fill="url(#postureFill)"
                isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <ChartTable
          summary="View trend as a table"
          caption="Risk posture sampled daily, oldest first."
          headers={['Date', 'Score']}
          rows={posture.history.map((point) => [formatDate(point.date), point.score])}
        />
      </div>
    </section>
  );
}
