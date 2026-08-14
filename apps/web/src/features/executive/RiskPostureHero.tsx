import { SeverityMark } from '@/components/ui/SeverityMark';
import { Icon } from '@/components/ui/Icon';
import { BAND_LABEL, BAND_NARRATIVE, bandToSeverity } from '@/lib/risk';
import { toRiskBand, type RiskPosture } from '@/types/domain';

/**
 * The headline. One number, what it means in a sentence, and whether it is moving the
 * right way — in that order, because that is the order the reader cares about.
 *
 * A falling score is an improvement, so the trend is labelled "improving" / "worsening"
 * rather than shown as a bare signed number that the reader has to interpret.
 *
 * There is no sparkline. `GET /dashboard/executive` returns `score`, `trend_30d` and
 * `band` — it has never returned a daily series, so the chart that used to sit here was
 * plotting `undefined` and rendering an empty box. Restoring it means the control plane
 * returning the samples first.
 */
export function RiskPostureHero({ posture }: { posture: RiskPosture }) {
  const band = toRiskBand(posture.band);
  const severity = band ? bandToSeverity(band) : 'none';
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
          {band ? BAND_LABEL[band] : 'Unrated'}
        </p>

        <p className="hero__narrative">
          {band
            ? BAND_NARRATIVE[band]
            : 'This score has not been placed in a band this version of the dashboard recognises.'}
        </p>

        <p className={`hero__trend hero__trend--${flat ? 'flat' : improving ? 'good' : 'bad'}`}>
          <Icon name={flat ? 'arrow-right' : improving ? 'arrow-down' : 'arrow-up'} size={15} />
          <span>
            <strong>{flat ? 'Holding steady' : improving ? 'Improving' : 'Worsening'}</strong>
            {' — '}
            {trendLabel}.
          </span>
        </p>
      </div>
    </section>
  );
}
