import type { MockDb } from './db';
import { MOCK_NOW } from './db';
import { bandForScore } from '@/lib/risk';
import type {
  AttackSurfaceGraph,
  ExecutiveDashboard,
  Exposure,
  ExposureSummary,
  GraphEdge,
  GraphNode,
  ServiceAtRisk,
} from '@/types/domain';

const DAY_MS = 86_400_000;
const NODE_CAP = 500;

/**
 * Everything the dashboards show is computed from the same rows the tables show. The
 * control plane does this in SQL; doing it the same way here keeps the mock honest — if a
 * finding is marked remediated in the UI, the headline moves with it.
 */

function openFindings(db: MockDb) {
  return db.findings.filter((f) => f.status === 'open');
}

/**
 * Posture is the mean of the top ten open findings rather than an average over all of
 * them. Averaging thousands of low findings would drown out the handful that actually
 * matter, and would make the number fall as the estate grows — which is backwards.
 */
export function riskScore(db: MockDb): number {
  const open = openFindings(db);
  if (open.length === 0) return 0;
  const top = [...open].sort((a, b) => b.business_risk_score - a.business_risk_score).slice(0, 10);
  const mean = top.reduce((sum, f) => sum + f.business_risk_score, 0) / top.length;
  return Math.round(mean);
}

function riskHistory(current: number): { date: string; score: number }[] {
  // A plausible 30-day walk that lands exactly on today's computed score, so the trend
  // line and the headline never disagree.
  const points: { date: string; score: number }[] = [];
  let value = current + 8;
  for (let daysAgo = 29; daysAgo >= 0; daysAgo--) {
    const drift = Math.sin(daysAgo / 3.1) * 2.2 - 0.28;
    value = Math.max(0, Math.min(100, value + drift));
    points.push({
      date: new Date(MOCK_NOW - daysAgo * DAY_MS).toISOString().slice(0, 10),
      score: daysAgo === 0 ? current : Math.round(value),
    });
  }
  return points;
}

export function buildExecutiveDashboard(db: MockDb): ExecutiveDashboard {
  const open = openFindings(db);
  const score = riskScore(db);
  const history = riskHistory(score);
  const oldest = history[0]?.score ?? score;

  const servicesAtRisk: ServiceAtRisk[] = db.services
    .map((service) => {
      const serviceAssetIds = new Set(
        db.assets.filter((a) => a.services.some((s) => s.id === service.id)).map((a) => a.id),
      );
      const serviceFindings = open.filter((f) => serviceAssetIds.has(f.asset_id));
      const affected = new Set(serviceFindings.map((f) => f.asset_id));

      return {
        service_id: service.id,
        name: service.name,
        criticality: service.criticality,
        revenue_at_risk: service.revenue_at_risk,
        open_findings: serviceFindings.length,
        worst_finding_score:
          serviceFindings.length > 0
            ? Math.max(...serviceFindings.map((f) => f.business_risk_score))
            : 0,
        assets_affected: affected.size,
      };
    })
    .filter((entry) => entry.open_findings > 0);

  // "sorted by business impact, not CVSS. That ordering is the product." (API.md)
  // Revenue at risk leads; the worst technical score only breaks ties between services
  // with the same money attached.
  servicesAtRisk.sort((a, b) => {
    const revenueA = Number(a.revenue_at_risk ?? 0);
    const revenueB = Number(b.revenue_at_risk ?? 0);
    if (revenueA !== revenueB) return revenueB - revenueA;
    return b.worst_finding_score - a.worst_finding_score;
  });

  const exposure_summary = db.assets.reduce<ExposureSummary>(
    (acc, asset) => ({ ...acc, [asset.exposure]: acc[asset.exposure] + 1 }),
    { internet: 0, dmz: 0, internal: 0, isolated: 0 },
  );

  const thirtyDaysAgo = MOCK_NOW - 30 * DAY_MS;
  const opened30d = db.findings.filter(
    (f) => new Date(f.first_seen_at).getTime() >= thirtyDaysAgo,
  ).length;
  const resolved30d = db.findings.filter(
    (f) => f.resolved_at !== null && new Date(f.resolved_at).getTime() >= thirtyDaysAgo,
  ).length;

  return {
    risk_posture: {
      score,
      trend_30d: score - oldest,
      band: bandForScore(score),
      history,
    },
    services_at_risk: servicesAtRisk,
    exposure_summary,
    kev_findings: open.filter((f) => f.kev_listed).length,
    remediation_progress: { opened_30d: opened30d, resolved_30d: resolved30d },
    generated_at: new Date(MOCK_NOW).toISOString(),
  };
}

/* ------------------------------------------------------------------ graph */

/**
 * Nodes are assets and business services; edges are `supports` (asset → service) and
 * `exposes` (asset → service, when the asset is internet-facing or in the DMZ).
 *
 * Past the 500-node cap the asset nodes are rolled up per (service, exposure) into
 * `aggregate` nodes and `aggregated: true` is set. API.md is explicit about why: "an
 * unbounded graph payload is how the v1 dashboard would have died on its first real
 * customer."
 */
export function buildAttackSurface(db: MockDb): AttackSurfaceGraph {
  const serviceNodes: GraphNode[] = db.services.map((service) => ({
    id: service.id,
    kind: 'service',
    label: service.name,
    weight: service.open_findings > 0 ? Math.min(100, 40 + service.open_findings * 2) : 25,
    exposure: null,
    criticality: service.criticality,
    open_findings: service.open_findings,
    represents: null,
  }));

  const assetNodes: GraphNode[] = db.assets.map((asset) => ({
    id: asset.id,
    kind: 'asset',
    label: asset.hostname ?? asset.ip,
    weight: asset.max_business_risk_score ?? 0,
    exposure: asset.exposure,
    criticality: null,
    open_findings: asset.open_findings,
    represents: null,
  }));

  const totalNodes = serviceNodes.length + assetNodes.length;

  if (totalNodes <= NODE_CAP) {
    const edges: GraphEdge[] = [];
    for (const asset of db.assets) {
      for (const service of asset.services) {
        edges.push({
          source: asset.id,
          target: service.id,
          kind: asset.exposure === 'internet' || asset.exposure === 'dmz' ? 'exposes' : 'supports',
        });
      }
    }
    return {
      nodes: [...serviceNodes, ...assetNodes],
      edges,
      aggregated: false,
      node_cap: NODE_CAP,
      total_nodes: totalNodes,
    };
  }

  const buckets = new Map<string, { service: string; exposure: Exposure; ids: string[] }>();
  for (const asset of db.assets) {
    for (const service of asset.services) {
      const key = `${service.id}:${asset.exposure}`;
      const bucket = buckets.get(key) ?? { service: service.id, exposure: asset.exposure, ids: [] };
      buckets.set(key, { ...bucket, ids: [...bucket.ids, asset.id] });
    }
  }

  const aggregateNodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  for (const [key, bucket] of buckets) {
    const members = db.assets.filter((a) => bucket.ids.includes(a.id));
    const worst = Math.max(0, ...members.map((a) => a.max_business_risk_score ?? 0));
    aggregateNodes.push({
      id: `agg-${key}`,
      kind: 'aggregate',
      label: `${members.length} ${bucket.exposure} assets`,
      weight: worst,
      exposure: bucket.exposure,
      criticality: null,
      open_findings: members.reduce((sum, a) => sum + a.open_findings, 0),
      represents: members.length,
    });
    edges.push({
      source: `agg-${key}`,
      target: bucket.service,
      kind: bucket.exposure === 'internet' || bucket.exposure === 'dmz' ? 'exposes' : 'supports',
    });
  }

  return {
    nodes: [...serviceNodes, ...aggregateNodes],
    edges,
    aggregated: true,
    node_cap: NODE_CAP,
    total_nodes: totalNodes,
  };
}
