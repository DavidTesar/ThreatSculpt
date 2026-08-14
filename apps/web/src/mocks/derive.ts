import type { MockDb } from './db';
import { MOCK_NOW } from './db';
import { bandForScore } from '@/lib/risk';
import { parseDecimal } from '@/lib/format';
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

/** Node id namespaces, matching `attack_surface.py`. Ids are shared across node kinds. */
const NODE_ASSET = 'asset';
const NODE_SERVICE = 'business_service';
const NODE_EXPOSURE = 'exposure';
const NODE_AGGREGATE = 'aggregated_assets';

const EDGE_SUPPORTS = 'supports';
const EDGE_EXPOSES = 'exposes';

/**
 * Everything the dashboards show is computed from the same rows the tables show. The
 * control plane does this in SQL; doing it the same way here keeps the mock honest — if a
 * finding is marked remediated in the UI, the headline moves with it.
 *
 * Shapes are the generated ones, so a payload this file cannot construct is a payload the
 * real API does not return either. That is the point: the mock server used to emit a
 * 30-day `history` array, a `generated_at` stamp, per-node `open_findings` and bare uuid
 * node ids, none of which the control plane has ever sent.
 */

function openFindings(db: MockDb) {
  return db.findings.filter((f) => f.status === 'open');
}

function scoreOf(finding: { business_risk_score: string }): number {
  return parseDecimal(finding.business_risk_score) ?? 0;
}

/**
 * Posture is the mean of the top ten open findings rather than an average over all of
 * them. Averaging thousands of low findings would drown out the handful that actually
 * matter, and would make the number fall as the estate grows — which is backwards.
 */
export function riskScore(db: MockDb): number {
  const open = openFindings(db);
  if (open.length === 0) return 0;
  const top = [...open].sort((a, b) => scoreOf(b) - scoreOf(a)).slice(0, 10);
  const mean = top.reduce((sum, f) => sum + scoreOf(f), 0) / top.length;
  return Math.round(mean);
}

/** Timestamps are optional and nullable on every finding field the API returns. */
function isSince(iso: string | null | undefined, since: number): boolean {
  return iso !== null && iso !== undefined && new Date(iso).getTime() >= since;
}

/** Asset ids supporting a given business service. */
function assetIdsForService(db: MockDb, serviceId: string): Set<string> {
  return new Set(
    db.assets.filter((a) => (a.services ?? []).some((s) => s.id === serviceId)).map((a) => a.id),
  );
}

export function buildExecutiveDashboard(db: MockDb): ExecutiveDashboard {
  const open = openFindings(db);
  const score = riskScore(db);

  const servicesAtRisk: ServiceAtRisk[] = db.services
    .map((service) => {
      const serviceAssetIds = assetIdsForService(db, service.id);
      const serviceFindings = open.filter((f) => serviceAssetIds.has(f.asset.id));
      const affected = new Set(serviceFindings.map((f) => f.asset.id));

      return {
        service_id: service.id,
        name: service.name,
        criticality: service.criticality,
        revenue_at_risk: service.revenue_at_risk,
        open_findings: serviceFindings.length,
        worst_finding_score:
          serviceFindings.length > 0
            ? Math.max(...serviceFindings.map(scoreOf)).toFixed(2)
            : '0.00',
        assets_affected: affected.size,
      };
    })
    .filter((entry) => entry.open_findings > 0);

  // "sorted by business impact, not CVSS. That ordering is the product." (API.md)
  // Revenue at risk leads; the worst technical score only breaks ties between services
  // with the same money attached.
  const rankedServices = [...servicesAtRisk].sort((a, b) => {
    const revenueA = parseDecimal(a.revenue_at_risk) ?? 0;
    const revenueB = parseDecimal(b.revenue_at_risk) ?? 0;
    if (revenueA !== revenueB) return revenueB - revenueA;
    return (parseDecimal(b.worst_finding_score) ?? 0) - (parseDecimal(a.worst_finding_score) ?? 0);
  });

  const exposure_summary = db.assets.reduce<ExposureSummary>(
    (acc, asset) => ({ ...acc, [asset.exposure]: acc[asset.exposure] + 1 }),
    { internet: 0, dmz: 0, internal: 0, isolated: 0 },
  );

  const thirtyDaysAgo = MOCK_NOW - 30 * DAY_MS;
  const opened30d = db.findings.filter((f) => isSince(f.first_seen_at, thirtyDaysAgo)).length;
  const resolved30d = db.findings.filter((f) => isSince(f.resolved_at, thirtyDaysAgo)).length;

  return {
    risk_posture: {
      score,
      // A single trailing-30-day delta, not a daily series: the API has never returned
      // one. Net new findings move the posture up; net closures move it down.
      trend_30d: opened30d - resolved30d,
      band: bandForScore(score),
    },
    services_at_risk: rankedServices,
    exposure_summary,
    kev_findings: open.filter((f) => f.cve.kev_listed).length,
    remediation_progress: { opened_30d: opened30d, resolved_30d: resolved30d },
  };
}

/* ------------------------------------------------------------------ graph */

/**
 * Nodes are exposure tiers, assets and business services; edges are `exposes`
 * (exposure tier → asset) and `supports` (asset → business service).
 *
 * Node ids are namespaced — `asset:<uuid>`, `business_service:<uuid>` — because the three
 * kinds share one id space in a single graph, and `weight` is a decimal string like every
 * other `numeric` the API returns.
 *
 * Past the 500-node cap the asset nodes are rolled up per (service, exposure) into
 * `aggregated_assets` nodes and `aggregated: true` is set. API.md is explicit about why:
 * "an unbounded graph payload is how the v1 dashboard would have died on its first real
 * customer."
 */
export function buildAttackSurface(db: MockDb): AttackSurfaceGraph {
  const openByService = new Map<string, number>();
  for (const service of db.services) {
    const ids = assetIdsForService(db, service.id);
    openByService.set(
      service.id,
      db.findings.filter((f) => f.status === 'open' && ids.has(f.asset.id)).length,
    );
  }

  const serviceNodes: GraphNode[] = db.services.map((service) => {
    const openCount = openByService.get(service.id) ?? 0;
    return {
      id: `${NODE_SERVICE}:${service.id}`,
      type: NODE_SERVICE,
      label: service.name,
      weight: (openCount > 0 ? Math.min(100, 40 + openCount * 2) : 25).toFixed(2),
      exposure: null,
      criticality: service.criticality,
      represents: null,
    };
  });

  const usedExposures = [...new Set(db.assets.map((a) => a.exposure))];
  const exposureNodes: GraphNode[] = usedExposures.map((value) => ({
    id: `${NODE_EXPOSURE}:${value}`,
    type: NODE_EXPOSURE,
    label: value,
    weight: '0.00',
    exposure: value,
    criticality: null,
    represents: null,
  }));

  const assetNodes: GraphNode[] = db.assets.map((asset) => ({
    id: `${NODE_ASSET}:${asset.id}`,
    type: NODE_ASSET,
    label: asset.hostname ?? asset.ip,
    weight: asset.worst_finding_score ?? '0.00',
    exposure: asset.exposure,
    criticality: null,
    represents: null,
  }));

  const totalAssets = db.assets.length;

  if (serviceNodes.length + exposureNodes.length + assetNodes.length <= NODE_CAP) {
    const edges: GraphEdge[] = [];
    for (const asset of db.assets) {
      edges.push({
        source: `${NODE_EXPOSURE}:${asset.exposure}`,
        target: `${NODE_ASSET}:${asset.id}`,
        type: EDGE_EXPOSES,
      });
      for (const service of asset.services ?? []) {
        edges.push({
          source: `${NODE_ASSET}:${asset.id}`,
          target: `${NODE_SERVICE}:${service.id}`,
          type: EDGE_SUPPORTS,
        });
      }
    }
    return {
      nodes: [...serviceNodes, ...exposureNodes, ...assetNodes],
      edges,
      aggregated: false,
      node_cap: NODE_CAP,
      total_assets: totalAssets,
    };
  }

  const buckets = new Map<string, { service: string; exposure: Exposure; ids: string[] }>();
  for (const asset of db.assets) {
    for (const service of asset.services ?? []) {
      const key = `${service.id}:${asset.exposure}`;
      const bucket = buckets.get(key) ?? { service: service.id, exposure: asset.exposure, ids: [] };
      buckets.set(key, { ...bucket, ids: [...bucket.ids, asset.id] });
    }
  }

  const aggregateNodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  for (const [key, bucket] of buckets) {
    const members = db.assets.filter((a) => bucket.ids.includes(a.id));
    const worst = Math.max(0, ...members.map((a) => parseDecimal(a.worst_finding_score) ?? 0));
    const id = `${NODE_AGGREGATE}:${key}`;
    aggregateNodes.push({
      id,
      type: NODE_AGGREGATE,
      label: `${members.length} ${bucket.exposure} assets`,
      weight: worst.toFixed(2),
      exposure: bucket.exposure,
      criticality: null,
      represents: members.length,
    });
    edges.push({
      source: id,
      target: `${NODE_SERVICE}:${bucket.service}`,
      type:
        bucket.exposure === 'internet' || bucket.exposure === 'dmz' ? EDGE_EXPOSES : EDGE_SUPPORTS,
    });
  }

  return {
    nodes: [...serviceNodes, ...aggregateNodes],
    edges,
    aggregated: true,
    node_cap: NODE_CAP,
    total_assets: totalAssets,
  };
}
