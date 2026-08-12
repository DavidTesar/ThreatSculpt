import { createRng, makeId, type Rng } from './seed';
import { CVE_CATALOG, OS_TEMPLATES, SERVICE_TEMPLATES, severityOf } from './catalog';
import {
  CRITICALITY_MULTIPLIER,
  EXPLOIT_MATURITY_MULTIPLIER,
  EXPOSURE_MULTIPLIER,
  computeBusinessRisk,
} from '@/lib/risk';
import type {
  Agent,
  Asset,
  AssetDetail,
  BusinessService,
  Criticality,
  Exposure,
  Finding,
  FindingDetail,
  Network,
  Org,
  Port,
  ScanJob,
  ScanProfile,
  ScanStatus,
  User,
  Vulnerability,
} from '@/types/domain';

/**
 * An in-memory fixture world for a plausible mid-market customer.
 *
 * Everything downstream is *derived* from these rows — the executive dashboard, the graph,
 * the counts on every screen. That matters: if the dashboard were hand-written constants,
 * the demo would show a headline that contradicts the findings table underneath it, and
 * the one thing this product sells is that those two agree.
 */

const SEED = 20260812;
const NOW = new Date('2026-08-12T09:00:00Z').getTime();
const DAY_MS = 86_400_000;

function isoDaysAgo(days: number): string {
  return new Date(NOW - days * DAY_MS).toISOString();
}

export interface MockDb {
  org: Org;
  users: User[];
  networks: Network[];
  services: BusinessService[];
  assets: AssetDetail[];
  findings: FindingDetail[];
  scans: ScanJob[];
  agents: Agent[];
  vulnerabilities: Map<string, Vulnerability>;
  /** asset id → business service ids */
  assetServices: Map<string, string[]>;
}

/* ------------------------------------------------------------------ builders */

function buildUsers(rng: Rng, createdAt: string): User[] {
  const people: { name: string; email: string; role: User['role'] }[] = [
    { name: 'Diane Whitfield', email: 'diane.whitfield@northwind-logistics.com', role: 'owner' },
    { name: 'Marcus Oyelaran', email: 'marcus.oyelaran@northwind-logistics.com', role: 'admin' },
    {
      name: 'Priya Raghunathan',
      email: 'priya.raghunathan@northwind-logistics.com',
      role: 'analyst',
    },
    { name: 'Tomas Lindqvist', email: 'tomas.lindqvist@northwind-logistics.com', role: 'analyst' },
    { name: 'Helen Abara', email: 'helen.abara@northwind-logistics.com', role: 'viewer' },
  ];

  return people.map((person, i) => ({
    id: makeId(rng, 'u', i),
    email: person.email,
    full_name: person.name,
    role: person.role,
    status: 'active',
    last_login_at: isoDaysAgo(rng.int(0, 9)),
    created_at: createdAt,
  }));
}

function buildNetworks(rng: Rng): Network[] {
  const definitions = [
    {
      name: 'HQ corporate LAN',
      cidr: '10.0.0.0/16',
      authorized: true,
      note: 'CHG-2291 — signed off by IT Director, 2026-01-14',
    },
    {
      name: 'Datacentre — production',
      cidr: '10.40.0.0/16',
      authorized: true,
      note: 'CHG-2301 — standing authorisation, reviewed quarterly',
    },
    {
      name: 'DMZ — public services',
      cidr: '192.168.70.0/24',
      authorized: true,
      note: 'CHG-2288 — perimeter scope, signed off by CISO',
    },
    { name: 'Warehouse OT segment', cidr: '172.16.20.0/24', authorized: false, note: null },
    {
      name: 'Branch offices (EU)',
      cidr: '10.90.0.0/16',
      authorized: true,
      note: 'CHG-2340 — approved by regional IT lead',
    },
    { name: 'Guest wireless', cidr: '192.168.200.0/24', authorized: false, note: null },
  ];

  return definitions.map((def, i) => ({
    id: makeId(rng, 'n', i),
    name: def.name,
    cidr: def.cidr,
    authorized: def.authorized,
    authorization_note: def.note,
    asset_count: 0, // filled once assets exist
    created_at: isoDaysAgo(220 - i * 8),
    updated_at: isoDaysAgo(rng.int(3, 60)),
  }));
}

function buildServices(rng: Rng): BusinessService[] {
  const definitions: {
    name: string;
    description: string;
    criticality: Criticality;
    revenue: string | null;
    owner: string;
    email: string;
  }[] = [
    {
      name: 'Payment processing',
      description:
        'Card authorisation and settlement for all sales channels. A stoppage halts revenue immediately.',
      criticality: 'critical',
      revenue: '4200000.00',
      owner: 'Diane Whitfield',
      email: 'diane.whitfield@northwind-logistics.com',
    },
    {
      name: 'Customer records',
      description:
        'The customer master database. Holds personal data in scope for GDPR and state privacy law.',
      criticality: 'critical',
      revenue: '2850000.00',
      owner: 'Ruth Delacroix',
      email: 'ruth.delacroix@northwind-logistics.com',
    },
    {
      name: 'Order fulfilment',
      description:
        'Warehouse pick, pack, and dispatch scheduling. Outages delay shipments within hours.',
      criticality: 'high',
      revenue: '1750000.00',
      owner: 'Samuel Achebe',
      email: 'samuel.achebe@northwind-logistics.com',
    },
    {
      name: 'Corporate website',
      description: 'Public marketing site and customer portal front door.',
      criticality: 'medium',
      revenue: '420000.00',
      owner: 'Ana Beltrán',
      email: 'ana.beltran@northwind-logistics.com',
    },
    {
      name: 'Employee HR portal',
      description: 'Payroll, benefits, and personnel records for 1,400 staff.',
      criticality: 'high',
      revenue: null,
      owner: 'Nadia Kaur',
      email: 'nadia.kaur@northwind-logistics.com',
    },
    {
      name: 'Warehouse control systems',
      description:
        'Conveyor and sortation control. Safety-relevant; cannot be patched outside a maintenance window.',
      criticality: 'critical',
      revenue: '980000.00',
      owner: 'Piotr Zieliński',
      email: 'piotr.zielinski@northwind-logistics.com',
    },
    {
      name: 'Internal analytics',
      description: 'Reporting warehouse used by finance and operations.',
      criticality: 'low',
      revenue: null,
      owner: 'Grace Okonkwo',
      email: 'grace.okonkwo@northwind-logistics.com',
    },
  ];

  return definitions.map((def, i) => ({
    id: makeId(rng, 's', i),
    name: def.name,
    description: def.description,
    criticality: def.criticality,
    revenue_at_risk: def.revenue,
    owner_name: def.owner,
    owner_email: def.email,
    asset_count: 0,
    open_findings: 0,
    created_at: isoDaysAgo(210 - i * 5),
    updated_at: isoDaysAgo(rng.int(2, 40)),
  }));
}

const HOSTNAME_ROLES = [
  'web',
  'app',
  'db',
  'cache',
  'queue',
  'auth',
  'file',
  'print',
  'dc',
  'vpn',
  'proxy',
  'build',
  'log',
  'mail',
  'bkp',
  'plc',
  'hmi',
  'kiosk',
  'nas',
  'jump',
];

function ipInNetwork(cidr: string, index: number): string {
  const [base = '10.0.0.0', bitsRaw] = cidr.split('/');
  const bits = Number(bitsRaw ?? 24);
  const octets = base.split('.').map(Number);
  if (bits >= 24) {
    return `${octets[0]}.${octets[1]}.${octets[2]}.${(index % 250) + 2}`;
  }
  return `${octets[0]}.${octets[1]}.${Math.floor(index / 250) + 1}.${(index % 250) + 2}`;
}

function buildAssets(rng: Rng, networks: Network[], services: BusinessService[]) {
  const assets: AssetDetail[] = [];
  const assetServices = new Map<string, string[]>();

  // Assets per network. The DMZ is small and internet-facing; the OT segment is
  // deliberately isolated; the corporate LAN carries the bulk.
  const plan: {
    network: Network;
    count: number;
    exposures: Exposure[];
    weights: number[];
    serviceIdx: number[];
  }[] = [
    {
      network: networks[0]!,
      count: 58,
      exposures: ['internal', 'dmz'],
      weights: [9, 1],
      serviceIdx: [1, 4, 6],
    },
    {
      network: networks[1]!,
      count: 46,
      exposures: ['internal', 'dmz', 'internet'],
      weights: [7, 2, 1],
      serviceIdx: [0, 1, 2, 6],
    },
    {
      network: networks[2]!,
      count: 14,
      exposures: ['internet', 'dmz'],
      weights: [6, 4],
      serviceIdx: [0, 3],
    },
    {
      network: networks[3]!,
      count: 22,
      exposures: ['isolated', 'internal'],
      weights: [8, 2],
      serviceIdx: [5, 2],
    },
    { network: networks[4]!, count: 31, exposures: ['internal'], weights: [1], serviceIdx: [2, 4] },
    { network: networks[5]!, count: 9, exposures: ['isolated'], weights: [1], serviceIdx: [] },
  ];

  let index = 0;
  for (const entry of plan) {
    for (let i = 0; i < entry.count; i++) {
      const id = makeId(rng, 'a', index);
      const exposure = rng.weighted(entry.exposures, entry.weights);
      const os = rng.pick(OS_TEMPLATES);
      const role = rng.pick(HOSTNAME_ROLES);

      const portCount = rng.int(1, 4);
      const ports: Port[] = [];
      const used = new Set<number>();
      for (let p = 0; p < portCount; p++) {
        const template = rng.pick(SERVICE_TEMPLATES);
        if (used.has(template.port)) continue;
        used.add(template.port);
        ports.push({
          id: makeId(rng, 'p', index * 10 + p),
          port: template.port,
          protocol: template.protocol,
          state: 'open',
          service: template.service,
          product: template.product,
          version: template.version || null,
          cpe: template.version
            ? [`cpe:/a:${template.product.toLowerCase().replace(/\s+/g, '_')}:${template.version}`]
            : [],
        });
      }

      // Every asset maps to zero or more business services. Guest wireless maps to none,
      // which is exactly the "unmapped asset" case the mapping screen exists to fix.
      const mapped =
        entry.serviceIdx.length === 0
          ? []
          : rng.bool(0.82)
            ? [services[rng.pick(entry.serviceIdx)]!]
            : [];
      if (mapped.length > 0 && rng.bool(0.22)) {
        const extra = services[rng.pick(entry.serviceIdx)]!;
        if (extra.id !== mapped[0]!.id) mapped.push(extra);
      }

      assetServices.set(
        id,
        mapped.map((s) => s.id),
      );

      assets.push({
        id,
        network_id: entry.network.id,
        network_name: entry.network.name,
        ip: ipInNetwork(entry.network.cidr, i),
        hostname: `${role}${String(i + 1).padStart(2, '0')}.${
          entry.network.name.toLowerCase().includes('branch') ? 'eu' : 'corp'
        }.northwind.local`,
        mac: `00:1b:${rng.int(16, 254).toString(16)}:${rng.int(16, 254).toString(16)}:${rng
          .int(16, 254)
          .toString(16)}:${rng.int(16, 254).toString(16)}`,
        os_family: os.family,
        os_version: os.version,
        exposure,
        first_seen_at: isoDaysAgo(rng.int(60, 200)),
        last_seen_at: isoDaysAgo(rng.int(0, 4)),
        services: mapped.map((s) => ({ id: s.id, name: s.name, criticality: s.criticality })),
        open_findings: 0,
        max_business_risk_score: null,
        ports,
      });

      index++;
    }
  }

  return { assets, assetServices };
}

function highestCriticality(services: { criticality: Criticality }[]): Criticality {
  const order: Criticality[] = ['critical', 'high', 'medium', 'low'];
  for (const tier of order) {
    if (services.some((s) => s.criticality === tier)) return tier;
  }
  // An asset mapped to no business service is scored as low — it has no known business
  // consequence yet, which is itself worth surfacing rather than assuming the worst.
  return 'low';
}

function buildFindings(rng: Rng, assets: AssetDetail[]): FindingDetail[] {
  const findings: FindingDetail[] = [];
  let index = 0;

  for (const asset of assets) {
    // More exposed hosts and busier hosts carry more findings.
    const base = asset.exposure === 'internet' ? 4 : asset.exposure === 'dmz' ? 3 : 2;
    const count = rng.int(0, base + asset.ports.length);

    const seen = new Set<string>();
    for (let i = 0; i < count; i++) {
      const port = asset.ports.length > 0 ? rng.pick(asset.ports) : null;
      const candidates = port ? CVE_CATALOG.filter((c) => c.product === port.product) : CVE_CATALOG;
      const entry = rng.pick(candidates.length > 0 ? candidates : CVE_CATALOG);

      const key = `${port?.id ?? 'none'}:${entry.cve_id}`;
      if (seen.has(key)) continue; // honours UNIQUE (org, asset, port, cve)
      seen.add(key);

      const criticality = highestCriticality(asset.services);
      const status = rng.weighted(
        ['open', 'open', 'open', 'remediated', 'accepted_risk', 'false_positive'] as const,
        [58, 0, 0, 26, 11, 5],
      );

      const score = computeBusinessRisk(
        entry.cvss_base,
        entry.exploit_maturity,
        asset.exposure,
        criticality,
      );

      const firstSeen = rng.int(1, 90);
      const resolved = status === 'remediated' || status === 'false_positive';

      findings.push({
        id: makeId(rng, 'f', index),
        asset_id: asset.id,
        asset_ip: asset.ip,
        asset_hostname: asset.hostname,
        port_id: port?.id ?? null,
        port: port?.port ?? null,
        protocol: port?.protocol ?? null,
        service: port?.service ?? null,
        product: port?.product ?? null,
        version: port?.version ?? null,
        scan_job_id: null,
        cve_id: entry.cve_id,
        status,
        business_risk_score: score,
        severity: severityOf(entry),
        kev_listed: entry.kev_listed,
        exposure: asset.exposure,
        services_affected: asset.services.map((s) => s.name),
        score_factors: {
          cvss_base: entry.cvss_base,
          exploit_maturity: {
            value: entry.exploit_maturity,
            multiplier: EXPLOIT_MATURITY_MULTIPLIER[entry.exploit_maturity],
          },
          exposure: {
            value: asset.exposure,
            multiplier: EXPOSURE_MULTIPLIER[asset.exposure],
          },
          asset_criticality: {
            value: criticality,
            multiplier: CRITICALITY_MULTIPLIER[criticality],
          },
          services_affected: asset.services.map((s) => s.name),
        },
        first_seen_at: isoDaysAgo(firstSeen),
        last_seen_at: isoDaysAgo(rng.int(0, 3)),
        resolved_at: resolved ? isoDaysAgo(rng.int(0, firstSeen)) : null,
        vulnerability: {
          cve_id: entry.cve_id,
          description: entry.description,
          cvss_base: entry.cvss_base,
          cvss_vector: entry.cvss_vector,
          severity: severityOf(entry),
          kev_listed: entry.kev_listed,
          kev_due_date: entry.kev_due_date,
          exploit_maturity: entry.exploit_maturity,
          published_at: entry.published_at,
        },
      });
      index++;
    }
  }

  return findings;
}

function buildAgents(rng: Rng): Agent[] {
  return [
    {
      id: makeId(rng, 'g', 0),
      name: 'hq-dc-scanner-01',
      key_prefix: 'tsa_9f2c',
      status: 'active',
      version: '2.0.1',
      allowlist: ['10.0.0.0/16', '10.40.0.0/16'],
      // Agent health is judged against the wall clock, not the frozen fixture clock — a
      // heartbeat pinned to MOCK_NOW would read as "not responding" the moment real time
      // moved past it, making every healthy agent look dead in the demo.
      last_seen_at: new Date(Date.now() - 42_000).toISOString(),
      created_at: isoDaysAgo(180),
    },
    {
      id: makeId(rng, 'g', 1),
      name: 'dmz-scanner-01',
      key_prefix: 'tsa_41ab',
      status: 'active',
      version: '2.0.1',
      allowlist: ['192.168.70.0/24'],
      last_seen_at: new Date(Date.now() - 128_000).toISOString(),
      created_at: isoDaysAgo(174),
    },
    {
      id: makeId(rng, 'g', 2),
      name: 'eu-branch-scanner-01',
      key_prefix: 'tsa_7d30',
      status: 'active',
      version: '2.0.0',
      allowlist: ['10.90.0.0/16'],
      last_seen_at: isoDaysAgo(6),
      created_at: isoDaysAgo(96),
    },
    {
      id: makeId(rng, 'g', 3),
      name: 'lab-scanner-decommissioned',
      key_prefix: 'tsa_0c58',
      status: 'revoked',
      version: '1.9.4',
      allowlist: [],
      last_seen_at: isoDaysAgo(58),
      created_at: isoDaysAgo(150),
    },
  ];
}

function buildScans(rng: Rng, networks: Network[], agents: Agent[], users: User[]): ScanJob[] {
  const statuses: { status: ScanStatus; days: number; progress: number | null }[] = [
    { status: 'running', days: 0, progress: 62 },
    { status: 'queued', days: 0, progress: null },
    { status: 'completed', days: 1, progress: 100 },
    { status: 'completed', days: 2, progress: 100 },
    { status: 'failed', days: 3, progress: null },
    { status: 'completed', days: 5, progress: 100 },
    { status: 'completed', days: 8, progress: 100 },
    { status: 'cancelled', days: 11, progress: null },
    { status: 'completed', days: 14, progress: 100 },
    { status: 'completed', days: 21, progress: 100 },
  ];

  const profiles: ScanProfile[] = ['discovery', 'service', 'vulnerability'];
  const authorized = networks.filter((n) => n.authorized);

  return statuses.map((entry, i) => {
    const network = authorized[i % authorized.length]!;
    const agent = agents[i % 3]!;
    const user = users[rng.int(0, 3)]!;
    const done = entry.status === 'completed';

    return {
      id: makeId(rng, 'j', i),
      network_id: network.id,
      network_name: network.name,
      target: network.cidr,
      profile: profiles[i % profiles.length]!,
      status: entry.status,
      agent_id: entry.status === 'queued' ? null : agent.id,
      agent_name: entry.status === 'queued' ? null : agent.name,
      progress_percent: entry.progress,
      attempts: entry.status === 'failed' ? 3 : 1,
      lease_expires_at:
        entry.status === 'running' ? new Date(NOW + 18 * 60_000).toISOString() : null,
      requested_by_user_id: user.id,
      requested_by_name: user.full_name,
      started_at: entry.status === 'queued' ? null : isoDaysAgo(entry.days),
      finished_at: done || entry.status === 'failed' ? isoDaysAgo(entry.days) : null,
      error:
        entry.status === 'failed'
          ? 'Agent lease expired three times without completing. Check that hq-dc-scanner-01 can reach the target range.'
          : null,
      hosts_discovered: done ? rng.int(12, 58) : 0,
      findings_created: done ? rng.int(4, 40) : 0,
      created_at: isoDaysAgo(entry.days),
    };
  });
}

/* ------------------------------------------------------------------ assembly */

export function buildDb(): MockDb {
  const rng = createRng(SEED);
  const createdAt = isoDaysAgo(240);

  const org: Org = {
    id: makeId(rng, 'o', 0),
    name: 'Northwind Logistics',
    slug: 'northwind-logistics',
    plan: 'standard',
    status: 'active',
  };

  const users = buildUsers(rng, createdAt);
  const networks = buildNetworks(rng);
  const services = buildServices(rng);
  const { assets, assetServices } = buildAssets(rng, networks, services);
  const findings = buildFindings(rng, assets);
  const agents = buildAgents(rng);
  const scans = buildScans(rng, networks, agents, users);

  // Roll up the derived counters so every screen agrees with every other screen.
  for (const asset of assets) {
    const open = findings.filter((f) => f.asset_id === asset.id && f.status === 'open');
    asset.open_findings = open.length;
    asset.max_business_risk_score =
      open.length > 0 ? Math.max(...open.map((f) => f.business_risk_score)) : null;
  }

  for (const network of networks) {
    network.asset_count = assets.filter((a) => a.network_id === network.id).length;
  }

  for (const service of services) {
    const serviceAssets = assets.filter((a) => a.services.some((s) => s.id === service.id));
    service.asset_count = serviceAssets.length;
    service.open_findings = findings.filter(
      (f) => f.status === 'open' && serviceAssets.some((a) => a.id === f.asset_id),
    ).length;
  }

  const vulnerabilities = new Map<string, Vulnerability>();
  for (const finding of findings) vulnerabilities.set(finding.cve_id, finding.vulnerability);

  return {
    org,
    users,
    networks,
    services,
    assets,
    findings,
    scans,
    agents,
    vulnerabilities,
    assetServices,
  };
}

/** The list shape drops the joined `ports`, matching `GET /assets`. */
export function toAssetSummary(asset: AssetDetail): Asset {
  const { ports: _ports, ...summary } = asset;
  return summary;
}

/** The list shape drops the joined `vulnerability`, matching `GET /findings`. */
export function toFindingSummary(finding: FindingDetail): Finding {
  const { vulnerability: _vulnerability, ...summary } = finding;
  return summary;
}

export const MOCK_NOW = NOW;
