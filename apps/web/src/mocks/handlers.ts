import { http, HttpResponse } from 'msw';
import { buildDb, toFindingSummary, toUserSummary, type MockDb } from './db';
import { buildAttackSurface, buildExecutiveDashboard } from './derive';
import {
  endSession,
  envelope,
  errorResponse,
  guarded,
  hasRefresh,
  isAuthorized,
  issueAccessToken,
  notFound,
  startSession,
  unauthorized,
} from './session';
import { parseDecimal } from '@/lib/format';
import type {
  AdminUser,
  Agent,
  BusinessService,
  EnrollmentToken,
  Finding,
  MatchConfidence,
  Network,
  ScanJob,
} from '@/types/domain';

const BASE = '*/api/v1';

/** Mutable across a session so the demo reflects what the user just did. */
let db: MockDb = buildDb();

export function resetDb(): void {
  db = buildDb();
}

export function getDb(): MockDb {
  return db;
}

/* ------------------------------------------------------------------ helpers */

const DEFAULT_PER_PAGE = 50;
const MAX_PER_PAGE = 200;

function paginate<T>(items: readonly T[], url: URL) {
  const page = Math.max(1, Number(url.searchParams.get('page') ?? 1) || 1);
  const requested =
    Number(url.searchParams.get('per_page') ?? DEFAULT_PER_PAGE) || DEFAULT_PER_PAGE;
  const perPage = Math.min(MAX_PER_PAGE, Math.max(1, requested));
  const start = (page - 1) * perPage;
  return {
    slice: items.slice(start, start + perPage),
    meta: { page, per_page: perPage, total: items.length },
  };
}

function nextId(prefix: string): string {
  const rand = Math.floor(Math.random() * 0xffffff)
    .toString(16)
    .padStart(6, '0');
  return `${prefix}${Date.now().toString(16).slice(-4)}-0000-4000-8000-${rand}${rand.slice(0, 6)}`.slice(
    0,
    36,
  );
}

async function readJson<T>(request: Request): Promise<T> {
  return (await request.json()) as T;
}

/* ------------------------------------------------------------------ auth */

/**
 * Any password of eight characters or more is accepted, for any address in the fixture
 * org. The demo is about the dashboard, not about guessing a password — but the failure
 * path is real so the login form's error handling can be seen and tested.
 */
const authHandlers = [
  http.post(`${BASE}/auth/login`, async ({ request }) => {
    const body = await readJson<{ email: string; password: string }>(request);
    const user = db.users.find((u) => u.email.toLowerCase() === body.email?.toLowerCase().trim());

    if (!user || !body.password || body.password.length < 8) {
      // Identical for "no such user" and "wrong password" (API.md).
      return errorResponse(401, 'invalid_credentials', 'Email or password is incorrect.');
    }

    const token = startSession();
    return envelope({
      access_token: token,
      token_type: 'bearer',
      expires_at: new Date(Date.now() + 900_000).toISOString(),
    });
  }),

  http.post(`${BASE}/auth/register`, async ({ request }) => {
    const body = await readJson<{ org_name: string; email: string; full_name: string }>(request);
    if (db.users.some((u) => u.email.toLowerCase() === body.email?.toLowerCase())) {
      return errorResponse(409, 'conflict', 'An account with this email already exists.', 'email');
    }
    const token = startSession();
    // `POST /auth/register` returns the new principal beside its first token, not a bare
    // token response — the two auth endpoints do not share a shape.
    return HttpResponse.json(
      {
        data: {
          user: toUserSummary(db.users[0]!),
          org: db.org,
          access_token: token,
          expires_at: new Date(Date.now() + 900_000).toISOString(),
        },
        error: null,
      },
      { status: 201 },
    );
  }),

  http.post(`${BASE}/auth/refresh`, () => {
    if (!hasRefresh()) {
      return errorResponse(401, 'session_expired', 'Your session has expired.');
    }
    return envelope({
      access_token: issueAccessToken(),
      token_type: 'bearer',
      expires_at: new Date(Date.now() + 900_000).toISOString(),
    });
  }),

  http.post(`${BASE}/auth/logout`, () => {
    endSession();
    return envelope({ revoked: true });
  }),

  http.get(`${BASE}/auth/me`, ({ request }) => {
    if (!isAuthorized(request)) return unauthorized();
    // `MeResponse` is `{ user, org }`. The role lives on the user, not beside it.
    return envelope({ user: toUserSummary(db.users[0]!), org: db.org });
  }),
];

/* ------------------------------------------------------------------ dashboards */

const dashboardHandlers = [
  http.get(`${BASE}/dashboard/executive`, ({ request }) =>
    guarded(request, () => envelope(buildExecutiveDashboard(db))),
  ),

  http.get(`${BASE}/dashboard/attack-surface`, ({ request }) =>
    guarded(request, () => envelope(buildAttackSurface(db))),
  ),
];

/* ------------------------------------------------------------------ findings */

const CONFIDENCE_RANK: Record<MatchConfidence, number> = { high: 3, medium: 2, low: 1 };

/** `min_confidence=medium` means "medium and above". */
function meetsConfidence(actual: MatchConfidence, minimum: string): boolean {
  const floor = CONFIDENCE_RANK[minimum as MatchConfidence];
  return floor === undefined || CONFIDENCE_RANK[actual] >= floor;
}

const findingsHandlers = [
  http.get(`${BASE}/findings`, ({ request }) =>
    guarded(request, () => {
      const url = new URL(request.url);
      const status = url.searchParams.get('status');
      const severity = url.searchParams.get('severity');
      const serviceId = url.searchParams.get('service_id');
      const assetId = url.searchParams.get('asset_id');
      const kevOnly = url.searchParams.get('kev_only') === 'true';
      const minConfidence = url.searchParams.get('min_confidence');

      const serviceName = serviceId ? db.services.find((s) => s.id === serviceId)?.name : undefined;

      const filtered = db.findings.filter((finding) => {
        if (status && finding.status !== status) return false;
        if (severity && finding.cve.severity !== severity) return false;
        if (assetId && finding.asset.id !== assetId) return false;
        if (kevOnly && !finding.cve.kev_listed) return false;
        if (serviceName && !(finding.services_affected ?? []).includes(serviceName)) return false;
        if (minConfidence && !meetsConfidence(finding.match.confidence, minConfidence))
          return false;
        return true;
      });

      // The API sorts by business risk, descending, and accepts no sort parameter.
      const sorted = [...filtered].sort(
        (a, b) =>
          (parseDecimal(b.business_risk_score) ?? 0) - (parseDecimal(a.business_risk_score) ?? 0),
      );

      const { slice, meta } = paginate(sorted, url);
      return envelope<Finding[]>(slice.map(toFindingSummary), meta);
    }),
  ),

  http.get(`${BASE}/findings/:id`, ({ request, params }) =>
    guarded(request, () => {
      const finding = db.findings.find((f) => f.id === params['id']);
      return finding ? envelope(finding) : notFound('Finding');
    }),
  ),

  http.patch(`${BASE}/findings/:id`, async ({ request, params }) => {
    if (!isAuthorized(request)) return unauthorized();
    const body = await readJson<{ status: Finding['status'] }>(request);
    const index = db.findings.findIndex((f) => f.id === params['id']);
    if (index === -1) return notFound('Finding');

    const existing = db.findings[index]!;
    const resolved = body.status === 'remediated' || body.status === 'false_positive';
    const updated = {
      ...existing,
      status: body.status,
      resolved_at: resolved ? new Date().toISOString() : null,
    };

    db = { ...db, findings: db.findings.map((f, i) => (i === index ? updated : f)) };
    return envelope(updated);
  }),
];

/* ------------------------------------------------------------------ assets */

const assetHandlers = [
  http.get(`${BASE}/assets`, ({ request }) =>
    guarded(request, () => {
      const url = new URL(request.url);
      const networkId = url.searchParams.get('network_id');
      const exposure = url.searchParams.get('exposure');
      const serviceId = url.searchParams.get('service_id');
      const q = url.searchParams.get('q')?.toLowerCase().trim();

      const filtered = db.assets.filter((asset) => {
        if (networkId && asset.network_id !== networkId) return false;
        if (exposure && asset.exposure !== exposure) return false;
        if (serviceId && !(asset.services ?? []).some((s) => s.id === serviceId)) return false;
        if (q && !`${asset.ip} ${asset.hostname ?? ''}`.toLowerCase().includes(q)) return false;
        return true;
      });

      const sorted = [...filtered].sort(
        (a, b) =>
          (parseDecimal(b.worst_finding_score) ?? -1) - (parseDecimal(a.worst_finding_score) ?? -1),
      );
      const { slice, meta } = paginate(sorted, url);
      return envelope(slice, meta);
    }),
  ),

  http.get(`${BASE}/assets/:id`, ({ request, params }) =>
    guarded(request, () => {
      const asset = db.assets.find((a) => a.id === params['id']);
      return asset ? envelope(asset) : notFound('Asset');
    }),
  ),

  http.put(`${BASE}/assets/:id/services`, async ({ request, params }) => {
    if (!isAuthorized(request)) return unauthorized();
    const body = await readJson<{ service_ids: string[] }>(request);
    const index = db.assets.findIndex((a) => a.id === params['id']);
    if (index === -1) return notFound('Asset');

    const services = db.services
      .filter((s) => body.service_ids.includes(s.id))
      .map((s) => ({ id: s.id, name: s.name, criticality: s.criticality }));

    const updated = { ...db.assets[index]!, services };
    db = { ...db, assets: db.assets.map((a, i) => (i === index ? updated : a)) };
    return envelope(updated);
  }),

  http.patch(`${BASE}/assets/:id`, async ({ request, params }) => {
    if (!isAuthorized(request)) return unauthorized();
    const body = await readJson<{ hostname?: string; exposure?: string }>(request);
    const index = db.assets.findIndex((a) => a.id === params['id']);
    if (index === -1) return notFound('Asset');

    const updated = { ...db.assets[index]!, ...body } as (typeof db.assets)[number];
    db = { ...db, assets: db.assets.map((a, i) => (i === index ? updated : a)) };
    return envelope(updated);
  }),
];

/* ------------------------------------------------------------------ networks */

const networkHandlers = [
  http.get(`${BASE}/networks`, ({ request }) =>
    guarded(request, () => {
      const { slice, meta } = paginate(db.networks, new URL(request.url));
      return envelope(slice, meta);
    }),
  ),

  http.post(`${BASE}/networks`, async ({ request }) => {
    if (!isAuthorized(request)) return unauthorized();
    const body = await readJson<Partial<Network>>(request);

    if (!body.cidr || !/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(body.cidr)) {
      return errorResponse(
        422,
        'semantic_validation_error',
        'Enter a valid IPv4 CIDR block.',
        'cidr',
      );
    }
    if (db.networks.some((n) => n.cidr === body.cidr)) {
      return errorResponse(409, 'conflict', 'This CIDR is already registered.', 'cidr');
    }

    const created: Network = {
      id: nextId('n'),
      name: body.name ?? 'Untitled network',
      cidr: body.cidr,
      authorized: body.authorized ?? false,
      authorization_note: body.authorization_note ?? null,
      authorized_at: body.authorized ? new Date().toISOString() : null,
      authorized_by_user_id: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    db = { ...db, networks: [...db.networks, created] };
    return HttpResponse.json({ data: created, error: null }, { status: 201 });
  }),

  http.patch(`${BASE}/networks/:id`, async ({ request, params }) => {
    if (!isAuthorized(request)) return unauthorized();
    const body = await readJson<Partial<Network>>(request);
    const index = db.networks.findIndex((n) => n.id === params['id']);
    if (index === -1) return notFound('Network');

    const updated = { ...db.networks[index]!, ...body, updated_at: new Date().toISOString() };
    db = { ...db, networks: db.networks.map((n, i) => (i === index ? updated : n)) };
    return envelope(updated);
  }),

  http.delete(`${BASE}/networks/:id`, ({ request, params }) => {
    if (!isAuthorized(request)) return unauthorized();
    const network = db.networks.find((n) => n.id === params['id']);
    if (!network) return notFound('Network');
    const assetCount = db.assets.filter((a) => a.network_id === network.id).length;
    if (assetCount > 0) {
      return errorResponse(
        409,
        'conflict',
        `This network still has ${assetCount} assets. Remove or reassign them first.`,
      );
    }
    db = { ...db, networks: db.networks.filter((n) => n.id !== params['id']) };
    return envelope(null);
  }),
];

/* ------------------------------------------------------------------ services */

const serviceHandlers = [
  http.get(`${BASE}/business-services`, ({ request }) =>
    guarded(request, () => {
      const { slice, meta } = paginate(db.services, new URL(request.url));
      return envelope(slice, meta);
    }),
  ),

  http.post(`${BASE}/business-services`, async ({ request }) => {
    if (!isAuthorized(request)) return unauthorized();
    const body = await readJson<Partial<BusinessService>>(request);
    if (!body.name?.trim()) {
      return errorResponse(422, 'semantic_validation_error', 'A service name is required.', 'name');
    }
    const created: BusinessService = {
      id: nextId('s'),
      name: body.name,
      description: body.description ?? null,
      criticality: body.criticality ?? 'medium',
      revenue_at_risk: body.revenue_at_risk ?? null,
      owner_name: body.owner_name ?? null,
      owner_email: body.owner_email ?? null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    db = { ...db, services: [...db.services, created] };
    return HttpResponse.json({ data: created, error: null }, { status: 201 });
  }),

  http.patch(`${BASE}/business-services/:id`, async ({ request, params }) => {
    if (!isAuthorized(request)) return unauthorized();
    const body = await readJson<Partial<BusinessService>>(request);
    const index = db.services.findIndex((s) => s.id === params['id']);
    if (index === -1) return notFound('Business service');
    const updated = { ...db.services[index]!, ...body, updated_at: new Date().toISOString() };
    db = { ...db, services: db.services.map((s, i) => (i === index ? updated : s)) };
    return envelope(updated);
  }),

  http.delete(`${BASE}/business-services/:id`, ({ request, params }) => {
    if (!isAuthorized(request)) return unauthorized();
    if (!db.services.some((s) => s.id === params['id'])) return notFound('Business service');
    db = { ...db, services: db.services.filter((s) => s.id !== params['id']) };
    return envelope(null);
  }),
];

/* ------------------------------------------------------------------ scans */

const scanHandlers = [
  http.get(`${BASE}/scans`, ({ request }) =>
    guarded(request, () => {
      const url = new URL(request.url);
      const status = url.searchParams.get('status');
      const filtered = status ? db.scans.filter((s) => s.status === status) : db.scans;
      const { slice, meta } = paginate(filtered, url);
      return envelope(slice, meta);
    }),
  ),

  http.get(`${BASE}/scans/:id`, ({ request, params }) =>
    guarded(request, () => {
      const scan = db.scans.find((s) => s.id === params['id']);
      return scan ? envelope(scan) : notFound('Scan');
    }),
  ),

  http.post(`${BASE}/scans`, async ({ request }) => {
    if (!isAuthorized(request)) return unauthorized();
    const body = await readJson<{
      network_id: string;
      target: string;
      profile: ScanJob['profile'];
    }>(request);
    const network = db.networks.find((n) => n.id === body.network_id);
    if (!network) return notFound('Network');

    // The refusal that matters: an unauthorized network cannot be scanned.
    if (!network.authorized) {
      return errorResponse(
        422,
        'network_not_authorized',
        'Scans require the network to be marked authorized.',
        'network_id',
      );
    }

    const created: ScanJob = {
      id: nextId('j'),
      network_id: network.id,
      target: body.target || network.cidr,
      profile: body.profile,
      status: 'queued',
      agent_id: null,
      progress_percent: null,
      attempts: 0,
      lease_expires_at: null,
      requested_by_user_id: db.users[0]!.id,
      started_at: null,
      finished_at: null,
      error: null,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    db = { ...db, scans: [created, ...db.scans] };
    return HttpResponse.json({ data: created, error: null }, { status: 201 });
  }),

  http.post(`${BASE}/scans/:id/cancel`, ({ request, params }) => {
    if (!isAuthorized(request)) return unauthorized();
    const index = db.scans.findIndex((s) => s.id === params['id']);
    if (index === -1) return notFound('Scan');

    const scan = db.scans[index]!;
    if (scan.status === 'completed' || scan.status === 'failed') {
      return errorResponse(409, 'conflict', 'This scan has already finished.');
    }
    const updated: ScanJob = {
      ...scan,
      status: 'cancelled',
      finished_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };
    db = { ...db, scans: db.scans.map((s, i) => (i === index ? updated : s)) };
    return envelope(updated);
  }),
];

/* ------------------------------------------------------------------ agents */

const agentHandlers = [
  http.get(`${BASE}/agents`, ({ request }) =>
    guarded(request, () => {
      const { slice, meta } = paginate(db.agents, new URL(request.url));
      return envelope(slice, meta);
    }),
  ),

  http.post(`${BASE}/agents`, async ({ request }) => {
    if (!isAuthorized(request)) return unauthorized();
    // `EnrollmentTokenCreate` carries an optional note and nothing else. The agent row
    // does not exist yet — it appears when something enrols with this token.
    await readJson<{ note?: string | null }>(request);

    const random = Array.from({ length: 4 }, () =>
      Math.floor(Math.random() * 0xffffffff).toString(36),
    ).join('');

    const token: EnrollmentToken = {
      enrollment_token: `tse_${random}`,
      // Enrollment tokens expire in 1 hour (DATA-MODEL.md).
      expires_at: new Date(Date.now() + 3_600_000).toISOString(),
    };

    return HttpResponse.json({ data: token, error: null }, { status: 201 });
  }),

  http.delete(`${BASE}/agents/:id`, ({ request, params }) => {
    if (!isAuthorized(request)) return unauthorized();
    const index = db.agents.findIndex((a) => a.id === params['id']);
    if (index === -1) return notFound('Agent');
    const updated: Agent = {
      ...db.agents[index]!,
      status: 'revoked',
      allowlist: [],
      updated_at: new Date().toISOString(),
    };
    db = { ...db, agents: db.agents.map((a, i) => (i === index ? updated : a)) };
    return envelope(updated);
  }),
];

/* ------------------------------------------------------------------ users */

const userHandlers = [
  http.get(`${BASE}/users`, ({ request }) =>
    guarded(request, () => {
      const { slice, meta } = paginate(db.users, new URL(request.url));
      return envelope(slice, meta);
    }),
  ),

  http.post(`${BASE}/users`, async ({ request }) => {
    if (!isAuthorized(request)) return unauthorized();
    const body = await readJson<{
      email: string;
      full_name?: string | null;
      role?: string;
      password: string;
    }>(request);
    if (db.users.some((u) => u.email.toLowerCase() === body.email?.toLowerCase())) {
      return errorResponse(409, 'conflict', 'A user with this email already exists.', 'email');
    }
    if (!body.password || body.password.length < 12) {
      return errorResponse(
        422,
        'semantic_validation_error',
        'An initial password of at least 12 characters is required.',
        'password',
      );
    }
    // The account starts unverified, exactly like a self-service sign-up.
    const created: AdminUser = {
      id: nextId('u'),
      email: body.email,
      full_name: body.full_name ?? null,
      role: body.role ?? 'viewer',
      status: 'active',
      last_login_at: null,
      locked: false,
      verified: false,
    };
    db = { ...db, users: [...db.users, created] };
    return HttpResponse.json({ data: created, error: null }, { status: 201 });
  }),

  http.patch(`${BASE}/users/:id`, async ({ request, params }) => {
    if (!isAuthorized(request)) return unauthorized();
    const body = await readJson<Partial<AdminUser>>(request);
    const index = db.users.findIndex((u) => u.id === params['id']);
    if (index === -1) return notFound('User');

    const existing = db.users[index]!;
    // "cannot remove the last owner" (API.md) — demoting the last one is the same loss.
    if (existing.role === 'owner' && body.role && body.role !== 'owner') {
      const owners = db.users.filter((u) => u.role === 'owner').length;
      if (owners <= 1) {
        return errorResponse(
          409,
          'last_owner',
          'This is the only owner. Promote another user to owner first.',
          'role',
        );
      }
    }

    const updated = { ...existing, ...body };
    db = { ...db, users: db.users.map((u, i) => (i === index ? updated : u)) };
    return envelope(updated);
  }),

  http.delete(`${BASE}/users/:id`, ({ request, params }) => {
    if (!isAuthorized(request)) return unauthorized();
    const user = db.users.find((u) => u.id === params['id']);
    if (!user) return notFound('User');
    if (user.role === 'owner' && db.users.filter((u) => u.role === 'owner').length <= 1) {
      return errorResponse(409, 'last_owner', 'You cannot remove the last owner.');
    }
    // DELETE deactivates rather than deleting, so the audit trail keeps naming the user.
    const deactivated: AdminUser = { ...user, status: 'disabled' };
    db = { ...db, users: db.users.map((u) => (u.id === user.id ? deactivated : u)) };
    return envelope(deactivated);
  }),
];

export const handlers = [
  ...authHandlers,
  ...dashboardHandlers,
  ...findingsHandlers,
  ...assetHandlers,
  ...networkHandlers,
  ...serviceHandlers,
  ...scanHandlers,
  ...agentHandlers,
  ...userHandlers,
];
