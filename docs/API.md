# ThreatSculpt v2 — Dashboard API Contract

Base path `/api/v1`. JSON only. This is the contract the web frontend is generated from —
the OpenAPI schema produced by FastAPI is the source of truth, and this document describes
the intent behind it.

## Rules that apply to every endpoint

1. **The org is never in the request.** It comes from the authenticated principal. There is no
   `userID`, `orgId`, or `tenant` parameter in any body, path, or query string. A request that
   contains one is a bug.
2. Every response is enveloped:
   ```json
   { "data": <payload>, "error": null, "meta": { "page": 1, "per_page": 50, "total": 213 } }
   ```
   `meta` present only on paginated collections.
3. Errors carry a stable machine-readable code, never a stack trace or a database message:
   ```json
   { "data": null, "error": { "code": "network_not_authorized",
     "message": "Scans require the network to be marked authorized.",
     "field": "network_id" } }
   ```
4. All collections paginate. Default 50, max 200. No unbounded query reaches the database.
5. Rate limits: `10/min` on auth endpoints per IP, `100/min` general per user.

## Auth

| Method | Path | Notes |
|---|---|---|
| POST | `/auth/register` | Creates org + owner user. Trial plan. |
| POST | `/auth/login` | → access token (body) + refresh token (`HttpOnly`, `Secure`, `SameSite=Lax` cookie) |
| POST | `/auth/refresh` | Rotates. Reuse of a spent token revokes the whole family. |
| POST | `/auth/logout` | Revokes the refresh family. |
| GET | `/auth/me` | Current user + org + role. |

Login responses are constant-time with respect to whether the email exists, and identical for
"no such user" and "wrong password". Failed attempts are rate-limited per account and per IP.

## Resources

| Method | Path | Min role |
|---|---|---|
| GET/POST | `/networks` | analyst / admin |
| GET/PATCH/DELETE | `/networks/{id}` | analyst / admin |
| GET/POST | `/business-services` | analyst |
| GET/PATCH/DELETE | `/business-services/{id}` | analyst / admin |
| GET | `/assets` | viewer — filters: `network_id`, `exposure`, `service_id`, `q` |
| GET/PATCH | `/assets/{id}` | viewer / analyst |
| PUT | `/assets/{id}/services` | analyst — map asset → business services |
| GET/POST | `/scans` | viewer / analyst |
| GET | `/scans/{id}` | viewer |
| POST | `/scans/{id}/cancel` | analyst |
| GET | `/findings` | viewer — filters: `status`, `severity`, `service_id`, `asset_id`, `kev_only`; sort by `business_risk_score` desc default |
| GET | `/findings/{id}` | viewer |
| PATCH | `/findings/{id}` | analyst — status transitions only |
| GET/POST | `/agents` | admin — POST issues an enrollment token |
| DELETE | `/agents/{id}` | admin — revoke |
| GET/POST | `/users` | admin |
| PATCH/DELETE | `/users/{id}` | admin — cannot remove the last owner |

## The views that make this a product

### `GET /dashboard/executive`
The headline screen. Not a list of CVEs.

```json
{
  "risk_posture": { "score": 72, "trend_30d": -8, "band": "elevated" },
  "services_at_risk": [
    { "service_id": "...", "name": "Payment processing", "criticality": "critical",
      "revenue_at_risk": 4200000.00, "open_findings": 12, "worst_finding_score": 94.5,
      "assets_affected": 4 }
  ],
  "exposure_summary": { "internet": 3, "dmz": 11, "internal": 84, "isolated": 6 },
  "kev_findings": 2,
  "remediation_progress": { "opened_30d": 31, "resolved_30d": 47 }
}
```

`services_at_risk` is sorted by business impact, not CVSS. That ordering is the product.

### `GET /dashboard/attack-surface`
Graph payload for the visualization: nodes are assets and business services, edges are
`supports` and `exposes`. Node weight is `business_risk_score`. Capped at 500 nodes with an
`aggregated` flag when the org exceeds it — an unbounded graph payload is how the v1 dashboard
would have died on its first real customer.

### `POST /reports`
```json
{ "type": "executive_summary", "format": "pdf",
  "scope": { "service_ids": [], "since": "2026-07-01" } }
→ 202 { "report_id": "uuid", "status": "generating" }
```
Generated async. `GET /reports/{id}` polls; `GET /reports/{id}/download` returns the artifact
via a short-lived signed URL. Report generation must never block a request thread.

## Status codes

`200` ok · `201` created · `202` accepted (async) · `400` validation · `401` unauthenticated ·
`403` authenticated but not permitted · `404` not found **or not in your org — these are
indistinguishable to the caller by design** · `409` conflict · `422` semantic validation ·
`429` rate limited.

A cross-tenant access attempt returns `404`, never `403`. `403` would confirm the resource
exists, which is an information leak.
