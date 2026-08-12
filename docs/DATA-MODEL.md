# ThreatSculpt v2 — Data Model

PostgreSQL 16+. All tables use `uuid` primary keys (`gen_random_uuid()`), `created_at`/
`updated_at` `timestamptz NOT NULL DEFAULT now()`.

Tables marked **[T]** are tenant-scoped: they carry `org_id uuid NOT NULL REFERENCES orgs(id)
ON DELETE CASCADE`, an index on `org_id`, and a Row-Level Security policy.

## Identity

### `orgs`
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| name | text NOT NULL | |
| slug | citext NOT NULL UNIQUE | |
| plan | text NOT NULL DEFAULT 'trial' | `trial` \| `standard` \| `enterprise` |
| status | text NOT NULL DEFAULT 'active' | `active` \| `suspended` |

### `users` **[T]**
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| org_id | uuid FK | |
| email | citext NOT NULL | UNIQUE `(org_id, email)` |
| password_hash | text NOT NULL | Argon2id. Never bcrypt, never plaintext. |
| full_name | text | |
| role | text NOT NULL | `owner` \| `admin` \| `analyst` \| `viewer` |
| status | text NOT NULL DEFAULT 'active' | `active` \| `disabled` |
| last_login_at | timestamptz | |

### `refresh_tokens` **[T]**
Rotating refresh tokens. Store `token_hash` (SHA-256), never the token.
`id, org_id, user_id, token_hash UNIQUE, expires_at, revoked_at, replaced_by uuid, user_agent, ip inet`

Reuse of an already-rotated token revokes the entire family — that is the detection signal for
a stolen refresh token.

## Agents

### `agents` **[T]**
| column | type | notes |
|---|---|---|
| id | uuid PK | |
| org_id | uuid FK | |
| name | text NOT NULL | |
| api_key_hash | text NOT NULL UNIQUE | SHA-256 of the key. The key is shown exactly once, at enrollment. |
| key_prefix | text NOT NULL | First 8 chars, for display/lookup. Not a secret. |
| status | text NOT NULL DEFAULT 'active' | `active` \| `revoked` |
| version | text | agent build version, self-reported |
| allowlist | cidr[] NOT NULL DEFAULT '{}' | what this agent is permitted to scan |
| last_seen_at | timestamptz | |

### `enrollment_tokens` **[T]**
One-time tokens that let a fresh agent trade up for an API key.
`id, org_id, token_hash UNIQUE, expires_at, used_at, used_by_agent_id, created_by_user_id`

Expiry is 1 hour. Single use, enforced by a conditional UPDATE, not a read-then-write.

## Inventory

### `networks` **[T]**
| column | type | notes |
|---|---|---|
| id, org_id | | |
| name | text NOT NULL | |
| cidr | cidr NOT NULL | native type — not text. UNIQUE `(org_id, cidr)` |
| authorized | boolean NOT NULL DEFAULT false | scans refuse unless true |
| authorization_note | text | who authorized, ticket ref |

### `business_services` **[T]**
The layer that makes this product different from every other scanner.

| column | type | notes |
|---|---|---|
| id, org_id | | |
| name | text NOT NULL | "Payment processing" |
| description | text | |
| criticality | text NOT NULL | `critical` \| `high` \| `medium` \| `low` |
| revenue_at_risk | numeric(14,2) | optional; annual revenue depending on this service |
| owner_name, owner_email | text | business owner, not IT owner |

### `assets` **[T]**
A host discovered by a scan or entered by hand.

| column | type | notes |
|---|---|---|
| id, org_id | | |
| network_id | uuid FK NULL | |
| ip | inet NOT NULL | UNIQUE `(org_id, ip)` |
| hostname | text | |
| mac | macaddr | |
| os_family, os_version | text | best-effort from fingerprinting |
| exposure | text NOT NULL DEFAULT 'internal' | `internet` \| `dmz` \| `internal` \| `isolated` |
| first_seen_at, last_seen_at | timestamptz | |

### `asset_services` **[T]**
Join: which business services an asset supports. `(asset_id, business_service_id)` UNIQUE.

## Scanning

### `scan_jobs` **[T]**
| column | type | notes |
|---|---|---|
| id, org_id | | |
| network_id | uuid FK | |
| target | cidr NOT NULL | must be contained by `networks.cidr` |
| profile | text NOT NULL | `discovery` \| `service` \| `vulnerability` |
| status | text NOT NULL DEFAULT 'queued' | see lifecycle in ARCHITECTURE.md |
| agent_id | uuid FK NULL | set on claim |
| lease_expires_at | timestamptz | |
| attempts | int NOT NULL DEFAULT 0 | max 3 |
| requested_by_user_id | uuid FK | |
| started_at, finished_at | timestamptz | |
| error | text | |

Index: `(org_id, status)`, and a partial index on `status = 'queued'` for the claim query.

### `scan_results` **[T]**
One row per (job, asset). Raw parsed nmap output for the host.
`id, org_id, scan_job_id, asset_id, state, raw jsonb`

### `ports` **[T]**
`id, org_id, scan_result_id, asset_id, port int, protocol text, state text, service text,
product text, version text, cpe text[]`

Note: v1 accumulated ports into a single list shared across hosts, so host #2 inherited host
#1's ports. Ports belong to a scan_result, which belongs to exactly one asset.

## Findings

### `vulnerabilities`
**Not tenant-scoped.** Global CVE reference data synced from NVD + CISA KEV.

| column | type | notes |
|---|---|---|
| cve_id | text PK | `CVE-2021-44228` |
| description | text | |
| cvss_base | numeric(3,1) | |
| cvss_vector | text | |
| severity | text | derived band |
| cpes | text[] | for matching |
| kev_listed | boolean NOT NULL DEFAULT false | CISA Known Exploited Vulnerabilities |
| kev_due_date | date | |
| exploit_maturity | text NOT NULL DEFAULT 'none' | `weaponized` \| `poc` \| `none` |
| published_at, last_synced_at | timestamptz | |

### `findings` **[T]**
A vulnerability observed on a specific asset. This is what the dashboard renders.

| column | type | notes |
|---|---|---|
| id, org_id | | |
| asset_id, port_id, scan_job_id | uuid FK | |
| cve_id | text FK → vulnerabilities | |
| status | text NOT NULL DEFAULT 'open' | `open` \| `accepted_risk` \| `remediated` \| `false_positive` |
| business_risk_score | numeric(5,2) NOT NULL | computed, see below |
| score_factors | jsonb NOT NULL | the inputs, so the UI can explain the number |
| first_seen_at, last_seen_at, resolved_at | timestamptz | |

UNIQUE `(org_id, asset_id, port_id, cve_id)` — rescanning updates `last_seen_at`, it does not
create duplicates.

`score_factors` shape:
```json
{
  "cvss_base": 10.0,
  "exploit_maturity": {"value": "weaponized", "multiplier": 1.5},
  "exposure": {"value": "internet", "multiplier": 1.4},
  "asset_criticality": {"value": "critical", "multiplier": 1.3},
  "services_affected": ["Payment processing"]
}
```

## Audit

### `audit_log` **[T]**
Append-only. No UPDATE or DELETE grant for the application role.
`id, org_id, actor_type ('user'|'agent'|'system'), actor_id, action, target_type, target_id,
metadata jsonb, ip inet, created_at`

Every authentication event, every scan job creation, every finding status change, every agent
enrollment and revocation.

## Migrations

Alembic. Every migration has a working `downgrade()`. RLS policies are created in migrations,
not applied by hand — an environment where they were forgotten is an environment with no
tenancy isolation.
