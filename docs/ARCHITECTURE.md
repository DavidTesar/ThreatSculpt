# ThreatSculpt v2 — Architecture

## Product

ThreatSculpt translates network vulnerability scan output into **business impact** that a
non-technical executive can act on. The differentiator is not scanning — nmap already does
that. It is the mapping layer: *asset → business service → exposure → money and obligation*.

## Deployment model

Multi-tenant SaaS control plane + customer-installed scan agent.

```
  Customer network                      ThreatSculpt cloud
  ┌────────────────────┐                ┌───────────────────────────┐
  │  scan-agent        │  outbound only │   control-plane (FastAPI) │
  │  - nmap            │ ─────────────► │   - REST API              │
  │  - result parser   │   HTTPS/443    │   - tenancy enforcement   │
  │  - job poller      │                │   - risk scoring          │
  └────────────────────┘                │   - report generation     │
                                        └───────────┬───────────────┘
  ┌────────────────────┐                            │
  │  operator browser  │ ───────────────────────────┤
  │  web (React/TS)    │        HTTPS               │
  └────────────────────┘                ┌───────────▼───────────────┐
                                        │   PostgreSQL              │
                                        └───────────────────────────┘
```

**The agent never accepts inbound connections.** It polls the control plane for jobs and
pushes results. This is the single most important constraint: it means the customer opens no
firewall ports, which is what makes the product installable in an enterprise at all.

## Why these choices

| Decision | Rationale |
|---|---|
| Python/FastAPI control plane | Same language as the agent, so both sides of the ingest contract are written against the same Pydantic idiom. FastAPI also publishes an OpenAPI schema at `/openapi.json`, which is what makes the contract checkable — see the caveat below. |
| PostgreSQL, not MongoDB | Tenancy isolation is the core security property. Row-level scoping against a relational schema with foreign keys is enforceable and auditable; the v1 Mongo schema had no constraint preventing cross-tenant reads, and that is exactly the bug it shipped. |
| Agent polls, never listens | No inbound firewall rules at the customer. Also means a compromised control plane cannot be used to make agents scan arbitrary targets without passing job validation. |
| React + TypeScript + Vite | Strict TypeScript across the client, so a shape the frontend gets wrong *about itself* fails at build time. Note this does **not** extend to the backend contract — see the caveat below. |

## Tenancy model

Every row that holds customer data carries `org_id`. Three layers enforce it:

1. **Schema** — `org_id` is `NOT NULL` with a foreign key on every tenant-scoped table.
2. **Query layer** — repositories take an `OrgScope` and inject the `org_id` predicate. There
   is no repository method that queries a tenant table without a scope.
3. **PostgreSQL Row-Level Security** — a policy on each tenant table matching
   `current_setting('threatsculpt.org_id')`, set per-transaction from the authenticated
   principal. This is the backstop for a bug in layer 2.

**No endpoint ever reads a tenant identifier from the request body or query string.** The org
is derived from the authenticated principal only. v1's `POST /getUserData {userID}` is the
canonical example of the bug this rules out.

## Repository layout

```
apps/control-plane/     FastAPI service — API, tenancy, risk scoring, reports
apps/scan-agent/        On-prem daemon — job poller, nmap runner, result submitter
apps/web/               React + TS dashboard
deploy/                 docker-compose, environment template, end-to-end proof
docs/                   This directory
```

### Caveat: nothing mechanically enforces the contract

There is no shared `packages/contracts/`. Each of the three apps declares its own models
against *this documentation*, and the web client's types are hand-maintained rather than
generated from the OpenAPI schema. So a backend response-shape change does **not** break
the frontend build — it fails at runtime, in front of a customer.

This is a known weakness, and it has already bitten once: the agent routes return the
standard `{data, error, meta}` envelope, but AGENT-PROTOCOL.md originally documented bare
response bodies, so an agent written literally against the spec could not enrol. It was
caught by `deploy/e2e.sh`, which is the only thing standing between a contract drift and
production.

Two consequences worth internalising:

1. **Treat every contract statement in these documents as load-bearing.** They are the
   only specification; there is no generated artifact to fall back on.
2. **`deploy/e2e.sh` is not a nice-to-have.** It runs the three apps against each other
   for real and is the sole mechanical check that they still agree. If it is ever
   skipped, disabled, or allowed to rot, the contract is unverified.

Generating the web client from `/openapi.json` would close this properly and is the
obvious next investment.

## Principals and authentication

Two distinct principal types, two distinct credential systems. They never overlap.

| Principal | Credential | Lifetime | Can do |
|---|---|---|---|
| User | Argon2id password → short-lived JWT access token + rotating refresh token in `HttpOnly` cookie | 15 min access / 30 day refresh | Everything in their org, subject to role |
| Agent | Enrollment token (one-time) → agent API key, stored hashed | Until revoked | Claim jobs for its org, submit results for those jobs. Nothing else. |

An agent key cannot read the dashboard API. A user token cannot claim scan jobs. Enforced by
separate dependency chains, not by a role check inside a shared one.

## Roles

`owner` > `admin` > `analyst` > `viewer`. Checked at the route layer via an explicit
dependency. Destructive operations (delete org, delete network, revoke agent) require `admin`
or above; v1 let an unauthenticated caller wipe an entire collection.

## Scan job lifecycle

```
queued ──claim──► claimed ──start──► running ──┬─► completed
                     │                          ├─► failed
                     └──── lease expiry ────────┴─► queued (retry, max 3)
```

A claimed job carries a lease. If the agent dies, the lease expires and the job returns to
`queued`. Jobs are claimed with `SELECT ... FOR UPDATE SKIP LOCKED` so two agents in the same
org never run the same job.

## Scan target validation — non-negotiable

A scan job is an instruction to send packets at a network. Both sides validate:

- **Control plane, at job creation:** the target must be inside a CIDR the org has registered
  as an owned network AND marked authorized. Public-internet ranges are rejected unless the
  org has an uploaded authorization record. Targets are stored as `CIDR`/`INET`, never strings.
- **Agent, at execution:** re-validates the target against its own locally configured
  allowlist before invoking nmap, and refuses if it does not match.

The agent's local allowlist is the important half. It means a compromised or malicious control
plane still cannot turn a customer's agent into a scanner-for-hire. v1 passed an unvalidated
user string straight into a subprocess.

nmap is invoked with an argument vector — never a shell string — from a fixed profile map.
Scan profiles are named constants (`discovery`, `service`, `vulnerability`); the API accepts a
profile name, never raw nmap flags.

## Risk scoring — the actual product

CVSS alone is what every scanner already prints and what executives already ignore. The score
that reaches the dashboard is:

```
business_risk = cvss_base
              × exploit_maturity      (KEV listed / weaponized / PoC / none)
              × exposure              (internet-facing / DMZ / internal / isolated)
              × asset_criticality     (from the business service the asset is mapped to)
```

Each factor is stored alongside the result so the report can explain *why* a finding ranks
where it does. An unexplained number is not persuasive to the audience this product targets.

Business services are customer-defined (`Payment processing`, `Customer records`) and carry a
criticality tier and optional revenue-at-risk figure. Assets map to services. This mapping is
what turns "CVE-2021-44228 on 10.0.4.12" into "Payment processing is exposed."

## Vulnerability enrichment

CVE data comes from the control plane, not the agent. The agent reports *what is running*
(service, product, version, CPE); the control plane matches CPEs against a synced NVD mirror
and CISA KEV catalog.

This is deliberate. v1 ran `nmap --script vulners` on the customer's network, which requires
the agent to have internet access and third-party API keys, and pins finding quality to
whatever nmap's script scraped that day. Moving enrichment server-side means the agent needs
no internet access beyond the control plane, enrichment improves for historical scans without
rescanning, and one NVD sync serves every tenant.

## What is explicitly out of scope

- Exploitation, session control, network pivoting. This is a visualization and prioritization
  product; it does not attack.
- Agentless cloud-API scanning (AWS/Azure posture). Reasonable v3, not now.
- Credentialed/authenticated scanning. Meaningful accuracy gain, but it means the product
  custodies customer admin credentials — a materially different security and liability posture
  that should be a deliberate decision, not a side effect of this build.
