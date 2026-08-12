# ThreatSculpt Control Plane

Multi-tenant FastAPI service: authentication, tenancy enforcement, and the data model
described in [`docs/DATA-MODEL.md`](../../docs/DATA-MODEL.md).

## Layout

```
main.py                     ASGI entrypoint (`main:app`)
alembic.ini                 Alembic config — deliberately holds no DSN
migrations/                 0001 schema · 0002 RLS policies · 0003 role grants
scripts/bootstrap_db.sql    Creates the non-superuser application role
src/threatsculpt/
  config.py                 pydantic-settings; no secret has a default
  app.py                    create_app()
  api/                      dependencies, handlers, middleware, limits, routes
  auth/                     register / login / refresh / logout, principals
  audit/                    append-only audit writer
  core/                     errors, envelope, pagination
  db/                       declarative base, engine, session + scope binding
  models/                   every table in the data model
  observability/            request context, JSON logging with redaction
  security/                 Argon2id, tokens, cookies, rate limiting
  tenancy/                  OrgScope, ORM guard, ScopedRepository, credential lookups
tests/                      pytest + httpx against a real PostgreSQL
```

## Tenancy: three layers

The org is **always** derived from the authenticated principal. No endpoint accepts a
tenant identifier in a body, path, or query string — request models use
`extra="forbid"`, so sending one is a 400 rather than a silently ignored field.

1. **Schema** — `org_id NOT NULL REFERENCES orgs(id) ON DELETE CASCADE` on all 13
   tenant tables, from `TenantModel`.
2. **Query layer** — `ScopedRepository` is the only supported way to reach a tenant
   table. Every statement it builds carries both the `org_id` predicate and an
   execution option; an ORM statement touching a tenant table *without* that option
   raises `TenancyViolationError` before it reaches the database. So
   `session.execute(select(Network))` is not a latent bug, it is an exception.
3. **Row-Level Security** — a policy per tenant table matching
   `NULLIF(current_setting('threatsculpt.org_id', true), '')::uuid`, set per
   transaction by `bind_scope`. `FORCE ROW LEVEL SECURITY` means it applies to the
   table owner too.

RLS only binds if the application connects as a **non-superuser, non-BYPASSRLS** role.
`scripts/bootstrap_db.sql` creates one; `.env.example` says to use it; the test suite
asserts it.

Cross-tenant access returns **404, never 403** — a 403 would confirm the row exists.

## Local setup

```bash
python3.13 -m venv .venv
./.venv/bin/pip install -e ".[dev]"

createdb threatsculpt_dev
psql -d threatsculpt_dev -v role_password="'$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')'" \
     -f scripts/bootstrap_db.sql

cp .env.example .env      # then fill in TS_DATABASE_URL and TS_JWT_SECRET
./.venv/bin/alembic upgrade head
./.venv/bin/python main.py
```

`TS_JWT_SECRET` must be 32+ characters and `TS_CORS_ORIGINS` must not be `*`; the
process refuses to start otherwise.

## Tests

```bash
createdb threatsculpt_test
export TS_TEST_ADMIN_DATABASE_URL="postgresql://<owner>@localhost:5432/threatsculpt_test"
./.venv/bin/python -m pytest -q --cov
```

The suite reads `TS_TEST_ADMIN_DATABASE_URL`, then falls back to `DATABASE_URL`. It
needs a DSN that can create roles and run DDL, on a database it may truncate.

The fixture creates the application role, migrates, and connects the app as that role,
so the RLS assertions are real rather than vacuous. If a DSN is configured but
unreachable the suite **fails** rather than skipping — a silent skip would report a
green build with every cross-tenant isolation test quietly not run.

```bash
./.venv/bin/ruff check . && ./.venv/bin/ruff format --check .
./.venv/bin/mypy
```

## Migrations

**Migrations need a DSN and nothing else.** `migrations/env.py` resolves its own
database URL and never builds the application `Settings`, so applying a schema does
not require the JWT signing secret — handing that key to a migration runner would
spread it for no benefit. Resolution order, first match wins:

1. `-x url=…`
2. `TS_DATABASE_URL`
3. `DATABASE_URL` — what CI and deploy platforms conventionally inject
4. `sqlalchemy.url` in `alembic.ini` (unset by default; a DSN carries a password and
   does not belong in a tracked file)

```bash
env -i PATH=$PATH DATABASE_URL='postgresql+psycopg://…' alembic upgrade head
alembic downgrade base
alembic revision --autogenerate -m "..."     # should be empty if models match
```

Every migration has a working `downgrade()`; `alembic downgrade base` leaves an
empty schema. Migration 0003 grants privileges to `TS_DB_APP_ROLE` and skips with a
notice if that role does not exist.

## Not built here

Agent endpoints (`/api/v1/agent/*`, [`docs/AGENT-PROTOCOL.md`](../../docs/AGENT-PROTOCOL.md))
belong to another workstream. The `current_agent` dependency, the API-key verification
helper, and the `agents` / `enrollment_tokens` models are in place for them to build on.
Scans, assets, findings, the dashboard views, and reports are likewise still to come;
`api/routes/networks.py` is the reference pattern to copy.
