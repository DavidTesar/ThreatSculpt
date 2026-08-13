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

### RLS binds only for an unprivileged role — enforced at startup

PostgreSQL **silently ignores every RLS policy** for a role with `SUPERUSER` or
`BYPASSRLS`. No error, no warning, no log line: the service keeps serving traffic
while layer 3 has stopped existing. Layer 2 does not cover the gap either, because
the ORM guard inspects ORM statements and raw `text()` SQL passes straight through.

This used to rest on deployment discipline. It no longer does — **the application
queries its own role at startup and refuses to boot** if it can bypass RLS, naming
the role and pointing at `scripts/bootstrap_db.sql`. Set `TS_ALLOW_SUPERUSER_DB=1`
to override for local development; the override is logged at CRITICAL on every boot
so one left on by accident is visible. Never set it in a deployed environment.

Relatedly, migration `0003` now **fails** when the application role does not exist,
rather than skipping grants silently. The silent skip was the first step of a bad
chain: an app with no privileges, `permission denied` on every query, and a
superuser DSN as the fastest way to make the errors stop. Skipping the grants on
purpose is still supported, explicitly:

```bash
alembic -x allow_missing_role=1 upgrade head
TS_ALLOW_MISSING_APP_ROLE=1 alembic upgrade head
```

`scripts/bootstrap_db.sql` creates the unprivileged role; `.env.example` says to use
it; the test suite asserts all of the above.

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

## Risk scoring, enrichment, and the dashboard

```
scoring/        pure arithmetic — multiplier table, the formula, score_factors
enrichment/     CPE 2.3 matching, version ranges, NVD/KEV sync, finding upsert, re-scoring
findings/       /findings queries, schemas, status-transition rules
assets/         /assets queries and schemas
dashboard/      executive and attack-surface aggregates
reports/        HTML rendering, background generation, signed download URLs
```

`scoring/` imports nothing from `models`, `db`, or `api`: it is a function of its inputs,
so every multiplier path is testable without a fixture. Persistence lives in
`enrichment/scoring_service.py`.

**The multiplier table is in `scoring/constants.py` and nowhere else.** The raw product
tops out at `10.0 × 1.6 × 1.4 × 1.3 = 29.12`, rescaled linearly to the 0-100 range
`docs/API.md` shows. Both the raw product and the divisor are written into
`score_factors`, so the UI can show the arithmetic rather than assert the result — an
unexplained number does not persuade the audience this product targets.

**Enrichment never hits the network in tests.** `VulnerabilityFeed` is a protocol;
`RemoteFeed` takes an injected `JsonFetcher`, and `StaticFeed` replays canned payloads.
There is no HTTP client anywhere in `src/`, so a test cannot reach nvd.nist.gov by accident
— a deployment must supply a `JsonFetcher` implementation.

**CPE matches carry a confidence.** `high` means vendor, product and a known version
inside a published range; `medium` means the advisory named no version bound at all;
`low` means the version is unknown or the match came from nmap's free-text product name.
Nothing weaker is emitted. Confidence is a column on `findings`, not a note in
`score_factors`, so it survives a re-score and can be filtered on.

**Re-scoring is re-runnable without a rescan.** `enrichment.scoring_service.rescore_findings`
recomputes historical findings when the CVE mirror learns something new, when an asset's
exposure is corrected, or when an asset is mapped to a business service. The `/assets`
endpoints invoke it directly on both of the latter.

Every dashboard number is aggregate SQL. Migration 0005 adds the composite indexes
that back them.

### Aggregates and the tenancy layer

`ScopedRepository` covers CRUD on one model; `core/scoped_sql.py` covers the aggregate
and multi-table statements it cannot express. It does not loosen tenancy — it refuses a
session bound to a different scope, still stamps the guard's execution option, and RLS is
still underneath. The cross-tenant tests exercise the *endpoints*, not just the
repository, because an aggregate is an easy place to leak a count.

## Not built here

Agent endpoints (`/api/v1/agent/*`, [`docs/AGENT-PROTOCOL.md`](../../docs/AGENT-PROTOCOL.md))
and the scan job lifecycle belong to another workstream.

PDF report export is not implemented. `POST /reports` with `"format": "pdf"` returns a
422 with `unsupported_report_format` rather than silently handing back HTML; only
`"html"` generates.

## Resolved defects worth remembering

### `updated_at` refresh raised `TenancyViolationError` — cause found, fixed, guarded

**Status: fully explained and fixed.** This entry was briefly filed as a "known unknown";
it is not one. The cause is `Mapper.eager_defaults`, and the record is kept because the
dependency is subtle, the failure was remote from its cause, and the diagnosis took a
wrong turn worth not repeating.

**Symptom.** `DELETE /api/v1/agents/{id}` returned 500. Serialising the updated ORM
entity into a response model tripped the tenancy guard while reading `updated_at`:

```
>       return ok(AgentOut.model_validate(revoked))
E       pydantic_core._pydantic_core.ValidationError: 1 validation error for AgentOut
E       updated_at
E         Error extracting attribute: TenancyViolationError: unscoped access to tenant
E         table(s) ['agents']: statements touching customer data must go through
E         ScopedRepository
```

`PATCH /api/v1/networks/{id}` failed in the same run. That is consistent with a shared
cause rather than a bug in either route: both read `updated_at` off an entity just
updated through `ScopedRepository.update`.

**Cause.** `updated_at` carries a SQL-expression `onupdate`. Whether SQLAlchemy fetches
the computed value with `UPDATE ... RETURNING` or leaves the attribute expired is decided
by `Mapper.eager_defaults`, which is **tri-state**: `True`, `False`, or the default
`"auto"`. The trap is that `"auto"` uses RETURNING for INSERT but **not** for UPDATE.

At the time of the failure `Base` declared no `__mapper_args__`, so every mapper ran on
`"auto"`. Measured on the three settings:

```
eager_defaults='auto'   UPDATE..RETURNING=False  expired=True   read raises TenancyViolationError
eager_defaults=False    UPDATE..RETURNING=False  expired=True   read raises TenancyViolationError
eager_defaults=True     UPDATE..RETURNING=True   expired=False  read ok
```

So the chain was: `"auto"` → no RETURNING on UPDATE → `updated_at` expired at flush → the
next read (`model_validate` on a response schema) emits a lazy refresh SELECT → that
SELECT carries no scoped execution option → `tenancy.guard` refuses it → 500. Fully
deterministic. It was never environmental.

**The system failed closed.** The 500 was the tenancy guard *correctly* refusing an
unscoped read of customer data. Nothing leaked; no cross-tenant row was returned. Anyone
reading this in six months should conclude the tenancy layer is strict, not that it is
flaky — an unscoped SELECT reached it and it stopped it, which is precisely its job.

**Fix.** `Base.__mapper_args__ = {"eager_defaults": True}` in `db/base.py`, so the
behaviour no longer depends on an auto-resolution that varies with dialect, driver, or
SQLAlchemy version. On a backend without `UPDATE ... RETURNING` this degrades to an extra
post-fetch rather than an expired attribute, which is a far better failure mode.

**Guarded by**, and these are the tests to keep green:

- `tests/test_model_invariants.py::test_every_mapper_fetches_server_defaults_eagerly` —
  registry-wide, so it covers models any workstream adds. Compares with `is not True`
  precisely because `"auto"` is a truthy string that a truthiness check would wave
  through. Verified to fail when a mapper is flipped to either `False` or `"auto"`.
- `tests/test_agent_timestamp_refresh.py` — the behavioural half, on the exact path that
  failed: update through `ScopedRepository`, then read the timestamps. Asserts no SELECT
  is emitted against the table after the UPDATE, that the UPDATE carried `RETURNING`, and
  that `updated_at` actually advanced. The flag is a proxy; these assert the behaviour it
  exists to produce, so a SQLAlchemy change that keeps the flag but alters its meaning
  still turns something red.
- `tests/test_findings_api.py::test_timestamp_columns_are_fetched_eagerly_on_update`.

**Diagnostic wrong turn, recorded deliberately.** The symptom stopped reproducing between
observation and re-test, and was written up as environmental — shared test database,
concurrent migrations, a rotating role password. All of that was real and none of it was
the cause. The fix had simply landed in between. The specific error was checking
`git status` on the relevant files, seeing a clean tree, and concluding "unchanged": the
change was *committed*, which is exactly the case a clean working tree cannot show. When a
failure stops reproducing, `git log -p -- <file>` across the window, not `git status`.

**If it returns**, check `sqlalchemy.inspect(Model).mapper.eager_defaults` first. Anything
other than `True` — especially the string `"auto"` — is the cause. The likeliest way to
reintroduce it is a model declaring its own `__mapper_args__` (for a polymorphic identity,
say) and silently replacing the inherited dict; the registry-wide test above exists for
exactly that.
