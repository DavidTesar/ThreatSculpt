# ThreatSculpt v2 — Runbook

Operating the three apps together: running the stack, enrolling an agent, proving
the whole loop works, and reading the failures you will actually hit.

For *what the system is*, read [ARCHITECTURE.md](ARCHITECTURE.md). This document is
about running it.

---

## Known gaps

Read this first. These are integration gaps found by running the three apps
against each other. Both are now fixed, but each fix depends on a process an
operator has to actually run — so the rows stay here rather than moving to
**Closed**.

| Gap | Effect | Where |
|---|---|---|
| ~~**Findings are never generated.**~~ **Fixed.** Ingest queues a completed job for enrichment in the same UPDATE that completes it, and the `enrichment` worker claims it. Run that process, or findings still will not appear. | — | `enrichment/worker.py`, `scanning/ingest.py:_finalise` |
| ~~**The CVE mirror is never synced.**~~ **Fixed.** `enrichment.http` supplies the HTTP client `RemoteFeed` always needed, paging is real, and `python -m threatsculpt.enrichment.sync_cli` runs it. Schedule that process, or the mirror stays empty. | — | `enrichment/{http,sync,sync_cli}.py` |

`deploy/e2e.sh` still seeds the mirror by running the **real** `sync_all` against
a `StaticFeed`, and should keep doing so: a gate must not depend on nvd.nist.gov
being up. Everything after that is the production path — ingest queues the
completed job and `python -m threatsculpt.enrichment` produces the findings the
script asserts on. Nothing in the script calls `generate_findings`, so a
regression in that wiring times the script out rather than passing.

### Sync the CVE mirror

```bash
export TS_NVD_API_KEY=…          # optional, and worth requesting: see below
python -m threatsculpt.enrichment.sync_cli
```

Safe to interrupt and safe to schedule. Progress is committed after every page
and recorded in `feed_sync_state`, so a killed run resumes where it stopped
rather than starting over.

`TS_CVE_SYNC_INTERVAL_HOURS` (default 24) is enforced by the command itself: a
run that finds the mirror synced more recently than that exits without touching
the network. So the cron entry can be **hourly** — which is what you want, since
it means a failed run retries an hour later instead of a day later — without
hammering a public, rate-limited API. `--force` overrides the check.

**Request an NVD API key.** NVD allows 5 requests per 30 seconds anonymously and
50 with a key, per source address. A cold sync of ~300,000 CVEs is roughly 150
requests with a key and roughly 1,500 without — about an hour versus about ten.
The key is read from `TS_NVD_API_KEY`, is never logged, and is only ever sent to
the host named by `TS_NVD_CVE_URL`.

The first run is a cold sync with no date filter. Every later run is incremental,
using `lastModStartDate`/`lastModEndDate` windows; NVD caps a window at 120 days,
so a long outage is walked as several consecutive windows rather than one.

### Closed

**The web dashboard did not match the API it called.** ~12 endpoints broke at
runtime: `/users` was unimplemented server-side, several request bodies were
rejected with 422, and the findings/assets/executive responses were read with
the wrong field names and types. The frontend's MSW mocks encoded the same wrong
assumptions, so its suite stayed green regardless.

Closed by generating the client from the control plane's OpenAPI schema:
`domain.ts` is now 32 aliases over generated types and restates no response
shape, `/users` is implemented and registered, and CI regenerates the schema and
runs `git diff --exit-code`, so a backend shape change turns the build red.

Two things that made this gap survivable are worth remembering, because both
were fixed alongside it. The web typecheck was `tsc --noEmit` against a solution
file with `"files": []` — it resolved zero inputs and passed unconditionally; it
is now `tsc -b`. And the mocks that hid the drift were the same mocks the tests
trusted. A generated type and a hand-written mock cannot disagree safely.

---

## Run the stack

### With Docker (deployment)

```bash
cp deploy/.env.example deploy/.env
# fill in POSTGRES_PASSWORD, TS_JWT_SECRET, and the mail relay settings —
# start-up fails on empty values, and compose refuses to render without them
openssl rand -base64 32   # POSTGRES_PASSWORD
openssl rand -hex 32      # TS_JWT_SECRET

docker compose -f deploy/docker-compose.yml up -d
```

Brings up postgres, a one-shot `migrate` job, the control plane, the lease
sweeper, the enrichment worker, and the web dashboard on
<http://127.0.0.1:8080>.

**The mail settings are required, not optional.** A new account is created
unverified and an unverified account cannot log in, so a stack that cannot
deliver a verification message onboards nobody — and the control plane refuses
to start rather than serve traffic in that state. `TS_ALLOW_UNDELIVERABLE_EMAIL`
turns that refusal off and is a development-only flag; it does not make
verification work.

The **scan agent is deliberately not in the default stack**. It runs on the
customer's network, holds a customer credential, and needs raw-socket access to
their LAN — starting it alongside the cloud services would both misrepresent the
architecture and put a scanner on whatever network the cloud stack runs in. For a
full local loop:

```bash
docker compose -f deploy/docker-compose.yml --profile agent up -d
```

### Natively (development)

```bash
# 1. database
createdb threatsculpt_dev
export TS_DATABASE_URL='postgresql+psycopg://postgres@localhost:5432/threatsculpt_dev'
export TS_JWT_SECRET="$(openssl rand -hex 32)"
export TS_ENVIRONMENT=development TS_COOKIE_SECURE=false

# 2. migrations
cd apps/control-plane && .venv/bin/alembic upgrade head

# 3. API
.venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000

# 4. lease sweeper, in another shell, same environment
.venv/bin/python -m threatsculpt.scanning

# 5. enrichment worker, in another shell, same environment.
#    Without it, scans produce assets and ports but never findings.
.venv/bin/python -m threatsculpt.enrichment

# 6. dashboard, in another shell
cd apps/web && npm run dev
```

Health endpoints are **unprefixed** — `/health` and `/ready`, not
`/api/v1/health`. `/health` is a liveness probe and does not touch the database;
`/ready` does. Use `/health` for restarts, or a database blip will restart a
perfectly healthy API.

---

## Run the end-to-end proof

```bash
deploy/e2e.sh
```

Creates a throwaway database, migrates it, starts the control plane on a free
port, registers an org over the real HTTP API, authorises `127.0.0.0/8`, issues an
enrollment token, enrols the **real** scan agent, queues a scan of `127.0.0.1/32`,
lets the agent run **real nmap**, submits real results, and asserts on what lands
in the database and on `/dashboard/executive` and `/findings`. Every step asserts;
the script exits non-zero on the first failure and dumps the control-plane log.

```bash
E2E_KEEP=1 deploy/e2e.sh      # leave the database and work dir for inspection
E2E_DB=ts_scratch deploy/e2e.sh
PGHOST=/var/run/postgresql PGPORT=5432 deploy/e2e.sh
```

It takes about 40 seconds, most of it the real `nmap -sS -sV -O --top-ports 1000`.

**nmap needs `CAP_NET_RAW`.** The agent must not run as root, so the capability
belongs on the binary — and on *the binary the kernel actually executes*, which
is not always the one on `PATH`:

```bash
# Find the real ELF first. On Debian and Kali /usr/bin/nmap is a shell WRAPPER
# around /usr/lib/nmap/nmap, and because it is a script rather than a symlink,
# `readlink -f` returns the wrapper. A capability set on a script does nothing:
# the kernel does not honour file capabilities on anything it runs through an
# interpreter.
file "$(command -v nmap)"                    # "a sh script" => use the path below
NMAP_ELF=/usr/lib/nmap/nmap                  # Debian, Kali
[ -e "$NMAP_ELF" ] || NMAP_ELF="$(readlink -f "$(command -v nmap)")"   # Ubuntu, others

sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$NMAP_ELF"
getcap "$NMAP_ELF"
```

Two ways this looks right and is not:

- **`getcap` shows the capability and scans still fail.** The mount can be the
  reason: on a `nosuid` filesystem the kernel ignores file capabilities while
  `getcap` still displays them. `findmnt -T "$NMAP_ELF"` shows the flags. A
  container that drops `CAP_NET_RAW` produces the same symptom.
- **The capability is honoured but nmap refuses anyway**, saying the scan type
  needs root. That is nmap's own privilege check, not the kernel's answer —
  Debian and Kali ship their wrapper precisely to pass `--privileged` for
  non-root users. Set `NMAP_PRIVILEGED=1` in the environment.

`deploy/e2e.sh` tells these apart for you: it prints what nmap actually said,
the capability and mount state of every candidate path, and whether an
unprivileged `-sT` of the same target works, before it offers any advice.

---

## Enroll an agent

1. **Issue a token** — `POST /api/v1/agents` as an `admin` or `owner`:

   ```bash
   curl -X POST https://app.example/api/v1/agents \
     -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H 'Content-Type: application/json' -d '{"note":"hq-dc-scanner-01"}'
   ```

   Returns `{"enrollment_token": "tse_…", "expires_at": …}`. **Single use, one
   hour.** It is shown once.

2. **Configure the agent host.** `/etc/threatsculpt/agent.toml`:

   ```toml
   control_plane_url = "https://app.example"
   agent_name = "hq-dc-scanner-01"
   allowlist = ["10.0.0.0/8", "192.168.0.0/16"]
   ```

   `allowlist` is the security boundary. The agent refuses any target outside it
   no matter what the control plane sends, which is what stops a compromised
   control plane turning a customer's agent into a scanner-for-hire. The
   server-supplied allowlist can only ever *narrow* this list.

3. **Supply the token** by environment or a `0600` file — never on the command
   line, where `ps` exposes it to every user on the host. The agent refuses to
   start if it finds a credential in `argv`.

   ```bash
   install -m 0600 /dev/stdin /var/lib/threatsculpt-agent/enrollment.token <<< "tse_…"
   # or: export TS_AGENT_ENROLLMENT_TOKEN=tse_…
   ```

4. **Start it.** On first start it trades the token for a permanent key and
   writes it to `/var/lib/threatsculpt-agent/agent.key` at mode `0600`. Restarts
   reuse that key and never touch `/enroll` again.

   ```bash
   threatsculpt-agent --check-config    # validate without contacting the server
   systemctl enable --now threatsculpt-agent
   ```

A scan job is only created for a target inside a network the org has registered
**and marked `authorized`**. An unauthorized target is refused at job creation
with `network_not_authorized`.

---

## Rotate an agent key

There is no rotate-in-place endpoint, and deliberately so: a key that can be
exchanged for a new key is a key that can be used to keep access after it should
have been lost. Rotation is revoke-then-re-enroll.

```bash
# 1. Revoke. Takes effect on the agent's next request — it gets a 401, wipes its
#    stored key, and exits 0. Do this FIRST if the key is believed compromised.
curl -X DELETE https://app.example/api/v1/agents/$AGENT_ID \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# 2. Issue a fresh enrollment token.
curl -X POST https://app.example/api/v1/agents \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' -d '{"note":"hq-dc-scanner-01 rotation"}'

# 3. On the agent host: remove the old key, install the new token, restart.
systemctl stop threatsculpt-agent
rm -f /var/lib/threatsculpt-agent/agent.key
install -m 0600 -o scanagent -g scanagent /dev/stdin \
  /var/lib/threatsculpt-agent/enrollment.token <<< "tse_…"
systemctl start threatsculpt-agent
```

The agent enrols only when it has **no key at all**, so step 3's `rm` is what
makes it re-enrol. Leaving the old key in place means the new token is never
used and silently expires after an hour.

Revocation and enrollment are both written to `audit_log`.

To narrow an agent's reach without rotating, `PATCH /api/v1/agents/{id}/allowlist`
— but remember it can only narrow. The agent's local file always wins.

---

## Common failures

### The agent starts, polls, and never picks up work

Claim returns `{"jobs": []}` forever.

- **No queued job for that org.** Check `GET /api/v1/scans?status=queued`.
- **`capacity` above 10.** The control plane caps a claim at 10 and returns
  `400 validation_error` on more. The agent's config is bounded to match.
- **The job was rejected back to `queued` by this same agent** — look for
  `scan_job.rejected` in `audit_log`. Its target is outside the agent's local
  allowlist. This is the allowlist doing its job; fix the target or the config,
  not the agent.

### `enrollment failed: … (400)` / the token does not work

- **Already used.** Tokens are single use, consumed by a conditional UPDATE. A
  crash *after* the server consumed it still burns it — issue a new one.
- **Expired.** One hour, no extension.
- **The agent already has a key.** It skips enrollment entirely and logs
  `using existing agent credential`. Remove `agent.key` to force re-enrollment.

### The agent exits 0 immediately, logging "credential revoked"

Working as designed: a `401` anywhere, or `revoked: true` on a heartbeat, wipes
the stored key and exits. Either the agent was revoked in the dashboard, or its
key no longer matches. Re-enroll.

### Jobs go back to `queued` on their own, then `failed` after three attempts

The lease expired: the agent claimed the job and did not finish within the lease.
Either the sweeper is doing its job after a genuine agent crash, or nmap is
outrunning the lease on a large target. Check that the `sweeper` process is
running exactly once, and that `nmap_timeout_seconds` is below the lease.

### `hosts_rejected` is non-empty in the ingest audit entry

The agent submitted a host outside the job's target CIDR. The control plane
re-validates every submitted IP and drops the ones outside range, audit-logging
each. A non-empty list means the agent and the control plane disagree about what
was asked for — worth investigating rather than ignoring.

### Scans complete, `assets` and `ports` fill up, but `findings` stays empty

Work through the queue in order — each step tells you which of the three it is.

```sql
-- 1. Did ingest queue the job? Anything but 'pending'/'running'/'complete'
--    here (especially NULL on a completed job) means the scan never finished.
select id, status, enrichment_status, enrichment_attempts, enrichment_lease_expires_at
  from scan_jobs order by created_at desc limit 5;

-- 2. Is there anything to match against? An empty mirror matches nothing, and
--    the pass still completes — correctly, with zero findings.
select count(*) from vulnerabilities;
```

3. **Is the worker running?** `python -m threatsculpt.enrichment`, or the
   `enrichment` service in the compose stack. Jobs sitting at `pending` with
   `enrichment_attempts = 0` mean nothing has claimed them: no worker.

A job stuck at `running` with a lapsed lease is a worker that died mid-pass; the
next pass reclaims it. After `MAX_ENRICHMENT_ATTEMPTS` it goes to `failed` and
stops being retried — the worker log has the exception, correlated by
`scan_job_id`. The scan's own `status` stays `completed`, because the scan did
succeed; only enrichment did not.

One thing this does **not** cover: a CVE the mirror learns about *after* a scan
was enriched produces no finding on that scan's ports. Matching happened against
the mirror as it stood, and nothing re-enriches a job whose pass already
completed. `rescore_findings` is not the answer either — it re-scores findings
that exist, it does not discover new ones. Re-run the scan, or re-queue the job
by setting `enrichment_status = 'pending'` and `enrichment_attempts = 0` on it.

### Sessions drop after 15 minutes

`TS_COOKIE_SECURE=true` over plain HTTP. The browser accepts the access token but
silently discards the refresh cookie, so the session dies when the 15-minute
access token expires. Set `TS_COOKIE_SECURE=false` for local HTTP development
only.

### Rate limits trip in testing

`10/min` per IP on auth endpoints, `100/min` general. Behind a proxy, check
`TS_TRUSTED_PROXY_COUNT` — if it is too low every request appears to come from
the proxy's IP and shares one bucket.

### `TS_JWT_SECRET must be at least 32 characters`

Working as designed. The process refuses to start on a weak or placeholder
secret rather than run with one.
