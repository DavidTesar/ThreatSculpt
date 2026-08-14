#!/usr/bin/env bash
#
# ThreatSculpt v2 — end-to-end proof, run natively on the host.
#
# Exercises the real control plane, the real scan agent, the real enrichment
# worker, and real nmap against a real PostgreSQL database. There are no mocks,
# stubs, or fixtures anywhere in this path: every step below is an HTTP call to a
# running server or a subprocess that actually scans 127.0.0.1.
#
# The findings it asserts on are produced the way a deployment produces them —
# ingest queues the completed job, `python -m threatsculpt.enrichment` claims it.
# Nothing here calls generate_findings directly; if the trigger regresses, step
# 12c times out instead of passing.
#
# It is a gate, not a smoke test. Every step asserts; any failed assertion exits
# non-zero and the script prints what it saw versus what it expected.
#
# Usage:
#   deploy/e2e.sh                 # full run, tears down afterwards
#   E2E_KEEP=1 deploy/e2e.sh      # leave the database and server up for inspection
#
# Configuration (all optional — defaults suit a local checkout):
#   PGHOST PGPORT PGUSER PGPASSWORD   libpq connection to an existing server
#   E2E_DB                            database name to create (default ts_e2e)
#   E2E_API_PORT                      control-plane port (default: first free from a list)
#   CP_PYTHON AGENT_PYTHON            interpreters (default: each app's .venv)
#   NMAP_PATH                         nmap binary (default /usr/bin/nmap)

set -euo pipefail

# --- configuration ----------------------------------------------------------

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CP_DIR="$REPO_ROOT/apps/control-plane"
AGENT_DIR="$REPO_ROOT/apps/scan-agent"

E2E_DB="${E2E_DB:-ts_e2e}"
E2E_KEEP="${E2E_KEEP:-0}"
NMAP_PATH="${NMAP_PATH:-/usr/bin/nmap}"
CP_PYTHON="${CP_PYTHON:-$CP_DIR/.venv/bin/python}"
AGENT_PYTHON="${AGENT_PYTHON:-$AGENT_DIR/.venv/bin/python}"

# Never a real secret: this database exists for the length of this script.
JWT_SECRET="e2e-only-secret-not-for-any-real-deployment-32+"
ORG_SLUG="acme-e2e"
# A reserved TLD (.test/.example) is refused by the API's email validator, by design.
USER_EMAIL="owner@acme-e2e.com"
USER_PASSWORD='CorrectHorseBatteryStaple9!'

WORK_DIR="$(mktemp -d)"
CP_PID=""
ENRICH_PID=""
LISTENER_PID=""
LISTENER_PORT=""

#: How long to wait for the enrichment worker to turn the completed scan into
#: findings. Its first pass runs at start-up, so this is slack for a slow
#: machine rather than a poll interval.
ENRICH_TIMEOUT_SECONDS=60

# --- output helpers ---------------------------------------------------------

if [[ -t 1 ]]; then
  BOLD=$'\033[1m'; RED=$'\033[31m'; GREEN=$'\033[32m'; DIM=$'\033[2m'; RESET=$'\033[0m'
else
  BOLD=""; RED=""; GREEN=""; DIM=""; RESET=""
fi

step()  { printf '\n%s=== %s ===%s\n' "$BOLD" "$*" "$RESET"; }
info()  { printf '%s%s%s\n' "$DIM" "$*" "$RESET"; }
pass()  { printf '%s  PASS%s %s\n' "$GREEN" "$RESET" "$*"; }
fail()  { printf '%s  FAIL%s %s\n' "$RED" "$RESET" "$*" >&2; exit 1; }

assert_eq() { # expected actual description
  [[ "$1" == "$2" ]] || fail "$3: expected '$1', got '$2'"
  pass "$3 = $2"
}

assert_ge() { # minimum actual description
  [[ "$2" -ge "$1" ]] || fail "$3: expected >= $1, got $2"
  pass "$3 = $2"
}

# --- teardown ---------------------------------------------------------------

cleanup() {
  local status=$?
  if [[ -n "$CP_PID" ]] && kill -0 "$CP_PID" 2>/dev/null; then
    kill "$CP_PID" 2>/dev/null || true
    wait "$CP_PID" 2>/dev/null || true
  fi
  if [[ -n "$ENRICH_PID" ]] && kill -0 "$ENRICH_PID" 2>/dev/null; then
    kill "$ENRICH_PID" 2>/dev/null || true
    wait "$ENRICH_PID" 2>/dev/null || true
  fi
  if [[ -n "$LISTENER_PID" ]] && kill -0 "$LISTENER_PID" 2>/dev/null; then
    kill "$LISTENER_PID" 2>/dev/null || true
  fi
  if [[ "$E2E_KEEP" == "1" ]]; then
    info "E2E_KEEP=1: leaving database '$E2E_DB' and work dir $WORK_DIR in place"
  else
    dropdb --if-exists "$E2E_DB" 2>/dev/null || true
    rm -rf "$WORK_DIR"
  fi
  if [[ $status -ne 0 && -f "$WORK_DIR/cp.log" ]]; then
    printf '\n%s--- control-plane log (last 40 lines) ---%s\n' "$RED" "$RESET" >&2
    tail -40 "$WORK_DIR/cp.log" >&2 || true
  fi
  if [[ $status -ne 0 && -f "$WORK_DIR/enrichment.log" ]]; then
    printf '\n%s--- enrichment worker log (last 40 lines) ---%s\n' "$RED" "$RESET" >&2
    tail -40 "$WORK_DIR/enrichment.log" >&2 || true
  fi
  exit $status
}
trap cleanup EXIT

# --- preflight --------------------------------------------------------------

step "0. Preflight"
for binary in psql createdb dropdb curl jq "$NMAP_PATH"; do
  command -v "$binary" >/dev/null 2>&1 || [[ -x "$binary" ]] \
    || fail "missing required binary: $binary"
done
[[ -x "$CP_PYTHON" ]]    || fail "control-plane interpreter not found: $CP_PYTHON"
[[ -x "$AGENT_PYTHON" ]] || fail "scan-agent interpreter not found: $AGENT_PYTHON"
psql -d postgres -c 'select 1' >/dev/null || fail "cannot reach PostgreSQL (check PGHOST/PGPORT/PGUSER)"
info "nmap:      $("$NMAP_PATH" --version | head -1)"
info "postgres:  $(psql -d postgres -tAc 'show server_version')"
info "work dir:  $WORK_DIR"

# --- nmap raw-socket probe --------------------------------------------------
#
# The agent's `service` and `vulnerability` profiles are `-sS -sV -O`, all of
# which need raw sockets, and the agent must NOT run as root (AGENT-PROTOCOL.md)
# — so the capability belongs on the binary. This block establishes whether that
# is actually true here, and if it is not, prints what nmap said rather than a
# guess about why.
#
# It used to guess. The check was `... >/dev/null 2>&1` with a failure message
# asserting the capability was missing, which sent a reader to `setcap` even in
# environments where `getcap` already showed the capability set. A check that
# discards the evidence and substitutes a diagnosis is worse than one that only
# fails: it is confidently wrong, and it costs somebody an afternoon.

NMAP_PROBE_ERR="$WORK_DIR/nmap-probe.err"

# The paths a capability could have to live on, deduplicated. `readlink -f` is
# NOT enough on its own: on Debian and Kali `/usr/bin/nmap` is a **shell
# wrapper** around `/usr/lib/nmap/nmap`, not a symlink, so `readlink -f` returns
# the wrapper and a capability set on it does nothing at all. On Ubuntu there is
# no wrapper and `/usr/bin/nmap` is the ELF that needs it.
nmap_binary_candidates() {
  local resolved seen=""
  resolved="$(readlink -f "$NMAP_PATH" 2>/dev/null || true)"
  local candidate
  for candidate in "$NMAP_PATH" "$resolved" /usr/lib/nmap/nmap; do
    [[ -n "$candidate" && -e "$candidate" ]] || continue
    case " $seen " in *" $candidate "*) continue ;; esac
    seen="$seen $candidate"
    printf '%s\n' "$candidate"
  done
}

# Everything a reader needs to tell the causes apart, printed before any advice.
nmap_environment_report() {
  printf '  running as: uid=%s (%s)\n' "$(id -u)" "$(id -un)"
  local candidate caps
  while read -r candidate; do
    if command -v getcap >/dev/null 2>&1; then
      caps="$(getcap "$candidate" 2>/dev/null)"
      [[ -n "$caps" ]] || caps="$candidate (no capabilities set)"
    else
      caps="$candidate (getcap not installed — apt-get install libcap2-bin)"
    fi
    printf '  capabilities: %s\n' "$caps"
    printf '        is a: %s\n' "$(file -b "$candidate" 2>/dev/null || echo unknown)"
    # A `nosuid` mount makes the kernel ignore file capabilities while getcap
    # still displays them — which looks exactly like "the capability is set and
    # does nothing".
    printf '     mounted: %s\n' \
      "$(findmnt -no TARGET,OPTIONS -T "$candidate" 2>/dev/null || echo unknown)"
  done < <(nmap_binary_candidates)
}

# One probe. Extra flags go before the target; stderr is kept, never discarded.
probe_nmap() { # scan-type [extra-flags...]
  "$NMAP_PATH" "$@" -p 22 --max-retries 0 -oX - 127.0.0.1 \
    >/dev/null 2>"$NMAP_PROBE_ERR"
}

if probe_nmap -sS; then
  pass "nmap can raw-socket scan without root"
elif probe_nmap -sS --privileged; then
  # The kernel allows the raw socket but nmap's own privilege check did not
  # believe it. Debian and Kali ship a wrapper that passes --privileged for
  # exactly this reason. NMAP_PRIVILEGED is the documented environment
  # equivalent, so exporting it here also reaches the agent's own nmap calls,
  # which this script does not control.
  #
  # This does not paper over a missing capability: with no raw-socket access
  # --privileged changes nothing, as the branch below proves by still failing.
  export NMAP_PRIVILEGED=1
  pass "nmap can raw-socket scan with NMAP_PRIVILEGED=1"
  info "nmap's own privilege check does not see the capability on this system;"
  info "NMAP_PRIVILEGED=1 is exported so the agent's scans get the same treatment."
else
  printf '\n%s  nmap could not run a SYN scan. What nmap said:%s\n' "$RED" "$RESET" >&2
  sed 's/^/    /' "$NMAP_PROBE_ERR" >&2
  printf '\n%s  Environment:%s\n' "$RED" "$RESET" >&2
  nmap_environment_report >&2

  # Narrow it down: is it raw sockets specifically, or is nmap unable to scan at
  # all? A connect scan needs no privileges whatsoever.
  if probe_nmap -sT; then
    printf '\n  An unprivileged connect scan (-sT) of the same target SUCCEEDS,\n' >&2
    printf '  so nmap and the network are fine and raw-socket access is what is missing.\n' >&2
  else
    printf '\n  An unprivileged connect scan (-sT) of the same target ALSO fails,\n' >&2
    printf '  so this is not a capability problem — nmap cannot scan 127.0.0.1 at all.\n' >&2
    sed 's/^/    /' "$NMAP_PROBE_ERR" >&2
  fi

  # Advice, offered as causes to check against the evidence above rather than as
  # a diagnosis. The first one is only the answer if the capability line above
  # says "no capabilities set".
  fail "nmap cannot raw-socket scan here. Possible causes, in order:
    1. The capability is not set on the binary the kernel actually runs:
         sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip <path>
       Use the path listed above whose type is ELF, NOT the wrapper script —
       on Debian and Kali that is /usr/lib/nmap/nmap, and 'readlink -f' does
       not resolve to it.
    2. The capability IS set but the kernel ignores it — a 'nosuid' mount does
       this, and getcap still displays the capability. Check the mount line.
    3. The container or sandbox denies CAP_NET_RAW outright, in which case no
       setcap on the host image will help.
  There is deliberately no unprivileged fallback: the agent's scan profiles are
  '-sS -sV -O', so a connect scan would not exercise what this gate exists to
  prove. See docs/RUNBOOK.md."
fi

# --- 1. fresh database + migrations ----------------------------------------

step "1. Create a fresh database and migrate it"
dropdb --if-exists "$E2E_DB"
createdb "$E2E_DB"

# The application must NOT connect as a superuser: PostgreSQL skips every RLS
# policy for SUPERUSER or BYPASSRLS, which silently removes the tenancy backstop.
# So this mirrors the production sequence exactly — create the unprivileged role
# first, migrate as the owner, then run the app as that role. Running the whole
# thing as `postgres` would make every cross-tenant assertion below vacuous.
APP_ROLE=threatsculpt_app
APP_ROLE_PASSWORD="$(head -c 18 /dev/urandom | base64 | tr -d '/+=')"
psql -q -d "$E2E_DB" -v role_password="'${APP_ROLE_PASSWORD}'" -v DBNAME="$E2E_DB" \
  -f "$CP_DIR/scripts/bootstrap_db.sql" >/dev/null \
  || fail "could not create the $APP_ROLE role"
pass "unprivileged role $APP_ROLE created (NOSUPERUSER, NOBYPASSRLS)"

# psycopg wants the socket directory as a `host` query parameter, not in the authority.
if [[ "${PGHOST:-}" == /* ]]; then
  ADMIN_DB_URL="postgresql+psycopg://${PGUSER:-postgres}@/${E2E_DB}?host=${PGHOST}&port=${PGPORT:-5432}"
  APP_DB_URL="postgresql+psycopg://${APP_ROLE}:${APP_ROLE_PASSWORD}@/${E2E_DB}?host=${PGHOST}&port=${PGPORT:-5432}"
else
  DB_AUTH="${PGUSER:-postgres}${PGPASSWORD:+:$PGPASSWORD}"
  ADMIN_DB_URL="postgresql+psycopg://${DB_AUTH}@${PGHOST:-127.0.0.1}:${PGPORT:-5432}/${E2E_DB}"
  APP_DB_URL="postgresql+psycopg://${APP_ROLE}:${APP_ROLE_PASSWORD}@${PGHOST:-127.0.0.1}:${PGPORT:-5432}/${E2E_DB}"
fi

export TS_JWT_SECRET="$JWT_SECRET"
export TS_ENVIRONMENT=test
export TS_COOKIE_SECURE=false
export TS_LOG_JSON=false
# The service refuses to start with no mail delivery configured, because an account that
# cannot be verified cannot log in — so that configuration onboards nobody. This branch has
# no mail provider, and the e2e completes verification directly in the database further
# down, so it takes the documented opt-out. Nothing in a deployed environment should.
export TS_ALLOW_UNDELIVERABLE_EMAIL=1

# Migrations run as the owner; the application does not.
TS_DATABASE_URL="$ADMIN_DB_URL" \
  bash -c "cd '$CP_DIR' && '$CP_PYTHON' -m alembic upgrade head" || fail "migrations failed"
export TS_DATABASE_URL="$APP_DB_URL"
TABLE_COUNT=$(psql -d "$E2E_DB" -tAc \
  "select count(*) from information_schema.tables where table_schema='public'")
assert_ge 17 "$TABLE_COUNT" "tables created"

# Layer 3 of the tenancy model must be present, not assumed.
RLS_COUNT=$(psql -d "$E2E_DB" -tAc \
  "select count(*) from pg_policies where schemaname='public'")
assert_ge 1 "$RLS_COUNT" "row-level security policies installed"

# --- 2. start the control plane --------------------------------------------

step "2. Start the control plane"
if [[ -n "${E2E_API_PORT:-}" ]]; then
  API_PORT="$E2E_API_PORT"
else
  API_PORT=""
  for candidate in 8817 8818 8819 8820 8821; do
    if ! (exec 3<>"/dev/tcp/127.0.0.1/$candidate") 2>/dev/null; then
      API_PORT="$candidate"; break
    fi
  done
  [[ -n "$API_PORT" ]] || fail "no free port for the control plane"
fi

(cd "$CP_DIR" && exec "$CP_PYTHON" -m uvicorn main:app \
  --host 127.0.0.1 --port "$API_PORT") > "$WORK_DIR/cp.log" 2>&1 &
CP_PID=$!
API="http://127.0.0.1:$API_PORT/api/v1"

for _ in $(seq 1 60); do
  sleep 0.5
  curl -sf "http://127.0.0.1:$API_PORT/health" >/dev/null 2>&1 && break
  kill -0 "$CP_PID" 2>/dev/null || fail "control plane exited during start-up"
done
curl -sf "http://127.0.0.1:$API_PORT/health" >/dev/null || fail "control plane never became healthy"
pass "control plane listening on port $API_PORT (pid $CP_PID)"
READY=$(curl -s "http://127.0.0.1:$API_PORT/ready" | jq -r '.data.database')
assert_eq "ok" "$READY" "readiness reports the database"

# --- 3. register an org + owner --------------------------------------------

step "3. Register an organisation and owner user"
curl -sS -X POST "$API/auth/register" -H 'Content-Type: application/json' -d "{
  \"org_name\":\"Acme E2E Corp\",\"org_slug\":\"$ORG_SLUG\",
  \"email\":\"$USER_EMAIL\",\"password\":\"$USER_PASSWORD\",\"full_name\":\"E2E Owner\"
}" > "$WORK_DIR/register.json"
jq -e '.error == null' "$WORK_DIR/register.json" >/dev/null || {
  jq . "$WORK_DIR/register.json"; fail "registration failed"; }
ORG_ID=$(jq -r '.data.org.id' "$WORK_DIR/register.json")
assert_eq "owner" "$(jq -r '.data.user.role' "$WORK_DIR/register.json")" "registered role"
info "org_id = $ORG_ID"

# A new account is created unverified and cannot log in until its address is
# proved. That is what stops an attacker claiming someone else's email, so the
# e2e must not weaken it — it has to satisfy the check the way a real user does.
#
# The verification token is stored as a SHA-256 hash and is deliberately never
# logged (it is a credential that grants control of an account), so there is no
# way to recover the plaintext here. This branch also has no mail delivery: the
# sender is a documented no-op. So the only honest option is to complete the
# out-of-band step directly in the database, exactly as clicking the emailed
# link would.
#
# This is the one assertion in this script that does not exercise a real code
# path, and it is called out here so nobody mistakes it for coverage. When a
# real delivery provider is wired, replace this with a fetch of the sent
# message and a POST to /auth/verify-email.
assert_eq "f" \
  "$(psql -d "$E2E_DB" -tAc "select email_verified_at is not null from users where email='$USER_EMAIL'")" \
  "a new account starts unverified"
psql -q -d "$E2E_DB" -c \
  "update users set email_verified_at = now(), verification_token_hash = null,
                    verification_expires_at = null
     where email = '$USER_EMAIL'" >/dev/null
pass "owner's email marked verified out of band (no mail provider on this branch)"

step "4. Log in over the real HTTP API"
curl -sS -X POST "$API/auth/login" -H 'Content-Type: application/json' \
  -d "{\"email\":\"$USER_EMAIL\",\"password\":\"$USER_PASSWORD\"}" > "$WORK_DIR/login.json"
TOKEN=$(jq -r '.data.access_token' "$WORK_DIR/login.json")
[[ -n "$TOKEN" && "$TOKEN" != "null" ]] || { jq . "$WORK_DIR/login.json"; fail "login returned no token"; }
AUTH="Authorization: Bearer $TOKEN"
pass "access token issued (${#TOKEN} chars)"
assert_eq "$USER_EMAIL" "$(curl -s -H "$AUTH" "$API/auth/me" | jq -r '.data.user.email')" \
  "GET /auth/me identifies the caller"

# --- 5. authorized network --------------------------------------------------

step "5. Register 127.0.0.0/8 as an authorized network"
curl -sS -X POST "$API/networks" -H "$AUTH" -H 'Content-Type: application/json' -d '{
  "name":"Loopback (e2e)","cidr":"127.0.0.0/8","authorized":true,
  "authorization_note":"Synthetic target owned by the test host"
}' > "$WORK_DIR/network.json"
jq -e '.error == null' "$WORK_DIR/network.json" >/dev/null || {
  jq . "$WORK_DIR/network.json"; fail "network creation failed"; }
NETWORK_ID=$(jq -r '.data.id' "$WORK_DIR/network.json")
assert_eq "true" "$(jq -r '.data.authorized' "$WORK_DIR/network.json")" "network authorized flag"

# --- 6. enrollment token ----------------------------------------------------

step "6. Issue an agent enrollment token"
curl -sS -X POST "$API/agents" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"note":"e2e agent"}' > "$WORK_DIR/token.json"
ENROLL_TOKEN=$(jq -r '.data.enrollment_token' "$WORK_DIR/token.json")
[[ "$ENROLL_TOKEN" == tse_* ]] || { jq . "$WORK_DIR/token.json"; fail "no enrollment token issued"; }
pass "enrollment token issued (${ENROLL_TOKEN:0:8}…, single use, 1h expiry)"

# --- 7. a real listening service for nmap to find ---------------------------

step "7. Start a real service for the scan to discover"
for candidate in 8080 8000 8888 9090 3000; do
  if ! (exec 3<>"/dev/tcp/127.0.0.1/$candidate") 2>/dev/null; then
    LISTENER_PORT="$candidate"; break
  fi
done
[[ -n "$LISTENER_PORT" ]] || fail "no free port in nmap's top-1000 for the test listener"
python3 -m http.server "$LISTENER_PORT" --bind 127.0.0.1 > "$WORK_DIR/listener.log" 2>&1 &
LISTENER_PID=$!
sleep 1
curl -sf -o /dev/null "http://127.0.0.1:$LISTENER_PORT/" || fail "test listener did not start"
pass "HTTP listener on 127.0.0.1:$LISTENER_PORT (pid $LISTENER_PID)"

# --- 8. enroll the real agent -----------------------------------------------

step "8. Enroll the real scan agent against the real control plane"
AGENT_STATE="$WORK_DIR/agent-state"
mkdir -p "$AGENT_STATE" && chmod 700 "$AGENT_STATE"
printf '%s' "$ENROLL_TOKEN" > "$AGENT_STATE/enrollment.token"
chmod 600 "$AGENT_STATE/enrollment.token"

cat > "$WORK_DIR/agent.toml" <<TOML
control_plane_url = "http://127.0.0.1:$API_PORT"
agent_name = "e2e-scanner-01"
state_dir = "$AGENT_STATE"
allowlist = ["127.0.0.0/8"]
nmap_path = "$NMAP_PATH"
poll_interval_seconds = 2.0
log_level = "INFO"
TOML

# --check-config validates the local allowlist without contacting the server.
(cd "$AGENT_DIR" && "$AGENT_PYTHON" -m threatsculpt_agent \
  --config "$WORK_DIR/agent.toml" --check-config) || fail "agent configuration is invalid"
pass "agent configuration valid"

# --- 9. queue a scan job ----------------------------------------------------

step "9. Create a scan job for 127.0.0.1/32"
curl -sS -X POST "$API/scans" -H "$AUTH" -H 'Content-Type: application/json' -d "{
  \"target\":\"127.0.0.1/32\",\"profile\":\"service\",\"network_id\":\"$NETWORK_ID\"
}" > "$WORK_DIR/scan.json"
jq -e '.error == null' "$WORK_DIR/scan.json" >/dev/null || {
  jq . "$WORK_DIR/scan.json"; fail "scan job creation failed"; }
JOB_ID=$(jq -r '.data.id' "$WORK_DIR/scan.json")
assert_eq "queued" "$(jq -r '.data.status' "$WORK_DIR/scan.json")" "job initial status"

# A target outside the org's authorized networks must be refused at creation.
REJECTED_HTTP=$(curl -s -o "$WORK_DIR/badscan.json" -w '%{http_code}' \
  -X POST "$API/scans" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"target":"8.8.8.0/24","profile":"discovery"}')
[[ "$REJECTED_HTTP" == 4* ]] \
  || fail "control plane accepted a scan of 8.8.8.0/24 (HTTP $REJECTED_HTTP) — target validation is broken"
pass "unauthorized target 8.8.8.0/24 refused (HTTP $REJECTED_HTTP, $(jq -r '.error.code' "$WORK_DIR/badscan.json"))"

# --- 10. the agent does the work -------------------------------------------

step "10. Run the agent: enroll, claim, real nmap, submit results"
info "this invokes nmap -sS -sV -O --top-ports 1000 and takes ~20s"
(cd "$AGENT_DIR" && "$AGENT_PYTHON" -m threatsculpt_agent \
  --config "$WORK_DIR/agent.toml" --once) 2>&1 | tee "$WORK_DIR/agent.log"

grep -q "enrolled as agent" "$WORK_DIR/agent.log" || fail "the agent never enrolled"
pass "agent enrolled and stored its key at 0600"
KEY_MODE=$(stat -c '%a' "$AGENT_STATE/agent.key")
assert_eq "600" "$KEY_MODE" "stored agent key file mode"
grep -q "finished: completed" "$WORK_DIR/agent.log" || {
  tail -30 "$WORK_DIR/agent.log"; fail "the agent did not complete the job"; }

# --- 11. confirm the results landed ----------------------------------------

step "11. Confirm the results reached the database"
JOB_STATUS=$(psql -d "$E2E_DB" -tAc "select status from scan_jobs where id='$JOB_ID'")
assert_eq "completed" "$JOB_STATUS" "job status"

ASSET_COUNT=$(psql -d "$E2E_DB" -tAc "select count(*) from assets where ip='127.0.0.1'")
assert_ge 1 "$ASSET_COUNT" "asset rows for 127.0.0.1"

RESULT_COUNT=$(psql -d "$E2E_DB" -tAc "select count(*) from scan_results where scan_job_id='$JOB_ID'")
assert_ge 1 "$RESULT_COUNT" "scan_result rows"

PORT_COUNT=$(psql -d "$E2E_DB" -tAc \
  "select count(*) from ports where port=$LISTENER_PORT and state='open'")
assert_ge 1 "$PORT_COUNT" "open port $LISTENER_PORT discovered by real nmap"

# The trigger, asserted where it happens. Ingest sets this in the same UPDATE
# that completes the job, so a completed scan is queued for enrichment or the
# scan never completed. If this reads empty, findings will never be generated in
# a running system no matter what the rest of the pipeline does.
ENRICH_QUEUED=$(psql -d "$E2E_DB" -tAc \
  "select coalesce(enrichment_status,'<null>') from scan_jobs where id='$JOB_ID'")
assert_eq "pending" "$ENRICH_QUEUED" "completing the job queued it for enrichment"

info "ports discovered:"
psql -d "$E2E_DB" -c \
  "select port, protocol, state, service, product, version, cpe from ports order by port"

# Every actor's work is on the permanent record.
for action in auth.register scan_job.created agent.enrolled scan_job.claimed scan_result.ingested; do
  COUNT=$(psql -d "$E2E_DB" -tAc "select count(*) from audit_log where action='$action'")
  assert_ge 1 "$COUNT" "audit_log entry '$action'"
done

# --- 12. the product layer: business impact --------------------------------

step "12. Map the asset to a business service"
ASSET_ID=$(psql -d "$E2E_DB" -tAc "select id from assets where ip='127.0.0.1'")

curl -sS -X POST "$API/business-services" -H "$AUTH" -H 'Content-Type: application/json' -d '{
  "name":"Payment processing","criticality":"critical","revenue_at_risk":"4200000.00",
  "owner_name":"Dana Finance","owner_email":"dana@acme-e2e.com"
}' > "$WORK_DIR/service.json"
SERVICE_ID=$(jq -r '.data.id' "$WORK_DIR/service.json")

curl -sS -X PATCH "$API/assets/$ASSET_ID" -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"exposure":"internet"}' > /dev/null
curl -sS -X PUT "$API/assets/$ASSET_ID/services" -H "$AUTH" -H 'Content-Type: application/json' \
  -d "{\"service_ids\":[\"$SERVICE_ID\"]}" > "$WORK_DIR/mapping.json"
assert_eq "Payment processing" \
  "$(jq -r '.data.services[0].name' "$WORK_DIR/mapping.json")" "asset mapped to service"

# --- 12b. the mirror, through the real sync ---------------------------------

step "12b. Sync the CVE mirror from a static feed"
# StaticFeed is the seam enrichment.feeds already provides for exactly this: the
# parsers, upserts and KEV flagging below are the production ones, and the only
# thing standing in is the HTTP fetch, which must not depend on nvd.nist.gov
# being up for this gate to mean something. The mirror is seeded BEFORE the
# worker starts, because a pass over an empty mirror legitimately produces no
# findings and marks the job done.
#
# This is the one remaining stand-in in this script: the sync has no production
# entry point yet (docs/RUNBOOK.md, "The CVE mirror is never synced").
"$CP_PYTHON" "$REPO_ROOT/deploy/e2e_mirror_seed.py" || fail "mirror sync failed"

CVE_COUNT=$(psql -d "$E2E_DB" -tAc "select count(*) from vulnerabilities where kev_listed")
assert_ge 1 "$CVE_COUNT" "KEV-listed CVE in the mirror"

# --- 12c. enrichment, by the process that does it in production -------------

step "12c. Start the enrichment worker and wait for it to find something"
# No direct call to generate_findings anywhere in this script, deliberately.
# The findings asserted below are produced by `python -m threatsculpt.enrichment`
# claiming the job that ingest queued — the same process deploy/docker-compose.yml
# runs. If that trigger is ever removed, this step times out rather than passing.
(cd "$CP_DIR" && exec "$CP_PYTHON" -m threatsculpt.enrichment) \
  > "$WORK_DIR/enrichment.log" 2>&1 &
ENRICH_PID=$!
info "enrichment worker started (pid $ENRICH_PID); its first pass runs immediately"

FINDING_COUNT=0
for _ in $(seq 1 "$ENRICH_TIMEOUT_SECONDS"); do
  kill -0 "$ENRICH_PID" 2>/dev/null || fail "the enrichment worker exited early"
  FINDING_COUNT=$(psql -d "$E2E_DB" -tAc "select count(*) from findings")
  [[ "$FINDING_COUNT" -ge 1 ]] && break
  sleep 1
done
assert_ge 1 "$FINDING_COUNT" "findings generated by the enrichment worker"

ENRICH_STATE=$(psql -d "$E2E_DB" -tAc \
  "select coalesce(enrichment_status,'<null>') from scan_jobs where id='$JOB_ID'")
assert_eq "complete" "$ENRICH_STATE" "the worker released the job"

# One attempt: the job was claimed once and never leased back out.
ENRICH_ATTEMPTS=$(psql -d "$E2E_DB" -tAc \
  "select enrichment_attempts from scan_jobs where id='$JOB_ID'")
assert_eq "1" "$ENRICH_ATTEMPTS" "enrichment attempts spent"

# Every finding is attributed to the job that produced it, which is what makes
# a rescan update rather than duplicate.
ORPHANS=$(psql -d "$E2E_DB" -tAc \
  "select count(*) from findings where scan_job_id is distinct from '$JOB_ID'")
assert_eq "0" "$ORPHANS" "findings attributed to the scan job"

# --- 13. the views a customer actually looks at ----------------------------

step "13. GET /dashboard/executive"
curl -sS -H "$AUTH" "$API/dashboard/executive" | tee "$WORK_DIR/executive.json" | jq .
jq -e '.error == null' "$WORK_DIR/executive.json" >/dev/null || fail "executive dashboard errored"
assert_ge 1 "$(jq -r '.data.services_at_risk | length' "$WORK_DIR/executive.json")" \
  "services_at_risk entries"
assert_eq "Payment processing" \
  "$(jq -r '.data.services_at_risk[0].name' "$WORK_DIR/executive.json")" "top service at risk"
assert_ge 1 "$(jq -r '.data.kev_findings' "$WORK_DIR/executive.json")" "KEV findings surfaced"

step "14. GET /findings"
curl -sS -H "$AUTH" "$API/findings" | tee "$WORK_DIR/findings.json" | jq .
jq -e '.error == null' "$WORK_DIR/findings.json" >/dev/null || fail "findings endpoint errored"
assert_ge 1 "$(jq -r '.meta.total' "$WORK_DIR/findings.json")" "findings total"
assert_eq "127.0.0.1" "$(jq -r '.data[0].asset.ip' "$WORK_DIR/findings.json")" "finding asset ip"
assert_eq "high" "$(jq -r '.data[0].match.confidence' "$WORK_DIR/findings.json")" "match confidence"

step "15. Cross-tenant isolation"
# A second org must not see the first org's data. 404, never 403 (docs/API.md).
curl -sS -X POST "$API/auth/register" -H 'Content-Type: application/json' -d '{
  "org_name":"Other Corp","org_slug":"other-e2e","email":"owner@other-e2e.com",
  "password":"AnotherLongPassphrase7!","full_name":"Other Owner"
}' > "$WORK_DIR/other.json"
# This org's owner must be verified too, exactly like the first one. Without it the
# session is unverified, every call below returns 403 from the verification gate, and
# both assertions stop testing tenancy: `.data | length` reads 0 from an error envelope
# whose `data` is null, so "sees no assets" passes for a caller who cannot reach the
# endpoint at all. An assertion that passes because the request failed is worse than no
# assertion, so the status code is checked explicitly before the body is trusted.
psql -q -d "$E2E_DB" -c \
  "update users set email_verified_at = now(), verification_token_hash = null,
                    verification_expires_at = null
     where email = 'owner@other-e2e.com'" >/dev/null
OTHER_TOKEN=$(curl -sS -X POST "$API/auth/login" -H 'Content-Type: application/json' \
  -d '{"email":"owner@other-e2e.com","password":"AnotherLongPassphrase7!"}' \
  | jq -r '.data.access_token')
[ -n "$OTHER_TOKEN" ] && [ "$OTHER_TOKEN" != "null" ] || fail "second org could not log in"

OTHER_LIST_HTTP=$(curl -s -o "$WORK_DIR/other_assets.json" -w '%{http_code}' \
  -H "Authorization: Bearer $OTHER_TOKEN" "$API/assets")
assert_eq "200" "$OTHER_LIST_HTTP" "second org can reach /assets (so the next check means something)"
assert_eq "0" "$(jq -r '.data | length' "$WORK_DIR/other_assets.json")" \
  "second org sees no assets from the first"

CROSS_HTTP=$(curl -s -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $OTHER_TOKEN" "$API/assets/$ASSET_ID")
assert_eq "404" "$CROSS_HTTP" "cross-tenant fetch returns 404 (not 403)"

printf '\n%s%s ALL END-TO-END ASSERTIONS PASSED %s\n' "$BOLD" "$GREEN" "$RESET"
