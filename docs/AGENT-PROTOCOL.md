# ThreatSculpt v2 — Agent Protocol

The contract between the on-prem `scan-agent` and the cloud `control-plane`.

Transport: HTTPS only, outbound from the agent. The agent never listens on a port.
Base path: `/api/v1/agent`. All requests carry `Authorization: Bearer <agent_api_key>`
except enrollment.

## 1. Enrollment

An operator creates an enrollment token in the dashboard and configures it on the agent host.
The agent trades it for a permanent API key on first start.

```
POST /api/v1/agent/enroll
{
  "enrollment_token": "tse_<opaque>",
  "name": "hq-dc-scanner-01",
  "version": "2.0.0",
  "hostname": "scanner01.corp.local"
}
→ 201
{
  "agent_id": "uuid",
  "api_key": "tsa_<opaque>",     // shown once, never retrievable again
  "org_id": "uuid",
  "allowlist": ["10.0.0.0/8", "192.168.0.0/16"],
  "poll_interval_seconds": 30
}
```

Enrollment tokens are single-use and expire in 1 hour. Consumption is a conditional UPDATE
(`SET used_at = now() WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()`)
returning the row — a read-then-write race would let one token enroll two agents.

The agent persists `api_key` to a file with mode `0600` and never logs it.

## 2. Heartbeat

```
POST /api/v1/agent/heartbeat
{ "version": "2.0.0", "nmap_version": "7.94", "healthy": true }
→ 200
{ "allowlist": ["10.0.0.0/8"], "poll_interval_seconds": 30, "revoked": false }
```

Updates `agents.last_seen_at`. The response is how the control plane pushes allowlist changes
and tells a revoked agent to shut down. An agent receiving `revoked: true` deletes its stored
key and exits.

## 3. Claiming work

```
POST /api/v1/agent/jobs/claim
{ "capacity": 1 }
→ 200
{
  "jobs": [{
    "job_id": "uuid",
    "target": "10.0.4.0/24",
    "profile": "service",
    "lease_expires_at": "2026-08-12T18:00:00Z"
  }]
}
```

Claim query — this exact shape, so two agents in one org never take the same job:

```sql
UPDATE scan_jobs SET status='claimed', agent_id=$1, lease_expires_at=now()+interval '30 min',
                     attempts = attempts + 1
WHERE id IN (
  SELECT id FROM scan_jobs
  WHERE org_id=$2 AND status='queued' AND attempts < 3
  ORDER BY created_at LIMIT $3
  FOR UPDATE SKIP LOCKED
) RETURNING ...;
```

A sweeper returns jobs whose `lease_expires_at` has passed to `queued`, or marks them `failed`
once `attempts >= 3`.

## 4. The agent validates the target before scanning

**This is the security boundary that matters most in this protocol.**

On receiving a job, before invoking nmap, the agent checks that `target` is contained by an
entry in its **locally configured** allowlist — the one in its own config file, not the one
the server just sent. If it is not, the agent rejects the job:

```
POST /api/v1/agent/jobs/{job_id}/reject
{ "reason": "target_not_in_local_allowlist", "detail": "10.0.4.0/24 not within configured ranges" }
```

The server-supplied allowlist from `/heartbeat` may only ever *narrow* the local one. A
compromised control plane must not be able to make a customer's agent scan a third party.
Because the local allowlist wins, it cannot.

## 5. Progress and results

```
POST /api/v1/agent/jobs/{job_id}/status
{ "status": "running", "progress_percent": 40 }
```

```
POST /api/v1/agent/jobs/{job_id}/results
{
  "started_at": "...", "finished_at": "...",
  "nmap_version": "7.94",
  "hosts": [{
    "ip": "10.0.4.12",
    "hostname": "db01.corp.local",
    "mac": "00:11:22:33:44:55",
    "state": "up",
    "os": {"family": "Linux", "version": "5.x", "accuracy": 96},
    "ports": [{
      "port": 443, "protocol": "tcp", "state": "open",
      "service": "https", "product": "nginx", "version": "1.18.0",
      "cpes": ["cpe:/a:nginx:nginx:1.18.0"]
    }]
  }]
}
→ 202 { "accepted": true, "hosts_ingested": 1 }
```

The agent submits **observations only** — what is running. It does not submit CVEs, severity,
or risk. Enrichment and scoring happen in the control plane. This keeps the agent's internet
requirement to exactly one host and lets historical scans improve as the CVE mirror updates.

Result payloads are capped (10 MB). Larger scans are submitted in chunked batches keyed by
job id; the ingest endpoint is idempotent on `(job_id, host_ip)` so a retried batch does not
double-insert.

The control plane **re-validates** every submitted host IP against the job's target CIDR and
the org's registered networks. Results outside that range are rejected and audit-logged. Never
trust a client, including your own agent.

## 6. Errors

`401` revoked or unknown key → agent wipes its key and exits.
`409` job no longer claimable (lease expired, reassigned) → agent drops it and re-polls.
`429` with `Retry-After` → agent backs off; poll loop uses exponential backoff with jitter.
`5xx` → retry with backoff, cap 5 attempts, then surface as job failure.

## Agent security requirements

- Runs as a dedicated unprivileged user. nmap gets `CAP_NET_RAW` via file capability, **not**
  by running the agent as root.
- The nmap argument vector is built from a fixed profile map. It is never a shell string and
  never contains a user-supplied flag.

```python
SCAN_PROFILES = {
    "discovery":     ["-sn", "-PE", "-PS443,80", "-T3"],
    "service":       ["-sS", "-sV", "--version-intensity", "5", "-O", "-T3", "--top-ports", "1000"],
    "vulnerability": ["-sS", "-sV", "--version-intensity", "7", "-O", "-T3", "-p-"],
}
```

- Output is parsed from nmap's **XML** (`-oX -`), not scraped from stdout text. v1 parsed
  `python-nmap`'s stringified dict and split on tabs; that breaks on any format change.
- Every subprocess call has a timeout. A hung nmap must not hold a job lease forever.
- The API key is never written to logs, never passed as a command-line argument (visible in
  `ps`), and is read from a `0600` file or an environment variable.
