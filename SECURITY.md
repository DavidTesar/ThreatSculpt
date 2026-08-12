# Security Policy

ThreatSculpt is a security product that runs inside customer networks and holds a map of their
weaknesses. A defect here is worth more to an attacker than a defect in most software. The
posture below reflects that.

## Reporting a vulnerability

Email **security@threatsculpt.example** with a description, reproduction steps, and impact.
Please do not open a public issue.

We acknowledge within 2 business days and aim to ship a fix within 30 days for high-severity
issues. We will credit you unless you prefer otherwise.

## Supported versions

| Version | Supported |
|---|---|
| v2 (`rewrite/v2`) | Yes |
| v1 (`main`) | **No.** Archived university capstone. See below. |

## v1 is not safe to run

v1 is retained for history only. If you deployed it, treat it as compromised:

- **MongoDB Atlas credentials were committed to this public repository** across 16 commits, and
  **Vulners and Pulsedive API keys** across 4. Revoke all of them.
- Passwords were stored in plaintext by the desktop application, and bcrypt-hashed by the web
  server, against the same user collection.
- There was no session mechanism. Endpoints accepted a `userID` in the request body and
  returned that user's data to any caller, so any user could read any other user's scan
  results by editing one field.
- An unauthenticated caller could delete the entire vulnerabilities collection.

## v2 security properties

### Tenant isolation
Enforced in three independent layers: `org_id` foreign keys in the schema, an `OrgScope` that
every tenant query must pass through, and PostgreSQL Row-Level Security as a backstop for a
bug in the second layer. No endpoint accepts an org identifier from the caller; it is derived
from the authenticated principal only.

Cross-tenant access returns `404`, never `403` — a `403` would confirm the resource exists.

### Authentication
Argon2id password hashing. Short-lived JWT access tokens with rotating refresh tokens stored
hashed and delivered as `HttpOnly`, `Secure`, `SameSite=Lax` cookies. Reuse of a rotated
refresh token revokes the entire family, which is the detection signal for a stolen token.
Login is constant-time with respect to whether an account exists. Auth endpoints are rate
limited per IP and per account.

Users and agents are separate principal types with separate credentials and separate
authentication dependency chains — not two roles sharing one mechanism.

### Scan authorization
A scan job is an instruction to send packets at a network, so it is validated twice:

1. The control plane refuses any target not contained by a network the org has registered and
   explicitly marked `authorized`.
2. The agent independently re-validates against the allowlist in its **own local config file**
   before invoking nmap. The server-supplied allowlist may only narrow the local one.

The second check is the one that matters. It means a compromised control plane cannot make a
customer's agent scan a third party.

nmap is invoked with an argument vector built from a fixed profile map — never a shell string,
never a caller-supplied flag. Output is parsed from nmap's XML, not scraped from stdout.

### Agent hardening
Runs as a dedicated unprivileged user. nmap receives `CAP_NET_RAW` via file capability rather
than the agent running as root. API keys are stored at mode `0600`, never passed as
command-line arguments (visible in `ps`), and never logged.

### Data handling
Secrets come from the environment or a secret manager and are never committed — enforced by
secret scanning in CI. Tokens and API keys are stored as SHA-256 hashes; the plaintext is
shown exactly once at issuance. Logs are structured and scrubbed of credentials. All
authentication events, scan creations, finding status changes, and agent enrollments are
written to an append-only audit log.

## Responsible use

ThreatSculpt sends unsolicited network traffic to whatever it is pointed at. In most
jurisdictions, scanning infrastructure you do not own or have written authorization to test is
illegal. The `authorized` flag on a network is not a formality — it is the record that you
asserted you had permission.

The product deliberately does not exploit, pivot, or control sessions. It observes and
prioritizes.
