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
refresh token revokes the entire family, which is the detection signal for a stolen token;
the revocation and its audit record are committed before the request is rejected, so the
detection survives the rejection that triggered it. Every login spends the same fixed
amount of Argon2 work — four verifications, padded with dummy work — so the response time is
constant with respect to whether the account exists, whether it is locked out, whether it has
been verified, and how many organisations the address holds an account in. That last one
matters in the consultancy market this product sells into, where a per-candidate cost let an
unauthenticated stopwatch count how many of your tenants somebody is a customer of. Auth
endpoints are rate limited per IP; everything else is rate limited per authenticated
principal, with a separate, smaller bucket for callers presenting no usable credential.

**Access tokens are stateless and are not revoked.** Logout, a password change, a password
reset and deactivating a user all revoke the refresh-token family immediately, so no new
access token can be minted — but an access token already issued stays valid until it
expires, which is at most `TS_ACCESS_TOKEN_TTL_MINUTES` (15 by default). There is no
denylist. That is the deliberate trade for statelessness: a denylist consulted on every
request needs shared state across workers, and the in-process store this service ships with
would enforce it on one worker and not the others — worse than not claiming it at all. Treat
15 minutes as the window in which a stolen access token remains usable, and revoke at the
refresh layer, which is where revocation is real.

An email address may hold an account in several organisations; `users` is unique on
`(org_id, email)`. Login verifies the presented password against every such account and
binds a tenant scope only for the one that matched.

### Email verification

Registration is open — anyone may submit any address — so **a claim on an address counts for
nothing until control of it is proved**. An unverified account is not a login candidate, so it
can neither authenticate nor absorb another account's failed attempts, and it does not occupy
one of the address's slots. Registering an address somebody else owns therefore takes nothing
away from them: not a sign-up, not a login, not a place in the candidate window. An
administrator adding a colleague is the same kind of assertion and is treated the same way.

Registration does return a session, because the registrant is holding the browser that made
the request. That session may call `GET /auth/me`, the two verification endpoints and
`POST /auth/logout`, and **nothing else** — every other endpoint answers `403
email_not_verified`, and the refresh token will not rotate, so it cannot renew itself
indefinitely without the address ever being proved. This service points scanners at networks
and issues agent enrollment tokens on request; neither should be reachable by somebody who
has not shown they own the address the audit log will attribute it to.

Verification tokens are opaque random values stored as SHA-256, shown once, replaced rather
than accumulated, and expired after `TS_EMAIL_VERIFICATION_TTL_HOURS` (24 by default). An
expired claim can no longer be verified.

The number of accounts one address may hold is capped as a backstop, and the cap is applied
at **verification** — the moment a slot is actually taken — never at registration. Applying it
at registration is what an earlier revision did, and it converted an account-lockout attack
into a denial of onboarding: ten unauthenticated registrations against a prospect's address
and its real owner met a conflict they had not caused and could not clear.

> **Delivery is not wired, and the service refuses to start because of it.** This branch has
> no mail infrastructure. The verification state machine is fully enforced, but no
> `TS_EMAIL_DELIVERY` value can actually deliver a message, so **no account could ever be
> verified and the service could onboard nobody**. Rather than start cleanly and then refuse
> every login for a reason no operator would connect back to a mail setting, `create_app`
> raises `UndeliverableEmailError` at boot with a message naming the setting and the fix —
> the same posture as the RLS check refusing a privileged database role.
>
> Wiring a provider is one class implementing `EmailSender` in `auth/delivery.py`, its name
> added to `DELIVERING_MODES`, and `TS_EMAIL_DELIVERY` set to it. Nothing that decides
> whether an address is proved changes with it.
>
> To run without delivery anyway — local development and the test suite — set
> `TS_ALLOW_UNDELIVERABLE_EMAIL=1`. It is logged at CRITICAL on every boot, and it does not
> make verification work: it only stops the refusal. There is deliberately **no** option to
> auto-verify when delivery is off, because that would silently disable the control that
> stops a stranger claiming an address they do not own. A deployment that refuses to start is
> considerably better than one that is quietly insecure.

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
