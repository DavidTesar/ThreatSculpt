# ThreatSculpt Scan Agent

The on-prem half of ThreatSculpt v2. A small Python daemon you install inside your own
network. It polls the ThreatSculpt control plane over outbound HTTPS, runs `nmap` locally
against ranges **you** have authorised, and submits what it observed.

It never listens on a port, so you open no inbound firewall rules. It never receives nmap
flags from the network — only a profile *name* out of a fixed table. And it validates every
scan target against an allowlist in its own config file before it will run anything.

## What it sends

Observations only: host, ports, service, product, version, CPE, OS fingerprint. No CVEs, no
severity, no risk score — enrichment happens in the control plane, so the agent needs no
internet access beyond that one host and no third-party API keys.

## The allowlist is the point

```toml
allowlist = ["10.0.0.0/8", "192.168.0.0/16"]
```

Before invoking nmap, the agent checks the job's target against **this** list, parsed with
Python's `ipaddress` module. Not a string prefix match — `10.0.0.0/8` and `100.0.0.0/8`
share a text prefix and share nothing else.

The control plane also sends an allowlist on every heartbeat. That list may only ever
**narrow** this one; it is intersected with the local list and can never add reach. A target
outside your configured ranges is rejected back to the server and never scanned.

This is what stops a compromised control plane from turning your agent into a
scanner-for-hire. Configure it as tightly as you can.

## Install

### Requirements

- Python 3.13+
- nmap 7.9+ with `CAP_NET_RAW`, granted as a **file capability** — the agent itself runs
  unprivileged and never elevates:

  ```bash
  sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(readlink -f "$(command -v nmap)")"
  ```

  On Debian/Kali `/usr/bin/nmap` is a shell wrapper; the capability belongs on the real
  binary at `/usr/lib/nmap/nmap`, which `readlink -f` above does not resolve for you —
  check with `getcap` and set it on whichever path is the ELF binary.

### From source

```bash
python3 -m venv /opt/threatsculpt-agent/venv
/opt/threatsculpt-agent/venv/bin/pip install /path/to/apps/scan-agent
```

### Docker

```bash
docker build -t threatsculpt/scan-agent:2.0.0 apps/scan-agent
docker run --rm \
  -e TS_AGENT_ENROLLMENT_TOKEN=tse_... \
  -v /etc/threatsculpt:/etc/threatsculpt:ro \
  -v threatsculpt-state:/var/lib/threatsculpt-agent \
  threatsculpt/scan-agent:2.0.0
```

The image runs as UID 10001 (`scanagent`), not root. nmap inside the image carries
`cap_net_raw+ep` as a file capability. Container runtimes drop file capabilities unless the
bounding set permits them, so add just that one:

```bash
docker run --cap-drop=ALL --cap-add=NET_RAW ...
```

For SYN scans and OS fingerprinting of other hosts on your LAN you will also want
`--network host`. Without `NET_RAW`, only the `discovery` profile's TCP-connect fallback
works.

### systemd

```bash
sudo useradd --system --home /var/lib/threatsculpt-agent --shell /usr/sbin/nologin threatsculpt
sudo install -d -o threatsculpt -g threatsculpt -m 0750 /var/lib/threatsculpt-agent /etc/threatsculpt
sudo install -m 0644 packaging/threatsculpt-agent.service /etc/systemd/system/
sudo install -m 0640 -o root -g threatsculpt packaging/agent.example.toml /etc/threatsculpt/agent.toml
sudo systemctl daemon-reload && sudo systemctl enable --now threatsculpt-agent
```

The unit runs with `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, a dedicated
unprivileged user, a read-only filesystem apart from its state directory, and a syscall
filter. See `packaging/threatsculpt-agent.service`.

**One thing worth knowing before you edit that unit:** `NoNewPrivileges=yes` and a setcap'd
nmap are mutually exclusive. With `NoNewPrivileges` set, an exec'd binary cannot *gain*
capabilities from its file capability set, so a setcap'd nmap quietly loses `CAP_NET_RAW`
and every SYN scan fails with a permission error. The unit therefore keeps
`NoNewPrivileges=yes` and grants the capability through systemd's ambient set instead,
confined by `CapabilityBoundingSet`:

```ini
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
```

The agent still runs as an unprivileged user and is never root — it holds exactly the two
capabilities nmap needs to put packets on the wire and nothing else. If you would rather
rely on the file capability (as the container image does, since Docker does not set
`NoNewPrivileges` by default), comment out `AmbientCapabilities` and set
`NoNewPrivileges=no`. Do not leave both the file capability and `NoNewPrivileges=yes` in
place expecting raw scans to work.

## Enrollment

1. In the dashboard, create an enrollment token (`tse_...`). It is single-use and expires in
   one hour.
2. Give it to the agent **without putting it in argv** — anything on the command line is
   visible to every user on the host via `ps`. The agent refuses to start if it spots a
   credential in its arguments.

   ```bash
   sudo install -m 0600 -o threatsculpt /dev/null /var/lib/threatsculpt-agent/enrollment.token
   printf 'tse_...' | sudo -u threatsculpt tee /var/lib/threatsculpt-agent/enrollment.token >/dev/null
   ```

   or `TS_AGENT_ENROLLMENT_TOKEN=tse_...` in the unit's `EnvironmentFile=` (mode 0600).
3. Start the agent. On first run it trades the token for a permanent API key and writes it
   to `/var/lib/threatsculpt-agent/agent.key` at mode 0600.

Enrollment is idempotent: if a key file already exists, the agent uses it and never calls
the enroll endpoint again, so a restart cannot burn a second token or create a duplicate
agent record. Delete the key file to force re-enrollment with a fresh token.

If the control plane revokes the agent — a `401`, or `revoked: true` on a heartbeat — the
agent deletes its stored key and exits 0. That is a normal end of life, not a crash.

## Configuration

TOML at `/etc/threatsculpt/agent.toml` (override with `--config` or
`TS_AGENT_CONFIG_FILE`). Every key can also be set as an environment variable with a
`TS_AGENT_` prefix, which wins over the file.

| Key | Default | Notes |
|---|---|---|
| `control_plane_url` | — | required; must be `https://` (plain http allowed only for localhost) |
| `agent_name` | — | required; shown in the dashboard |
| `allowlist` | `[]` | **required in practice** — an empty list rejects every job |
| `state_dir` | `/var/lib/threatsculpt-agent` | holds `agent.key` |
| `api_key_file` | `<state_dir>/agent.key` | must be mode 0600 |
| `poll_interval_seconds` | `30` | the server may override this per heartbeat |
| `capacity` | `1` | concurrent job leases requested per claim |
| `nmap_path` | `/usr/bin/nmap` | |
| `nmap_timeout_seconds` | `3600` | hard kill; a hung nmap never holds a lease forever |
| `include_port_states` | `["open", "open\|filtered"]` | closed ports are observed but not submitted |
| `max_payload_bytes` | `9437184` | chunk size; the protocol caps a POST at 10 MB |
| `backoff_*`, `max_request_attempts` | see `config.py` | exponential backoff with jitter |
| `shutdown_grace_seconds` | `30` | how long a SIGTERM waits for an in-flight scan |
| `verify_tls` | `true` | do not turn this off |
| `log_level` | `INFO` | |

Secrets (`api_key`, `enrollment_token`) are accepted from the environment or a 0600 file
only. They are never logged: a redaction filter scrubs `tsa_`/`tse_` values and
`Authorization` headers from every log record as a backstop.

See `packaging/agent.example.toml` for a commented starting point.

## Running

```bash
threatsculpt-agent --check-config     # validate config and allowlist, exit
threatsculpt-agent --once             # a single poll cycle, then exit
threatsculpt-agent                    # poll forever (what systemd runs)
```

On `SIGTERM`/`SIGINT` the agent stops claiming work, gives an in-flight scan
`shutdown_grace_seconds` to finish, and if it does not finish, kills nmap and explicitly
releases the job so the control plane can requeue it immediately instead of waiting out the
lease.

## Scan profiles

The job supplies a profile *name*. Flags live only in `profiles.py`:

| Profile | Flags |
|---|---|
| `discovery` | `-sn -PE -PS443,80 -T3` |
| `service` | `-sS -sV --version-intensity 5 -O -T3 --top-ports 1000` |
| `vulnerability` | `-sS -sV --version-intensity 7 -O -T3 -p-` |

An unrecognised profile is rejected back to the server, not guessed at.

## Development

```bash
python3 -m venv .venv && ./.venv/bin/pip install -e '.[dev]'
./.venv/bin/pytest --cov=threatsculpt_agent
./.venv/bin/ruff check . && ./.venv/bin/mypy
```

The HTTP side is mocked with `respx`; nmap XML parsing is tested against fixtures captured
from a real `nmap 7.99` run (`tests/fixtures/*.xml`), regenerable with
`tests/fixtures/regenerate.sh`.
