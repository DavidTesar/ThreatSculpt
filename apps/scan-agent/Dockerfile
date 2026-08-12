# ThreatSculpt scan agent.
#
# The agent runs as an unprivileged user (UID 10001). It never runs as root and never
# elevates. nmap gets CAP_NET_RAW as a *file capability* on the binary, so raw-socket
# scans work while the Python process itself holds no capabilities at all.

FROM python:3.13-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir --prefix=/install .


FROM python:3.13-slim

# libcap2-bin provides setcap; it is removed again once the capability is set.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap libcap2-bin \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

# On Debian /usr/bin/nmap is the ELF binary; on some derivatives it is a shell wrapper
# around /usr/lib/nmap/nmap, and the capability has to live on the real binary.
RUN set -eux; \
    if [ -x /usr/lib/nmap/nmap ]; then NMAP_BIN=/usr/lib/nmap/nmap; \
    else NMAP_BIN="$(readlink -f /usr/bin/nmap)"; fi; \
    setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$NMAP_BIN"; \
    getcap "$NMAP_BIN"; \
    apt-get purge -y libcap2-bin && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 scanagent \
 && useradd --system --uid 10001 --gid scanagent \
      --home-dir /var/lib/threatsculpt-agent --shell /usr/sbin/nologin scanagent \
 && install -d -o scanagent -g scanagent -m 0700 /var/lib/threatsculpt-agent \
 && install -d -o root -g scanagent -m 0750 /etc/threatsculpt

ENV TS_AGENT_STATE_DIR=/var/lib/threatsculpt-agent \
    TS_AGENT_CONFIG_FILE=/etc/threatsculpt/agent.toml \
    PYTHONUNBUFFERED=1

VOLUME ["/var/lib/threatsculpt-agent"]
USER 10001:10001
WORKDIR /var/lib/threatsculpt-agent

# Cheap liveness signal: the configuration and local allowlist still parse.
HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 \
    CMD ["threatsculpt-agent", "--check-config"]

ENTRYPOINT ["threatsculpt-agent"]

# Run with the capability the file capability needs to be usable, and nothing else:
#   docker run --cap-drop=ALL --cap-add=NET_RAW --network host \
#     -e TS_AGENT_ENROLLMENT_TOKEN=tse_... \
#     -v /etc/threatsculpt:/etc/threatsculpt:ro \
#     -v threatsculpt-state:/var/lib/threatsculpt-agent \
#     threatsculpt/scan-agent:2.0.0
#
# A file capability can only grant what the container's bounding set already permits, so
# --cap-drop=ALL without --cap-add=NET_RAW leaves nmap unable to send raw packets.
