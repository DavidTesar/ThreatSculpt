# Where the control plane lives, and how its name is resolved.
#
# THIS IS THE ONE FILE TO REPLACE PER PLATFORM. It is separate from nginx.conf so a
# deployment can bind-mount its own copy — or COPY a different one in a derived image —
# without forking the rest of the server config.
#
# Why the indirection at all
# --------------------------
# nginx resolves a literal `proxy_pass http://control-plane:8000` hostname ONCE, at
# startup, and refuses to start if the name does not resolve:
#
#     [emerg] host not found in upstream "control-plane"
#
# That turns any control-plane outage into a *frontend* outage: the web tier will not
# come up while the API is down, restarting, or merely slower to start, and compose's
# `depends_on` does not help because it waits for the container, not for its DNS record.
# Putting the upstream in a variable defers resolution to request time, so nginx always
# starts and an unreachable backend degrades to a 502 on /api only — the dashboard shell
# still serves.
#
# Per-platform resolver
# ---------------------
# 127.0.0.11 is Docker's embedded DNS. It exists on user-defined networks (which is what
# `docker compose` creates) and NOT on the default bridge, so a bare `docker run` without
# `--network` will fail to resolve and every /api request will 502 after `resolver_timeout`.
# That is the intended degraded behaviour, but it is worth knowing why it happens.
#
#   Docker / compose   resolver 127.0.0.11 valid=10s;      (this file, as shipped)
#   Kubernetes         resolver kube-dns.kube-system.svc.cluster.local valid=10s;
#                      — and set $control_plane to the Service DNS name
#   VM / bare metal    resolver <the host's nameserver> valid=10s;   e.g. from /etc/resolv.conf
#
# `valid=10s` caps how long a resolved address is cached, so a control plane that moves
# (a rescheduled pod, a new container IP) is picked up within ten seconds instead of the
# record's own TTL, which may be much longer.
resolver 127.0.0.11 valid=10s;

# Bounded, so a missing or unreachable resolver fails fast to 502 rather than hanging the
# request for the 30s default.
resolver_timeout 5s;

# No URI path here on purpose: with a variable and no URI part, nginx passes the client's
# original request URI through unchanged, which is what the literal form did. Adding a
# path would silently start rewriting /api/v1/... instead.
set $control_plane "http://control-plane:8000";
