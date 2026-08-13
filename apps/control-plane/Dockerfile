# ThreatSculpt control plane — FastAPI API, tenancy enforcement, risk scoring.
#
# Runs as an unprivileged user (UID 10002) with no capabilities. Migrations are
# NOT run at start-up: a container that migrates on boot races itself the moment
# you run two replicas. Run them as a one-shot job (see deploy/docker-compose.yml).

FROM python:3.13-slim AS builder

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir --prefix=/install .


FROM python:3.13-slim

# curl is the healthcheck's only runtime dependency.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

WORKDIR /app
COPY main.py alembic.ini ./
COPY migrations ./migrations

RUN groupadd --system --gid 10002 controlplane \
 && useradd --system --uid 10002 --gid controlplane \
      --home-dir /app --shell /usr/sbin/nologin controlplane \
 && chown -R controlplane:controlplane /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

USER 10002:10002
EXPOSE 8000

# /health is unauthenticated and does not touch the database; /ready does.
# Liveness must not fail because Postgres blipped — that would restart a healthy API.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["curl", "-fsS", "http://127.0.0.1:8000/health"]

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]
