# ThreatSculpt web dashboard — static React/Vite bundle behind nginx.
#
# The API base URL is baked in at build time (Vite inlines import.meta.env), so
# VITE_API_BASE_URL is a build argument, not a runtime environment variable.
# Nothing secret may ever be passed here: everything in the bundle is public.

FROM node:24-slim AS builder

WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci

COPY . .

ARG VITE_API_BASE_URL=/api/v1
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
RUN npm run build


FROM nginxinc/nginx-unprivileged:1.27-alpine

# The unprivileged image already runs as UID 101 and listens on 8080.
COPY --from=builder /build/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["wget", "-q", "--spider", "http://127.0.0.1:8080/"]
