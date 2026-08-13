#!/usr/bin/env bash
#
# Asserts that every route class the dashboard serves carries its security headers.
#
# This exists because the failure it guards against is completely invisible: nginx
# inherits `add_header` from an outer block only while the inner block declares no
# `add_header` of its own. Adding one `add_header Cache-Control ...` to a location
# silently strips every security header from that location, with no warning, no config
# error, and no change anywhere near the security headers themselves. That is exactly
# what had happened here — the headers were declared once at server level and reached
# only the /api proxy, while every HTML document and every asset was served bare.
#
# Reading the config cannot catch it. Only a real request can.
#
# Usage:
#   apps/web/check-security-headers.sh [base-url]      # default http://127.0.0.1:8080
set -uo pipefail

BASE="${1:-http://127.0.0.1:8080}"

REQUIRED_HEADERS=(
  "x-content-type-options"
  "x-frame-options"
  "referrer-policy"
  "permissions-policy"
  "strict-transport-security"
  "content-security-policy"
)

failures=0

note_failure() {
  echo "  FAIL: $1"
  failures=$((failures + 1))
}

headers_for() {
  # -s so a 404 or 502 is still fetched: `always` means the headers must be there too.
  curl -sS -o /dev/null -D - "${BASE}$1" 2>/dev/null | tr -d '\r'
}

check_route() {
  local path="$1" headers status
  headers="$(headers_for "$path")"
  status="$(printf '%s\n' "$headers" | awk 'NR==1 {print $2}')"

  if [ -z "$status" ]; then
    note_failure "$path — no response at all"
    return
  fi

  echo "GET $path -> $status"
  for header in "${REQUIRED_HEADERS[@]}"; do
    if ! printf '%s\n' "$headers" | grep -qi "^${header}:"; then
      note_failure "$path is missing ${header}"
    fi
  done

  # The clickjacking control that actually matters: revoke-agent and delete-network
  # are one click each behind an authenticated session.
  if ! printf '%s\n' "$headers" | grep -qi "content-security-policy:.*frame-ancestors 'none'"; then
    note_failure "$path CSP does not set frame-ancestors 'none'"
  fi

  # Guards against a future "just make it work" weakening of the policy.
  local csp
  csp="$(printf '%s\n' "$headers" | grep -i '^content-security-policy:')"
  if printf '%s\n' "$csp" | grep -qE "script-src[^;]*'unsafe-inline'"; then
    note_failure "$path CSP allows inline script"
  fi
  if printf '%s\n' "$csp" | grep -qE "script-src[^;]*'unsafe-eval'"; then
    note_failure "$path CSP allows eval"
  fi

  # Two Cache-Control headers means `expires` and `add_header` are fighting, and which
  # one a given cache honours is not worth finding out.
  local cc_count
  cc_count="$(printf '%s\n' "$headers" | grep -ci '^cache-control:')"
  if [ "$cc_count" -gt 1 ]; then
    note_failure "$path sends $cc_count Cache-Control headers"
  fi
}

# Discover a real hashed asset rather than guessing a filename.
asset_path="$(curl -sS "${BASE}/" 2>/dev/null | grep -oE '/assets/[A-Za-z0-9._-]+\.css' | head -1)"
if [ -z "$asset_path" ]; then
  echo "FAIL: could not find a CSS asset in the served index.html — is ${BASE} the app?"
  exit 1
fi

echo "Checking ${BASE}"
echo

for route in / /index.html /findings /settings "$asset_path" /api/v1/health /no-such-path; do
  check_route "$route"
done

echo
if [ "$failures" -ne 0 ]; then
  echo "${failures} security-header check(s) failed."
  exit 1
fi
echo "All routes carry their security headers."
