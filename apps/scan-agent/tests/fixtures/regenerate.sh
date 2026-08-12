#!/usr/bin/env bash
# Regenerate the nmap XML fixtures used by tests/test_xml_parser.py.
#
# These are captured from a REAL nmap run through the agent's own NmapRunner, not
# hand-written, so the parser is tested against output nmap actually produces. A local HTTP
# listener is started first so at least one port comes back open with a product, version,
# and CPE to parse.
#
# Requires nmap with CAP_NET_RAW (see README). Run from the scan-agent directory:
#   ./tests/fixtures/regenerate.sh
set -euo pipefail

cd "$(dirname "$0")/../.."
PYTHON="${PYTHON:-./.venv/bin/python}"
PORT="${FIXTURE_PORT:-8080}"

"$PYTHON" -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 &
LISTENER=$!
trap 'kill "$LISTENER" 2>/dev/null || true' EXIT
sleep 1

"$PYTHON" tests/fixtures/capture.py
echo "fixtures written to tests/fixtures/"
