#!/bin/sh
# Runs mqueue's tests against tools/fakemx.py, with the tls package's test certificate for STARTTLS.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
fixtures="$here/../../../../../CeeSafeLibs/tls/tests/fixtures"
log=$(mktemp -d)
python3 "$here/../tools/fakemx.py" 52600 "$log" "$fixtures/localhost.pem" "$fixtures/localhost.key" > "$log/ready" &
fake=$!
trap 'kill $fake; rm -rf "$log"' EXIT
for i in $(seq 1 50); do grep -q ready "$log/ready" 2>/dev/null && break; sleep 0.1; done
cd "$here/.." && env FAKEMX_PORT=52600 FAKEMX_LOG="$log" ceesafec test "$@"
