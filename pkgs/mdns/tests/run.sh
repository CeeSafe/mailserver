#!/bin/sh
# Starts tools/fakedns.py with tests/zone.yaml and runs the tests against it.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
port=${DNS_TEST_PORT:-55353}
python3 "$here/../tools/fakedns.py" "$port" "$here/zone.yaml" > /dev/null &
server=$!
trap 'kill $server' EXIT
sleep 0.5
cd "$here/.." && DNS_TEST_PORT=$port ceesafec test "$@"
