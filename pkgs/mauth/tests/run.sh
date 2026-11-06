#!/bin/sh
# Unit tests, plus the live ones against mdns's fakedns.py serving tests/auth-zone.yaml and the DKIM keys. The
# RFC 7208 suite and the DKIM differential are separate: tests/spf/run.py and tests/dkim/run.py.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
port=${DNS_TEST_PORT:-55357}
zone=$(mktemp)
cat "$here/auth-zone.yaml" "$here/dkim/zone.yaml" > "$zone"
python3 "$here/../../mdns/tools/fakedns.py" "$port" "$zone" > /dev/null &
server=$!
trap 'kill $server; rm -f "$zone"' EXIT
sleep 0.5
cd "$here/.." && DNS_TEST_PORT=$port ceesafec test "$@"
