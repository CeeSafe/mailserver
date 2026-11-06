#!/bin/sh
# Runs msieve's tests: the unit tests, then (with Docker) the differential test against Pigeonhole's sieve-test.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cd "$here/.."
ceesafec test
if command -v docker > /dev/null && docker info > /dev/null 2>&1; then
    (cd examples/run && ceesafec build > /dev/null)
    python3 "$here/differential/compare.py" "$here/../examples/run/out/run" "$@"
else
    echo "docker is not running: the differential test was skipped"
fi
