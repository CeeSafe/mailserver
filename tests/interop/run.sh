#!/bin/sh
# The relay against a real Postfix: builds tests/interop/postfix, runs it on 127.0.0.1:52525, and runs the
# conformance harness's RealMx tests with the relay pointed there.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
docker build -q -t mailserver-postfix-interop "$here/postfix" > /dev/null
docker rm -f mailserver-postfix > /dev/null 2>&1 || true
docker run -d --name mailserver-postfix -p 127.0.0.1:52525:25 mailserver-postfix-interop > /dev/null
trap 'docker rm -f mailserver-postfix > /dev/null' EXIT
for i in $(seq 1 50); do
    python3 -c "import smtplib; smtplib.SMTP('127.0.0.1', 52525, timeout=1).quit()" 2>/dev/null && break
    sleep 0.2
done
REAL_MX=1 RELAY_PORT=52525 "$here/../conformance/run.sh"
