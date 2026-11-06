#!/bin/sh
# Runs mscan's tests: against tools/fakescan.py always, and against the Docker scanners if they are up:
#   docker run -d --name mscan-clamd -p 127.0.0.1:53310:3310 clamav/clamav-debian:stable
#   docker run -d --name mscan-spamd --platform linux/amd64 -p 127.0.0.1:50783:783 --entrypoint spamd \
#       dinkel/spamassassin:latest --syslog=stderr -i 0.0.0.0:783 -A 0.0.0.0/0 -u nobody --max-children 2
set -eu
here=$(cd "$(dirname "$0")" && pwd)
python3 "$here/../tools/fakescan.py" 53311 50784 > /dev/null &
fake=$!
trap 'kill $fake' EXIT
sleep 0.5
extra=""
docker ps --format '{{.Names}}' | grep -q mscan-clamd && extra="CLAMD_PORT=53310"
docker ps --format '{{.Names}}' | grep -q mscan-spamd && extra="$extra SPAMD_PORT=50783"
cd "$here/.." && env FAKE_CLAMD_PORT=53311 FAKE_SPAMD_PORT=50784 $extra ceesafec test "$@"
