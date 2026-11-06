#!/bin/sh
# Builds the server, starts it against a fresh database on the Postgres of PostgresClient/tests/setup-docker.sh,
# and runs the black-box SMTP tests (Python's smtplib, an independent client) against it.
#
#   tests/conformance/run.sh                    # PG_TEST_PORT defaults to 55432
#   tests/conformance/run.sh --imap [Class.test ...]   # only the IMAP tests (imaplib and raw sockets)
#   IMAP_PLAINTEXT_AUTH=true tests/conformance/run.sh --imap   # also IDLE over plaintext
#   tests/conformance/run.sh --web [Class.test ...]    # only the HTTP tests
#   tests/conformance/run.sh --admin [Class.test ...]  # the admin JSON API
#   tests/conformance/run.sh --acme                     # certificate issuance and renewal against a fake CA
#   tests/conformance/run.sh --import                   # import-cosmomail from a CosmoMail database and fake S3
#   tests/conformance/run.sh --proxy                    # PROXY protocol headers, required from 127.0.0.1
#   tests/conformance/run.sh --dav [Class.test ...]     # CalDAV and CardDAV
#   tests/conformance/run.sh --ews [Class.test ...]     # EWS (SOAP) on the HTTPS listener
#   tests/conformance/run.sh --eas [Class.test ...]     # ActiveSync (eas_test.py, its own WBXML codec)
#   tests/conformance/run.sh --search-differential [-v]   # pkgs/mimap/tools/search-differential.py
#   tests/conformance/run.sh --fetch-differential [-v]    # pkgs/mimap/tools/fetch-differential.py
#   tests/conformance/run.sh --imaptest [--secs N] [--clients N]   # pkgs/mimap/tools/imaptest.py
#   tests/conformance/run.sh --imap-latency [-n N] [--tls] [--smtp] [--no-dovecot]   # pkgs/mimap/tools/latency.py
#   tests/conformance/run.sh --imap-bench [...]   # pkgs/mimap/tools/bench.py (raises the open-files limit)
#   tests/conformance/run.sh --load [clients] [messages each]
#   REAL_SCANNERS=1 CLAMD=127.0.0.1:53310 SPAMD=127.0.0.1:50783 SCAN_TIMEOUT=60 tests/conformance/run.sh
#       (against mscan's Docker ClamAV and SpamAssassin: see pkgs/mscan/tests/run.sh)
set -eu
# One run at a time on this machine (the ports and the database are fixed), from whichever tree: later runs wait.
lock=${CONFORMANCE_LOCK:-/tmp/mailserver-conformance.lock}
while ! mkdir "$lock" 2>/dev/null; do
    holder=$(cat "$lock/pid" 2>/dev/null || true)
    if [ -n "$holder" ] && ! kill -0 "$holder" 2>/dev/null; then
        rm -rf "$lock"   # left by a run that was killed
        continue
    fi
    sleep 2
done
echo $$ > "$lock/pid"
here=$(cd "$(dirname "$0")" && pwd)
root="$here/../.."
fixtures="$root/../../CeeSafeLibs/tls/tests/fixtures"
port=${PG_TEST_PORT:-55432}
work=$(mktemp -d)
server=""
dns=""
sts=""
acme=""
s3=""
trap 'kill $server $dns $scanners $mx $sts $acme $s3 2>/dev/null || true; rm -rf "$work" "$lock"' EXIT

(cd "$root" && ceesafec build -o out/mailserver --cflag -O2 >/dev/null)
cat "$here/zone.yaml" "$root/pkgs/mauth/tests/dkim/zone.yaml" > "$work/zone.yaml"
FAKEDNS_LOG=1 python3 "$root/pkgs/mdns/tools/fakedns.py" 55358 "$work/zone.yaml" > /dev/null 2> "$work/dns.log" &
dns=$!
python3 "$root/pkgs/mscan/tools/fakescan.py" 53321 50794 > "$work/scan.log" &
scanners=$!
for i in $(seq 1 50); do grep -q ready "$work/scan.log" 2>/dev/null && break; sleep 0.1; done
# The remote MX hosts the relay delivers to: every MX in zone.yaml is 127.0.0.1, on fakemx's port.
python3 "$root/pkgs/mqueue/tools/fakemx.py" 52700 "$work/mx" "$fixtures/localhost.pem" "$fixtures/localhost.key" \
    > "$work/mx.log" &
mx=$!
for i in $(seq 1 50); do grep -q ready "$work/mx.log" 2>/dev/null && break; sleep 0.1; done
# MTA-STS: a policy server with a self-signed certificate for its mta-sts.* names, which the relay trusts beside the
# fixtures' CA (that one for fakemx's localhost certificate).
openssl=${OPENSSL:-/opt/homebrew/opt/openssl@3/bin/openssl}
[ -x "$openssl" ] || openssl=openssl
"$openssl" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj "/CN=mta-sts test" \
    -addext "subjectAltName=DNS:mta-sts.sts.test,DNS:mta-sts.stsbad.test,DNS:mta-sts.stscert.test,DNS:mta-sts.ststesting.test" \
    -keyout "$work/sts.key" -out "$work/sts.pem" 2>/dev/null
cat "$fixtures/ca.pem" "$work/sts.pem" > "$work/trust.pem"
python3 "$root/pkgs/mqueue/tools/fakests.py" 52800 "$work/sts.pem" "$work/sts.key" "$here/sts.yaml" \
    > "$work/sts.ready" 2> "$work/sts.log" &
sts=$!
for i in $(seq 1 50); do grep -q ready "$work/sts.ready" 2>/dev/null && break; sleep 0.1; done
# --acme: a fake CA (pkgs/macme/tools/fakeacme.py), and the server starts with no certificate: it makes a placeholder,
# then orders one, answering HTTP-01 on its port 2080. Every 3rd POST is a badNonce; mta-sts.fail.example is refused.
acme_conf=""
mode_conf=""
s3=""
if [ "${1:-}" = "--import" ]; then
    mkdir -p "$work/s3"
    python3 "$here/fakes3.py" 52950 "$work/s3" import-access import-secret eu-test-1 "$work/s3.log" \
        > "$work/s3.ready" 2>&1 &
    s3=$!
    for i in $(seq 1 50); do grep -q ready "$work/s3.ready" 2>/dev/null && break; sleep 0.1; done
    mode_conf="[import]
source = \"postgres://cee:cee_test_pw@127.0.0.1:$port/cosmomail_src?sslmode=disable\"
s3_endpoint = \"http://127.0.0.1:52950\"
s3_bucket = \"mailstore\"
s3_region = \"eu-test-1\"
s3_access_key = \"import-access\"
s3_secret_key = \"import-secret\""
fi
if [ "${1:-}" = "--proxy" ]; then
    mode_conf="[proxy]
from = \"127.0.0.1\""
fi
if [ "${1:-}" = "--ews" ]; then
    mode_conf="[http]
advertise_exchange = true"
fi
if [ "${1:-}" = "--acme" ]; then
    python3 "$root/pkgs/macme/tools/fakeacme.py" 52900 "$fixtures/localhost.pem" "$fixtures/localhost.key" 2080 \
        "$work/acme.log" --bad-nonce-every 3 --fail mta-sts.fail.example > "$work/acme.ready" 2>&1 &
    acme=$!
    for i in $(seq 1 100); do grep -q ready "$work/acme.ready" 2>/dev/null && break; sleep 0.1; done
    acme_conf="[acme]
directory = \"https://localhost:52900/dir\"
email = \"postmaster@test.example\"
account_key = \"$work/acme-account.pem\"
names = \"mx.test.example\"
check_interval = 2
retry_interval = 2
trust_file = \"$fixtures/ca.pem\""
fi
docker exec ceesafe-pg-test psql -q -U cee -d ceetest -c "DROP DATABASE IF EXISTS mailserver_test WITH (FORCE)" \
    -c "CREATE DATABASE mailserver_test" >/dev/null
# imaptest, the latency tool and the benchmarks log in over plaintext.
case "${1:-}" in --imaptest|--imap-latency|--imap-bench) IMAP_PLAINTEXT_AUTH=${IMAP_PLAINTEXT_AUTH:-true} ;; esac
# The benchmarks open thousands of connections (the server and the tool need the descriptors) and APPEND 50 MB.
if [ "${1:-}" = "--imap-bench" ]; then
    if [ "$(ulimit -n)" != unlimited ] && [ "$(ulimit -n)" -lt 20000 ]; then
        ulimit -n 20000 2>/dev/null || ulimit -n "$(ulimit -Hn)" 2>/dev/null || true
    fi
    MAX_APPEND_SIZE=${MAX_APPEND_SIZE:-60000000}
    IMAP_MAX_CONNECTIONS=${IMAP_MAX_CONNECTIONS:-10000}
fi
# The IMAP tests APPEND and FETCH 10 MB messages (and read this to know what is too big).
MAX_APPEND_SIZE=${MAX_APPEND_SIZE:-16000000}
export MAX_APPEND_SIZE
cat > "$work/mailserver.toml" <<CONF
hostname = "mx.test.example"
database = "postgres://cee:cee_test_pw@127.0.0.1:$port/mailserver_test?sslmode=disable"
blobs = "$work/blobs"
workers = ${RUNTIME_THREADS:-4}
[smtp]
mx = "127.0.0.1:2525"
submission = "127.0.0.1:2587"
submissions = "127.0.0.1:2465"
max_message_size = 3000000
[imap]
imap = "127.0.0.1:2143"
imaps = "127.0.0.1:2993"
allow_plaintext_auth = ${IMAP_PLAINTEXT_AUTH:-false}
max_append_size = $MAX_APPEND_SIZE
max_connections = ${IMAP_MAX_CONNECTIONS:-1000}
[dns]
servers = "127.0.0.1"
port = 55358
inbound_auth = ${INBOUND_AUTH:-true}
[scan]
clamd = "${CLAMD:-127.0.0.1:53321}"
spamd = "${SPAMD:-127.0.0.1:50794}"
clamd_timeout = ${SCAN_TIMEOUT:-1}
spamd_timeout = ${SCAN_TIMEOUT:-1}
[relay]
workers = ${RELAY_WORKERS:-4}
port = ${RELAY_PORT:-52700}
retry = "1"
max_age = 4
connect_timeout = 1
command_timeout = 3
delay_notice = 2
breaker_threshold = 2
breaker_seconds = 30
srs_secret = "conformance-secret"
pool_size = ${POOL_SIZE:-64}
starttls = ${RELAY_STARTTLS:-true}
tls_policy = "${TLS_POLICY:-published}"
tls_trust_file = "$work/trust.pem"
mta_sts_port = 52800
[http]
http = "127.0.0.1:2080"
https = "127.0.0.1:2443"
admin = "127.0.0.1:2918"
[admin]
jwt_secret = "conformance-jwt-secret-0123456789abcdef"
token = "conformance-static-token"
[tls]
certificate = "$work/server.pem"
key = "$work/server.key"
reload_interval = 1
$acme_conf
$mode_conf
CONF
if [ -z "$acme" ]; then
    cp "$fixtures/localhost.pem" "$work/server.pem"
    cp "$fixtures/localhost.key" "$work/server.key"
fi
bin="$root/out/mailserver"
"$bin" --config "$work/mailserver.toml" add-domain example.org
"$bin" --config "$work/mailserver.toml" add-user alice@example.org alice-pw
"$bin" --config "$work/mailserver.toml" add-user bob@example.org bob-pw 2000
"$bin" --config "$work/mailserver.toml" add-user carol@example.org carol-pw
"$bin" --config "$work/mailserver.toml" add-user relay@example.org relay-pw
"$bin" --config "$work/mailserver.toml" add-user imap@example.org imap-pw
"$bin" --config "$work/mailserver.toml" add-user imap2@example.org imap2-pw
"$bin" --config "$work/mailserver.toml" add-domain tenant.example
"$bin" --config "$work/mailserver.toml" add-user web@example.org web-pw-1234
"$bin" --config "$work/mailserver.toml" add-admin admin admin-pw-1234
"$bin" --config "$work/mailserver.toml" add-admin orgadmin orgadmin-pw-1234 example.org
if [ "${1:-}" = "--eas" ]; then
    "$bin" --config "$work/mailserver.toml" add-user eas@example.org eas-pw-1234
    "$bin" --config "$work/mailserver.toml" add-user eas2@example.org eas2-pw-1234
fi
if [ "${1:-}" = "--ews" ]; then
    "$bin" --config "$work/mailserver.toml" add-user ews@example.org ews-pw-1234
    "$bin" --config "$work/mailserver.toml" add-user ews2@example.org ews2-pw-1234
fi
if [ -n "$acme" ]; then
    # example.org publishes an MTA-STS policy, so its mta-sts host is in the first order.
    docker exec ceesafe-pg-test psql -q -U cee -d mailserver_test \
        -c "UPDATE domains SET mta_sts_mode = 'enforce' WHERE name = 'example.org'" >/dev/null
fi
"$bin" --config "$work/mailserver.toml" serve 2> "$work/server.log" &
server=$!
for i in $(seq 1 50); do grep -q listening "$work/server.log" 2>/dev/null && break; sleep 0.1; done
status=0
if [ "${REAL_MX:-}" = "1" ]; then
    MAILSERVER_BLOBS="$work/blobs" CA="$fixtures/ca.pem" FAKEMX_LOG="$work/mx" REAL_MX=1 \
        python3 "$here/smtp_test.py" RealMx || status=$?
elif [ "${REAL_SCANNERS:-}" = "1" ]; then
    MAILSERVER_BLOBS="$work/blobs" CA="$fixtures/ca.pem" REAL_SCANNERS=1 python3 "$here/smtp_test.py" RealScanners || status=$?
elif [ "${1:-}" = "--relay-load" ]; then
    python3 "$here/relay_load.py" "${2:-500}" "${3:-300}" || status=$?
    tail -5 "$work/server.log"
elif [ "${1:-}" = "--imap" ]; then
    shift
    SERVER_LOG="$work/server.log" MAILSERVER_BLOBS="$work/blobs" MAILSERVER_BIN="$bin" MAILSERVER_CONFIG="$work/mailserver.toml" CA="$fixtures/ca.pem" IMAP_PLAINTEXT_AUTH="${IMAP_PLAINTEXT_AUTH:-false}" python3 "$here/imap_test.py" "$@" || status=$?
elif [ "${1:-}" = "--acme" ]; then
    shift
    SERVER_LOG="$work/server.log" MAILSERVER_BIN="$bin" MAILSERVER_CONFIG="$work/mailserver.toml" \
        ACME_LOG="$work/acme.log" ACME_CA="$work/acme.log.ca.pem" python3 "$here/acme_test.py" "$@" || status=$?
    echo "--- ACME log"; cat "$work/acme.log"
elif [ "${1:-}" = "--import" ]; then
    shift
    SERVER_LOG="$work/server.log" MAILSERVER_BIN="$bin" MAILSERVER_CONFIG="$work/mailserver.toml" CA="$fixtures/ca.pem" \
        S3_ROOT="$work/s3" S3_LOG="$work/s3.log" python3 "$here/import_test.py" "$@" || status=$?
elif [ "${1:-}" = "--proxy" ]; then
    shift
    SERVER_LOG="$work/server.log" CA="$fixtures/ca.pem" python3 "$here/proxy_test.py" "$@" || status=$?
elif [ "${1:-}" = "--dav" ]; then
    shift
    SERVER_LOG="$work/server.log" MAILSERVER_BIN="$bin" MAILSERVER_CONFIG="$work/mailserver.toml" CA="$fixtures/ca.pem" \
        python3 "$here/dav_test.py" "$@" || status=$?
elif [ "${1:-}" = "--eas" ]; then
    shift
    SERVER_LOG="$work/server.log" MAILSERVER_BIN="$bin" MAILSERVER_CONFIG="$work/mailserver.toml" CA="$fixtures/ca.pem" \
        FAKEMX_LOG="$work/mx" PG_PORT="$port" python3 "$here/eas_test.py" "$@" || status=$?
elif [ "${1:-}" = "--ews" ]; then
    shift
    SERVER_LOG="$work/server.log" FAKEMX_LOG="$work/mx" CA="$fixtures/ca.pem" python3 "$here/ews_test.py" "$@" || status=$?
elif [ "${1:-}" = "--admin" ]; then
    shift
    SERVER_LOG="$work/server.log" MAILSERVER_BIN="$bin" MAILSERVER_CONFIG="$work/mailserver.toml" CA="$fixtures/ca.pem" \
        python3 "$here/admin_test.py" "$@" || status=$?
elif [ "${1:-}" = "--web" ]; then
    shift
    SERVER_LOG="$work/server.log" MAILSERVER_BIN="$bin" MAILSERVER_CONFIG="$work/mailserver.toml" CA="$fixtures/ca.pem" \
        SERVER_CERT="$work/server.pem" SERVER_KEY="$work/server.key" python3 "$here/web_test.py" "$@" || status=$?
elif [ "${1:-}" = "--search-differential" ]; then
    # pkgs/mimap/tools/search-differential.py: SEARCH against Dovecot 2.4.5's.
    shift
    CA="$fixtures/ca.pem" python3 "$root/pkgs/mimap/tools/search-differential.py" --ours "$@" || status=$?
    exit $status
elif [ "${1:-}" = "--fetch-differential" ]; then
    # pkgs/mimap/tools/fetch-differential.py: FETCH against Dovecot 2.4.5's, byte for byte.
    shift
    CA="$fixtures/ca.pem" python3 "$root/pkgs/mimap/tools/fetch-differential.py" --ours "$@" || status=$?
    exit $status
elif [ "${1:-}" = "--imaptest" ]; then
    # pkgs/mimap/tools/imaptest.py: Dovecot's imaptest, scripted and stress, against us and Dovecot (plaintext login).
    shift
    MAILSERVER_BIN="$bin" MAILSERVER_CONFIG="$work/mailserver.toml" CA="$fixtures/ca.pem" \
        python3 "$root/pkgs/mimap/tools/imaptest.py" --ours "$@" || status=$?
    [ $status = 0 ] || tail -20 "$work/server.log"
    exit $status
elif [ "${1:-}" = "--imap-latency" ]; then
    # pkgs/mimap/tools/latency.py: each command's round trip, ours and Dovecot's.
    shift
    CA="$fixtures/ca.pem" python3 "$root/pkgs/mimap/tools/latency.py" --ours "$@" || status=$?
    [ $status = 0 ] || tail -20 "$work/server.log"
    exit $status
elif [ "${1:-}" = "--imap-bench" ]; then
    # pkgs/mimap/tools/bench.py: FETCH throughput, SEARCH BODY and idle connections, ours and Dovecot's.
    shift
    SERVER_PID=$server MAILSERVER_BIN="$bin" MAILSERVER_CONFIG="$work/mailserver.toml" CA="$fixtures/ca.pem" \
        python3 "$root/pkgs/mimap/tools/bench.py" --ours "$@" || status=$?
    [ $status = 0 ] || tail -20 "$work/server.log"
    exit $status
elif [ "${1:-}" = "--load" ]; then
    python3 "$here/load.py" "${2:-16}" "${3:-100}" || status=$?
    grep -v accepted "$work/server.log" | sort | uniq -c | head -5
else
    MAILSERVER_BLOBS="$work/blobs" MAILSERVER_BIN="$bin" MAILSERVER_CONFIG="$work/mailserver.toml" \
        FAKEMX_LOG="$work/mx" FAKESTS_LOG="$work/sts.log" SERVER_LOG="$work/server.log" CA="$fixtures/ca.pem" DKIM_CASES="$root/pkgs/mauth/tests/dkim/cases" python3 "$here/smtp_test.py" "$@" || status=$?
    SERVER_LOG="$work/server.log" MAILSERVER_BLOBS="$work/blobs" MAILSERVER_BIN="$bin" MAILSERVER_CONFIG="$work/mailserver.toml" CA="$fixtures/ca.pem" python3 "$here/imap_test.py" || status=$?
    SERVER_LOG="$work/server.log" MAILSERVER_BIN="$bin" MAILSERVER_CONFIG="$work/mailserver.toml" CA="$fixtures/ca.pem" SERVER_CERT="$work/server.pem" SERVER_KEY="$work/server.key" python3 "$here/web_test.py" || status=$?
    SERVER_LOG="$work/server.log" MAILSERVER_BIN="$bin" MAILSERVER_CONFIG="$work/mailserver.toml" CA="$fixtures/ca.pem" python3 "$here/admin_test.py" || status=$?
fi
echo "--- DNS queries: $(wc -l < "$work/dns.log")"; sort "$work/dns.log" | uniq -c | sort -rn | head -5
echo "--- MTA-STS fetches"; cat "$work/sts.log"
echo "--- server log"
cat "$work/server.log"
exit $status
