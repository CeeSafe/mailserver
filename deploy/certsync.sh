#!/bin/sh
# Copies a TLS-terminating proxy's certificate for the mail host (CosmoProxy keeps its files root-only) into the mail
# server's tls directory, readable by the container's user (65532), when it changed. The server polls the files
# ([tls] reload_interval) and installs a new certificate for new connections. Run it from a timer
# (mailserver-certsync.timer).
#
#   CERT_SRC=/data/zatca/cosmoproxy/conf/certs/mail.example.com CERT_DST=/data/mailserver/tls certsync.sh
set -eu
src=${CERT_SRC:?the proxy's certificate directory (fullchain.pem, key.pem)}
dst=${CERT_DST:-/data/mailserver/tls}
[ -s "$src/fullchain.pem" ] && [ -s "$src/key.pem" ] || exit 0
if cmp -s "$src/fullchain.pem" "$dst/fullchain.pem" && cmp -s "$src/key.pem" "$dst/key.pem"; then
    exit 0
fi
install -o 65532 -g 65532 -m 600 "$src/key.pem" "$dst/key.pem.new"
install -o 65532 -g 65532 -m 644 "$src/fullchain.pem" "$dst/fullchain.pem.new"
mv "$dst/key.pem.new" "$dst/key.pem"
mv "$dst/fullchain.pem.new" "$dst/fullchain.pem"
echo "mailserver-certsync: installed a new certificate"
