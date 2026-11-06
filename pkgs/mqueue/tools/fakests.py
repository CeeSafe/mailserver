#!/usr/bin/env python3
"""A fake MTA-STS policy server (RFC 8461 §3.3) for the relay's tests, over HTTPS.

    fakests.py PORT CERT KEY POLICIES.yaml

POLICIES.yaml maps a host name (mta-sts.<domain>) to its policy file's text, or to a mapping with `status`,
`type` (Content-Type) and `body` for misbehaving servers. Only GET /.well-known/mta-sts.txt is served; anything else is
404. Each request is logged to standard error as `fetch HOST STATUS`. The file is re-read when it changes.
"""
import http.server
import os
import ssl
import sys
import threading

import yaml

port, cert, key, path = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
_policies, _mtime = {}, None
lock = threading.Lock()


def policies():
    global _policies, _mtime
    with lock:
        m = os.stat(path).st_mtime_ns
        if m != _mtime:
            _policies = {str(k).lower(): v for k, v in (yaml.safe_load(open(path)) or {}).items()}
            _mtime = m
        return _policies


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        entry = policies().get(host)
        status, ctype, body = 404, "text/plain", "not found\n"
        if self.path == "/.well-known/mta-sts.txt" and entry is not None:
            if isinstance(entry, dict):
                status, ctype, body = int(entry.get("status", 200)), entry.get("type", "text/plain"), entry.get("body", "")
            else:
                status, body = 200, entry
        data = body.encode()
        print(f"fetch {host} {status}", file=sys.stderr, flush=True)
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    print("fakests: ready", flush=True)
    server.serve_forever()
