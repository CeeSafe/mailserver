#!/usr/bin/env python3
"""A strict S3 GET server for the importer's tests: objects are files under ROOT (/<bucket>/<key> is
ROOT/<bucket>/<key>). Every request must carry a valid AWS Signature Version 4 for ACCESS/SECRET/REGION (header
form, as the importer signs), with an x-amz-date within 15 minutes; a bad one is 403. Each request is logged to LOG
as "<status> <path>".

    fakes3.py PORT ROOT ACCESS SECRET REGION LOG
"""
import datetime, hashlib, hmac, http.server, os, sys, urllib.parse

PORT, ROOT, ACCESS, SECRET, REGION, LOG = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]
EMPTY = hashlib.sha256(b"").hexdigest()


def mac(key: bytes, text: str) -> bytes:
    return hmac.new(key, text.encode(), hashlib.sha256).digest()


def expected_signature(method, path, headers, signed, stamp, scope_day):
    canonical_headers = "".join(f"{h}:{headers.get(h, '').strip()}\n" for h in signed)
    canonical = "\n".join([method, path, "", canonical_headers, ";".join(signed),
                           headers.get("x-amz-content-sha256", "")])
    scope = f"{scope_day}/{REGION}/s3/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", stamp, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    key = mac(("AWS4" + SECRET).encode(), scope_day)
    for part in (REGION, "s3", "aws4_request"):
        key = mac(key, part)
    return hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def answer(self, status, body=b""):
        with open(LOG, "a") as f:
            f.write(f"{status} {self.path}\n")
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        headers = {k.lower(): v for k, v in self.headers.items()}
        auth = headers.get("authorization", "")
        if not auth.startswith("AWS4-HMAC-SHA256 "):
            return self.answer(403, b"no signature")
        fields = dict(p.strip().split("=", 1) for p in auth[len("AWS4-HMAC-SHA256 "):].split(","))
        credential = fields.get("Credential", "").split("/")
        signed = fields.get("SignedHeaders", "").split(";")
        stamp = headers.get("x-amz-date", "")
        if (len(credential) != 5 or credential[0] != ACCESS or credential[2] != REGION or credential[3] != "s3"
                or credential[4] != "aws4_request" or not stamp.startswith(credential[1])):
            return self.answer(403, b"bad credential")
        if "host" not in signed or "x-amz-date" not in signed or headers.get("x-amz-content-sha256") != EMPTY:
            return self.answer(403, b"unsigned fields")
        when = datetime.datetime.strptime(stamp, "%Y%m%dT%H%M%SZ").replace(tzinfo=datetime.timezone.utc)
        if abs((datetime.datetime.now(datetime.timezone.utc) - when).total_seconds()) > 900:
            return self.answer(403, b"stale")
        want = expected_signature("GET", self.path, headers, signed, stamp, credential[1])
        if not hmac.compare_digest(want, fields.get("Signature", "")):
            return self.answer(403, b"bad signature")
        name = os.path.normpath(os.path.join(ROOT, urllib.parse.unquote(self.path.lstrip("/"))))
        if not name.startswith(os.path.abspath(ROOT) + os.sep) or not os.path.isfile(name):
            return self.answer(404, b"<Error><Code>NoSuchKey</Code></Error>")
        with open(name, "rb") as f:
            self.answer(200, f.read())


server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
print("ready", flush=True)
server.serve_forever()
