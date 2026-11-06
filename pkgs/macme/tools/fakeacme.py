#!/usr/bin/env python3
"""A fake ACME CA (RFC 8555) for the server's renewal tests, over HTTPS: enough of the protocol to be strict about
what a client sends, and to issue real certificates.

    fakeacme.py PORT CERT KEY HTTP01_PORT LOG [--bad-nonce-every N] [--fail NAME,...]

- The directory is at https://localhost:PORT/dir. Every POST must be a flattened JWS (RS256) whose protected header
  has a nonce this server issued and has not seen, the request's own URL, and either a jwk (newAccount only) or the
  kid of a registered account; the signature is checked. Anything else is a problem document, as RFC 8555 §6.7 says.
- HTTP-01 is validated for real: GET http://127.0.0.1:HTTP01_PORT/.well-known/acme-challenge/<token> with the name as
  Host, and the body must be the key authorization. Names in --fail are refused without looking.
- On finalize, the CSR's signature and names are checked against the order, and a certificate is issued by a CA made
  at start (90 days, the CSR's names, the CSR's key). Its certificate is written to LOG + ".ca.pem".
- --bad-nonce-every N answers every Nth POST with badNonce, to exercise the client's retry.
- Each event is a line in LOG: `account new|existing`, `order NAMES`, `validated NAME`, `invalid NAME why`,
  `issued NAMES`, `badNonce`, `problem TYPE`.
"""
import base64
import datetime
import hashlib
import http.client
import http.server
import json
import secrets
import ssl
import sys
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

port, cert_file, key_file, http01_port, log_path = int(sys.argv[1]), sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
args = sys.argv[6:]
bad_nonce_every = int(args[args.index("--bad-nonce-every") + 1]) if "--bad-nonce-every" in args else 0
fail_names = set(args[args.index("--fail") + 1].lower().split(",")) if "--fail" in args else set()
BASE = f"https://localhost:{port}"

lock = threading.Lock()
nonces, accounts, orders, authzs = set(), {}, {}, {}
posts = [0]

ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fake ACME CA")])
now = datetime.datetime.now(datetime.timezone.utc)
ca_cert = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
           .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
           .not_valid_after(now + datetime.timedelta(days=3650))
           .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
           .sign(ca_key, hashes.SHA256()))
with open(log_path + ".ca.pem", "wb") as f:
    f.write(ca_cert.public_bytes(serialization.Encoding.PEM))


def log(line: str):
    with lock:
        with open(log_path, "a") as f:
            f.write(line + "\n")


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwk_key(jwk: dict):
    if jwk.get("kty") != "RSA":
        raise ValueError("only RSA keys")
    n, e = int.from_bytes(b64d(jwk["n"]), "big"), int.from_bytes(b64d(jwk["e"]), "big")
    return rsa.RSAPublicNumbers(e, n).public_key()


def thumbprint(jwk: dict) -> str:
    canonical = json.dumps({"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}, separators=(",", ":"), sort_keys=True)
    return b64e(hashlib.sha256(canonical.encode()).digest())


class Problem(Exception):
    def __init__(self, status, kind, detail):
        self.status, self.kind, self.detail = status, kind, detail


def new_nonce() -> str:
    n = secrets.token_urlsafe(16)
    with lock:
        nonces.add(n)
    return n


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def send(self, status, body=b"", ctype="application/json", headers=None):
        self.send_response(status)
        self.send_header("Replay-Nonce", new_nonce())
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, status, obj, headers=None):
        self.send(status, json.dumps(obj).encode(), headers=headers)

    def do_GET(self):
        if self.path == "/dir":
            self.send_json(200, {"newNonce": BASE + "/nonce", "newAccount": BASE + "/acct", "newOrder": BASE + "/order",
                                 "meta": {"termsOfService": BASE + "/terms"}})
        elif self.path == "/nonce":
            self.send(204)
        else:
            self.send(404, b"{}")

    do_HEAD = do_GET

    def verify(self, body: bytes, need_jwk: bool):
        try:
            jws = json.loads(body)
            protected = json.loads(b64d(jws["protected"]))
            payload_text = jws["payload"]
            signature = b64d(jws["signature"])
        except Exception:
            raise Problem(400, "malformed", "not a flattened JWS")
        if protected.get("alg") != "RS256":
            raise Problem(400, "badSignatureAlgorithm", "RS256 only")
        if protected.get("url") != BASE + self.path:
            raise Problem(401, "unauthorized", f"url {protected.get('url')} is not {BASE + self.path}")
        nonce = protected.get("nonce")
        with lock:
            fresh = nonce in nonces
            nonces.discard(nonce)
            posts[0] += 1
            forced = bad_nonce_every and posts[0] % bad_nonce_every == 0
        if not fresh or forced:
            log("badNonce")
            raise Problem(400, "badNonce", "unknown or reused nonce")
        if need_jwk:
            if "jwk" not in protected or "kid" in protected:
                raise Problem(400, "malformed", "newAccount takes a jwk")
            jwk = protected["jwk"]
            key = jwk_key(jwk)
            account = None
        else:
            if "kid" not in protected or "jwk" in protected:
                raise Problem(400, "malformed", "a kid is required")
            account = accounts.get(protected["kid"])
            if account is None:
                raise Problem(400, "accountDoesNotExist", "no such account")
            jwk, key = account["jwk"], jwk_key(account["jwk"])
        try:
            key.verify(signature, (jws["protected"] + "." + payload_text).encode(), padding.PKCS1v15(), hashes.SHA256())
        except Exception:
            raise Problem(400, "malformed", "bad signature")
        payload = None if payload_text == "" else json.loads(b64d(payload_text))
        return jwk, account, payload

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            if self.headers.get("Content-Type") != "application/jose+json":
                raise Problem(415, "malformed", "Content-Type must be application/jose+json")
            self.route(body)
        except Problem as p:
            log(f"problem {p.kind}")
            self.send(p.status, json.dumps({"type": "urn:ietf:params:acme:error:" + p.kind, "detail": p.detail}).encode(),
                      ctype="application/problem+json")

    def route(self, body):
        path = self.path
        if path == "/acct":
            jwk, _, payload = self.verify(body, need_jwk=True)
            if not payload or payload.get("termsOfServiceAgreed") is not True:
                raise Problem(403, "userActionRequired", "agree to the terms")
            kid = BASE + "/acct/" + thumbprint(jwk)[:16]
            existing = kid in accounts
            accounts[kid] = {"jwk": jwk, "contact": payload.get("contact", [])}
            log("account " + ("existing" if existing else "new"))
            self.send_json(200 if existing else 201, {"status": "valid", "contact": payload.get("contact", [])},
                           {"Location": kid})
            return
        jwk, account, payload = self.verify(body, need_jwk=False)
        if path == "/order":
            names = [i["value"].lower() for i in payload["identifiers"] if i["type"] == "dns"]
            oid = secrets.token_hex(6)
            order = {"status": "pending", "names": names, "authz": [], "cert": None, "thumb": thumbprint(jwk)}
            for name in names:
                aid = secrets.token_hex(6)
                authzs[aid] = {"name": name, "status": "pending", "token": secrets.token_urlsafe(24),
                               "thumb": thumbprint(jwk), "error": None}
                order["authz"].append(aid)
            orders[oid] = order
            log("order " + ",".join(names))
            self.send_json(201, self.order_json(oid), {"Location": f"{BASE}/order/{oid}"})
        elif path.startswith("/order/"):
            self.send_json(200, self.order_json(path[7:]))
        elif path.startswith("/authz/"):
            self.send_json(200, self.authz_json(path[7:]))
        elif path.startswith("/chall/"):
            aid = path[7:]
            if payload != {}:
                raise Problem(400, "malformed", "a challenge response is {}")
            threading.Thread(target=self.validate, args=(aid,), daemon=True).start()
            a = authzs[aid]
            self.send_json(200, {"type": "http-01", "url": f"{BASE}/chall/{aid}", "token": a["token"], "status": "processing"})
        elif path.startswith("/finalize/"):
            oid = path[10:]
            order = orders[oid]
            if any(authzs[a]["status"] != "valid" for a in order["authz"]):
                raise Problem(403, "orderNotReady", "authorizations are not all valid")
            csr = x509.load_der_x509_csr(b64d(payload["csr"]))
            if not csr.is_signature_valid:
                raise Problem(400, "badCSR", "the CSR's signature does not verify")
            san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            names = sorted(n.lower() for n in san.get_values_for_type(x509.DNSName))
            if names != sorted(order["names"]):
                raise Problem(400, "badCSR", f"the CSR names {names}, the order {sorted(order['names'])}")
            leaf = (x509.CertificateBuilder()
                    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, order["names"][0])]))
                    .issuer_name(ca_name).public_key(csr.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - datetime.timedelta(hours=1)).not_valid_after(now + datetime.timedelta(days=90))
                    .add_extension(san, critical=False).sign(ca_key, hashes.SHA256()))
            order["cert"] = (leaf.public_bytes(serialization.Encoding.PEM) + ca_cert.public_bytes(serialization.Encoding.PEM))
            order["status"] = "valid"
            log("issued " + ",".join(order["names"]))
            # As a real CA may: still processing at first, with Retry-After.
            self.send_json(200, dict(self.order_json(oid), status="processing", certificate=None), {"Retry-After": "1"})
        elif path.startswith("/cert/"):
            self.send(200, orders[path[6:]]["cert"], ctype="application/pem-certificate-chain")
        else:
            raise Problem(404, "malformed", "no such resource")

    def order_json(self, oid):
        o = orders[oid]
        out = {"status": o["status"], "identifiers": [{"type": "dns", "value": n} for n in o["names"]],
               "authorizations": [f"{BASE}/authz/{a}" for a in o["authz"]], "finalize": f"{BASE}/finalize/{oid}"}
        if all(authzs[a]["status"] == "valid" for a in o["authz"]) and o["status"] == "pending":
            out["status"] = "ready"
        if any(authzs[a]["status"] == "invalid" for a in o["authz"]):
            out["status"] = "invalid"
        if o["cert"]:
            out["certificate"] = f"{BASE}/cert/{oid}"
        return out

    def authz_json(self, aid):
        a = authzs[aid]
        challenge = {"type": "http-01", "url": f"{BASE}/chall/{aid}", "token": a["token"], "status": a["status"]}
        if a["error"]:
            challenge["error"] = {"type": "urn:ietf:params:acme:error:unauthorized", "detail": a["error"]}
        dns = {"type": "dns-01", "url": f"{BASE}/chall/{aid}-dns", "token": "x", "status": "pending"}
        return {"status": a["status"], "identifier": {"type": "dns", "value": a["name"]}, "challenges": [dns, challenge]}

    def validate(self, aid):
        a = authzs[aid]
        if a["name"] in fail_names:
            a["status"], a["error"] = "invalid", "refused by --fail"
            log(f"invalid {a['name']} refused")
            return
        try:
            c = http.client.HTTPConnection("127.0.0.1", http01_port, timeout=5)
            c.request("GET", "/.well-known/acme-challenge/" + a["token"], headers={"Host": a["name"]})
            r = c.getresponse()
            got = r.read().decode(errors="replace")
            c.close()
        except Exception as e:
            a["status"], a["error"] = "invalid", f"fetch failed: {e}"
            log(f"invalid {a['name']} unreachable")
            return
        want = a["token"] + "." + a["thumb"]
        if r.status == 200 and got == want:
            a["status"] = "valid"
            log(f"validated {a['name']}")
        else:
            a["status"], a["error"] = "invalid", f"got {r.status} {got!r}"
            log(f"invalid {a['name']} wrong-answer")


server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(cert_file, key_file)
server.socket = context.wrap_socket(server.socket, server_side=True)
print("ready", flush=True)
server.serve_forever()
