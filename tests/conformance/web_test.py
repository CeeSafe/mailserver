#!/usr/bin/env python3
"""Black-box HTTP tests against a running mailserver (see run.sh): plain HTTP on 2080, HTTPS on 2443 and the admin
listener on 2918. The public endpoints (MTA-STS, autoconfig, autodiscover, ACME challenges, health) and HTTP/1.1
itself (persistent connections, HEAD, chunked bodies, 100-continue, limits and malformed requests), over raw sockets
where the wire matters."""
import hashlib, http.client, json, os, shutil, socket, ssl, subprocess, sys, tempfile, time, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from smtp_test import sql, tls_context  # noqa: E402

HOST = "127.0.0.1"
HTTP, HTTPS, ADMIN = 2080, 2443, 2918


def request(port: int, method: str, path: str, host: str = "localhost", body=None, headers=None, secure=None):
    secure = (port == HTTPS) if secure is None else secure
    if secure:
        c = http.client.HTTPSConnection(HOST, port, context=tls_context(), timeout=10)
    else:
        c = http.client.HTTPConnection(HOST, port, timeout=10)
    h = {"Host": host}
    h.update(headers or {})
    c.request(method, path, body=body, headers=h)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r, data


class Raw:
    """A raw HTTP/1.1 connection, for wire-level checks."""

    def __init__(self, port: int = HTTP, secure: bool = False):
        s = socket.create_connection((HOST, port), timeout=10)
        self.sock = tls_context().wrap_socket(s, server_hostname="localhost") if secure else s
        self.buffer = b""

    def send(self, data: bytes):
        self.sock.sendall(data)

    def _fill(self) -> bool:
        chunk = self.sock.recv(65536)
        if not chunk:
            return False
        self.buffer += chunk
        return True

    def response(self):
        """(status, headers dict lowercased, body) of the next response; None when the server closed."""
        while b"\r\n\r\n" not in self.buffer:
            if not self._fill():
                return None
        head, self.buffer = self.buffer.split(b"\r\n\r\n", 1)
        lines = head.decode().split("\r\n")
        status = int(lines[0].split(" ")[1])
        headers = {}
        for line in lines[1:]:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
        n = int(headers.get("content-length", "0"))
        while len(self.buffer) < n:
            if not self._fill():
                break
        body, self.buffer = self.buffer[:n], self.buffer[n:]
        return status, headers, body

    def closed(self) -> bool:
        try:
            self.sock.settimeout(5)
            return self.sock.recv(1) == b""
        except (ConnectionResetError, ssl.SSLError):
            return True

    def close(self):
        self.sock.close()


def set_mta_sts(domain: str, mode: str, max_age: int = 86400, mx=None):
    mx_sql = "NULL" if mx is None else "'" + mx.replace("'", "''") + "'"
    sql(f"UPDATE domains SET mta_sts_mode = '{mode}', mta_sts_max_age = {max_age}, mta_sts_mx = {mx_sql} "
        f"WHERE name = '{domain}'")


class Health(unittest.TestCase):
    def test_every_listener(self):
        for port in (HTTP, HTTPS, ADMIN):
            r, data = request(port, "GET", "/api/health")
            self.assertEqual(r.status, 200, port)
            self.assertTrue(r.getheader("Content-Type").startswith("application/json"))
            body = json.loads(data)
            self.assertEqual(body["status"], "ok")
            self.assertRegex(body["time"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
            self.assertTrue(r.getheader("Date").endswith(" GMT"))

    def test_unknown_paths(self):
        r, _ = request(HTTP, "GET", "/nothing")
        self.assertEqual(r.status, 404)
        # The admin API exists only on the admin listener.
        r, _ = request(HTTPS, "GET", "/api/domains")
        self.assertEqual(r.status, 404)
        self.assertTrue(r.getheader("Content-Type").startswith("text/plain"))


class MtaSts(unittest.TestCase):
    def tearDown(self):
        set_mta_sts("example.org", "none")

    def test_policy(self):
        set_mta_sts("example.org", "enforce", 604800)
        r, data = request(HTTPS, "GET", "/.well-known/mta-sts.txt", host="mta-sts.example.org")
        self.assertEqual(r.status, 200)
        self.assertEqual(r.getheader("Content-Type"), "text/plain; charset=utf-8")
        self.assertEqual(r.getheader("Cache-Control"), "public, max-age=600")
        self.assertEqual(data, b"version: STSv1\r\nmode: enforce\r\nmx: mail.example.org\r\nmax_age: 604800\r\n")

    def test_patterns_and_testing_mode(self):
        set_mta_sts("example.org", "testing", 86400, "mx1.example.org, *.backup.example.net  mx2.example.org")
        r, data = request(HTTPS, "GET", "/.well-known/mta-sts.txt", host="MTA-STS.Example.ORG.:443")
        self.assertEqual(r.status, 200)
        self.assertEqual(data, b"version: STSv1\r\nmode: testing\r\nmx: mx1.example.org\r\nmx: *.backup.example.net\r\n"
                               b"mx: mx2.example.org\r\nmax_age: 86400\r\n")

    def test_no_policy(self):
        set_mta_sts("example.org", "none")
        r, _ = request(HTTPS, "GET", "/.well-known/mta-sts.txt", host="mta-sts.example.org")
        self.assertEqual(r.status, 404, "a domain without a policy")
        r, _ = request(HTTPS, "GET", "/.well-known/mta-sts.txt", host="mta-sts.unknown.example")
        self.assertEqual(r.status, 404, "an unknown domain")
        set_mta_sts("example.org", "enforce")
        r, _ = request(HTTPS, "GET", "/.well-known/mta-sts.txt", host="example.org")
        self.assertEqual(r.status, 404, "not the mta-sts host")
        r, _ = request(HTTP, "GET", "/.well-known/mta-sts.txt", host="mta-sts.example.org")
        self.assertEqual(r.status, 404, "never over plain HTTP")
        r, _ = request(HTTPS, "POST", "/.well-known/mta-sts.txt", host="mta-sts.example.org", body=b"")
        self.assertEqual(r.status, 405)

    def test_forwarded_host_on_the_admin_listener_only(self):
        set_mta_sts("example.org", "enforce")
        r, data = request(ADMIN, "GET", "/.well-known/mta-sts.txt", host="127.0.0.1:2918",
                          headers={"X-Forwarded-Host": "mta-sts.example.org:443, proxy.internal"})
        self.assertEqual(r.status, 200)
        self.assertIn(b"mode: enforce", data)
        r, _ = request(HTTPS, "GET", "/.well-known/mta-sts.txt", host="localhost",
                       headers={"X-Forwarded-Host": "mta-sts.example.org"})
        self.assertEqual(r.status, 404, "a public listener ignores X-Forwarded-Host")


class Autoconfig(unittest.TestCase):
    def test_thunderbird(self):
        for port, path in ((HTTP, "/mail/config-v1.1.xml"), (HTTPS, "/.well-known/autoconfig/mail/config-v1.1.xml")):
            r, data = request(port, "GET", path + "?emailaddress=alice%40example.org", host="autoconfig.example.org")
            self.assertEqual(r.status, 200)
            self.assertTrue(r.getheader("Content-Type").startswith("text/xml"))
            text = data.decode()
            self.assertIn('<emailProvider id="example.org">', text)
            self.assertIn("<hostname>mail.example.org</hostname>", text)
            self.assertIn("<port>993</port>", text)
            self.assertIn("<port>465</port>", text)
            self.assertIn("<username>%EMAILADDRESS%</username>", text)
            import xml.dom.minidom
            xml.dom.minidom.parseString(data)

    def test_host_from_the_address(self):
        _, data = request(HTTP, "GET", "/mail/config-v1.1.xml?emailaddress=bob%40Other.Example", host="localhost")
        self.assertIn(b"<hostname>mail.other.example</hostname>", data)

    def test_escaping(self):
        _, data = request(HTTP, "GET", "/mail/config-v1.1.xml?emailaddress=a%40%3Cscript%3E%22%26.org",
                          host="autoconfig.example.org")
        self.assertNotIn(b"<script>", data)
        self.assertIn(b"&lt;script&gt;&quot;&amp;.org", data)
        import xml.dom.minidom
        xml.dom.minidom.parseString(data)


POX = """<?xml version="1.0" encoding="utf-8"?>
<a:Autodiscover xmlns:a="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
  <a:Request>
    <a:EMailAddress>{email}</a:EMailAddress>
    <a:AcceptableResponseSchema>{schema}</a:AcceptableResponseSchema>
  </a:Request>
</a:Autodiscover>"""
OUTLOOK = "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a"
MOBILE = "http://schemas.microsoft.com/exchange/autodiscover/mobilesync/responseschema/2006"


def basic(user, password):
    import base64
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()}


class Autodiscover(unittest.TestCase):
    def test_pox(self):
        body = POX.format(email="alice@example.org", schema=OUTLOOK).encode()
        r, data = request(HTTPS, "POST", "/Autodiscover/Autodiscover.xml", host="autodiscover.example.org", body=body,
                          headers={"Content-Type": "text/xml", **basic("alice@example.org", "alice-pw")})
        self.assertEqual(r.status, 200)
        text = data.decode()
        self.assertIn("<AutoDiscoverSMTPAddress>alice@example.org</AutoDiscoverSMTPAddress>", text)
        self.assertIn("<Type>IMAP</Type>\n        <Server>mail.example.org</Server>\n        <Port>993</Port>", text)
        self.assertIn("<Type>SMTP</Type>\n        <Server>mail.example.org</Server>\n        <Port>465</Port>", text)
        # IMAP, SMTP and (with [http] advertise_exchange, the default) EWS.
        self.assertEqual(text.count("<LoginName>alice@example.org</LoginName>"), 3)
        self.assertIn("<Type>EXPR</Type>", text)
        self.assertIn("https://mail.example.org/EWS/Exchange.asmx", text)
        import xml.dom.minidom
        xml.dom.minidom.parseString(data)

    def test_unprefixed_and_mobilesync(self):
        plain = POX.replace("a:", "").replace(":a=", "=")
        r, data = request(HTTPS, "POST", "/autodiscover/autodiscover.xml", host="localhost",
                          body=plain.format(email="bob@example.org", schema=OUTLOOK).encode(),
                          headers=basic("bob@example.org", "bob-pw"))
        self.assertEqual(r.status, 200)
        self.assertIn(b"<Server>mail.example.org</Server>", data)
        r, data = request(HTTPS, "POST", "/autodiscover/autodiscover.xml", host="localhost",
                          body=POX.format(email="bob@example.org", schema=MOBILE).encode(),
                          headers=basic("bob@example.org", "bob-pw"))
        self.assertEqual(r.status, 200, "ActiveSync")
        self.assertIn(b"<Type>MobileSync</Type>", data)
        self.assertIn(b"<Url>https://mail.example.org/Microsoft-Server-ActiveSync</Url>", data)
        r, _ = request(HTTPS, "GET", "/autodiscover/autodiscover.xml")
        self.assertEqual(r.status, 405)

    def test_login_required(self):
        """As Exchange and Z-Push: 401 with a Basic challenge for no credentials, a wrong password, or a user name that
        does not log in. iOS 27 sends `bob` and `bob@example.org` at once and takes the one that logs in; when both
        were answered, it asked for the server by hand."""
        body = POX.format(email="bob@example.org", schema=MOBILE).encode()
        for headers, why in [({}, "no credentials"), (basic("bob@example.org", "wrong"), "a wrong password"),
                             (basic("bob", "bob-pw"), "the bare user name")]:
            r, data = request(HTTPS, "POST", "/autodiscover/autodiscover.xml", host="autodiscover.example.org",
                              body=body, headers=headers)
            self.assertEqual(r.status, 401, why)
            self.assertIn("Basic", r.getheader("WWW-Authenticate"), why)
            self.assertNotIn(b"MobileSync", data, why)

    def test_v2_json(self):
        r, data = request(HTTPS, "GET", "/autodiscover/autodiscover.json/v1.0/alice%40example.org?Protocol=Imap",
                          host="localhost")
        self.assertEqual(r.status, 200)
        body = json.loads(data)
        self.assertEqual((body["Protocol"], body["Server"], body["Port"], body["SSL"]), ("IMAP", "mail.example.org", 993, "on"))
        _, data = request(HTTPS, "GET", "/autodiscover/autodiscover.json/v1.0/alice@example.org?Protocol=smtp")
        self.assertEqual(json.loads(data)["Port"], 465)
        _, data = request(HTTPS, "GET", "/autodiscover/autodiscover.json/v1.0/alice@example.org?Protocol=AutodiscoverV1",
                          host="autodiscover.example.org")
        self.assertEqual(json.loads(data), {"Protocol": "AutodiscoverV1",
                                            "Url": "https://mail.example.org/Autodiscover/Autodiscover.xml"})
        # Not ActiveSync: answering it sent iOS down the Exchange Online path, which it gives up on (see wellknown.cee).
        r, data = request(HTTPS, "GET", "/autodiscover/autodiscover.json?Email=alice@example.org&Protocol=ActiveSync")
        self.assertEqual(r.status, 404)
        self.assertEqual(json.loads(data)["ErrorCode"], "ProtocolNotSupported")
        r, data = request(HTTPS, "GET", "/autodiscover/autodiscover.json?Email=alice@example.org&Protocol=Pop3")
        self.assertEqual(r.status, 404)
        self.assertEqual(json.loads(data)["ErrorCode"], "ProtocolNotSupported")


class Acme(unittest.TestCase):
    def test_unknown_token(self):
        r, _ = request(HTTP, "GET", "/.well-known/acme-challenge/nothing-here")
        self.assertEqual(r.status, 404)
        r, _ = request(HTTP, "GET", "/.well-known/acme-challenge/")
        self.assertEqual(r.status, 404)


class Protocol(unittest.TestCase):
    def test_persistent_connection_and_pipelining(self):
        c = Raw()
        c.send(b"GET /api/health HTTP/1.1\r\nHost: a\r\n\r\nHEAD /api/health HTTP/1.1\r\nHost: a\r\n\r\n"
               b"GET /api/health HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n")
        s1, h1, b1 = c.response()
        self.assertEqual(s1, 200)
        self.assertNotIn("connection", h1)
        # HEAD: the length of the GET's body, and no body.
        while b"\r\n\r\n" not in c.buffer:
            c._fill()
        head, c.buffer = c.buffer.split(b"\r\n\r\n", 1)
        self.assertIn(b"Content-Length: " + str(len(b1)).encode(), head)
        s3, h3, b3 = c.response()
        self.assertEqual((s3, h3.get("connection")), (200, "close"))
        self.assertTrue(c.closed())
        c.close()

    def test_http10_closes(self):
        c = Raw()
        c.send(b"GET /api/health HTTP/1.0\r\n\r\n")
        status, headers, _ = c.response()
        self.assertEqual((status, headers.get("connection")), (200, "close"))
        self.assertTrue(c.closed())
        c.close()

    def test_chunked_body_and_continue(self):
        body = POX.format(email="carol@example.org", schema=OUTLOOK).encode()
        c = Raw(HTTPS, secure=True)
        chunks = b"".join(b"%x;ext=1\r\n%s\r\n" % (len(body[i:i + 100]), body[i:i + 100]) for i in range(0, len(body), 100))
        auth = basic("carol@example.org", "carol-pw")["Authorization"].encode()
        c.send(b"POST /autodiscover/autodiscover.xml HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n"
               b"Authorization: " + auth + b"\r\nExpect: 100-continue\r\n\r\n")
        status, _, _ = c.response()
        self.assertEqual(status, 100)
        c.send(chunks + b"0\r\nX-Trailer: 1\r\n\r\n")
        status, _, data = c.response()
        self.assertEqual(status, 200)
        self.assertIn(b"carol@example.org", data)
        c.close()

    def test_malformed_requests(self):
        cases = [
            (b"GET /\r\n\r\n", 400),
            (b"GET / HTTP/1.1\r\n\r\n", 400),  # no Host
            (b"GET / HTTP/2.0\r\nHost: a\r\n\r\n", 505),
            (b"GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n", 400),
            (b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n", 400),
            (b"POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip\r\n\r\n", 501),
            (b"POST /autodiscover/autodiscover.xml HTTP/1.1\r\nHost: a\r\nContent-Length: 99999999\r\n\r\n", 413),
            (b"GET / HTTP/1.1\r\nHost: a\r\nX: " + b"y" * 9000 + b"\r\n\r\n", 431),
            (b"GET /" + b"a" * 9000 + b" HTTP/1.1\r\nHost: a\r\n\r\n", 431),
        ]
        for wire, want in cases:
            c = Raw()
            c.send(wire)
            got = c.response()
            self.assertIsNotNone(got, wire[:40])
            self.assertEqual(got[0], want, wire[:40])
            self.assertEqual(got[1].get("connection"), "close", wire[:40])
            self.assertTrue(c.closed(), wire[:40])
            c.close()

    def test_idle_connection_survives_and_tls(self):
        c = Raw(HTTPS, secure=True)
        time.sleep(1)
        c.send(b"GET /api/health HTTP/1.1\r\nHost: a\r\n\r\n")
        self.assertEqual(c.response()[0], 200)
        c.close()


def served_certificate(port: int) -> bytes:
    """The SHA-256 of the certificate the server presents on `port` (not verified: the test swaps in its own)."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((HOST, port), timeout=10) as s:
        with context.wrap_socket(s, server_hostname="localhost") as t:
            return hashlib.sha256(t.getpeercert(binary_form=True)).digest()


def wait_for_certificate(port: int, want: bytes, seconds: float = 10) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if served_certificate(port) == want:
            return True
        time.sleep(0.2)
    return False


def server_log() -> str:
    with open(os.environ["SERVER_LOG"]) as f:
        return f.read()


class CertificateReload(unittest.TestCase):
    """The certificate files are watched (run.sh: reload_interval = 1): a renewal is served without a restart, on
    every TLS listener, and a broken one is refused while the old certificate stays."""

    def setUp(self):
        self.cert, self.key = os.environ["SERVER_CERT"], os.environ["SERVER_KEY"]
        self.saved = tempfile.mkdtemp()
        shutil.copy(self.cert, self.saved)
        shutil.copy(self.key, self.saved)

    def tearDown(self):
        # Back to the fixture, so the other tests' CA checks pass again.
        original = os.path.join(self.saved, os.path.basename(self.cert))
        shutil.copy(os.path.join(self.saved, os.path.basename(self.key)), self.key + ".new")
        shutil.copy(original, self.cert + ".new")
        os.replace(self.key + ".new", self.key)
        os.replace(self.cert + ".new", self.cert)
        with open(original, "rb") as f:
            pem = f.read()
        der = ssl.PEM_cert_to_DER_cert(pem.decode().split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n")
        self.assertTrue(wait_for_certificate(HTTPS, hashlib.sha256(der).digest()), "the fixture is back")
        shutil.rmtree(self.saved)

    def renew(self, directory: str):
        cert, key = os.path.join(directory, "c.pem"), os.path.join(directory, "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                        "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost"],
                       check=True, capture_output=True)
        with open(cert, "rb") as f:
            der = ssl.PEM_cert_to_DER_cert(f.read().decode())
        return cert, key, hashlib.sha256(der).digest()

    def test_renewal_is_served(self):
        before = served_certificate(HTTPS)
        with tempfile.TemporaryDirectory() as d:
            cert, key, fingerprint = self.renew(d)
            self.assertNotEqual(fingerprint, before)
            # As a renewal tool writes them: the key first, then the chain (each replaced atomically).
            shutil.copy(key, self.key + ".new")
            os.replace(self.key + ".new", self.key)
            shutil.copy(cert, self.cert + ".new")
            os.replace(self.cert + ".new", self.cert)
            self.assertTrue(wait_for_certificate(HTTPS, fingerprint), "HTTPS serves the renewed certificate")
            self.assertEqual(served_certificate(IMAPS), fingerprint, "and IMAPS")
            self.assertEqual(served_certificate(SMTPS), fingerprint, "and SMTPS")
            self.assertIn("installed the renewed TLS certificate", server_log())

    def test_broken_renewal_is_refused(self):
        before = served_certificate(HTTPS)
        with open(self.key, "w") as f:
            f.write("-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n")
        deadline = time.time() + 10
        while "could not be used; keeping the old one" not in server_log() and time.time() < deadline:
            time.sleep(0.2)
        self.assertIn("could not be used; keeping the old one", server_log())
        self.assertEqual(served_certificate(HTTPS), before, "the old certificate stays")
        # New connections still work.
        r, _ = request(HTTPS, "GET", "/api/health")
        self.assertEqual(r.status, 200)


IMAPS, SMTPS = 2993, 2465


if __name__ == "__main__":
    unittest.main(verbosity=2)
