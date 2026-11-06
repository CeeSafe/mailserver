#!/usr/bin/env python3
"""Black-box tests of the PROXY protocol (run.sh --proxy): the server takes PROXY headers from 127.0.0.1, as from
CosmoProxy in front of it, and requires one on every SMTP and IMAP connection from there. The client's address it
gives is the one the session uses (logs, Received, the failed-login guard)."""
import imaplib, os, smtplib, socket, ssl, struct, sys, time, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from smtp_test import tls_context  # noqa: E402

MX, SUBMISSION, IMAPS = 2525, 2587, 2993
SIGNATURE = b"\r\n\r\n\x00\r\nQUIT\n"


def v2(client: str, port: int, local: bool = False) -> bytes:
    if local:
        return SIGNATURE + bytes([0x20, 0x00]) + struct.pack("!H", 0)
    body = socket.inet_aton(client) + socket.inet_aton("127.0.0.1") + struct.pack("!HH", port, 25)
    return SIGNATURE + bytes([0x21, 0x11]) + struct.pack("!H", len(body)) + body


def v1(client: str, port: int) -> bytes:
    return f"PROXY TCP4 {client} 127.0.0.1 {port} 25\r\n".encode()


class ProxiedSMTP(smtplib.SMTP):
    def __init__(self, header: bytes, host: str, port: int):
        self.header = header
        super().__init__(host, port, timeout=10)

    def _get_socket(self, host, port, timeout):
        s = socket.create_connection((host, port), timeout)
        s.sendall(self.header)
        return s


class ProxiedIMAPS(imaplib.IMAP4_SSL):
    """The header goes first, in the clear, then TLS."""

    def __init__(self, header: bytes):
        self.header = header
        super().__init__("127.0.0.1", IMAPS, ssl_context=tls_context())

    def _create_socket(self, timeout=None):
        s = socket.create_connection((self.host, self.port), timeout)
        s.sendall(self.header)
        return self.ssl_context.wrap_socket(s, server_hostname=self.host)


def logged(text: str, within: float = 5.0) -> bool:
    deadline = time.time() + within
    while time.time() < deadline:
        with open(os.environ["SERVER_LOG"], errors="replace") as f:
            if text in f.read():
                return True
        time.sleep(0.1)
    return False


def closed_without_banner(port: int, first: bytes) -> bool:
    s = socket.create_connection(("127.0.0.1", port), timeout=15)
    try:
        s.sendall(first)
        return s.recv(100) == b""
    except ConnectionResetError:
        return True
    finally:
        s.close()


class Proxy(unittest.TestCase):
    def test_version_two_gives_the_client_address(self):
        with ProxiedSMTP(v2("203.0.113.9", 40000), "127.0.0.1", MX) as c:
            self.assertEqual(c.sendmail("a@remote.test", ["alice@example.org"], "Subject: via proxy\r\n\r\nhi\r\n"), {})
        self.assertTrue(logged("smtp [203.0.113.9] accepted"))

    def test_version_one_survives_starttls(self):
        with ProxiedSMTP(v1("198.51.100.77", 40001), "127.0.0.1", MX) as c:
            c.starttls(context=tls_context())
            self.assertEqual(c.sendmail("b@remote.test", ["alice@example.org"], "Subject: v1 tls\r\n\r\nhi\r\n"), {})
        self.assertTrue(logged("smtp [198.51.100.77] accepted"))

    def test_local_keeps_the_peer(self):
        # The proxy's own health check: LOCAL, no address; the connection is served as the proxy's.
        with ProxiedSMTP(v2("", 0, local=True), "127.0.0.1", MX) as c:
            self.assertEqual(c.noop()[0], 250)

    def test_imaps_header_before_tls(self):
        with ProxiedIMAPS(v2("203.0.113.10", 40002)) as c:
            self.assertEqual(c.login("imap@example.org", "imap-pw")[0], "OK")
            c.logout()

    def test_submission(self):
        with ProxiedSMTP(v2("203.0.113.11", 40003), "127.0.0.1", SUBMISSION) as c:
            c.starttls(context=tls_context())
            c.login("relay@example.org", "relay-pw")
            self.assertEqual(c.noop()[0], 250)

    def test_a_proxy_connection_without_a_header_is_closed(self):
        self.assertTrue(closed_without_banner(MX, b"EHLO no.header\r\n"))
        self.assertTrue(closed_without_banner(MX, b"PROXY TCP4 1.2.3.4 5.6.7.8 1\r\n"))
        self.assertTrue(closed_without_banner(MX, SIGNATURE[:6] + b"garbage!!!"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
