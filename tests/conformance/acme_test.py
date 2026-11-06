#!/usr/bin/env python3
"""Certificate issuance and renewal against a fake ACME CA (run.sh --acme, pkgs/macme/tools/fakeacme.py).

The server starts with no certificate: it writes a self-signed placeholder, starts TLS with it, then orders a
certificate for its name (mx.test.example) and mta-sts.example.org (example.org publishes an MTA-STS policy),
answering HTTP-01 on its port 2080. The CA answers every 3rd POST with badNonce, which the client must retry. A domain
added later is ordered at the next check (check_interval = 2); the CA refuses mta-sts.fail.example, and the old
certificate stays."""
import os, socket, ssl, subprocess, sys, time, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from smtp_test import sql, admin  # noqa: E402

HTTPS, IMAPS = 2443, 2993


def presented(port: int, verify_with: str = None):
    """The certificate the server presents, decoded (verified against `verify_with` when given)."""
    context = ssl.create_default_context(cafile=verify_with) if verify_with else ssl.create_default_context()
    context.check_hostname = False
    if not verify_with:
        context.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        with context.wrap_socket(s, server_hostname="mx.test.example") as t:
            der = t.getpeercert(binary_form=True)
    from cryptography import x509
    return x509.load_der_x509_certificate(der)


def names_of(cert) -> set:
    from cryptography import x509
    return set(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))


def issuer_of(cert) -> str:
    return cert.issuer.rfc4514_string()


def acme_log() -> str:
    with open(os.environ["ACME_LOG"]) as f:
        return f.read()


def server_log() -> str:
    with open(os.environ["SERVER_LOG"]) as f:
        return f.read()


def wait_until(predicate, seconds: float = 30) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.25)
    return False


class Issuance(unittest.TestCase):
    def test_1_first_certificate(self):
        self.assertTrue(wait_until(lambda: "CN=Fake ACME CA" in issuer_of(presented(HTTPS))),
                        "the CA's certificate is served:\n" + server_log() + "\n" + acme_log())
        cert = presented(HTTPS, verify_with=os.environ["ACME_CA"])
        self.assertEqual(names_of(cert), {"mx.test.example", "mta-sts.example.org"})
        self.assertEqual(issuer_of(presented(IMAPS)), issuer_of(cert), "IMAPS too")
        log = acme_log()
        self.assertIn("account new", log)
        self.assertIn("validated mx.test.example", log)
        self.assertIn("validated mta-sts.example.org", log)
        self.assertIn("issued", log)
        self.assertIn("badNonce", log, "the client met badNonce and retried")
        self.assertIn("ordering a certificate for mx.test.example mta-sts.example.org", server_log())
        self.assertIn("installed the renewed TLS certificate", server_log())
        # The account key was kept for next time.
        with open(os.environ["MAILSERVER_CONFIG"]) as f:
            config = f.read()
        account_key = config.split('account_key = "')[1].split('"')[0]
        with open(account_key) as f:
            self.assertTrue(f.read().startswith("-----BEGIN PRIVATE KEY-----"))

    def test_2_no_needless_renewal(self):
        orders = acme_log().count("order ")
        time.sleep(5)  # two more checks
        self.assertEqual(acme_log().count("order "), orders, "a valid certificate is left alone")

    def test_3_refused_name_keeps_the_old_certificate(self):
        before = presented(HTTPS)
        result = admin("add-domain", "fail.example")
        self.assertEqual(result.returncode, 0, result.stderr)
        sql("UPDATE domains SET mta_sts_mode = 'enforce' WHERE name = 'fail.example'")
        self.assertTrue(wait_until(lambda: "invalid mta-sts.fail.example refused" in acme_log()), acme_log())
        self.assertTrue(wait_until(lambda: "an authorization failed" in server_log()), server_log())
        self.assertIn("refused by --fail", server_log(), "the CA's reason is logged")
        self.assertEqual(presented(HTTPS).serial_number, before.serial_number, "the old certificate stays")
        # It is retried (retry_interval = 2) while the name stays wanted; once it is not, nothing more is ordered.
        sql("UPDATE domains SET mta_sts_mode = 'none' WHERE name = 'fail.example'")
        time.sleep(3)
        orders = acme_log().count("order ")
        time.sleep(5)
        self.assertEqual(acme_log().count("order "), orders)
        self.assertEqual(acme_log().count("account new"), 1, "the same account each time")

    def test_4_new_name_is_added(self):
        before = presented(HTTPS)
        result = admin("add-domain", "second.example")
        self.assertEqual(result.returncode, 0, result.stderr)
        sql("UPDATE domains SET mta_sts_mode = 'testing' WHERE name = 'second.example'")
        self.assertTrue(wait_until(lambda: "mta-sts.second.example" in names_of(presented(HTTPS))), acme_log())
        after = presented(HTTPS, verify_with=os.environ["ACME_CA"])
        self.assertNotEqual(after.serial_number, before.serial_number)
        self.assertEqual(after.public_key().public_numbers(), before.public_key().public_numbers(),
                         "the key is kept, so a DANE 3 1 1 record stays right")
        self.assertEqual(names_of(after), {"mx.test.example", "mta-sts.example.org", "mta-sts.second.example"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
