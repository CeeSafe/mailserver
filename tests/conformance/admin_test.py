#!/usr/bin/env python3
"""Black-box tests of the admin JSON API (run.sh --admin), on the admin listener (2918), as the admin UI's Nitro
server calls it: a bearer token from POST /api/auth/login. Accounts from run.sh: admin / admin-pw-1234 (the
server), orgadmin / orgadmin-pw-1234 (example.org only), web@example.org / web-pw-1234 (a mail user). The shapes are
those of CosmoMailAdmin's C# API (see the spec the port followed)."""
import http.client, imaplib, json, os, ssl, sys, time, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from smtp_test import admin, sql, tls_context  # noqa: E402

ADMIN = 2918
IMAPS = 2993
_tokens = {}


def call(method, path, body=None, token=None, headers=None, raw=None):
    c = http.client.HTTPConnection("127.0.0.1", ADMIN, timeout=30)
    h = {"Host": "127.0.0.1:2918"}
    if token:
        h["Authorization"] = "Bearer " + token
    h.update(headers or {})
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    if data is not None:
        h["Content-Type"] = "application/json"
    c.request(method, path, body=data, headers=h)
    r = c.getresponse()
    text = r.read()
    c.close()
    try:
        parsed = json.loads(text) if text else None
    except ValueError:
        parsed = text
    return r.status, parsed


def token(who):
    if who not in _tokens:
        users = {"admin": ("admin", "admin-pw-1234"), "org": ("orgadmin", "orgadmin-pw-1234"),
                 "user": ("web@example.org", "web-pw-1234")}
        status, body = call("POST", "/api/auth/login", {"username": users[who][0], "password": users[who][1]})
        assert status == 200, (status, body)
        _tokens[who] = body["token"]
    return _tokens[who]


def domain_id(name):
    return int(sql(f"SELECT id FROM domains WHERE name = '{name}'"))


def user_id(email):
    return int(sql(f"SELECT id FROM users WHERE email = '{email}'"))


class Auth(unittest.TestCase):
    def test_login_shapes(self):
        status, body = call("POST", "/api/auth/login", {"username": "admin", "password": "admin-pw-1234"})
        self.assertEqual(status, 200)
        self.assertEqual(body["user"]["role"], "server")
        self.assertEqual(body["user"]["source"], "admin_users")
        self.assertIsNone(body["user"]["domainId"])
        self.assertEqual(body["expiresIn"], 86400)
        self.assertEqual(body["token"].count("."), 2)
        _, org = call("POST", "/api/auth/login", {"username": "orgadmin", "password": "orgadmin-pw-1234"})
        self.assertEqual((org["user"]["role"], org["user"]["domainName"]), ("domain", "example.org"))
        _, user = call("POST", "/api/auth/login", {"username": "web@example.org", "password": "web-pw-1234"})
        self.assertEqual((user["user"]["role"], user["user"]["source"]), ("user", "users"))
        self.assertEqual(user["user"]["username"], "web@example.org")

    def test_refusals(self):
        self.assertEqual(call("POST", "/api/auth/login", {"username": "admin", "password": "nope"})[0], 401)
        self.assertEqual(call("POST", "/api/auth/login", {"username": "nobody", "password": "nope"})[0], 401)
        self.assertEqual(call("POST", "/api/auth/login", {"username": "", "password": ""})[0], 400)
        status, body = call("GET", "/api/domains")
        self.assertEqual((status, body["error"]), (401, "Unauthorized"), "no credentials (a static token is set)")
        self.assertEqual(call("GET", "/api/domains", token="a.b.c")[0], 401)
        # A token signed with another key.
        forged = token("admin")[:-4] + ("AAAA" if not token("admin").endswith("AAAA") else "BBBB")
        self.assertEqual(call("GET", "/api/domains", token=forged)[0], 401)
        # A mail user is not an admin.
        self.assertEqual(call("GET", "/api/domains", token=token("user"))[0], 403)

    def test_static_token(self):
        status, body = call("GET", "/api/stats", headers={"X-CosmoMail-Admin-Token": "conformance-static-token"})
        self.assertEqual(status, 200)
        self.assertEqual(set(body), {"domains", "users", "queue_size"})
        self.assertEqual(call("GET", "/api/stats", headers={"X-CosmoMail-Admin-Token": "wrong"})[0], 401)

    def test_me(self):
        status, body = call("GET", "/api/auth/me", token=token("org"))
        self.assertEqual(status, 200)
        self.assertEqual((body["username"], body["role"], body["domainName"]), ("orgadmin", "domain", "example.org"))

    def test_audit_trail(self):
        status, logs = call("GET", "/api/audit-logs?limit=500", token=token("admin"))
        self.assertEqual(status, 200)
        actions = {l["action"] for l in logs}
        self.assertIn("admin.login.success", actions)
        self.assertTrue(all("ipAddress" in l and "resourceType" in l for l in logs))


class Domains(unittest.TestCase):
    def test_list_and_scope(self):
        status, domains = call("GET", "/api/domains", token=token("admin"))
        self.assertEqual(status, 200)
        names = [d["name"] for d in domains]
        self.assertIn("example.org", names)
        self.assertIn("tenant.example", names)
        d = next(d for d in domains if d["name"] == "example.org")
        for key in ("max_users", "spf_dns_server", "rate_limit_smtp_per_ip", "mta_sts_mode", "dkim_signing_enabled",
                    "created_at", "spam_reject_score"):
            self.assertIn(key, d)
        self.assertNotIn("dkim_private_key", d)
        _, mine = call("GET", "/api/domains", token=token("org"))
        self.assertEqual([d["name"] for d in mine], ["example.org"], "a domain admin sees their domain")
        self.assertEqual(call("GET", f"/api/domains/{domain_id('tenant.example')}", token=token("org"))[0], 404)
        self.assertEqual(call("GET", f"/api/domains/{domain_id('example.org')}", token=token("org"))[0], 200)

    def test_settings_round_trip(self):
        did = domain_id("tenant.example")
        _, d = call("GET", f"/api/domains/{did}", token=token("admin"))
        d.update({"spf_enabled": True, "spam_reject_score": 7.5, "rate_limit_smtp_per_ip": "50/1h",
                  "catchall_email": "boss@tenant.example", "mta_sts_mode": "enforce", "mta_sts_max_age": 604800,
                  "mta_sts_mx_patterns": "mx1.tenant.example mx2.tenant.example", "dkim_private_key": "evil",
                  "name": "renamed.example"})
        status, _ = call("PUT", f"/api/domains/{did}", d, token=token("admin"))
        self.assertEqual(status, 200)
        _, after = call("GET", f"/api/domains/{did}", token=token("admin"))
        self.assertEqual(after["name"], "tenant.example", "the name is not changed")
        self.assertEqual((after["spf_enabled"], after["spam_reject_score"], after["rate_limit_smtp_per_ip"]),
                         (True, 7.5, "50/1h"))
        self.assertEqual(after["catchall_email"], "boss@tenant.example")
        self.assertNotIn("dkim_private_key", after)
        self.assertEqual(sql(f"SELECT catchall FROM domains WHERE id = {did}"), "boss@tenant.example")
        # The MTA-STS policy is served, with a new id for the TXT record.
        first_id = sql(f"SELECT mta_sts_id FROM domains WHERE id = {did}")
        c = http.client.HTTPSConnection("127.0.0.1", 2443, context=tls_context(), timeout=10)
        c.request("GET", "/.well-known/mta-sts.txt", headers={"Host": "mta-sts.tenant.example"})
        policy = c.getresponse().read()
        c.close()
        self.assertIn(b"mode: enforce\r\nmx: mx1.tenant.example\r\nmx: mx2.tenant.example\r\nmax_age: 604800", policy)
        after["mta_sts_mode"] = "testing"
        call("PUT", f"/api/domains/{did}", after, token=token("admin"))
        self.assertNotEqual(sql(f"SELECT mta_sts_id FROM domains WHERE id = {did}"), first_id, "a new policy id")
        after["status"] = "suspended"
        call("PUT", f"/api/domains/{did}", after, token=token("admin"))
        self.assertEqual(sql(f"SELECT active FROM domains WHERE id = {did}"), "f")
        after.update({"status": "active", "mta_sts_mode": "none", "catchall_email": ""})
        call("PUT", f"/api/domains/{did}", after, token=token("admin"))
        self.assertEqual(sql(f"SELECT coalesce(catchall, 'none') FROM domains WHERE id = {did}"), "none")
        # Bad values are 400, not 500.
        status, body = call("PUT", f"/api/domains/{did}", {"mta_sts_mode": "sometimes"}, token=token("admin"))
        self.assertEqual(status, 400, body)
        self.assertEqual(call("PUT", f"/api/domains/{did}", raw=b"[1]", token=token("admin"))[0], 400)

    def test_setup_and_dkim(self):
        body = {"name": " Setup.Example ", "mailOnly": True, "spfEnabled": True, "dmarcEnabled": True,
                "dmarcPolicy": "reject", "dmarcReportEmail": "", "spamEnabled": False, "greylistEnabled": False,
                "rateLimitEnabled": False, "cloudflareZoneId": None, "serverIp": "203.0.113.7",
                "firstUserEmail": "first@setup.example", "firstUserPassword": "first-pw-1234"}
        self.assertEqual(call("POST", "/api/domains/setup", body, token=token("org"))[0], 403, "server only")
        status, result = call("POST", "/api/domains/setup", body, token=token("admin"))
        self.assertEqual(status, 200, result)
        records = {(r["type"], r["name"]): r["value"] for r in result["dns"]}
        self.assertEqual(records[("A", "mail.setup.example")], "203.0.113.7")
        self.assertEqual(records[("MX", "setup.example")], "mail.setup.example (priority 10)")
        self.assertEqual(records[("TXT", "_dmarc.setup.example")], "v=DMARC1; p=reject; rua=mailto:postmaster@setup.example")
        dkim = records[("TXT", "mail._domainkey.setup.example")]
        self.assertTrue(dkim.startswith("v=DKIM1; k=rsa; p=MII"), dkim)
        self.assertEqual(records[("A", "autoconfig.setup.example")], "203.0.113.7")
        self.assertEqual(sql("SELECT active FROM dkim_keys WHERE domain = 'setup.example' AND selector = 'mail'"), "f",
                         "the key waits for its DNS record")
        self.assertEqual(sql("SELECT count(*) FROM mailboxes m JOIN users u ON u.id = m.user_id "
                             "WHERE u.email = 'first@setup.example'"), "6")
        did = result["domainId"]
        _, d = call("GET", f"/api/domains/{did}", token=token("admin"))
        self.assertEqual((d["dmarc_policy"], d["dmarc_enabled"], d["dkim_selector"]), ("reject", True, "mail"))
        self.assertTrue(d["dkim_public_key"].startswith("-----BEGIN PUBLIC KEY-----"))
        # Setup again keeps the key.
        _, again = call("POST", "/api/domains/setup", body, token=token("admin"))
        self.assertEqual({(r["type"], r["name"]): r["value"] for r in again["dns"]}[("TXT", "mail._domainkey.setup.example")], dkim)
        # Regenerate: a new key, off until signing is turned on again.
        status, regen = call("POST", f"/api/domains/{did}/regenerate-dkim", token=token("admin"))
        self.assertEqual(status, 200)
        self.assertNotEqual("v=DKIM1; k=rsa; p=" + regen["publicKeyDns"], dkim)
        d["dkim_signing_enabled"] = True
        call("PUT", f"/api/domains/{did}", d, token=token("admin"))
        self.assertEqual(sql("SELECT active FROM dkim_keys WHERE domain = 'setup.example'"), "t")
        # The first user can log in over IMAP.
        imap = imaplib.IMAP4_SSL("127.0.0.1", IMAPS, ssl_context=tls_context())
        imap.login("first@setup.example", "first-pw-1234")
        imap.logout()


class Aliases(unittest.TestCase):
    def test_crud(self):
        did = domain_id("example.org")
        path = f"/api/domains/{did}/aliases"
        self.assertEqual(call("POST", path, {"email": "Sales@Example.org", "destination": " alice@example.org "},
                              token=token("org"))[0], 200)
        self.assertEqual(call("POST", path, {"email": "sales@example.org", "destination": "bob@example.org"},
                              token=token("org"))[0], 409, "a duplicate")
        status, body = call("POST", path, {"email": "x@tenant.example", "destination": "a@b.c"}, token=token("org"))
        self.assertEqual(status, 400, "another domain's address")
        self.assertEqual(call("POST", path, {"email": "", "destination": ""}, token=token("org"))[1]["error"],
                         "email and destination are required")
        _, aliases = call("GET", path, token=token("org"))
        sales = next(a for a in aliases if a["email"] == "sales@example.org")
        self.assertEqual((sales["destination"], sales["active"]), ("alice@example.org", True))
        self.assertIn("createdAt", sales)
        self.assertEqual(call("POST", f"/api/domains/{domain_id('tenant.example')}/aliases",
                              {"email": "a@tenant.example", "destination": "b@c.d"}, token=token("org"))[0], 404)
        self.assertEqual(call("PUT", f"/api/aliases/{sales['id']}", {"email": "sales@example.org",
                              "destination": "bob@example.org", "active": False}, token=token("org"))[0], 200)
        self.assertEqual(sql("SELECT destination || ' ' || active FROM aliases WHERE address = 'sales@example.org'"),
                         "bob@example.org false")
        self.assertEqual(call("DELETE", f"/api/aliases/{sales['id']}", token=token("org"))[0], 200)
        self.assertEqual(call("DELETE", f"/api/aliases/{sales['id']}", token=token("org"))[0], 404)


class Users(unittest.TestCase):
    def test_lifecycle(self):
        did = domain_id("example.org")
        status, body = call("POST", "/api/users", {"email": "new@example.org", "password": "new-pw-1234",
                                                   "domainId": did}, token=token("org"))
        self.assertEqual((status, body["mailboxes"]), (200, 6), body)
        self.assertEqual(call("POST", "/api/users", {"email": "dup@tenant.example", "password": "x-pw-12345",
                                                     "domainId": did}, token=token("org"))[0], 400, "wrong domain")
        self.assertEqual(call("POST", "/api/users", {"email": "new@example.org", "password": "new-pw-1234",
                                                     "domainId": did}, token=token("org"))[0], 409)
        self.assertEqual(call("POST", "/api/users", {"email": "t@tenant.example", "password": "new-pw-1234",
                                                     "domainId": domain_id("tenant.example")}, token=token("org"))[0], 404)
        _, users = call("GET", f"/api/users?domainId={did}", token=token("admin"))
        new = next(u for u in users if u["email"] == "new@example.org")
        self.assertEqual(new["domain"]["name"], "example.org")
        self.assertNotIn("password_hash", new)
        self.assertNotIn("totp_secret", new)
        for key in ("used_quota", "auth_method", "last_login", "forward_to", "auto_reply_enabled"):
            self.assertIn(key, new)
        _, all_users = call("GET", "/api/users", token=token("org"))
        self.assertTrue(all(u["email"].endswith("@example.org") for u in all_users), "scoped")
        uid = new["id"]
        status, _ = call("PUT", f"/api/users/{uid}", {"role": "admin", "quota": 5000000, "forwardTo": "x@y.z",
                                                     "status": None, "language": None}, token=token("org"))
        self.assertEqual(status, 200)
        _, got = call("GET", f"/api/users/{uid}", token=token("org"))
        self.assertEqual((got["role"], got["quota"], got["forward_to"], got["status"]), ("admin", 5000000, "x@y.z", "active"))
        call("PUT", f"/api/users/{uid}", {"forwardTo": "", "role": "root"}, token=token("org"))
        _, got = call("GET", f"/api/users/{uid}", token=token("org"))
        self.assertEqual((got["forward_to"], got["role"]), (None, "admin"), "forwarding cleared; a bad role ignored")
        self.assertEqual(call("PUT", f"/api/users/{uid}/password", {"newPassword": "changed-pw-1"}, token=token("org"))[0], 200)
        imap = imaplib.IMAP4_SSL("127.0.0.1", IMAPS, ssl_context=tls_context())
        imap.login("new@example.org", "changed-pw-1")
        imap.logout()
        # A promoted user logs in to the UI as a domain admin.
        status, login = call("POST", "/api/auth/login", {"username": "new@example.org", "password": "changed-pw-1"})
        self.assertEqual((status, login["user"]["role"]), (200, "domain_admin"))
        self.assertEqual(call("GET", "/api/domains", token=login["token"])[0], 200)
        self.assertEqual(call("POST", f"/api/users/{uid}/reset-totp", token=token("org"))[0], 200)
        self.assertEqual(call("DELETE", f"/api/users/{uid}", token=token("org"))[0], 200)
        self.assertEqual(call("GET", f"/api/users/{uid}", token=token("org"))[0], 404)
        self.assertEqual(sql(f"SELECT count(*) FROM mailboxes WHERE user_id = {uid}"), "0")
        other = user_id("first@setup.example") if sql("SELECT count(*) FROM users WHERE email = 'first@setup.example'") == "1" else None
        if other:
            self.assertEqual(call("GET", f"/api/users/{other}", token=token("org"))[0], 404, "another domain's user")


class Mailboxes(unittest.TestCase):
    def test_crud(self):
        uid = user_id("web@example.org")
        status, boxes = call("GET", f"/api/users/{uid}/mailboxes", token=token("org"))
        self.assertEqual(status, 200)
        self.assertEqual({b["name"] for b in boxes}, {"INBOX", "Sent", "Drafts", "Trash", "Junk", "Archive"})
        inbox = next(b for b in boxes if b["name"] == "INBOX")
        for key in ("current_size", "message_count", "max_size", "retention_days", "special_use", "subscribed"):
            self.assertIn(key, inbox)
        status, made = call("POST", f"/api/users/{uid}/mailboxes", {"name": "Projects/2026", "specialUse": None,
                            "maxSize": 1000, "retentionDays": 30, "description": "work"}, token=token("org"))
        self.assertEqual(status, 200, made)
        self.assertEqual((made["name"], made["max_size"], made["retention_days"], made["description"]),
                         ("Projects/2026", 1000, 30, "work"))
        self.assertEqual(call("POST", f"/api/users/{uid}/mailboxes", {"name": "Projects/2026"}, token=token("org"))[0], 409)
        status, put = call("PUT", f"/api/mailboxes/{made['id']}", {"subscribed": False, "description": None},
                           token=token("org"))
        self.assertEqual((status, put["subscribed"], put["description"]), (200, False, None))
        self.assertEqual(call("DELETE", f"/api/mailboxes/{inbox['id']}", token=token("org"))[1]["error"], "Cannot delete INBOX")
        status, _ = call("DELETE", f"/api/mailboxes/{made['id']}", token=token("org"))
        self.assertEqual(status, 204)
        self.assertEqual(call("GET", f"/api/mailboxes/{made['id']}", token=token("org"))[0], 404)


class Sieve(unittest.TestCase):
    def test_scripts(self):
        uid = user_id("web@example.org")
        path = f"/api/users/{uid}/sieve-scripts"
        status, body = call("POST", path, {"name": "bad", "content": "fileinto \"x\""}, token=token("org"))
        self.assertEqual(status, 400)
        self.assertIn("does not compile", body["error"])
        good = 'require "fileinto";\nif header :contains "subject" "x" { fileinto "Junk"; }\n'
        self.assertEqual(call("POST", path, {"name": "main", "content": good}, token=token("org"))[0], 200)
        self.assertEqual(call("POST", path, {"name": "other", "content": "keep;\n"}, token=token("org"))[0], 200)
        _, scripts = call("GET", path, token=token("org"))
        main = next(s for s in scripts if s["name"] == "main")
        self.assertFalse(main["active"], "new scripts are inactive")
        self.assertEqual(call("POST", f"/api/sieve-scripts/{main['id']}/activate", token=token("org"))[0], 200)
        self.assertEqual(sql(f"SELECT sieve_active FROM users WHERE id = {uid}"), "main")
        _, scripts = call("GET", path, token=token("org"))
        self.assertEqual(scripts[0]["name"], "main", "the active one first")
        self.assertEqual(call("PUT", f"/api/sieve-scripts/{main['id']}", {"name": "renamed", "content": good},
                              token=token("org"))[0], 200)
        self.assertEqual(sql(f"SELECT sieve_active FROM users WHERE id = {uid}"), "renamed", "it stays active")
        self.assertEqual(call("POST", f"/api/sieve-scripts/{main['id']}/deactivate", token=token("org"))[0], 200)
        self.assertEqual(sql(f"SELECT coalesce(sieve_active, '-') FROM users WHERE id = {uid}"), "-")
        for s in scripts:
            self.assertEqual(call("DELETE", f"/api/sieve-scripts/{s['id']}", token=token("org"))[0], 200)
        self.assertEqual(call("GET", path, token=token("org"))[1], [])


class Profile(unittest.TestCase):
    def test_profile(self):
        status, me = call("GET", "/api/profile", token=token("user"))
        self.assertEqual(status, 200)
        self.assertEqual((me["email"], me["domainName"], me["status"]), ("web@example.org", "example.org", "active"))
        for key in ("quota", "usedQuota", "language", "totpEnabled", "forwardTo", "autoReplyEnabled", "authMethod"):
            self.assertIn(key, me)
        self.assertEqual(call("PUT", "/api/profile", {"language": "de", "forwardTo": "", "autoReplyEnabled": True,
                              "autoReplySubject": "Away", "autoReplyBody": "Back soon"}, token=token("user"))[0], 200)
        _, me = call("GET", "/api/profile", token=token("user"))
        self.assertEqual((me["language"], me["autoReplySubject"], me["forwardTo"]), ("de", "Away", None))
        status, body = call("PUT", "/api/profile/password", {"currentPassword": "wrong", "newPassword": "x-pw-12345"},
                            token=token("user"))
        self.assertEqual((status, body["error"]), (400, "Current password is incorrect."), "not 401: that logs out")
        self.assertEqual(call("PUT", "/api/profile/password", {"currentPassword": "web-pw-1234",
                              "newPassword": "web-pw-1234"}, token=token("user"))[0], 200)
        self.assertEqual(call("GET", "/api/profile", token=token("admin"))[0], 403, "admins have no profile")


class Queue(unittest.TestCase):
    def test_queue(self):
        status, items = call("GET", "/api/queue", token=token("admin"))
        self.assertEqual(status, 200)
        self.assertIsInstance(items, list)
        self.assertEqual(call("GET", "/api/queue", token=token("org"))[0], 403)
        self.assertEqual(call("POST", "/api/queue/999999999/retry", token=token("admin"))[0], 404)


class DnsRecords(unittest.TestCase):
    def test_zone(self):
        sql("UPDATE domains SET mta_sts_mode = 'enforce' WHERE name = 'example.org'")
        try:
            result = admin("dns-records", "example.org")
        finally:
            sql("UPDATE domains SET mta_sts_mode = 'none' WHERE name = 'example.org'")
        self.assertEqual(result.returncode, 0, result.stderr)
        out = result.stdout
        self.assertIn("example.org. IN MX 10 mx.test.example.\n", out)
        self.assertIn('example.org. IN TXT "v=spf1 mx -all"', out)
        self.assertIn('_dmarc.example.org. IN TXT "v=DMARC1; p=quarantine; rua=mailto:postmaster@example.org"', out)
        self.assertRegex(out, r'_mta-sts\.example\.org\. IN TXT "v=STSv1; id=\d+"')
        self.assertIn("mta-sts.example.org. IN CNAME mx.test.example.", out)
        # The TLSA record is SHA-256 of the served certificate's SubjectPublicKeyInfo.
        import hashlib, socket
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection(("127.0.0.1", 2443)) as raw:
            with context.wrap_socket(raw) as t:
                cert = x509.load_der_x509_certificate(t.getpeercert(binary_form=True))
        spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.assertIn("_25._tcp.mx.test.example. IN TLSA 3 1 1 " + hashlib.sha256(spki).hexdigest(), out)
        self.assertNotEqual(admin("dns-records", "nowhere.example").returncode, 0)


class Unsupported(unittest.TestCase):
    def test_pages_load(self):
        for path in ("/api/greylist", "/api/ip-blacklist", "/api/retention-rules", "/api/webhooks", "/api/oauth/clients"):
            status, body = call("GET", path, token=token("admin"))
            self.assertEqual((status, body), (200, []), path)
        self.assertEqual(call("POST", "/api/webhooks", {"url": "https://x"}, token=token("admin"))[0], 501)
        self.assertEqual(call("GET", "/api/tools/mx?domain=example.org", token=token("admin"))[0], 501)
        self.assertEqual(call("GET", "/api/nothing", token=token("admin"))[0], 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
