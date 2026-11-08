#!/usr/bin/env python3
"""Black-box tests of the transactional email API (run.sh --postmark), as the C# server's PostmarkController and
TransactionalController answered it and its samples call it: on the HTTPS listener (2443), with
X-Postmark-Server-Token "conformance-postmark-token". Local recipients (alice@example.org) are read from the
database and the blobs; remote ones from the fake MX (reject* get 550, defer* 451)."""
import base64, email, email.policy, http.client, json, os, re, sys, time, unittest, uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from smtp_test import latest_blob, message_count, relayed, sql, tls_context  # noqa: E402

HTTPS, HTTP = 2443, 2080
TOKEN = "conformance-postmark-token"


def call(method, path, body=None, token=TOKEN, port=HTTPS, raw=None):
    if port == HTTPS:
        c = http.client.HTTPSConnection("127.0.0.1", port, timeout=30, context=tls_context())
    else:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    h = {"Host": "mail.example.org"}
    if token is not None:
        h["X-Postmark-Server-Token"] = token
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
        parsed = text.decode()
    return r.status, parsed


def parse(data):
    if isinstance(data, str):
        data = data.encode()
    return email.message_from_bytes(data, policy=email.policy.default)


def status_of(message_id, want, wait=15):
    """The message's status once it is `want` (or the last one seen after `wait` seconds)."""
    deadline = time.time() + wait
    while True:
        code, body = call("GET", f"/postmark/messages/{message_id}/status")
        if (code == 200 and body["status"] == want) or time.time() > deadline:
            return code, body
        time.sleep(0.2)


class Auth(unittest.TestCase):
    def test_tokens(self):
        status, body = call("POST", "/postmark/email", {"From": "a@example.org"}, token=None)
        self.assertEqual((status, body), (401, {"errorCode": 10, "message": "Missing API Token"}))
        status, body = call("POST", "/postmark/email", {"From": "a@example.org"}, token="wrong")
        self.assertEqual((status, body["errorCode"], body["message"]), (401, 10, "Invalid API Token"))
        status, body = call("GET", "/postmark/templates?domain=example.org", port=HTTP)
        self.assertEqual(status, 403, "never over plain HTTP")

    def test_unknown_routes(self):
        self.assertEqual(call("GET", "/postmark/nothing")[0], 404)
        self.assertEqual(call("GET", "/postmark/templates/abc")[0], 404)
        self.assertEqual(call("GET", "/postmark/email")[0], 405)


class SendEmail(unittest.TestCase):
    """POST /postmark/email."""

    def test_local_recipient(self):
        before = message_count("alice@example.org")
        status, body = call("POST", "/postmark/email", {
            "From": "Example Shop <noreply@example.org>", "To": "alice@example.org", "Subject": "Your order",
            "HtmlBody": "<b>Hello</b>", "TextBody": "Hello", "Tag": "orders"})
        self.assertEqual(status, 200, body)
        self.assertEqual((body["to"], body["errorCode"], body["message"]), ("alice@example.org", 0, "OK"))
        uuid.UUID(body["messageID"])
        self.assertRegex(body["submittedAt"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(message_count("alice@example.org"), before + 1)
        m = parse(latest_blob("alice@example.org"))
        self.assertEqual(m["Subject"], "Your order")
        self.assertEqual(m["From"].addresses[0].display_name, "Example Shop")
        self.assertEqual(m["X-PM-Tag"], "orders")
        self.assertTrue(m["Message-ID"].startswith(f"<{body['messageID']}@example.org>"))
        self.assertEqual(m.get_content_type(), "multipart/alternative")
        self.assertEqual(m.get_body(("plain",)).get_content().strip(), "Hello")
        self.assertEqual(m.get_body(("html",)).get_content().strip(), "<b>Hello</b>")
        code, st = status_of(body["messageID"], "delivered")
        self.assertEqual((code, st["status"], st["messageId"]), (200, "delivered", body["messageID"]))
        _, events = call("GET", f"/postmark/messages/{body['messageID']}/events")
        self.assertEqual([e["eventType"] for e in events], ["queued", "sent", "delivered"])
        self.assertEqual(events[1]["details"], "alice@example.org")
        self.assertEqual(set(events[0]), {"id", "messageId", "eventType", "details", "createdAt"})

    def test_remote_recipients_cc_and_bcc(self):
        status, body = call("POST", "/postmark/email", {
            "from": "noreply@example.org", "to": "ok@remote.test", "cc": "\"Ann, B.\" <ok@twomx.test>",
            "bcc": "hidden@remote.test", "replyTo": "help@example.org", "subject": "Grüße aus Köln 🎉",
            "textBody": "Straße und Größe\nzweite Zeile " + "x" * 120})
        self.assertEqual(status, 200, body)
        mid = body["messageID"]
        code, st = status_of(mid, "delivered")
        self.assertEqual(st["status"], "delivered")
        _, events = call("GET", f"/postmark/messages/{mid}/events")
        kinds = [e["eventType"] for e in events]
        self.assertEqual(kinds[0], "queued")
        self.assertEqual(sorted(e["details"] for e in events if e["eventType"] == "sent"),
                         ["hidden@remote.test", "ok@remote.test", "ok@twomx.test"])
        self.assertEqual(kinds[-1], "delivered")
        got = relayed("hidden@remote.test")
        self.assertTrue(got, "the Bcc recipient got it")
        m = parse(got[-1])
        self.assertEqual(m["Subject"], "Grüße aus Köln 🎉")
        self.assertNotIn("Bcc", m)
        self.assertNotIn("hidden@remote.test", got[-1].split("\r\n\r\n", 1)[0])
        self.assertEqual(m["Cc"].addresses[0].display_name, "Ann, B.")
        self.assertEqual(m["Reply-To"], "help@example.org")
        self.assertEqual(m["Content-Transfer-Encoding"], "quoted-printable")
        self.assertEqual(m.get_content().replace("\r\n", "\n"), "Straße und Größe\nzweite Zeile " + "x" * 120 + "\n")
        for line in got[-1].split("\r\n"):
            self.assertLessEqual(len(line), 78, line)

    def test_failed_and_deferred(self):
        _, body = call("POST", "/postmark/email", {
            "From": "noreply@example.org", "To": "reject@remote.test", "TextBody": "x"})
        code, st = status_of(body["messageID"], "failed")
        self.assertEqual(st["status"], "failed")
        self.assertTrue(st["details"].startswith("reject@remote.test: 550"), st)
        _, body = call("POST", "/postmark/email", {
            "From": "noreply@example.org", "To": "defer@remote.test", "TextBody": "x"})
        code, st = status_of(body["messageID"], "deferred")
        self.assertEqual(st["status"], "deferred")
        self.assertIn("451", st["details"])

    def test_unknown_local_user(self):
        _, body = call("POST", "/postmark/email", {
            "From": "noreply@example.org", "To": "nobody@example.org", "TextBody": "x"})
        code, st = status_of(body["messageID"], "failed")
        self.assertEqual((st["status"], st["details"]), ("failed", "nobody@example.org: 550 5.1.1 No such user here"))

    def test_attachments(self):
        data = bytes(range(256)) * 10
        status, body = call("POST", "/postmark/email", {
            "From": "noreply@example.org", "To": "alice@example.org", "Subject": "Invoice", "TextBody": "Attached.",
            "Attachments": [
                {"Name": "invoice.pdf", "Content": base64.b64encode(data).decode(), "ContentType": "application/pdf"},
                {"Name": "naïve résumé.txt", "Content": base64.b64encode(b"hi").decode()},
            ]})
        self.assertEqual(status, 200, body)
        m = parse(latest_blob("alice@example.org"))
        self.assertEqual(m.get_content_type(), "multipart/mixed")
        parts = list(m.iter_attachments())
        self.assertEqual([p.get_filename() for p in parts], ["invoice.pdf", "naïve résumé.txt"])
        self.assertEqual(parts[0].get_content_type(), "application/pdf")
        self.assertEqual(parts[0].get_content(), data)
        self.assertEqual(parts[1].get_content_type(), "application/octet-stream")
        self.assertEqual(m.get_body(("plain",)).get_content().strip(), "Attached.")
        status, body = call("POST", "/postmark/email", {
            "From": "noreply@example.org", "To": "alice@example.org", "Attachments": [{"Content": "!!not base64"}]})
        self.assertEqual((status, body["errorCode"]), (400, 300))
        status, body = call("POST", "/postmark/email", {
            "From": "noreply@example.org", "To": "alice@example.org",
            "Attachments": [{"Content": "QUJD", "ContentType": "text/plain\r\nX-Evil: 1"}]})
        self.assertEqual(status, 400, "a header injection in ContentType")
        status, body = call("POST", "/postmark/email", {
            "From": "noreply@example.org", "To": "alice@example.org",
            "Attachments": [{"Content": "A" * (26 * 1024 * 1024 * 4 // 3)}]})
        self.assertEqual((status, body), (413, {"errorCode": 413, "message": "Total attachment size exceeds 25 MB limit"}))

    def test_refusals(self):
        status, body = call("POST", "/postmark/email", {"To": "alice@example.org"})
        self.assertEqual((status, body), (400, "Missing From address"))
        status, body = call("POST", "/postmark/email", {"From": "x@nowhere.example", "To": "alice@example.org"})
        self.assertEqual((status, body), (401, "Domain not configured on this server"))
        status, body = call("POST", "/postmark/email", {"From": "noreply@example.org"})
        self.assertEqual((status, body["errorCode"]), (400, 300), "no recipient")
        status, body = call("POST", "/postmark/email", {"From": "noreply@example.org", "To": "not an address"})
        self.assertEqual(status, 400)
        status, body = call("POST", "/postmark/email", {
            "From": "noreply@example.org", "To": "alice@example.org", "Subject": "a\r\nBcc: evil@remote.test"})
        self.assertEqual(status, 200, "a CRLF in the subject is folded away, not a new field")
        m = parse(latest_blob("alice@example.org"))
        self.assertIsNone(m["Bcc"])
        self.assertEqual(call("POST", "/postmark/email", raw=b"[1]")[0], 400)


class Templates(unittest.TestCase):
    def setUp(self):
        sql("DELETE FROM email_templates")
        sql("DELETE FROM suppression_list")

    def create(self, **fields):
        body = {"name": "welcome", "domainName": "example.org", "subject": "Welcome to {{ company_name }}, {{ first_name }}!",
                "htmlBody": "<h1>Welcome, {{ first_name }}!</h1>{% if plan == \"Premium\" %}<p>Premium</p>{% endif %}",
                "textBody": "Hi {{ first_name }}.{% for item in items %} {{ item.name }} x{{ item.qty }}{% endfor %}"}
        body.update(fields)
        return call("POST", "/postmark/templates", body)

    def test_crud(self):
        status, t = self.create()
        self.assertEqual(status, 200, t)
        self.assertEqual(set(t), {"id", "domainId", "name", "subject", "htmlBody", "textBody", "active", "createdAt",
                                  "updatedAt"})
        self.assertEqual((t["name"], t["active"]), ("welcome", True))
        self.assertEqual(self.create()[0], 409, "the name is taken in the domain")
        status, got = call("GET", f"/postmark/templates/{t['id']}")
        self.assertEqual((status, got["subject"]), (200, t["subject"]))
        status, listed = call("GET", "/postmark/templates?domain=example.org")
        self.assertEqual([x["id"] for x in listed], [t["id"]])
        self.assertEqual(call("GET", "/postmark/templates?domain=tenant.example")[1], [])
        self.assertEqual(call("GET", "/postmark/templates")[0], 400)
        self.assertEqual(call("GET", "/postmark/templates?domain=nowhere.example")[0], 404)
        status, updated = call("PUT", f"/postmark/templates/{t['id']}", {"subject": "New", "active": False})
        self.assertEqual((status, updated["subject"], updated["name"], updated["active"]), (200, "New", "welcome", False))
        self.assertEqual(updated["htmlBody"], t["htmlBody"], "unchanged when not given")
        self.assertEqual(call("PUT", "/postmark/templates/999999", {"subject": "x"})[0], 404)
        self.assertEqual(call("DELETE", f"/postmark/templates/{t['id']}")[0], 204)
        self.assertEqual(call("DELETE", f"/postmark/templates/{t['id']}")[0], 204, "as the C# server answered")
        self.assertEqual(call("GET", f"/postmark/templates/{t['id']}"), (404, {"error": "Template not found"}))
        self.assertEqual(self.create(domainName="nowhere.example"), (400, {"error": "Domain not found"}))
        self.assertEqual(self.create(name="")[0], 400)

    def test_send_by_name_and_id(self):
        _, t = self.create()
        model = {"first_name": "Ana", "company_name": "Acme", "plan": "Premium",
                 "items": [{"name": "Pen", "qty": 2}, {"name": "Ink", "qty": 1}]}
        status, body = call("POST", "/postmark/templates/welcome/send",
                            {"from": "noreply@example.org", "to": "alice@example.org", "templateModel": model,
                             "tag": "welcome"})
        self.assertEqual(status, 200, body)
        self.assertEqual((body["to"], body["errorCode"], body["message"]), ("alice@example.org", 0, "OK"))
        m = parse(latest_blob("alice@example.org"))
        self.assertEqual(m["Subject"], "Welcome to Acme, Ana!")
        self.assertEqual(m["X-PM-Tag"], "welcome")
        self.assertEqual(m.get_body(("html",)).get_content().strip(), "<h1>Welcome, Ana!</h1><p>Premium</p>")
        self.assertEqual(m.get_body(("plain",)).get_content().strip(), "Hi Ana. Pen x2 Ink x1")
        status, body = call("POST", f"/postmark/templates/{t['id']}/send",
                            {"From": "noreply@example.org", "To": "alice@example.org"})
        self.assertEqual(status, 200, body)
        m = parse(latest_blob("alice@example.org"))
        self.assertEqual(m["Subject"], "Welcome to , !", "no model: the variables are empty")
        self.assertEqual(status_of(body["messageID"], "delivered")[1]["status"], "delivered")

    def test_send_refusals(self):
        _, t = self.create()
        self.assertEqual(call("POST", "/postmark/templates/welcome/send", {"from": "noreply@example.org"}),
                         (400, {"error": "From and To are required"}))
        self.assertEqual(call("POST", "/postmark/templates/welcome/send",
                              {"from": "a@nowhere.example", "to": "alice@example.org"}),
                         (401, {"error": "Sender domain not configured"}))
        self.assertEqual(call("POST", "/postmark/templates/nope/send",
                              {"from": "noreply@example.org", "to": "alice@example.org"}),
                         (404, {"error": "Template not found or inactive"}))
        self.assertEqual(call("POST", "/postmark/templates/welcome/send",
                              {"from": "noreply@tenant.example", "to": "alice@example.org"})[0], 404,
                         "another domain's template")
        call("PUT", f"/postmark/templates/{t['id']}", {"active": False})
        self.assertEqual(call("POST", "/postmark/templates/welcome/send",
                              {"from": "noreply@example.org", "to": "alice@example.org"})[0], 404, "inactive")

    def test_batch(self):
        self.create(name="receipt", subject="Receipt {{ order_id }}", htmlBody=None, textBody="Total {{ total }}")
        call("POST", "/postmark/suppressions", {"domain": "example.org", "email": "Suppressed@Remote.test"})
        before = message_count("alice@example.org")
        status, results = call("POST", "/postmark/templates/batch-send", {
            "from": "billing@example.org", "templateName": "receipt", "recipients": [
                {"to": "alice@example.org", "templateModel": {"order_id": "A1", "total": "9.50"}},
                {"to": "ok@remote.test", "templateModel": {"order_id": "B2", "total": "3.00"}},
                {"to": "suppressed@remote.test"},
                {"to": ""}]})
        self.assertEqual(status, 200, results)
        self.assertEqual([(r["to"], r["errorCode"], r["message"]) for r in results],
                         [("alice@example.org", 0, "OK"), ("ok@remote.test", 0, "OK"),
                          ("suppressed@remote.test", 406, "Recipient suppressed"), ("", 400, "Missing To")])
        self.assertNotEqual(results[0]["messageID"], results[1]["messageID"])
        self.assertEqual(message_count("alice@example.org"), before + 1)
        m = parse(latest_blob("alice@example.org"))
        self.assertEqual((m["Subject"], m.get_content().strip()), ("Receipt A1", "Total 9.50"))
        self.assertEqual(m.get_content_type(), "text/plain")
        self.assertEqual(status_of(results[1]["messageID"], "delivered")[1]["status"], "delivered")
        self.assertEqual(call("POST", "/postmark/templates/batch-send",
                              {"from": "billing@example.org", "templateName": "receipt", "recipients": []}),
                         (400, {"error": "Recipients required"}))
        self.assertEqual(call("POST", "/postmark/templates/batch-send", {
            "from": "billing@example.org", "templateName": "receipt",
            "recipients": [{"to": "a@remote.test"}] * 501}), (400, {"error": "Maximum 500 recipients per batch"}))


class Suppressions(unittest.TestCase):
    def setUp(self):
        sql("DELETE FROM suppression_list")

    def test_list_add_remove(self):
        self.assertEqual(call("POST", "/postmark/suppressions",
                              {"domain": "example.org", "email": " Blocked@Remote.TEST ", "reason": "complaint"}),
                         (200, {"success": True}))
        self.assertEqual(call("POST", "/postmark/suppressions", {"domain": "example.org", "email": "blocked@remote.test"}),
                         (200, {"success": True}), "again: nothing changes")
        status, listed = call("GET", "/postmark/suppressions?domain=example.org")
        self.assertEqual([(s["email"], s["reason"]) for s in listed], [("blocked@remote.test", "complaint")])
        self.assertEqual(set(listed[0]), {"id", "domainId", "email", "reason", "createdAt"})
        self.assertEqual(call("GET", "/postmark/suppressions?domain=tenant.example")[1], [])
        status, body = call("POST", "/postmark/email",
                            {"From": "noreply@example.org", "To": "blocked@remote.test", "TextBody": "x"})
        self.assertEqual((status, body), (406, {"errorCode": 406, "message": "Recipient is suppressed",
                                                "email": "blocked@remote.test"}))
        self.assertEqual(call("POST", "/postmark/email",
                              {"From": "noreply@tenant.example", "To": "blocked@remote.test", "TextBody": "x"})[0], 200,
                         "only for example.org")
        call("POST", "/postmark/templates", {"name": "s", "domainName": "example.org", "textBody": "x"})
        self.assertEqual(call("POST", "/postmark/templates/s/send", {"from": "a@example.org", "to": "blocked@remote.test"}),
                         (422, {"error": "Recipient is suppressed", "email": "blocked@remote.test"}))
        self.assertEqual(call("DELETE", "/postmark/suppressions", {"domain": "example.org", "email": "BLOCKED@remote.test"})[0],
                         204)
        self.assertEqual(call("GET", "/postmark/suppressions?domain=example.org")[1], [])
        self.assertEqual(call("POST", "/postmark/suppressions", {"domain": "nowhere.example", "email": "a@b.c"}),
                         (404, {"error": "Domain not found"}))
        self.assertEqual(call("GET", "/postmark/messages/no-such-id/status"), (404, {"error": "Message not found"}))
        self.assertEqual(call("GET", "/postmark/messages/no-such-id/events"), (200, []))


if __name__ == "__main__":
    unittest.main(verbosity=2)
