#!/usr/bin/env python3
"""Black-box SMTP tests against a running mailserver (see run.sh): MX on 2525, submission on 2587, SMTPS on 2465,
users alice@example.org (alice-pw), bob@example.org (bob-pw, 2000-byte quota) and carol@example.org (carol-pw,
for the Sieve tests). The database is read with psql
in the ceesafe-pg-test container."""
import base64, email, re, email.policy, json, os, smtplib, socket, ssl, subprocess, sys, time, unittest

HOST = "127.0.0.1"
MX, SUBMISSION, SMTPS = 2525, 2587, 2465


def sql(query: str) -> str:
    out = subprocess.run(
        ["docker", "exec", "ceesafe-pg-test", "psql", "-At", "-U", "cee", "-d", "mailserver_test", "-c", query],
        capture_output=True, check=True, text=True)
    return out.stdout.strip()


def tls_context():
    context = ssl.create_default_context(cafile=os.environ["CA"])
    context.check_hostname = False  # the fixture certificate names localhost; we connect to 127.0.0.1
    return context


def message_count(email: str, mailbox: str = "INBOX") -> int:
    return int(sql(f"SELECT messages FROM mailboxes m JOIN users u ON u.id = m.user_id "
                   f"WHERE u.email = '{email}' AND m.name = '{mailbox}'"))


def raw(port: int, lines: bytes, read_until: bytes = b"221", timeout: float = 5) -> bytes:
    """Sends `lines` at once (pipelined) on a plain connection and returns everything the server said."""
    with socket.create_connection((HOST, port), timeout=timeout) as s:
        s.recv(4096)  # banner
        s.sendall(lines)
        data = b""
        deadline = time.time() + timeout
        while read_until not in data and time.time() < deadline:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        return data


class Mx(unittest.TestCase):
    def test_banner_and_capabilities(self):
        with smtplib.SMTP(HOST, MX) as c:
            code, banner = c.ehlo("client.example")
            self.assertEqual(code, 250)
            caps = banner.decode()
            for cap in ("PIPELINING", "SIZE 3000000", "8BITMIME", "ENHANCEDSTATUSCODES", "SMTPUTF8", "STARTTLS"):
                self.assertIn(cap, caps)
            self.assertNotIn("AUTH", caps, "no AUTH on the MX port")

    def test_delivers_to_a_local_user(self):
        before = message_count("alice@example.org")
        body = "From: someone@remote.test\r\nTo: alice@example.org\r\nSubject: hello\r\n\r\nHi Alice.\r\n.leading dot\r\n"
        with smtplib.SMTP(HOST, MX) as c:
            c.ehlo("remote.test")
            refused = c.sendmail("someone@remote.test", ["Alice@Example.org"], body)
            self.assertEqual(refused, {})
        self.assertEqual(message_count("alice@example.org"), before + 1)
        # The stored message: a Received header first, the body with its dot unstuffed, and a part index.
        blob = sql("SELECT encode(blob, 'hex') FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id "
                   "JOIN users u ON u.id = b.user_id WHERE u.email = 'alice@example.org' ORDER BY m.uid DESC LIMIT 1")
        path = os.path.join(os.environ["MAILSERVER_BLOBS"], blob[0:2], blob[2:4], blob)
        with open(path, "rb") as f:
            stored = f.read()
        self.assertTrue(stored.startswith(b"Authentication-Results: mx.test.example;\r\n\tspf=pass smtp.mailfrom=remote.test;"
                                          b"\r\n\tdkim=none;\r\n\tdmarc=none header.from=remote.test\r\n"), stored[:200])
        self.assertIn(b"\r\nReceived: from remote.test ([127.0.0.1])\r\n\tby mx.test.example with ESMTP id ", stored)
        self.assertIn(b"\tfor <Alice@Example.org>; ", stored)
        self.assertTrue(stored.endswith(b"Hi Alice.\r\n.leading dot\r\n"), stored[-40:])
        self.assertEqual(sql("SELECT meta IS NOT NULL FROM messages ORDER BY mailbox_id, uid DESC LIMIT 1"), "t")

    def test_refuses_unknown_users_and_relaying(self):
        with smtplib.SMTP(HOST, MX) as c:
            c.ehlo("remote.test")
            c.mail("someone@remote.test")
            code, text = c.rcpt("nobody@example.org")
            self.assertEqual(code, 550)
            self.assertIn(b"5.1.1", text)
            code, text = c.rcpt("victim@elsewhere.test")
            self.assertEqual(code, 550, "no open relay")
            self.assertIn(b"5.7.1", text)
            with self.assertRaises(smtplib.SMTPDataError) as refused:
                c.data("Subject: x\r\n\r\nx\r\n")
            self.assertEqual(refused.exception.smtp_code, 554, "DATA with no accepted recipient")

    def test_sequence_errors(self):
        out = raw(MX, b"MAIL FROM:<a@b.test>\r\nEHLO c.test\r\nRCPT TO:<alice@example.org>\r\nDATA\r\n"
                      b"MAIL FROM:<a@b.test> FOO=BAR\r\nMAIL FROM:<a b>\r\nAUTH PLAIN\r\nQUIT\r\n")
        lines = [l for l in out.split(b"\r\n") if l and not l.startswith(b"250-")]
        codes = [l[:3] for l in lines]
        self.assertEqual(codes, [b"503", b"250", b"503", b"503", b"555", b"501", b"503", b"221"], out)

    def test_pipelining(self):
        msg = b"Subject: piped\r\n\r\nbody\r\n.\r\n"
        out = raw(MX, b"EHLO c.test\r\nMAIL FROM:<a@remote.test>\r\nRCPT TO:<alice@example.org>\r\n"
                      b"RCPT TO:<bob@example.org>\r\nDATA\r\n" + msg + b"QUIT\r\n")
        lines = [l for l in out.split(b"\r\n") if l and not l.startswith(b"250-")]
        self.assertEqual([l[:3] for l in lines], [b"250", b"250", b"250", b"250", b"354", b"250", b"221"], out)

    def test_quota(self):
        with smtplib.SMTP(HOST, MX) as c:
            c.ehlo("remote.test")
            c.mail("someone@remote.test", ["SIZE=5000"])
            code, text = c.rcpt("bob@example.org")
            self.assertEqual(code, 452, "over bob's 2000-byte quota")
            self.assertIn(b"4.2.2", text)

    def test_message_size_limit(self):
        with smtplib.SMTP(HOST, MX) as c:
            c.ehlo("remote.test")
            code, _ = c.mail("someone@remote.test", ["SIZE=4000000"])
            self.assertEqual(code, 552)
            c.rset()
            c.mail("someone@remote.test")
            c.rcpt("alice@example.org")
            code, _ = c.data("Subject: big\r\n\r\n" + ("x" * 998 + "\r\n") * 3100)
            self.assertEqual(code, 552)
            self.assertEqual(c.noop()[0], 250, "the session stays in step after a refused message")

    def test_smuggling_is_not_split(self):
        # <LF>.<LF> and <LF>.<CR><LF> are data: a second message cannot be smuggled inside the first.
        before = message_count("alice@example.org")
        payload = (b"EHLO c.test\r\nMAIL FROM:<a@remote.test>\r\nRCPT TO:<alice@example.org>\r\nDATA\r\n"
                   b"Subject: outer\r\n\r\nfirst\n.\nMAIL FROM:<x@y.test>\nRCPT TO:<alice@example.org>\nDATA\n"
                   b"Subject: smuggled\n\nsecond\n.\r\nstill data\r\n.\r\nQUIT\r\n")
        out = raw(MX, payload)
        self.assertEqual(message_count("alice@example.org"), before + 1, out)

    def test_starttls(self):
        with smtplib.SMTP(HOST, MX) as c:
            c.ehlo("remote.test")
            c.starttls(context=tls_context())
            code, caps = c.ehlo("remote.test")
            self.assertEqual(code, 250)
            self.assertNotIn(b"STARTTLS", caps)
            self.assertEqual(c.sendmail("a@remote.test", ["alice@example.org"], "Subject: tls\r\n\r\nsecure\r\n"), {})

    def test_starttls_drops_pipelined_plaintext(self):
        # A command pipelined after STARTTLS was sent in the clear: it must not run inside the TLS session.
        with socket.create_connection((HOST, MX), timeout=5) as s:
            s.recv(4096)
            s.sendall(b"EHLO c.test\r\n")
            time.sleep(0.2)
            s.recv(4096)
            s.sendall(b"STARTTLS\r\nRSET\r\n")
            self.assertTrue(s.recv(4096).startswith(b"220"))
            t = tls_context().wrap_socket(s, server_hostname="localhost")
            t.sendall(b"NOOP\r\n")
            reply = t.recv(4096)
            self.assertTrue(reply.startswith(b"250 2.0.0 OK"), reply)  # NOOP's reply, not RSET's left over
            t.sendall(b"QUIT\r\n")
            t.close()


def latest_blob(email: str, mailbox: str = "INBOX") -> bytes:
    blob = sql("SELECT encode(m.blob, 'hex') FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id "
               f"JOIN users u ON u.id = b.user_id WHERE u.email = '{email}' AND b.name = '{mailbox}' "
               "ORDER BY m.uid DESC LIMIT 1")
    with open(os.path.join(os.environ["MAILSERVER_BLOBS"], blob[0:2], blob[2:4], blob), "rb") as f:
        return f.read()


class InboundAuth(unittest.TestCase):
    def test_dmarc_reject(self):
        before = message_count("alice@example.org")
        with smtplib.SMTP(HOST, MX) as c:
            c.ehlo("spoofer.test")
            with self.assertRaises(smtplib.SMTPDataError) as refused:
                c.sendmail("ceo@spoofed.test", ["alice@example.org"], "From: ceo@spoofed.test\r\nSubject: wire money\r\n\r\nnow\r\n")
            self.assertEqual(refused.exception.smtp_code, 550)
            self.assertIn(b"DMARC", refused.exception.smtp_error)
        self.assertEqual(message_count("alice@example.org"), before)

    def test_dmarc_quarantine_goes_to_junk(self):
        junk = message_count("alice@example.org", "Junk")
        with smtplib.SMTP(HOST, MX) as c:
            c.ehlo("sender.test")
            c.sendmail("x@quarantine.test", ["alice@example.org"], "From: x@quarantine.test\r\nSubject: maybe\r\n\r\nhm\r\n")
        self.assertEqual(message_count("alice@example.org", "Junk"), junk + 1)
        self.assertIn(b"dmarc=fail (p=quarantine dis=quarantine) header.from=quarantine.test", latest_blob("alice@example.org", "Junk"))

    def test_dkim_signed_message_passes(self):
        # Signed by dkimpy for alice@example.org (the test domain's keys are in the zone). SPF fails (127.0.0.1 is not
        # 192.0.2.1), but the aligned DKIM pass carries DMARC; and the message must arrive unchanged for that.
        with open(os.path.join(os.environ["DKIM_CASES"], "065-oversigned.eml"), "rb") as f:
            message = f.read()
        with smtplib.SMTP(HOST, MX) as c:
            c.ehlo("mail.example.org")
            self.assertEqual(c.sendmail("bounce@example.org", ["bob@example.org"], message), {})
        stored = latest_blob("bob@example.org")
        self.assertIn(b"\tspf=fail smtp.mailfrom=example.org;\r\n\tdkim=pass header.d=example.org header.s=rsa2048", stored)
        self.assertIn(b"\tdmarc=pass (p=reject) header.from=example.org", stored)
        self.assertTrue(stored.endswith(message), "the message is stored as sent, after our header fields")

    def test_forged_results_are_removed(self):
        forged = ("Authentication-Results: mx.test.example; dkim=pass header.d=bank.test\r\n"
                  "Authentication-Results: other.example; spf=pass\r\n"
                  "From: x@remote.test\r\nSubject: trust me\r\n\r\nbody\r\n")
        with smtplib.SMTP(HOST, MX) as c:
            c.ehlo("remote.test")
            c.sendmail("x@remote.test", ["alice@example.org"], forged)
        stored = latest_blob("alice@example.org")
        self.assertEqual(stored.count(b"Authentication-Results: mx.test.example"), 1, "only ours")
        self.assertNotIn(b"header.d=bank.test", stored)
        self.assertIn(b"Authentication-Results: other.example; spf=pass", stored, "another server's is kept")

    def test_large_message_spools(self):
        body = ("y" * 998 + "\r\n") * 1800  # about 1.8 MB: past the 1 MiB held in memory
        message = "From: big@remote.test\r\nSubject: large\r\n\r\n" + body
        with smtplib.SMTP(HOST, MX) as c:
            c.ehlo("remote.test")
            self.assertEqual(c.sendmail("big@remote.test", ["alice@example.org"], message), {})
        stored = latest_blob("alice@example.org")
        self.assertTrue(stored.endswith(message.encode()), "the spooled part read back intact")
        self.assertTrue(stored.startswith(b"Authentication-Results: mx.test.example;\r\n\tspf=pass"))


class Scanning(unittest.TestCase):
    """Against mscan's tools/fakescan.py: EICAR-FAKE is a virus, HANG never answers, X-Test-Score sets the score."""

    def send(self, body, port=MX, sender="x@remote.test", to="alice@example.org"):
        with smtplib.SMTP(HOST, port) as c:
            if port == SUBMISSION:
                c.starttls(context=tls_context())
                c.login("alice@example.org", "alice-pw")
                sender = "alice@example.org"
            else:
                c.ehlo("remote.test")
            c.sendmail(sender, [to], "From: " + sender + "\r\nSubject: scan\r\n\r\n" + body)

    def test_virus_rejected_on_both_ports(self):
        for port in (MX, SUBMISSION):
            with self.assertRaises(smtplib.SMTPDataError) as refused:
                self.send("EICAR-FAKE\r\n", port=port, to="bob@example.org")
            self.assertEqual(refused.exception.smtp_code, 554)
            self.assertIn(b"Fake.Signature", refused.exception.smtp_error)

    def test_scanner_timeout_is_temporary(self):
        with self.assertRaises(smtplib.SMTPDataError) as refused:
            self.send("HANG\r\n")
        self.assertEqual(refused.exception.smtp_code, 451, "a scan that cannot finish is retried, not bounced")

    def test_spam_scores_route_mail(self):
        inbox, junk = message_count("alice@example.org"), message_count("alice@example.org", "Junk")
        self.send("X-Test-Score: 1.2\r\nham\r\n")
        self.assertEqual(message_count("alice@example.org"), inbox + 1)
        stored = latest_blob("alice@example.org")
        self.assertIn(b"X-Spam-Score: 1.2\r\nX-Spam-Status: No, score=1.2 required=5.0\r\n", stored)
        self.send("X-Test-Score: 7.5\r\nspammy\r\n")
        self.assertEqual(message_count("alice@example.org", "Junk"), junk + 1, "at 5 or more: Junk")
        self.assertIn(b"X-Spam-Status: Yes, score=7.5", latest_blob("alice@example.org", "Junk"))
        with self.assertRaises(smtplib.SMTPDataError) as refused:
            self.send("X-Test-Score: 12.0\r\nvery spammy\r\n")
        self.assertEqual(refused.exception.smtp_code, 550, "at 10 or more: refused")

    def test_forged_spam_headers_removed(self):
        with smtplib.SMTP(HOST, MX) as c:
            c.ehlo("remote.test")
            c.sendmail("x@remote.test", ["alice@example.org"],
                       "X-Spam-Status: No, score=-100\r\nX-Spam-Score: -100\r\nFrom: x@remote.test\r\n\r\nX-Test-Score: 0.5\r\n")
        stored = latest_blob("alice@example.org")
        self.assertNotIn(b"-100", stored)
        self.assertEqual(stored.count(b"X-Spam-Status:"), 1)


def admin(*args) -> subprocess.CompletedProcess:
    return subprocess.run([os.environ["MAILSERVER_BIN"], "--config", os.environ["MAILSERVER_CONFIG"], *args],
                          capture_output=True, text=True)


def set_sieve(script: str) -> subprocess.CompletedProcess:
    path = os.path.join(os.environ["MAILSERVER_BLOBS"], "..", "carol.sieve")
    with open(path, "w") as f:
        f.write(script)
    return admin("set-sieve", "carol@example.org", path)


def queued(recipient: str, sender: str = None) -> int:
    where = f"'{recipient}' = ANY(recipients)"
    if sender is not None:
        where += f" AND sender = '{sender}'"
    return int(sql(f"SELECT count(*) FROM queue WHERE {where}"))


def mx_records() -> list:
    """What the fake remote MX (pkgs/mqueue/tools/fakemx.py) received."""
    d = os.environ["FAKEMX_LOG"]
    if not os.path.isdir(d):
        return []
    out = []
    for name in sorted(os.listdir(d)):
        if name.endswith(".json"):
            with open(os.path.join(d, name)) as f:
                out.append(json.load(f))
    return out


def server_log() -> str:
    with open(os.environ["SERVER_LOG"]) as f:
        return f.read()


def relayed(recipient: str, sender: str = None, wait: float = 15) -> list:
    """The messages the relay delivered to `recipient` (from `sender`, when given), once nothing for it is left in
    the queue: the message data of each."""
    deadline = time.time() + wait
    while queued(recipient) > 0 and time.time() < deadline:
        time.sleep(0.2)
    return [r["data"] for r in mx_records()
            if recipient in r["rcpts"] and (sender is None or r["mail"].startswith(f"MAIL FROM:<{sender}>"))]


class Sieve(unittest.TestCase):
    """carol@example.org's Sieve script decides where her mail goes (msieve; the language itself is tested against
    Pigeonhole in pkgs/msieve/tests/differential)."""

    def tearDown(self):
        admin("clear-sieve", "carol@example.org")

    def send(self, subject="hello", sender="dave@remote.test", extra="", to="carol@example.org", body="Hi.\r\n"):
        with smtplib.SMTP(HOST, MX) as c:
            c.ehlo("remote.test")
            c.sendmail(sender, [to], f"From: {sender}\r\nTo: {to}\r\nSubject: {subject}\r\n"
                                     f"Message-ID: <{time.time()}@remote.test>\r\n{extra}\r\n{body}")

    def test_fileinto_with_flags(self):
        p = set_sieve('require ["fileinto", "imap4flags"];\n'
                      'if header :contains "subject" "invoice" { fileinto :flags ["\\\\Flagged", "$Bill"] "Archive"; }')
        self.assertEqual(p.returncode, 0, p.stderr)
        inbox, archive = message_count("carol@example.org"), message_count("carol@example.org", "Archive")
        self.send("Your Invoice 42")
        self.assertEqual(message_count("carol@example.org", "Archive"), archive + 1)
        self.assertEqual(message_count("carol@example.org"), inbox, "fileinto cancels the implicit keep")
        flags = sql("SELECT m.flags, array_to_string(m.keywords, ' ') FROM messages m JOIN mailboxes b "
                    "ON b.id = m.mailbox_id JOIN users u ON u.id = b.user_id WHERE u.email = 'carol@example.org' "
                    "AND b.name = 'Archive' ORDER BY m.uid DESC LIMIT 1")
        self.assertEqual(flags, "4|$Bill")
        self.send("something else")
        self.assertEqual(message_count("carol@example.org"), inbox + 1, "no match: the INBOX")

    def test_spam_headers_are_visible_to_scripts(self):
        set_sieve('require "fileinto"; if header :contains "x-spam-score" "3.0" { fileinto "Archive"; }')
        archive = message_count("carol@example.org", "Archive")
        self.send(body="X-Test-Score: 3.0\r\n")
        self.assertEqual(message_count("carol@example.org", "Archive"), archive + 1)

    def test_discard_and_missing_mailbox(self):
        set_sieve('require "fileinto"; if header :is "subject" "drop" { discard; } else { fileinto "Nowhere"; }')
        inbox = message_count("carol@example.org")
        self.send("drop")
        self.assertEqual(message_count("carol@example.org"), inbox, "discarded")
        self.send("keep me")
        self.assertEqual(message_count("carol@example.org"), inbox + 1, "a missing mailbox: kept in the INBOX")

    def test_redirect(self):
        set_sieve('require "copy"; redirect :copy "carol.elsewhere@remote.test";')
        inbox = message_count("carol@example.org")
        before = len(relayed("carol.elsewhere@remote.test"))
        self.send()
        self.assertEqual(len(relayed("carol.elsewhere@remote.test")), before + 1, "relayed")
        self.assertEqual(message_count("carol@example.org"), inbox + 1, ":copy keeps it too")

    def test_vacation_once_per_sender(self):
        p = admin("set-vacation", "carol@example.org", "7", "Out of office", "Back on Monday.")
        self.assertEqual(p.returncode, 0, p.stderr)
        sender = f"v{int(time.time() * 1000)}@remote.test"
        self.send(sender=sender)
        self.send(sender=sender)
        replies = relayed(sender, "")
        self.assertEqual(len(replies), 1, "one reply per 7 days, from the null sender")
        text = replies[0]
        self.assertIn("Subject: Out of office\r\n", text)
        self.assertIn("Auto-Submitted: auto-replied (vacation)\r\n", text)
        self.assertIn("In-Reply-To: <", text)
        self.assertIn("\r\n\r\nBack on Monday.\r\n", text)

    def test_no_vacation_for_lists_bulk_or_bcc(self):
        admin("set-vacation", "carol@example.org", "1", "Away", "Away.")
        for n, (extra, to) in enumerate([("Precedence: bulk\r\n", "carol@example.org"),
                                         ("List-Id: <l.remote.test>\r\n", "carol@example.org"),
                                         ("", "list@remote.test")]):
            sender = f"n{n}{int(time.time() * 1000)}@remote.test"
            with smtplib.SMTP(HOST, MX) as c:
                c.ehlo("remote.test")
                c.sendmail(sender, ["carol@example.org"],
                           f"From: {sender}\r\nTo: {to}\r\nSubject: x\r\n{extra}\r\nbody\r\n")
            self.assertEqual(len(relayed(sender)), 0, extra or "not addressed to carol")

    def test_spam_is_not_filtered(self):
        set_sieve('require "vacation"; redirect "fwd@remote.test"; vacation "away";')
        junk = message_count("carol@example.org", "Junk")
        before = len(relayed("fwd@remote.test"))
        sender = f"s{int(time.time() * 1000)}@remote.test"
        self.send(sender=sender, body="X-Test-Score: 7.0\r\n")
        self.assertEqual(message_count("carol@example.org", "Junk"), junk + 1, "spam goes to Junk")
        self.assertEqual(len(relayed("fwd@remote.test")), before, "spam is not forwarded")
        self.assertEqual(len(relayed(sender)), 0, "nor answered")

    def test_broken_script_refused(self):
        p = set_sieve('if header :frob "a" "b" { keep; }')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("line 1", p.stderr)


class Relay(unittest.TestCase):
    """The queue's relay workers (pkgs/mqueue) delivering to the fake remote MX: every MX in zone.yaml is 127.0.0.1.
    reject* recipients get 550, defer* 451 (see fakemx.py). They send as relay@example.org, whose INBOX gets their
    bounces, so other tests' mailboxes stay quiet; and they wait for the queue to drain before the next class."""

    @classmethod
    def tearDownClass(cls):
        deadline = time.time() + 30
        while int(sql("SELECT count(*) FROM queue")) > 0 and time.time() < deadline:
            time.sleep(0.3)

    def submit(self, recipients, subject):
        marker = f"{subject}-{time.time()}"
        with smtplib.SMTP(HOST, SUBMISSION) as c:
            c.starttls(context=tls_context())
            c.login("relay@example.org", "relay-pw")
            c.sendmail("relay@example.org", recipients,
                       f"From: relay@example.org\r\nSubject: {marker}\r\nMessage-ID: <{marker}@example.org>\r\n"
                       f"\r\n.a line with a dot\r\n")
        return marker

    def bounce_for(self, marker, wait=15, action="failed"):
        """The report in relay@example.org's INBOX that quotes `marker` (a bounce, or with action="delayed" a delay notice),
        parsed."""
        deadline = time.time() + wait
        while time.time() < deadline:
            rows = sql("SELECT encode(m.blob, 'hex') FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id "
                       "JOIN users u ON u.id = b.user_id WHERE u.email = 'relay@example.org' AND b.name = 'INBOX' "
                       "ORDER BY m.uid DESC LIMIT 20").split()
            for blob in rows:
                with open(os.path.join(os.environ["MAILSERVER_BLOBS"], blob[0:2], blob[2:4], blob), "rb") as f:
                    raw = f.read()
                if marker.encode() in raw and b"multipart/report" in raw and f"Action: {action}".encode() in raw:
                    return email.message_from_bytes(raw, policy=email.policy.default)
            time.sleep(0.3)
        self.fail("no bounce for " + marker)

    @staticmethod
    def statuses(bounce):
        """Each recipient's (Final-Recipient, Action, Status) from the message/delivery-status part."""
        out = {}
        for part in bounce.walk():
            if part.get_content_type() == "message/delivery-status":
                for group in part.get_payload()[1:]:
                    out[group["Final-Recipient"].split(";")[1].strip()] = (group["Action"], group["Status"])
        return out

    def test_delivers_and_bounces_per_recipient(self):
        marker = self.submit(["ok@remote.test", "reject@remote.test", "ok@twomx.test", "ok@implicit.test"], "relay")
        got = [r for r in mx_records() if marker in r["data"]]
        deadline = time.time() + 15
        while len([r for r in got]) < 3 and time.time() < deadline:
            time.sleep(0.2)
            got = [r for r in mx_records() if marker in r["data"]]
        rcpts = sorted(a for r in got for a in r["rcpts"])
        self.assertEqual(rcpts, ["ok@implicit.test", "ok@remote.test", "ok@twomx.test"],
                         "the implicit MX, and the second MX after a dead first")
        record = got[0]
        self.assertTrue(record["tls"], "opportunistic STARTTLS")
        self.assertEqual(record["helo"], "mx.test.example")
        self.assertIn("\r\n..a line with a dot\r\n", record["data"], "dot-stuffed on the wire")
        bounce = self.bounce_for(marker)
        self.assertEqual(bounce["From"], "Mail Delivery System <MAILER-DAEMON@mx.test.example>")
        self.assertEqual(bounce["Auto-Submitted"], "auto-replied")
        self.assertEqual(bounce.get_content_type(), "multipart/report")
        self.assertEqual(self.statuses(bounce), {"reject@remote.test": ("failed", "5.1.1")})
        headers = [p for p in bounce.walk() if p.get_content_type() == "text/rfc822-headers"]
        self.assertIn(marker, headers[0].get_content())
        self.assertEqual(queued("ok@remote.test"), 0, "the queue row is gone")

    def test_domains_without_mail(self):
        marker = self.submit(["a@nodomain.test", "b@nullmx.test"], "nomail")
        self.assertEqual(self.statuses(self.bounce_for(marker)),
                         {"a@nodomain.test": ("failed", "5.1.2"), "b@nullmx.test": ("failed", "5.1.10")})

    def test_retries_then_expires(self):
        marker = self.submit(["defer@remote.test"], "expire")
        time.sleep(2.5)
        attempts = sql("SELECT attempts FROM queue WHERE 'defer@remote.test' = ANY(recipients) "
                       "AND last_error LIKE '451 4.2.1%'")
        self.assertTrue(attempts and int(attempts.split()[0]) >= 1, "retried with the server's reply kept")
        bounce = self.bounce_for(marker, wait=20)
        self.assertEqual(self.statuses(bounce), {"defer@remote.test": ("failed", "4.4.7")}, "expired after max_age")

    def test_dkim_signs_once_activated(self):
        try:
            import dkim
        except ImportError:
            self.skipTest("needs dkimpy on PYTHONPATH")
        previous = None
        for kind, selector in (("rsa", f"r{int(time.time())}"), ("ed25519", f"e{int(time.time())}")):
            made = admin("dkim-generate", "Example.org", selector, kind)
            self.assertEqual(made.returncode, 0, made.stderr)
            self.assertIn(f"{selector}._domainkey.example.org. IN TXT (", made.stdout)
            marker = self.submit([f"ok-{selector}@remote.test"], "unsigned")
            data = relayed(f"ok-{selector}@remote.test")
            if previous is None:
                self.assertTrue(data and "DKIM-Signature" not in data[0], "no active key: unsigned")
            else:
                self.assertIn(f"s={previous};", data[0], "a new key does not sign until activated")
            previous = selector
            self.assertEqual(admin("dkim-activate", "example.org", selector).returncode, 0)
            shown = admin("dkim-show", "example.org").stdout
            record = "".join(re.findall(r'"([^"]*)"', shown))
            self.assertTrue(record.startswith(f"v=DKIM1; k={kind}; p="), shown)
            self.submit([f"signed-{selector}@remote.test"], "signed")
            data = relayed(f"signed-{selector}@remote.test")
            self.assertEqual(len(data), 1)
            # fakemx logs DATA as received, dot-stuffed: undo that, as a receiving server does.
            message = data[0].encode("latin-1").replace(b"\r\n..", b"\r\n.")
            self.assertTrue(message.startswith(b"DKIM-Signature: v=1; a=" + (b"rsa" if kind == "rsa" else b"ed25519")))
            lookup = {f"{selector}._domainkey.example.org": record}
            verified = dkim.verify(message, dnsfunc=lambda name, timeout=5: lookup.get(name.decode().rstrip("."), "").encode())
            self.assertTrue(verified, f"dkimpy verifies the {kind} signature")
        # Unknown keys are refused.
        self.assertNotEqual(admin("dkim-activate", "example.org", "nosuch").returncode, 0)

    def test_delay_notice_once_then_bounce(self):
        marker = self.submit(["defer-d@remote.test"], "delay")
        notice = self.bounce_for(marker, action="delayed")
        self.assertEqual(notice["Subject"], "Delayed Mail (still being retried)")
        self.assertEqual(self.statuses(notice), {"defer-d@remote.test": ("delayed", "4.2.1")})
        self.assertIn("Will-Retry-Until:", notice.as_string())
        self.bounce_for(marker, wait=20)  # then it expires
        time.sleep(1)
        notices = [r for r in self.all_reports(marker) if b"Action: delayed" in r]
        self.assertEqual(len(notices), 1, "one delay notice per message")

    def all_reports(self, marker):
        rows = sql("SELECT encode(m.blob, 'hex') FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id "
                   "JOIN users u ON u.id = b.user_id WHERE u.email = 'relay@example.org' AND b.name = 'INBOX'").split()
        out = []
        for blob in rows:
            with open(os.path.join(os.environ["MAILSERVER_BLOBS"], blob[0:2], blob[2:4], blob), "rb") as f:
                raw = f.read()
            if marker.encode() in raw and b"multipart/report" in raw:
                out.append(raw)
        return out

    def test_suppression(self):
        tag = int(time.time() * 1000)
        gone, refused = f"reject-s{tag}@remote.test", f"datafail-s{tag}@remote.test"
        marker = self.submit([gone, refused], "suppress")
        self.assertEqual(set(self.statuses(self.bounce_for(marker))), {gone, refused})
        with smtplib.SMTP(HOST, SUBMISSION) as c:
            c.starttls(context=tls_context())
            c.login("relay@example.org", "relay-pw")
            with self.assertRaises(smtplib.SMTPRecipientsRefused) as caught:
                c.sendmail("relay@example.org", [gone], "Subject: again\r\n\r\nx\r\n")
            code, text = caught.exception.recipients[gone]
            self.assertEqual(code, 550)
            self.assertIn(b"bounced recently", text)
            self.assertIn(b"no such user", text, "with the reason it bounced")
            # A content rejection (5.6.0) says nothing about the address: not suppressed.
            self.assertEqual(c.sendmail("relay@example.org", [refused], "Subject: again\r\n\r\nx\r\n"), {})
        self.assertEqual(admin("unsuppress", gone).returncode, 0)
        with smtplib.SMTP(HOST, SUBMISSION) as c:
            c.starttls(context=tls_context())
            c.login("relay@example.org", "relay-pw")
            self.assertEqual(c.sendmail("relay@example.org", [gone], "Subject: again\r\n\r\nx\r\n"), {})

    def test_breaker_skips_dead_domains(self):
        self.submit(["a@deadonly.test"], "breaker1")
        deadline = time.time() + 15
        while time.time() < deadline and "waiting before trying again: deadonly.test" not in server_log():
            time.sleep(0.2)
        self.assertIn("waiting before trying again: deadonly.test", server_log(), "two failures in a row open it")
        marker = self.submit(["b@deadonly.test"], "breaker2")
        bounce = self.bounce_for(marker, wait=20)
        diagnostic = [p for p in bounce.walk() if p.get_content_type() == "text/plain"][0].get_content()
        self.assertIn("not tried this time", diagnostic, "while the breaker is open, no connection is tried")

    def test_srs_for_forwarded_mail(self):
        set_sieve('redirect "fwd-srs@remote.test";')
        try:
            sender = f"srs{int(time.time() * 1000)}@remote.test"
            with smtplib.SMTP(HOST, MX) as c:
                c.ehlo("remote.test")
                c.sendmail(sender, ["carol@example.org"], f"From: {sender}\r\nSubject: forward me\r\n\r\nx\r\n")
            records = [r for r in mx_records() if "fwd-srs@remote.test" in r["rcpts"] and sender.split("@")[0] in r["mail"]]
            deadline = time.time() + 15
            while not records and time.time() < deadline:
                time.sleep(0.2)
                records = [r for r in mx_records() if "fwd-srs@remote.test" in r["rcpts"] and sender.split("@")[0] in r["mail"]]
            self.assertTrue(records, "forwarded")
            srs = re.search(r"MAIL FROM:<([^>]*)>", records[0]["mail"]).group(1)
            self.assertTrue(srs.startswith("SRS0=") and srs.endswith(f"=remote.test={sender.split('@')[0]}@mx.test.example"), srs)
            # A bounce to the SRS address goes on to the original sender.
            with smtplib.SMTP(HOST, MX) as c:
                c.ehlo("remote.test")
                self.assertEqual(c.sendmail("", [srs], "Subject: bounce\r\n\r\nyour mail bounced\r\n"), {})
            self.assertEqual(len(relayed(sender, "")), 1, "to the original sender, from the null sender")
            # A forged one is refused.
            forged = srs.replace("SRS0=", "SRS0=X", 1)
            with smtplib.SMTP(HOST, MX) as c:
                c.ehlo("remote.test")
                c.mail("")
                code, _ = c.rcpt(f"<{forged}>")
                self.assertEqual(code, 550)
        finally:
            admin("clear-sieve", "carol@example.org")

    def test_sessions_are_reused(self):
        markers = [self.submit([f"reuse{i}@remote.test"], f"reuse{i}") for i in range(3)]
        for i in range(3):
            self.assertEqual(len(relayed(f"reuse{i}@remote.test")), 1)
        records = [r for r in mx_records() if any(m in r["data"] for m in markers)]
        self.assertTrue(any(r["commands"][0] == "RSET" for r in records),
                        "a later message rode an open session: RSET, no EHLO, no STARTTLS")
        # The fake MX closes sessions idle for 3 seconds: the next message finds its pooled session dead, and is
        # delivered on a new one all the same.
        time.sleep(4)
        late = self.submit(["reuse-late@remote.test"], "late")
        self.assertEqual(len(relayed("reuse-late@remote.test")), 1, "a stale pooled session costs nothing")
        record = [r for r in mx_records() if late in r["data"]][0]
        self.assertTrue(record["commands"][0].startswith("EHLO"), record["commands"][:3])

    def test_bounces_are_not_bounced(self):
        # A bounce (from the null sender) that fails is dropped: there is no one to bounce it to.
        inbox = message_count("relay@example.org")
        rows_before = int(sql("SELECT count(*) FROM queue"))
        sql("INSERT INTO queue (blob, size, sender, recipients) SELECT m.blob, m.size, '', ARRAY['reject-null@remote.test'] "
            "FROM messages m LIMIT 1")
        deadline = time.time() + 15
        while queued("reject-null@remote.test") > 0 and time.time() < deadline:
            time.sleep(0.2)
        self.assertEqual(queued("reject-null@remote.test"), 0, "tried and dropped")
        time.sleep(1)
        self.assertEqual(int(sql("SELECT count(*) FROM queue")), rows_before, "no new bounce queued")
        self.assertEqual(message_count("relay@example.org"), inbox)


def postfix_mail(local: str, wait: float = 20) -> list:
    """The messages the real Postfix (tests/interop/postfix) stored for local@remote.test."""
    deadline = time.time() + wait
    while time.time() < deadline:
        out = subprocess.run(["docker", "exec", "mailserver-postfix", "sh", "-c",
                              "for f in /var/mail/vhosts/remote.test/new/*; do cat \"$f\"; printf '\\0'; done"],
                             capture_output=True).stdout
        found = [m for m in out.split(b"\0") if f"Delivered-To: {local}@remote.test".encode() in m]
        if found:
            return found
        time.sleep(0.3)
    return []


@unittest.skipIf(os.environ.get("REAL_MX"), "the fake MX's domains only")
class StrictTls(unittest.TestCase):
    """`[relay] tls_policy = "published"`: DANE (RFC 7672) and MTA-STS (RFC 8461) against the fake MX, whose
    certificate is localhost.pem. The domains are in zone.yaml (SECURE names get AD from fakedns) and the policies in
    sts.yaml (served by fakests.py). A host that cannot give the TLS its domain asks is never used in the clear."""

    submit = Relay.submit

    @classmethod
    def tearDownClass(cls):
        Relay.tearDownClass()

    def last_error(self, recipient, wait=6):
        """The queue row's last error for `recipient`, once it has one."""
        deadline = time.time() + wait
        while time.time() < deadline:
            row = sql(f"SELECT last_error FROM queue WHERE '{recipient}' = ANY(recipients) AND last_error <> ''")
            if row:
                return row
            time.sleep(0.2)
        return ""

    def delivered_over_tls(self, recipient):
        records = [r for r in mx_records() if recipient in r["rcpts"]]
        return len(records) > 0 and all(r["tls"] for r in records)

    def test_dane_authenticates_the_server(self):
        self.submit(["user@dane.test"], "dane")
        self.assertTrue(relayed("user@dane.test"), "delivered")
        self.assertTrue(self.delivered_over_tls("user@dane.test"), "over TLS the TLSA record authenticated")

    def test_dane_mismatch_is_never_sent_in_the_clear(self):
        self.submit(["user@danebad.test"], "danebad")
        error = self.last_error("user@danebad.test")
        self.assertTrue(error.startswith("451 4.7.5") and "DANE" in error, error)
        self.assertEqual([r for r in mx_records() if "user@danebad.test" in r["rcpts"]], [], "nothing delivered")

    def test_dane_needs_validated_dns(self):
        # The same wrong TLSA record, but the MX answer is not validated: DANE does not apply.
        self.submit(["user@daneinsecure.test"], "daneinsecure")
        self.assertTrue(relayed("user@daneinsecure.test"), "delivered as without DANE")

    def test_mta_sts_enforce(self):
        self.submit(["one@sts.test"], "sts1")
        self.assertTrue(relayed("one@sts.test"), "delivered to the listed MX")
        self.assertTrue(self.delivered_over_tls("one@sts.test"), "over certificate-checked TLS")
        self.submit(["two@sts.test"], "sts2")
        self.assertTrue(relayed("two@sts.test"), "delivered again")
        with open(os.environ["FAKESTS_LOG"]) as f:
            fetches = [line for line in f if line.startswith("fetch mta-sts.sts.test ")]
        self.assertEqual(len(fetches), 1, "the policy is fetched once, then cached")
        self.assertEqual(sql("SELECT policy_id FROM mta_sts_policies WHERE domain = 'sts.test'"), "20261105",
                         "and kept in the database")

    def test_mta_sts_unlisted_mx_is_skipped(self):
        self.submit(["user@stsbad.test"], "stsbad")
        error = self.last_error("user@stsbad.test")
        self.assertTrue(error.startswith("451 4.7.0") and "MTA-STS" in error, error)
        self.assertEqual([r for r in mx_records() if "user@stsbad.test" in r["rcpts"]], [], "nothing delivered")

    def test_mta_sts_needs_a_valid_certificate(self):
        # The MX is listed, but its certificate is for localhost, not mx.stscert.test.
        self.submit(["user@stscert.test"], "stscert")
        error = self.last_error("user@stscert.test")
        self.assertTrue(error.startswith("451 4.7.5") and "MTA-STS" in error, error)
        self.assertEqual([r for r in mx_records() if "user@stscert.test" in r["rcpts"]], [], "nothing delivered")

    def test_mta_sts_testing_mode_does_not_block(self):
        self.submit(["user@ststesting.test"], "ststesting")
        self.assertTrue(relayed("user@ststesting.test"), "delivered: testing mode only reports")


@unittest.skipUnless(os.environ.get("REAL_MX"), "needs the Postfix container (tests/interop/run.sh)")
class RealMx(Relay):
    """The relay against a real Postfix (REAL_MX=1, RELAY_PORT=52525): what it stores is what we sent."""

    test_delivers_and_bounces_per_recipient = None
    test_domains_without_mail = None
    test_retries_then_expires = None
    test_bounces_are_not_bounced = None
    test_dkim_signs_once_activated = None
    test_delay_notice_once_then_bounce = None
    test_suppression = None
    test_breaker_skips_dead_domains = None
    test_srs_for_forwarded_mail = None
    test_sessions_are_reused = None

    def test_postfix_receives_what_was_sent(self):
        tag = f"pf{int(time.time() * 1000)}"
        body = ("From: relay@example.org\r\nSubject: interop " + tag + "\r\nContent-Type: text/plain; charset=utf-8\r\n"
                "Content-Transfer-Encoding: 8bit\r\n\r\n.one dot\r\n..two dots\r\n.\r\nGrüße\r\n" + "x" * 990 + "\r\nend\r\n")
        with smtplib.SMTP(HOST, SUBMISSION) as c:
            c.starttls(context=tls_context())
            c.login("relay@example.org", "relay-pw")
            c.sendmail("relay@example.org", [f"{tag}@remote.test", f"reject-{tag}@remote.test"], body.encode())
        got = postfix_mail(tag)
        self.assertEqual(len(got), 1, "stored by Postfix")
        stored = got[0]
        self.assertIn(b"\n.one dot\n..two dots\n.\nGr\xc3\xbc\xc3\x9fe\n", stored.replace(b"\r\n", b"\n"),
                      "dots un-stuffed by Postfix exactly as sent, 8-bit intact")
        self.assertIn(b"with ESMTPS", stored, "over STARTTLS")
        self.assertIn(b"x" * 990, stored)
        bounce = self.bounce_for(tag)
        self.assertEqual(self.statuses(bounce), {f"reject-{tag}@remote.test": ("failed", "5.1.1")})
        report = [p for p in bounce.walk() if p.get_content_type() == "message/delivery-status"][0]
        self.assertIn("no such user here", str(report), "Postfix's own words")

    def test_postfix_size_limit(self):
        tag = f"big{int(time.time() * 1000)}"
        body = "From: relay@example.org\r\nSubject: big " + tag + "\r\n\r\n" + ("y" * 76 + "\r\n") * 30000
        with smtplib.SMTP(HOST, SUBMISSION) as c:
            c.starttls(context=tls_context())
            c.login("relay@example.org", "relay-pw")
            c.sendmail("relay@example.org", [f"{tag}@remote.test"], body)
        bounce = self.bounce_for(tag)
        self.assertEqual(self.statuses(bounce), {f"{tag}@remote.test": ("failed", "5.3.4")}, "SIZE 2000000 refused")

    def test_postfix_smtputf8(self):
        tag = f"u{int(time.time() * 1000)}"
        with smtplib.SMTP(HOST, SUBMISSION) as c:
            c.starttls(context=tls_context())
            c.login("relay@example.org", "relay-pw")
            c.sendmail("relay@example.org", [f"jörg{tag}@remote.test"],
                       f"From: relay@example.org\r\nSubject: utf8 {tag}\r\n\r\nhi\r\n".encode(),
                       mail_options=["SMTPUTF8"])
        self.assertEqual(len(postfix_mail(f"jörg{tag}")), 1, "an internationalized address delivered")


class AuthGuard(unittest.TestCase):
    """The persisted half of the brute-force guard: a block in the database refuses even a right password, though
    this process's memory has seen no failure from the address."""

    def login(self):
        with smtplib.SMTP(HOST, SUBMISSION) as c:
            c.starttls(context=tls_context())
            c.login("alice@example.org", "alice-pw")

    def test_block_and_unblock(self):
        p = admin("block-ip", "127.0.0.1", "1")
        self.assertEqual(p.returncode, 0, p.stderr)
        try:
            with self.assertRaises(smtplib.SMTPAuthenticationError) as refused:
                self.login()
            self.assertEqual(refused.exception.smtp_code, 454)
        finally:
            admin("unblock-ip", "127.0.0.1")
        self.login()

    def test_ipv6_blocks_by_prefix(self):
        self.assertEqual(admin("block-ip", "2001:db8:1:2:aaaa::1").returncode, 0)
        self.assertEqual(sql("SELECT key FROM auth_failures WHERE key LIKE '2001%'"), "2001:db8:1:2::/64")
        admin("unblock-ip", "2001:db8:1:2::ffff")
        self.assertEqual(sql("SELECT count(*) FROM auth_failures WHERE key LIKE '2001%'"), "0")

    def test_failures_are_recorded(self):
        with smtplib.SMTP(HOST, SUBMISSION) as c:
            c.starttls(context=tls_context())
            with self.assertRaises(smtplib.SMTPAuthenticationError):
                c.login("Nobody@example.org", "wrong")
        self.assertGreaterEqual(int(sql("SELECT failures FROM auth_failures WHERE kind = 2 "
                                        "AND key = 'nobody@example.org'")), 1)
        self.login()  # a good login clears the address's count
        self.assertEqual(sql("SELECT count(*) FROM auth_failures WHERE kind = 1 AND key = '127.0.0.1'"), "0")


@unittest.skipUnless(os.environ.get("REAL_SCANNERS"), "needs the Docker ClamAV and SpamAssassin")
class RealScanners(unittest.TestCase):
    def test_eicar_and_gtube(self):
        eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-" + "STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        gtube = "XJS*C4JDBQADN1.NSBN3*2IDNEN*GTUBE-" + "STANDARD-ANTI-UBE-TEST-EMAIL*C.34X"
        with smtplib.SMTP(HOST, MX, timeout=120) as c:
            c.ehlo("remote.test")
            with self.assertRaises(smtplib.SMTPDataError) as virus:
                c.sendmail("x@remote.test", ["alice@example.org"], "From: x@remote.test\r\n\r\n" + eicar + "\r\n")
            self.assertEqual(virus.exception.smtp_code, 554)
            self.assertIn(b"Eicar", virus.exception.smtp_error)
            with self.assertRaises(smtplib.SMTPDataError) as spam:
                c.sendmail("x@remote.test", ["alice@example.org"], "From: x@remote.test\r\nSubject: hi\r\n\r\n" + gtube + "\r\n")
            self.assertEqual(spam.exception.smtp_code, 550)
            before = message_count("alice@example.org")
            self.assertEqual(c.sendmail("x@remote.test", ["alice@example.org"],
                                        "From: x@remote.test\r\nSubject: lunch\r\n\r\nThursday at noon?\r\n"), {})
        self.assertEqual(message_count("alice@example.org"), before + 1)
        self.assertIn(b"X-Spam-Status: No, score=", latest_blob("alice@example.org"))


class Submission(unittest.TestCase):
    def test_requires_authentication(self):
        with smtplib.SMTP(HOST, SUBMISSION) as c:
            code, caps = c.ehlo("laptop")
            self.assertNotIn(b"AUTH", caps, "AUTH is offered only after STARTTLS")
            code, text = c.docmd("AUTH", "PLAIN AGFsaWNlQGV4YW1wbGUub3JnAGFsaWNlLXB3")
            self.assertEqual(code, 538)
            code, _ = c.mail("alice@example.org")
            self.assertEqual(code, 530)

    def test_sends_with_auth_plain(self):
        sent_before = message_count("alice@example.org", "Sent")
        relayed_before = len(relayed("carol@remote.test"))
        bob_before = message_count("bob@example.org")
        with smtplib.SMTP(HOST, SUBMISSION) as c:
            c.starttls(context=tls_context())
            c.login("alice@example.org", "alice-pw")
            refused = c.sendmail("alice@example.org", ["bob@example.org", "carol@remote.test"],
                                 "From: alice@example.org\r\nSubject: out\r\n\r\nhello\r\n")
            self.assertEqual(refused, {})
        self.assertEqual(message_count("bob@example.org"), bob_before + 1, "local recipient delivered")
        self.assertEqual(message_count("alice@example.org", "Sent"), sent_before + 1, "a copy in Sent")
        self.assertEqual(len(relayed("carol@remote.test", "alice@example.org")), relayed_before + 1,
                         "the remote recipient relayed, alone (bob was delivered here)")
        self.assertEqual(sql("SELECT flags FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id "
                             "WHERE b.name = 'Sent' ORDER BY uid DESC LIMIT 1"), "1", "the Sent copy is \\Seen")

    def test_auth_login_and_sender_check(self):
        with smtplib.SMTP_SSL(HOST, SMTPS, context=tls_context()) as c:
            c.ehlo("laptop")
            c.user, c.password = "alice@example.org", "alice-pw"
            code, _ = c.auth("LOGIN", c.auth_login, initial_response_ok=False)
            self.assertEqual(code, 235)
            code, text = c.mail("ceo@other-company.test")
            self.assertEqual(code, 550, "a sender outside the user's domain")
            self.assertEqual(c.mail("alice@example.org")[0], 250)

    def test_wrong_password(self):
        plain = lambda user, password: base64.b64encode(f"\0{user}\0{password}".encode()).decode()
        with smtplib.SMTP(HOST, SUBMISSION) as c:
            c.starttls(context=tls_context())
            c.ehlo("laptop")
            timings = []
            for user in ("alice@example.org", "ghost@example.org"):
                started = time.time()
                code, text = c.docmd("AUTH", "PLAIN " + plain(user, "wrong"))
                timings.append(time.time() - started)
                self.assertEqual(code, 535, text)
            # An unknown user costs the same bcrypt check as a known one: timing does not tell them apart.
            self.assertGreater(min(timings), 0.15)
            self.assertLess(abs(timings[0] - timings[1]), 0.5 * max(timings))
            code, text = c.docmd("AUTH", "PLAIN " + plain("alice@example.org", "wrong"))
            self.assertEqual(code, 535)
            code, _ = c.getreply()
            self.assertEqual(code, 421, "closed after the third failure")


if __name__ == "__main__":
    unittest.main(verbosity=2)
