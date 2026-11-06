#!/usr/bin/env python3
"""Black-box IMAP tests against a running mailserver (see run.sh): IMAP with STARTTLS on 2143, IMAPS on 2993, with
`allow_plaintext_auth = false` and `max_append_size` from MAX_APPEND_SIZE (16000000). Users imap@example.org
(imap-pw) and imap2@example.org (imap2-pw) are the IMAP tests' own; bob@example.org (bob-pw) has a 2000-byte quota. Messages are
delivered through SMTP (port 2525), so they have the meta SMTP stores. Python's imaplib where it is enough, and a
raw client (`Raw`) for exact wire checks."""
import base64, email, functools, email.policy, imaplib, os, re, smtplib, socket, sys, threading, time, unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from smtp_test import HOST, MX, SUBMISSION, admin, sql, tls_context  # noqa: E402

IMAP, IMAPS = 2143, 2993
USER, PASSWORD = "imap@example.org", "imap-pw"
USER2, PASSWORD2 = "imap2@example.org", "imap2-pw"
# run.sh's IMAP_PLAINTEXT_AUTH=true: LOGIN is allowed before TLS (the LOGINDISABLED tests are skipped, IDLE is also
# tested over plaintext).
PLAINTEXT_AUTH = os.environ.get("IMAP_PLAINTEXT_AUTH") == "true"
# How soon IDLE must report another session's change: well under slice 1's 2-second poll, with room for a loaded
# machine. The notify bus wakes IDLE at once; the measured latencies are printed.
IDLE_LATENCY = float(os.environ.get("IDLE_LATENCY", "0.5"))
MAX_APPEND = int(os.environ.get("MAX_APPEND_SIZE", "16000000"))
_counter = [0]


def unique(prefix: str) -> str:
    _counter[0] += 1
    return f"{prefix}{int(time.time() * 1000) % 10_000_000}x{_counter[0]}"


def deliver(to: str, message: bytes):
    with smtplib.SMTP(HOST, MX) as c:
        c.ehlo("remote.test")
        refused = c.sendmail("sender@remote.test", [to], message)
        assert refused == {}, refused


def simple(subject: str, body: str = "Hello there.\r\n") -> bytes:
    return (f"From: Sender <sender@remote.test>\r\nTo: imap@example.org\r\nSubject: {subject}\r\n"
            f"Message-ID: <{subject}@remote.test>\r\nDate: Thu, 05 Nov 2026 10:00:00 +0000\r\n\r\n{body}").encode()


# A multipart message built from known pieces, so every section's bytes are known independently of the server.
P1_HDR = b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
P1_BODY = b"First part, plain text.\r\nSecond line.\r\n"
P2_HDR = b"Content-Type: text/html\r\nContent-Transfer-Encoding: 7bit\r\n\r\n"
P2_BODY = b"<p>Second part</p>\r\n"
INNER_HDR = b"From: Inner <inner@remote.test>\r\nSubject: inner message\r\nContent-Type: text/plain\r\n\r\n"
INNER_BODY = b"Inner body.\r\nIts second line.\r\n"
P3_HDR = b"Content-Type: message/rfc822\r\n\r\n"


def multipart(subject: str) -> bytes:
    header = (f"From: Sender <sender@remote.test>\r\nTo: imap@example.org\r\nSubject: {subject}\r\n"
              f"X-Folded: one\r\n two\r\nMIME-Version: 1.0\r\n"
              f"Content-Type: multipart/mixed; boundary=\"XYZ\"\r\n\r\n").encode()
    return (header + b"Preamble.\r\n--XYZ\r\n" + P1_HDR + P1_BODY + b"\r\n--XYZ\r\n" + P2_HDR + P2_BODY +
            b"\r\n--XYZ\r\n" + P3_HDR + INNER_HDR + INNER_BODY + b"\r\n--XYZ--\r\n")


def header_fields(header: bytes, names, keep: bool) -> bytes:
    """HEADER.FIELDS (keep) or HEADER.FIELDS.NOT of a header block, computed here: whole fields, folding kept, then
    the blank line."""
    lines = header.split(b"\r\n")[:-2]  # without the blank line
    fields = []
    for line in lines:
        if line[:1] in (b" ", b"\t") and fields:
            fields[-1] += b"\r\n" + line
        else:
            fields.append(line)
    wanted = {n.lower() for n in names}
    out = b"".join(f + b"\r\n" for f in fields if (f.split(b":")[0].strip().lower() in wanted) == keep)
    return out + b"\r\n"


def db_uids(user: str, mailbox: str) -> list:
    out = sql(f"SELECT m.uid FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id JOIN users u ON u.id = b.user_id "
              f"WHERE u.email = '{user}' AND b.name = '{mailbox}' ORDER BY m.uid")
    return [int(x) for x in out.split()] if out else []


def db_mailbox(user: str, mailbox: str, column: str) -> int:
    return int(sql(f"SELECT b.{column} FROM mailboxes b JOIN users u ON u.id = b.user_id "
                   f"WHERE u.email = '{user}' AND b.name = '{mailbox}'"))


def compress(uids) -> bytes:
    out, i = [], 0
    while i < len(uids):
        j = i
        while j + 1 < len(uids) and uids[j + 1] == uids[j] + 1:
            j += 1
        out.append(str(uids[i]) if i == j else f"{uids[i]}:{uids[j]}")
        i = j + 1
    return ",".join(out).encode()


# ---- A raw client ----

class Raw:
    def __init__(self, tls: bool = True, port: int = None, timeout: float = 10):
        sock = socket.create_connection((HOST, port or (IMAPS if tls else IMAP)), timeout=timeout)
        if tls:
            sock = tls_context().wrap_socket(sock, server_hostname="localhost")
        self.sock, self.buf = sock, b""
        self.greeting = self.line()

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def fill(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise EOFError("connection closed")
        self.buf += chunk

    def line(self) -> bytes:
        while b"\r\n" not in self.buf:
            self.fill()
        i = self.buf.index(b"\r\n") + 2
        line, self.buf = self.buf[:i], self.buf[i:]
        return line

    def response(self) -> bytes:
        """One response, its literals inline."""
        out = self.line()
        while (m := re.search(rb"\{(\d+)\}\r\n$", out)):
            n = int(m.group(1))
            while len(self.buf) < n:
                self.fill()
            out += self.buf[:n]
            self.buf = self.buf[n:]
            out += self.line()
        return out

    def send(self, data: bytes):
        self.sock.sendall(data)

    def until(self, tag: bytes) -> list:
        responses = []
        while True:
            r = self.response()
            responses.append(r)
            if r.startswith(tag + b" "):
                return responses

    def cmd(self, tag: bytes, text: bytes) -> list:
        self.send(tag + b" " + text + b"\r\n")
        return self.until(tag)

    def ok(self, tag: bytes, text: bytes) -> list:
        responses = self.cmd(tag, text)
        assert responses[-1].startswith(tag + b" OK"), responses
        return responses

    def login(self, user: str = USER, password: str = PASSWORD):
        return self.ok(b"L", b"LOGIN " + user.encode() + b" " + password.encode())


def parse_value(data: bytes, i: int):
    while data[i:i + 1] == b" ":
        i += 1
    c = data[i:i + 1]
    if c == b"(":
        items, i = [], i + 1
        while True:
            while data[i:i + 1] == b" ":
                i += 1
            if data[i:i + 1] == b")":
                return items, i + 1
            v, i = parse_value(data, i)
            items.append(v)
    if c == b'"':
        out, i = b"", i + 1
        while data[i:i + 1] != b'"':
            if data[i:i + 1] == b"\\":
                i += 1
            out += data[i:i + 1]
            i += 1
        return out, i + 1
    if c == b"{":
        end = data.index(b"}", i)
        n = int(data[i + 1:end].rstrip(b"+"))
        start = end + 3
        return data[start:start + n], start + n
    start, depth = i, 0
    while i < len(data):
        ch = data[i:i + 1]
        if ch == b"[":
            depth += 1
        elif ch == b"]":
            depth -= 1
        elif depth == 0 and ch in (b" ", b")", b"(", b"\r"):
            break
        i += 1
    return data[start:i], i


def parse_fetch(response: bytes):
    """`* n FETCH (...)`: the sequence number, and the items as a dict (name → value), in order."""
    m = re.match(rb"\* (\d+) FETCH ", response)
    assert m, response
    items, _ = parse_value(response, m.end())
    return int(m.group(1)), {items[k].decode(): items[k + 1] for k in range(0, len(items), 2)}


def fetches(responses) -> list:
    return [parse_fetch(r) for r in responses if re.match(rb"\* \d+ FETCH ", r)]


def imaps() -> imaplib.IMAP4_SSL:
    c = imaplib.IMAP4_SSL(HOST, IMAPS, ssl_context=tls_context())
    c.login(USER, PASSWORD)
    return c


def folder_with(messages, user: str = USER, password: str = PASSWORD, prefix: str = "T") -> str:
    """A new mailbox holding `messages`, delivered through SMTP (to INBOX, then moved there), in order."""
    name = unique(prefix)
    for m in messages:
        deliver(user, m)
    with Raw() as c:
        c.login(user, password)
        c.ok(b"c", b"CREATE " + name.encode())
        c.ok(b"s", b"SELECT INBOX")
        c.ok(b"m", b"MOVE 1:* " + name.encode())
    assert len(db_uids(user, name)) == len(messages)
    return name


# ---- Tests ----

class Connection(unittest.TestCase):
    @unittest.skipIf(PLAINTEXT_AUTH, "allow_plaintext_auth is on")
    def test_plaintext_port_refuses_login(self):
        with Raw(tls=False) as c:
            self.assertTrue(c.greeting.startswith(b"* OK [CAPABILITY IMAP4rev1 "), c.greeting)
            for cap in (b" STARTTLS", b" LOGINDISABLED", b" LITERAL+", b" IDLE", b" UIDPLUS", b" MOVE", b" ID",
                        b" ENABLE", b" NAMESPACE", b" UNSELECT", b" CHILDREN", b" SPECIAL-USE", b" SASL-IR"):
                self.assertIn(cap, c.greeting)
            self.assertNotIn(b"AUTH=PLAIN", c.greeting)
            caps = c.cmd(b"a", b"CAPABILITY")
            self.assertTrue(caps[0].startswith(b"* CAPABILITY IMAP4rev1 ") and b"LOGINDISABLED" in caps[0])
            self.assertEqual(c.cmd(b"b", b"LOGIN imap@example.org imap-pw")[-1][:22], b"b NO [PRIVACYREQUIRED]")
            plain = base64.b64encode(b"\0imap@example.org\0imap-pw")
            self.assertEqual(c.cmd(b"c", b"AUTHENTICATE PLAIN " + plain)[-1][:22], b"c NO [PRIVACYREQUIRED]")
            self.assertTrue(c.cmd(b"d", b"SELECT INBOX")[-1].startswith(b"d BAD"), "not authenticated")

    @unittest.skipIf(PLAINTEXT_AUTH, "allow_plaintext_auth is on")
    def test_starttls(self):
        c = imaplib.IMAP4(HOST, IMAP)
        self.assertIn("LOGINDISABLED", c.capabilities)
        c.starttls(ssl_context=tls_context())
        self.assertNotIn("STARTTLS", c.capabilities)
        self.assertNotIn("LOGINDISABLED", c.capabilities)
        self.assertIn("AUTH=PLAIN", c.capabilities)
        self.assertEqual(c.login(USER, PASSWORD)[0], "OK")
        self.assertEqual(c.select("INBOX")[0], "OK")
        c.logout()

    def test_starttls_discards_pipelined_plaintext(self):
        sock = socket.create_connection((HOST, IMAP), timeout=10)
        sock.recv(4096)
        sock.sendall(b"a STARTTLS\r\nb CAPABILITY\r\n")
        data = b""
        while b"a OK" not in data:
            data += sock.recv(4096)
        self.assertNotIn(b"b ", data)
        tls = tls_context().wrap_socket(sock, server_hostname="localhost")
        tls.sendall(b"c NOOP\r\n")
        reply = tls.recv(4096)
        self.assertEqual(reply, b"c OK NOOP completed\r\n", "the injected command never ran")
        tls.close()

    def test_implicit_tls_and_authenticate(self):
        c = imaplib.IMAP4_SSL(HOST, IMAPS, ssl_context=tls_context())
        self.assertIn("AUTH=PLAIN", c.capabilities)
        self.assertNotIn("STARTTLS", c.capabilities)
        typ, _ = c.authenticate("PLAIN", lambda _: b"\0" + USER.encode() + b"\0" + PASSWORD.encode())
        self.assertEqual(typ, "OK")
        c.logout()
        with Raw() as r:
            # SASL-IR: the initial response in the command; the tagged OK carries the new capabilities.
            plain = base64.b64encode(b"\0imap@example.org\0imap-pw")
            done = r.cmd(b"a", b"AUTHENTICATE PLAIN " + plain)[-1]
            self.assertTrue(done.startswith(b"a OK [CAPABILITY IMAP4rev1 "), done)
            self.assertNotIn(b"AUTH=PLAIN", done)
        with Raw() as r:
            r.send(b"a AUTHENTICATE PLAIN\r\n")
            self.assertEqual(r.line(), b"+ \r\n")
            r.send(b"*\r\n")
            self.assertTrue(r.until(b"a")[-1].startswith(b"a BAD"), "cancelled")
            bad = r.cmd(b"b", b"LOGIN imap@example.org wrong")[-1]
            self.assertTrue(bad.startswith(b"b NO [AUTHENTICATIONFAILED]"), bad)
            r.login()

    def test_three_failures_end_the_session(self):
        with Raw() as r:
            for tag in (b"a", b"b"):
                self.assertTrue(r.cmd(tag, b"LOGIN imap@example.org wrong")[-1].startswith(tag + b" NO"))
            r.send(b"c LOGIN imap@example.org wrong\r\n")
            self.assertTrue(r.line().startswith(b"c NO [AUTHENTICATIONFAILED]"))
            self.assertTrue(r.line().startswith(b"* BYE"))
        with Raw() as r:
            r.login()  # clears the address's failures

    def test_blocked_address_gets_bye(self):
        p = admin("block-ip", "127.0.0.1", "1")
        self.assertEqual(p.returncode, 0, p.stderr)
        try:
            with Raw() as r:
                self.assertTrue(r.greeting.startswith(b"* BYE"), r.greeting)
        finally:
            admin("unblock-ip", "127.0.0.1")
        with Raw() as r:
            r.login()

    def test_any_state_commands(self):
        with Raw() as r:
            self.assertEqual(r.cmd(b"a", b"NOOP"), [b"a OK NOOP completed\r\n"])
            ident = r.cmd(b"b", b'ID ("name" "test" "version" "1")')
            self.assertEqual(ident[0], b'* ID ("name" "CeeSafe-mailserver")\r\n')
            self.assertEqual(r.cmd(b"c", b"ID NIL")[-1], b"c OK ID completed\r\n")
            r.login()
            self.assertEqual(r.cmd(b"d", b"ENABLE CONDSTORE"), [b"* ENABLED\r\n", b"d OK ENABLE completed\r\n"])
            self.assertEqual(r.cmd(b"e", b"NAMESPACE")[0], b'* NAMESPACE (("" "/")) NIL NIL\r\n')
            caps = r.cmd(b"f", b"CAPABILITY")[0]
            self.assertNotIn(b"AUTH=", caps)
            self.assertEqual(r.cmd(b"g", b"LOGOUT"), [b"* BYE Logging out\r\n", b"g OK LOGOUT completed\r\n"])
            with self.assertRaises((EOFError, ConnectionError)):
                r.line()

    def test_errors_and_states(self):
        with Raw() as r:
            self.assertTrue(r.cmd(b"a", b"FROB")[-1].startswith(b"a BAD"))
            self.assertTrue(r.cmd(b"b", b"FETCH 1 FLAGS")[-1].startswith(b"b BAD"))
            r.login()
            self.assertTrue(r.cmd(b"c", b"LOGIN a b")[-1].startswith(b"c BAD"), "already authenticated")
            self.assertTrue(r.cmd(b"d", b"FETCH 1 FLAGS")[-1].startswith(b"d BAD"), "nothing selected")
            self.assertEqual(r.cmd(b"d2", b"SEARCH ALL")[-1], b"d2 BAD No mailbox selected\r\n")
            self.assertTrue(r.cmd(b"e", b"SELECT")[-1].startswith(b"e BAD"))
            self.assertTrue(r.cmd(b"f", b"STATUS INBOX (BOGUS)")[-1].startswith(b"f BAD"))
            self.assertEqual(r.cmd(b"g", b"SELECT nosuchbox")[-1][:16], b"g NO [NONEXISTEN")
            r.ok(b"h", b"SELECT INBOX")
            self.assertTrue(r.cmd(b"i", b"SEARCH ALL")[-1].startswith(b"i OK SEARCH completed"))
            self.assertTrue(r.cmd(b"j", b"FETCH 99999 FLAGS")[-1].startswith(b"j BAD"), "no such message")
            r.send(b"\x01bad\r\n")
            self.assertTrue(r.line().startswith(b"* BAD"))
            r.ok(b"k", b"NOOP")

    def test_over_long_line_gets_bye(self):
        with Raw() as r:
            r.send(b"a NOOP " + b"x" * 70000 + b"\r\n")
            self.assertTrue(r.line().startswith(b"* BYE"))
            with self.assertRaises((EOFError, ConnectionError)):
                r.line()


class Literals(unittest.TestCase):
    def test_synchronizing_and_non_synchronizing(self):
        with Raw() as r:
            r.send(b"a LOGIN {16}\r\n")
            self.assertTrue(r.line().startswith(b"+ "))
            r.send(b"imap@example.org {7+}\r\nimap-pw\r\n")
            self.assertTrue(r.until(b"a")[-1].startswith(b"a OK"))
            # One command, three literals of both kinds.
            name = unique("Lit")
            r.send(b"b CREATE {" + str(len(name)).encode() + b"+}\r\n" + name.encode() + b"\r\n")
            r.until(b"b")
            r.send(b"c STATUS {" + str(len(name)).encode() + b"}\r\n")
            self.assertTrue(r.line().startswith(b"+ "))
            r.send(name.encode() + b" (MESSAGES)\r\n")
            out = r.until(b"c")
            self.assertEqual(out[0], b"* STATUS " + name.encode() + b" (MESSAGES 0)\r\n")

    def test_literal_limits(self):
        with Raw() as r:
            r.login()
            # A synchronizing literal over the limit: NO, and it is never read (no "+").
            r.send(b"a CREATE {70000}\r\n")
            self.assertTrue(r.line().startswith(b"a NO [TOOBIG]"))
            # A non-synchronizing one is read and thrown away, with the rest of its command.
            r.send(b"b CREATE {70000+}\r\n" + b"y" * 70000 + b"\r\n")
            self.assertTrue(r.line().startswith(b"b NO [TOOBIG]"))
            self.assertEqual(r.cmd(b"c", b"NOOP"), [b"c OK NOOP completed\r\n"], "still in step")
            r.send(b"d APPEND INBOX {" + str(MAX_APPEND + 1).encode() + b"}\r\n")
            self.assertTrue(r.line().startswith(b"d NO [TOOBIG]"), "over max_append_size")
            r.ok(b"e", b"NOOP")

    def test_utf8_and_quoted_mailbox_names(self):
        with Raw() as r:
            r.login()
            utf8 = ("Grüße " + unique("u")).encode()
            r.send(b"a CREATE {" + str(len(utf8)).encode() + b"+}\r\n" + utf8 + b"\r\n")
            self.assertTrue(r.until(b"a")[-1].startswith(b"a OK"))
            listed = r.cmd(b"b", b'LIST "" "Gr*"')
            self.assertIn(b"* LIST (\\HasNoChildren) \"/\" {" + str(len(utf8)).encode() + b"}\r\n" + utf8 + b"\r\n",
                          listed)
            quoted = unique('q "x" \\ y')
            r.ok(b"c", b"CREATE \"" + quoted.replace("\\", "\\\\").replace('"', '\\"').encode() + b"\"")
            listed = r.cmd(b"d", b'LIST "" "q *"')
            self.assertIn(b'* LIST (\\HasNoChildren) "/" "' + quoted.replace("\\", "\\\\").replace('"', '\\"').encode()
                          + b'"\r\n', listed)


class Mailboxes(unittest.TestCase):
    def test_create_list_delete(self):
        top = unique("Top")
        t = top.encode()
        with Raw() as r:
            r.login()
            r.ok(b"a", b"CREATE " + t + b"/b/c")
            listed = r.cmd(b"b", b'LIST "" ' + t + b"*")
            self.assertEqual(listed, [b'* LIST (\\HasChildren) "/" ' + t + b"\r\n",
                                      b'* LIST (\\HasChildren) "/" ' + t + b"/b\r\n",
                                      b'* LIST (\\HasNoChildren) "/" ' + t + b"/b/c\r\n",
                                      b"b OK LIST completed\r\n"])
            self.assertEqual(r.cmd(b"c", b'LIST "" ' + t + b"%")[:-1], [b'* LIST (\\HasChildren) "/" ' + t + b"\r\n"])
            # The reference is prefixed to the pattern.
            self.assertEqual(r.cmd(b"d", b'LIST ' + t + b'/ %')[:-1], [b'* LIST (\\HasChildren) "/" ' + t + b"/b\r\n"])
            self.assertEqual(r.cmd(b"e", b'LIST "" ""')[0], b'* LIST (\\Noselect) "/" ""\r\n')
            self.assertTrue(r.cmd(b"f", b"CREATE " + t)[-1].startswith(b"f NO [ALREADYEXISTS]"))
            self.assertTrue(r.cmd(b"g", b"CREATE inbox")[-1].startswith(b"g NO"))
            r.ok(b"h", b"CREATE " + t + b"/trailing/")
            self.assertIn(b'* LIST (\\HasNoChildren) "/" ' + t + b"/trailing\r\n", r.cmd(b"i", b'LIST "" ' + t + b"/%"))
            # A deleted parent stays as a \Noselect name while it has children.
            r.ok(b"j", b"DELETE " + t + b"/b")
            self.assertEqual(r.cmd(b"k", b'LIST "" ' + t + b"/%")[:-1],
                             [b'* LIST (\\Noselect \\HasChildren) "/" ' + t + b"/b\r\n",
                              b'* LIST (\\HasNoChildren) "/" ' + t + b"/trailing\r\n"])
            self.assertTrue(r.cmd(b"l", b"DELETE " + t + b"/b")[-1].startswith(b"l NO [NONEXISTENT]"))
            self.assertTrue(r.cmd(b"m", b"DELETE INBOX")[-1].startswith(b"m NO"))
            # INBOX in any case; special-use attributes from the store.
            inbox = r.cmd(b"n", b'LIST "" InBoX')
            self.assertEqual(inbox[0][:27], b"* LIST (\\HasNoChildren) \"/\"")
            self.assertTrue(inbox[0].endswith(b" INBOX\r\n"))
            everything = b"".join(r.cmd(b"o", b'LIST "" *'))
            self.assertIn(b'\\Sent) "/" Sent\r\n', everything)
            self.assertIn(b'\\Junk) "/" Junk\r\n', everything)

    def test_rename_and_subscribe(self):
        a, b = unique("Ren").encode(), unique("Moved").encode()
        with Raw() as r:
            r.login()
            r.ok(b"a", b"CREATE " + a + b"/child")
            r.ok(b"b", b"RENAME " + a + b" " + b + b"/sub")
            listed = r.cmd(b"c", b'LIST "" ' + b + b"*")[:-1]
            self.assertEqual(listed, [b'* LIST (\\HasChildren) "/" ' + b + b"\r\n",
                                      b'* LIST (\\HasChildren) "/" ' + b + b"/sub\r\n",
                                      b'* LIST (\\HasNoChildren) "/" ' + b + b"/sub/child\r\n"])
            self.assertTrue(r.cmd(b"d", b"RENAME " + a + b" x")[-1].startswith(b"d NO [NONEXISTENT]"))
            self.assertTrue(r.cmd(b"e", b"RENAME " + b + b" INBOX")[-1].startswith(b"e NO"))
            sub = b'* LSUB () "/" ' + b + b"/sub\r\n"
            r.ok(b"f", b"UNSUBSCRIBE " + b + b"/sub")
            self.assertNotIn(sub, r.cmd(b"g", b"LSUB \"\" " + b + b"*"))
            r.ok(b"h", b"SUBSCRIBE " + b + b"/sub")
            self.assertIn(sub, r.cmd(b"i", b"LSUB \"\" " + b + b"*"))
            self.assertEqual(sql(f"SELECT subscribed FROM mailboxes WHERE name = '{b.decode()}/sub'"), "t")
            self.assertTrue(r.cmd(b"j", b"SUBSCRIBE nosuch" + b)[-1].startswith(b"j NO"))
            # CREATE does not subscribe, nor the parents it makes (imaptest's subscribe test, as Dovecot).
            r.ok(b"k", b"CREATE " + b + b"/new/leaf")
            self.assertEqual(r.cmd(b"l", b'LSUB "" ' + b + b"/new*"), [b"l OK LSUB completed\r\n"])
            self.assertEqual(sql(f"SELECT string_agg(subscribed::text, ',') FROM mailboxes "
                                 f"WHERE name LIKE '{b.decode()}/new%'"), "false,false")
            r.ok(b"m", b"SUBSCRIBE " + b + b"/new/leaf")
            self.assertEqual(sorted(r.cmd(b"n", b'LSUB "" ' + b + b"/%")[:-1]),
                             [b'* LSUB () "/" ' + b + b"/sub\r\n", b'* LSUB (\\Noselect) "/" ' + b + b"/new\r\n"])

    def test_inbox_rename(self):
        deliver(USER2, simple("first"))
        deliver(USER2, simple("second"))
        before = db_uids(USER2, "INBOX")
        self.assertGreaterEqual(len(before), 2)
        target = unique("Old/Inbox")
        with Raw() as r:
            r.login(USER2, PASSWORD2)
            r.ok(b"a", b"RENAME INBOX " + target.encode())
            self.assertEqual(r.cmd(b"b", b"STATUS INBOX (MESSAGES)")[0], b"* STATUS INBOX (MESSAGES 0)\r\n")
            self.assertEqual(r.cmd(b"c", b"STATUS " + target.encode() + b" (MESSAGES)")[0],
                             b"* STATUS " + target.encode() + b" (MESSAGES " + str(len(before)).encode() + b")\r\n")
            r.ok(b"d", b"SELECT INBOX")
        self.assertEqual(db_uids(USER2, "INBOX"), [])
        self.assertEqual(len(db_uids(USER2, target)), len(before))

    def test_status(self):
        name = folder_with([simple("s1"), simple("s2")])
        with Raw() as r:
            r.login()
            r.ok(b"a", b"SELECT " + name.encode())
            r.ok(b"b", b"STORE 1 +FLAGS (\\Seen)")
            r.ok(b"c", b"UNSELECT")
            out = r.cmd(b"d", b"STATUS " + name.encode() + b" (MESSAGES RECENT UIDNEXT UIDVALIDITY UNSEEN)")
            want = (f"* STATUS {name} (MESSAGES 2 RECENT 0 UIDNEXT {db_mailbox(USER, name, 'uid_next')} "
                    f"UIDVALIDITY {db_mailbox(USER, name, 'uid_validity')} UNSEEN 1)\r\n").encode()
            self.assertEqual(out[0], want)


class Select(unittest.TestCase):
    def test_select_and_examine(self):
        name = folder_with([simple("a"), simple("b"), simple("c")])
        n = name.encode()
        uids = db_uids(USER, name)
        with Raw() as r:
            r.login()
            r.ok(b"x", b"SELECT " + n)
            r.ok(b"y", b"STORE 1 +FLAGS.SILENT (\\Seen)")
            out = r.cmd(b"a", b"SELECT " + n)
            self.assertEqual(out, [
                b"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n",
                b"* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Flags permitted\r\n",
                b"* 3 EXISTS\r\n",
                b"* 0 RECENT\r\n",
                b"* OK [UNSEEN 2] First unseen\r\n",
                f"* OK [UIDVALIDITY {db_mailbox(USER, name, 'uid_validity')}] UIDs valid\r\n".encode(),
                f"* OK [UIDNEXT {uids[-1] + 1}] Predicted next UID\r\n".encode(),
                b"a OK [READ-WRITE] SELECT completed\r\n"])
            out = r.cmd(b"b", b"EXAMINE " + n)
            self.assertIn(b"* OK [PERMANENTFLAGS ()] No permanent flags permitted\r\n", out)
            self.assertEqual(out[-1], b"b OK [READ-ONLY] EXAMINE completed\r\n")
            self.assertTrue(r.cmd(b"c", b"STORE 1 +FLAGS (\\Deleted)")[-1].startswith(b"c NO"), "read-only")
            self.assertTrue(r.cmd(b"d", b"EXPUNGE")[-1].startswith(b"d NO"), "read-only")
            r.ok(b"e", b"CLOSE")
            self.assertTrue(r.cmd(b"f", b"FETCH 1 FLAGS")[-1].startswith(b"f BAD"), "closed")


class Append(unittest.TestCase):
    def test_append_with_flags_and_date(self):
        name = unique("App")
        message = multipart("appended")
        with Raw() as r:
            r.login()
            self.assertTrue(r.cmd(b"a", b"APPEND " + name.encode() + b" {5+}\r\nhello")[-1]
                            .startswith(b"a NO [TRYCREATE]"))
            r.ok(b"b", b"CREATE " + name.encode())
            r.send(b"c APPEND " + name.encode() + b' (\\Seen \\Flagged $Work) "05-Nov-2026 12:34:56 +0100" {'
                   + str(len(message)).encode() + b"}\r\n")
            self.assertTrue(r.line().startswith(b"+ "))
            r.send(message + b"\r\n")
            done = r.until(b"c")[-1]
            m = re.match(rb"c OK \[APPENDUID (\d+) (\d+)\] APPEND completed\r\n", done)
            self.assertTrue(m, done)
            self.assertEqual(int(m.group(1)), db_mailbox(USER, name, "uid_validity"))
            self.assertEqual([int(m.group(2))], db_uids(USER, name))
            self.assertEqual(sql(f"SELECT meta IS NOT NULL FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id "
                                 f"WHERE b.name = '{name}'"), "t", "indexed at ingest")
            # LITERAL+ needs no continuation.
            done = r.cmd(b"d", b"APPEND " + name.encode() + b" {11+}\r\nSubject: x\r\n")[-1]
            self.assertTrue(done.startswith(b"d OK [APPENDUID "), done)
            r.ok(b"e", b"SELECT " + name.encode())
            (seq, items), = fetches(r.cmd(b"f", b"FETCH 1 (FLAGS INTERNALDATE RFC822.SIZE BODY.PEEK[] BODYSTRUCTURE)"))
            self.assertEqual(items["FLAGS"], [b"\\Flagged", b"\\Seen", b"$Work"])
            self.assertEqual(items["INTERNALDATE"], b"05-Nov-2026 11:34:56 +0000")
            self.assertEqual(items["RFC822.SIZE"], str(len(message)).encode())
            self.assertEqual(items["BODY[]"], message)
            self.assertIn(b"mixed", items["BODYSTRUCTURE"])

    def test_quota(self):
        with Raw() as r:
            r.login("bob@example.org", "bob-pw")
            big = b"Subject: big\r\n\r\n" + b"x" * 2500 + b"\r\n"
            done = r.cmd(b"a", b"APPEND INBOX {" + str(len(big)).encode() + b"+}\r\n" + big)[-1]
            self.assertTrue(done.startswith(b"a NO [OVERQUOTA]"), done)
            # From the announced size, before the message is read: no "+" for a synchronizing literal.
            r.send(b"b APPEND INBOX {" + str(len(big)).encode() + b"}\r\n")
            self.assertTrue(r.line().startswith(b"b NO [OVERQUOTA]"))
            r.ok(b"c", b"NOOP")


class Fetch(unittest.TestCase):
    def stored(self, name: str) -> bytes:
        blob = sql(f"SELECT encode(m.blob, 'hex') FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id "
                   f"WHERE b.name = '{name}' ORDER BY m.uid LIMIT 1")
        with open(os.path.join(os.environ["MAILSERVER_BLOBS"], blob[0:2], blob[2:4], blob), "rb") as f:
            return f.read()

    def test_simple_items(self):
        name = folder_with([simple("items", "Body text.\r\n")])
        stored = self.stored(name)
        header, text = stored.split(b"\r\n\r\n", 1)
        with Raw() as r:
            r.login()
            r.ok(b"a", b"EXAMINE " + name.encode())
            (seq, items), = fetches(r.cmd(b"b", b"FETCH 1 (UID FLAGS RFC822.SIZE INTERNALDATE ENVELOPE BODY RFC822 "
                                               b"RFC822.HEADER RFC822.TEXT)"))
            self.assertEqual(seq, 1)
            self.assertEqual(int(items["UID"]), db_uids(USER, name)[0])
            self.assertEqual(items["FLAGS"], [])
            self.assertEqual(int(items["RFC822.SIZE"]), len(stored))
            self.assertRegex(items["INTERNALDATE"].decode(), r"^\d\d-[A-Z][a-z]{2}-\d{4} \d\d:\d\d:\d\d \+0000$")
            envelope = items["ENVELOPE"]
            self.assertEqual(envelope[0], b"Thu, 05 Nov 2026 10:00:00 +0000")
            self.assertEqual(envelope[1], b"items")
            self.assertEqual(envelope[2], [[b"Sender", b"NIL", b"sender", b"remote.test"]])
            self.assertEqual(envelope[9], b"<items@remote.test>")
            self.assertEqual(items["BODY"][:2], [b"text", b"plain"])
            self.assertEqual(items["RFC822"], stored)
            self.assertEqual(items["RFC822.HEADER"], header + b"\r\n\r\n")
            self.assertEqual(items["RFC822.TEXT"], text)
            self.assertEqual(items["FLAGS"], [], "EXAMINE: RFC822 does not set \\Seen")
            for macro, names in ((b"FAST", {"FLAGS", "INTERNALDATE", "RFC822.SIZE"}),
                                 (b"ALL", {"FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE"}),
                                 (b"FULL", {"FLAGS", "INTERNALDATE", "RFC822.SIZE", "ENVELOPE", "BODY"})):
                (_, got), = fetches(r.cmd(b"c", b"FETCH 1 " + macro))
                self.assertEqual(set(got), names)
            (_, got), = fetches(r.cmd(b"d", b"UID FETCH 1:* FLAGS"))
            self.assertEqual(set(got), {"UID", "FLAGS"}, "UID FETCH always gives the UID")

    def test_sections_byte_for_byte(self):
        name = folder_with([multipart("sections")])
        stored = self.stored(name)
        header = stored[:stored.index(b"\r\n\r\n") + 4]
        parsed = email.message_from_bytes(stored, policy=email.policy.default)
        with Raw() as r:
            r.login()
            r.ok(b"a", b"SELECT " + name.encode())
            out = r.cmd(b"b", b"FETCH 1 (BODY.PEEK[] BODY.PEEK[HEADER] BODY.PEEK[TEXT] BODY.PEEK[1] BODY.PEEK[1.MIME] "
                              b"BODY.PEEK[2] BODY.PEEK[2.MIME] BODY.PEEK[3] BODY.PEEK[3.HEADER] BODY.PEEK[3.TEXT] "
                              b"BODY.PEEK[3.1] BODY.PEEK[3.MIME] BODY.PEEK[9] "
                              b"BODY.PEEK[HEADER.FIELDS (Subject FROM x-folded)] "
                              b"BODY.PEEK[HEADER.FIELDS.NOT (Received Authentication-Results)] "
                              b"BODY.PEEK[3.HEADER.FIELDS (SUBJECT)] "
                              b"BODY.PEEK[]<0.10> BODY.PEEK[1]<5.7> BODY.PEEK[2]<1000.5>)")
            (seq, items), = fetches(out)
            self.assertEqual(items["BODY[]"], stored)
            self.assertEqual(items["BODY[HEADER]"], header)
            self.assertEqual(items["BODY[TEXT]"], stored[len(header):])
            self.assertEqual(items["BODY[1]"], P1_BODY)
            self.assertEqual(items["BODY[1.MIME]"], P1_HDR)
            self.assertEqual(items["BODY[2]"], P2_BODY)
            self.assertEqual(items["BODY[2.MIME]"], P2_HDR)
            self.assertEqual(items["BODY[3]"], INNER_HDR + INNER_BODY)
            self.assertEqual(items["BODY[3.HEADER]"], INNER_HDR)
            self.assertEqual(items["BODY[3.TEXT]"], INNER_BODY)
            self.assertEqual(items["BODY[3.1]"], INNER_BODY)
            self.assertEqual(items["BODY[3.MIME]"], P3_HDR)
            self.assertEqual(items["BODY[9]"], b"NIL")
            fields = items["BODY[HEADER.FIELDS (Subject FROM x-folded)]"]
            self.assertEqual(fields, header_fields(header, [b"subject", b"from", b"x-folded"], True))
            self.assertIn(b"X-Folded: one\r\n two\r\n", fields)
            self.assertEqual(items["BODY[HEADER.FIELDS.NOT (Received Authentication-Results)]"],
                             header_fields(header, [b"received", b"authentication-results"], False))
            self.assertEqual(items["BODY[3.HEADER.FIELDS (SUBJECT)]"], b"Subject: inner message\r\n\r\n")
            self.assertEqual(items["BODY[]<0>"], stored[:10])
            self.assertEqual(items["BODY[1]<5>"], P1_BODY[5:12])
            self.assertEqual(items["BODY[2]<1000>"], b"")
            # The same parts as Python's email package reads them.
            parts = list(parsed.iter_parts())
            self.assertEqual(parts[0].get_content().replace("\r\n", "\n"), P1_BODY.decode().replace("\r\n", "\n"))
            self.assertEqual(parts[1].get_content_type(), "text/html")
            inner = email.message_from_bytes(items["BODY[3]"], policy=email.policy.default)
            self.assertEqual(inner["Subject"], "inner message")
            self.assertEqual(email.message_from_bytes(fields)["Subject"], parsed["Subject"])
            self.assertEqual(seq, 1)
            # \Seen was not set by any of these.
            (_, flags), = fetches(r.cmd(b"c", b"FETCH 1 FLAGS"))
            self.assertEqual(flags["FLAGS"], [])

    def test_body_sets_seen_but_peek_does_not(self):
        name = folder_with([simple("seen1"), simple("seen2")])
        with Raw() as r:
            r.login()
            r.ok(b"a", b"SELECT " + name.encode())
            out = r.cmd(b"b", b"FETCH 1 BODY.PEEK[TEXT]")
            (_, items), = fetches(out)
            self.assertEqual(set(items), {"BODY[TEXT]"})
            out = r.cmd(b"c", b"FETCH 1:2 (BODY[TEXT] RFC822.SIZE)")
            got = fetches(out)
            self.assertEqual([s for s, _ in got], [1, 2])
            for _, items in got:
                self.assertEqual(items["FLAGS"], [b"\\Seen"], "the new flags in the same response")
            self.assertEqual(sql(f"SELECT string_agg(flags::text, ',') FROM messages m JOIN mailboxes b "
                                 f"ON b.id = m.mailbox_id WHERE b.name = '{name}'"), "1,1")
            (_, items), = fetches(r.cmd(b"d", b"FETCH 1 (FLAGS BODY[HEADER])"))
            self.assertEqual(items["FLAGS"], [b"\\Seen"])
            self.assertNotIn(b"FLAGS", out[-1])

    def test_imaplib_fetch_many_literals(self):
        name = folder_with([multipart("lib1"), simple("lib2")])
        c = imaps()
        c.select(name)
        typ, data = c.fetch("1:2", "(BODY.PEEK[1] BODY.PEEK[2] UID)")
        self.assertEqual(typ, "OK")
        literals = [part[1] for part in data if isinstance(part, tuple)]
        self.assertEqual(literals[:2], [P1_BODY, P2_BODY])
        c.logout()


class Store(unittest.TestCase):
    def test_store_forms(self):
        name = folder_with([simple("st1"), simple("st2"), simple("st3")])
        uids = db_uids(USER, name)
        with Raw() as r:
            r.login()
            r.ok(b"a", b"SELECT " + name.encode())
            # A keyword new to the client is announced in FLAGS before a FETCH shows it (RFC 3501 §7.2.6).
            self.assertEqual(r.cmd(b"b", b"STORE 1:2 +FLAGS (\\Flagged $Label1)"),
                             [b"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft $Label1)\r\n",
                              b"* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft $Label1 \\*)] "
                              b"Flags permitted\r\n",
                              b"* 1 FETCH (FLAGS (\\Flagged $Label1))\r\n", b"* 2 FETCH (FLAGS (\\Flagged $Label1))\r\n",
                              b"b OK STORE completed\r\n"])
            self.assertEqual(r.cmd(b"c", b"STORE 2 -FLAGS \\Flagged"),
                             [b"* 2 FETCH (FLAGS ($Label1))\r\n", b"c OK STORE completed\r\n"])
            self.assertEqual(r.cmd(b"d", b"STORE 3 FLAGS.SILENT (\\Answered \\Draft)"), [b"d OK STORE completed\r\n"])
            self.assertEqual(r.cmd(b"e", b"UID STORE " + str(uids[2]).encode() + b" FLAGS (\\Seen)"),
                             [f"* 3 FETCH (FLAGS (\\Seen) UID {uids[2]})\r\n".encode(), b"e OK UID STORE completed\r\n"])
            self.assertEqual(r.cmd(b"f", b"STORE 1 -FLAGS ($Label1)"),
                             [b"* 1 FETCH (FLAGS (\\Flagged))\r\n", b"f OK STORE completed\r\n"])
            self.assertTrue(r.cmd(b"g", b"STORE 1 +FLAGS (\\Bogus)")[-1].startswith(b"g BAD"))
            self.assertTrue(r.cmd(b"h", b"STORE 1 FROB (\\Seen)")[-1].startswith(b"h BAD"))
        self.assertEqual(sql(f"SELECT string_agg(flags::text || ':' || array_to_string(keywords, ' '), ',' ORDER BY uid) "
                             f"FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id WHERE b.name = '{name}'"),
                         "4:,0:$Label1,1:")


    def test_keywords_in_flags(self):
        # imaptest: "Keyword used without being in FLAGS". SELECT lists the mailbox's keywords; a keyword another
        # session adds is announced before its FETCH.
        name = folder_with([simple("k1"), simple("k2")])
        with Raw() as r, Raw() as other:
            r.login()
            other.login()
            r.ok(b"a", b"SELECT " + name.encode())
            r.ok(b"b", b"STORE 1 +FLAGS.SILENT ($Old)")
            selected = other.cmd(b"c", b"SELECT " + name.encode())
            self.assertEqual(selected[0], b"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft $Old)\r\n")
            self.assertIn(b"* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft $Old \\*)] "
                          b"Flags permitted\r\n", selected)
            r.ok(b"d", b"STORE 2 +FLAGS.SILENT ($New $old)")
            self.assertEqual(other.cmd(b"e", b"NOOP"),
                             [b"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft $Old $New)\r\n",
                              b"* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft $Old $New \\*)] "
                              b"Flags permitted\r\n",
                              b"* 2 FETCH (FLAGS ($New $old))\r\n", b"e OK NOOP completed\r\n"])
            # Known now: no FLAGS again, in any case.
            self.assertEqual(other.cmd(b"f", b"FETCH 1:2 FLAGS"),
                             [b"* 1 FETCH (FLAGS ($Old))\r\n", b"* 2 FETCH (FLAGS ($New $old))\r\n",
                              b"f OK FETCH completed\r\n"])
            # EXAMINE: no permanent flags.
            examined = other.cmd(b"g", b"EXAMINE " + name.encode())
            self.assertEqual(examined[:2], [b"* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft $Old $New)\r\n",
                                            b"* OK [PERMANENTFLAGS ()] No permanent flags permitted\r\n"])


class Expunge(unittest.TestCase):
    def test_renumbering(self):
        name = folder_with([simple(f"e{i}") for i in range(1, 6)])
        uids = db_uids(USER, name)
        with Raw() as r:
            r.login()
            r.ok(b"a", b"SELECT " + name.encode())
            r.ok(b"b", b"STORE 2,4 +FLAGS.SILENT (\\Deleted)")
            self.assertEqual(r.cmd(b"c", b"EXPUNGE"),
                             [b"* 4 EXPUNGE\r\n", b"* 2 EXPUNGE\r\n", b"c OK EXPUNGE completed\r\n"])
            got = fetches(r.cmd(b"d", b"FETCH 1:* UID"))
            self.assertEqual([(s, int(i["UID"])) for s, i in got], [(1, uids[0]), (2, uids[2]), (3, uids[4])])
            self.assertTrue(r.cmd(b"e", b"FETCH 4 UID")[-1].startswith(b"e BAD"), "only three now")
            # UID EXPUNGE removes only the UIDs given.
            r.ok(b"f", b"STORE 1:3 +FLAGS.SILENT (\\Deleted)")
            self.assertEqual(r.cmd(b"g", b"UID EXPUNGE " + str(uids[2]).encode()),
                             [b"* 2 EXPUNGE\r\n", b"g OK UID EXPUNGE completed\r\n"])
            self.assertEqual(db_uids(USER, name), [uids[0], uids[4]])
            # UNSELECT leaves \Deleted messages; CLOSE removes them silently.
            r.ok(b"h", b"UNSELECT")
            self.assertEqual(len(db_uids(USER, name)), 2)
            r.ok(b"i", b"SELECT " + name.encode())
            self.assertEqual(r.cmd(b"j", b"CLOSE"), [b"j OK CLOSE completed\r\n"])
            self.assertEqual(db_uids(USER, name), [])


class CopyMove(unittest.TestCase):
    def test_copy(self):
        name = folder_with([simple("c1"), simple("c2"), simple("c3")])
        target = unique("CopyTo")
        source = db_uids(USER, name)
        with Raw() as r:
            r.login()
            r.ok(b"a", b"SELECT " + name.encode())
            self.assertTrue(r.cmd(b"b", b"COPY 1 " + target.encode())[-1].startswith(b"b NO [TRYCREATE]"))
            r.ok(b"c", b"CREATE " + target.encode())
            done = r.cmd(b"d", b"COPY 1,3 " + target.encode())[-1]
            copied = db_uids(USER, target)
            self.assertEqual(done, f"d OK [COPYUID {db_mailbox(USER, target, 'uid_validity')} ".encode()
                             + compress([source[0], source[2]]) + b" " + compress(copied) + b"] COPY completed\r\n")
            done = r.cmd(b"e", b"UID COPY " + str(source[1]).encode() + b" " + target.encode())[-1]
            self.assertTrue(done.startswith(b"e OK [COPYUID "), done)
            self.assertEqual(len(db_uids(USER, target)), 3)
            self.assertEqual(len(db_uids(USER, name)), 3, "copying leaves the source")

    def test_move(self):
        name = folder_with([simple("m1"), simple("m2"), simple("m3")])
        target = unique("MoveTo")
        source = db_uids(USER, name)
        with Raw() as r:
            r.login()
            r.ok(b"a", b"CREATE " + target.encode())
            r.ok(b"b", b"SELECT " + name.encode())
            out = r.cmd(b"c", b"MOVE 2:3 " + target.encode())
            moved = db_uids(USER, target)
            self.assertEqual(out, [f"* OK [COPYUID {db_mailbox(USER, target, 'uid_validity')} ".encode()
                                   + compress(source[1:]) + b" " + compress(moved) + b"] Moved\r\n",
                                   b"* 3 EXPUNGE\r\n", b"* 2 EXPUNGE\r\n", b"c OK MOVE completed\r\n"])
            self.assertEqual(db_uids(USER, name), source[:1])
            out = r.cmd(b"d", b"UID MOVE " + str(source[0]).encode() + b" " + target.encode())
            self.assertEqual(out[-2:], [b"* 1 EXPUNGE\r\n", b"d OK MOVE completed\r\n"])
            self.assertTrue(r.cmd(b"e", b"MOVE 1 " + target.encode())[-1].startswith(b"e BAD"), "empty now")
            # A MOVE to the selected mailbox itself gives the message a new UID (RFC 6851; imaptest's move test).
            r.ok(b"f", b"SELECT " + target.encode())
            before = db_uids(USER, target)
            out = r.cmd(b"g", b"MOVE 1 " + target.encode())
            after = db_uids(USER, target)
            self.assertEqual(after, before[1:] + [before[-1] + 1])
            self.assertEqual(out, [f"* OK [COPYUID {db_mailbox(USER, target, 'uid_validity')} {before[0]} "
                                   f"{after[-1]}] Moved\r\n".encode(),
                                   b"* 1 EXPUNGE\r\n", b"* 3 EXISTS\r\n", b"g OK MOVE completed\r\n"])
            got = fetches(r.cmd(b"h", b"FETCH 1:* UID"))
            self.assertEqual([int(i["UID"]) for _, i in got], after)
        self.assertEqual(len(db_uids(USER, target)), 3)
        self.assertEqual(db_mailbox(USER, target, "messages"), 3)


class Concurrent(unittest.TestCase):
    def wait_for(self, client: Raw, pattern: bytes, seconds: float = 8) -> list:
        """Lines until one matches `pattern`."""
        deadline, seen = time.time() + seconds, []
        client.sock.settimeout(seconds)
        while time.time() < deadline:
            line = client.response()
            seen.append(line)
            if re.match(pattern, line):
                return seen
        self.fail(f"no {pattern!r} in {seen!r}")

    def test_noop_sees_other_sessions(self):
        name = folder_with([simple("n1"), simple("n2"), simple("n3")])
        n = name.encode()
        with Raw() as a, Raw() as b:
            a.login()
            b.login()
            a.ok(b"a1", b"SELECT " + n)
            b.ok(b"b1", b"SELECT " + n)
            b.ok(b"b2", b"STORE 2 +FLAGS.SILENT (\\Flagged)")
            self.assertEqual(a.cmd(b"a2", b"NOOP"), [b"* 2 FETCH (FLAGS (\\Flagged))\r\n", b"a2 OK NOOP completed\r\n"])
            self.assertEqual(a.cmd(b"a3", b"NOOP"), [b"a3 OK NOOP completed\r\n"], "reported once")
            b.ok(b"b3", b"STORE 1 +FLAGS.SILENT (\\Deleted)")
            b.ok(b"b4", b"EXPUNGE")
            # Not during FETCH (RFC 3501 §7.4.1): the expunged message is left out, and announced on NOOP.
            out = a.cmd(b"a4", b"FETCH 1:3 (FLAGS)")
            self.assertFalse([l for l in out if b"EXPUNGE" in l], out)
            self.assertEqual([s for s, _ in fetches(out)], [2, 3])
            self.assertEqual(a.cmd(b"a5", b"NOOP"), [b"* 1 EXPUNGE\r\n", b"a5 OK NOOP completed\r\n"])
            # A new message: EXISTS.
            msg = simple("n4")
            b.ok(b"b5", b"APPEND " + n + b" {" + str(len(msg)).encode() + b"+}\r\n" + msg)
            self.assertEqual(a.cmd(b"a6", b"NOOP"), [b"* 3 EXISTS\r\n", b"a6 OK NOOP completed\r\n"])
            got = fetches(a.cmd(b"a7", b"FETCH 1:* UID"))
            self.assertEqual([int(i["UID"]) for _, i in got], db_uids(USER, name))

    def idle_with_changes(self, during: bool, tls: bool = True):
        """Session A idles while B flags, expunges and adds messages. With `during`, A sees each change while idling
        (woken by the notify bus); else it reads them all once IDLE ends, before the tagged OK."""
        name = folder_with([simple("i1"), simple("i2")])
        n = name.encode()
        with Raw(tls=tls) as a, Raw() as b:
            a.login()
            b.login()
            a.ok(b"a1", b"SELECT " + n)
            b.ok(b"b1", b"SELECT " + n)
            a.send(b"a2 IDLE\r\n")
            self.assertEqual(a.line(), b"+ idling\r\n")
            b.ok(b"b2", b"STORE 1 +FLAGS.SILENT (\\Answered)")
            if during:
                self.wait_for(a, rb"\* 1 FETCH \(FLAGS \(\\Answered\)\)\r\n")
            b.ok(b"b3", b"STORE 2 +FLAGS.SILENT (\\Deleted)")
            b.ok(b"b4", b"EXPUNGE")
            if during:
                self.wait_for(a, rb"\* 2 EXPUNGE\r\n")
            deliver(USER, simple("i3"))
            b.ok(b"b5", b"SELECT INBOX")
            b.ok(b"b6", b"MOVE 1:* " + n)
            if during:
                self.wait_for(a, rb"\* 2 EXISTS\r\n")
            a.sock.settimeout(10)
            a.send(b"DONE\r\n")
            out = a.until(b"a2")
            self.assertEqual(out[-1], b"a2 OK IDLE terminated\r\n")
            if not during:
                # The \\Deleted flag shows when A was woken between B's STORE and its EXPUNGE.
                deleted = b"* 2 FETCH (FLAGS (\\Deleted))\r\n"
                self.assertEqual([l for l in out if l != deleted],
                                 [b"* 1 FETCH (FLAGS (\\Answered))\r\n", b"* 2 EXPUNGE\r\n", b"* 2 EXISTS\r\n",
                                  b"a2 OK IDLE terminated\r\n"])
            self.assertEqual(a.cmd(b"a3", b"NOOP"), [b"a3 OK NOOP completed\r\n"])
            got = fetches(a.cmd(b"a4", b"FETCH 1:* UID"))
            self.assertEqual([int(i["UID"]) for _, i in got], db_uids(USER, name))

    def test_idle_reports_changes_at_done(self):
        self.idle_with_changes(during=False)

    @unittest.skipUnless(PLAINTEXT_AUTH, "logging in over plaintext needs IMAP_PLAINTEXT_AUTH=true")
    def test_idle_reports_while_idling_plaintext(self):
        self.idle_with_changes(during=True, tls=False)

    def test_idle_reports_while_idling(self):
        self.idle_with_changes(during=True)


# SEARCH's messages: (flags, internal date, message). Built so that each key picks a different subset.
SEARCH_MESSAGES = [
    (r"\Seen \Answered $Work", "05-Mar-2021 12:00:00 +0000",
     b"From: Alice Example <alice@remote.test>\r\nTo: Bob <bob@remote.test>\r\nSubject: Quarterly report\r\n"
     b"Date: Fri, 05 Mar 2021 23:30:00 -0500\r\nMessage-ID: <q1@remote.test>\r\n\r\nThe numbers are in.\r\n"),
    (r"\Flagged", "01-Jan-2020 08:00:00 +0000",
     b"From: =?ISO-8859-1?Q?Andr=E9?= <andre@remote.test>\r\nTo: alice@remote.test\r\n"
     b"Subject: =?ISO-8859-1?Q?Caf=E9_menu?=\r\nMIME-Version: 1.0\r\n"
     b"Content-Type: text/html; charset=iso-8859-1\r\nContent-Transfer-Encoding: base64\r\n\r\n"
     + base64.encodebytes("<html><body><p>Crème <b>brûlée</b> tonight</p></body></html>\r\n"
                          .encode("latin-1")).replace(b"\n", b"\r\n")),
    (r"\Draft \Deleted Later", "10-Jun-2022 06:30:00 +0000",
     b"From: Carol <carol@remote.test>\r\nTo: Bob <bob@remote.test>\r\nCc: Dave <dave@remote.test>\r\n"
     b"Bcc: eve@remote.test\r\nSubject: Greetings\r\nX-Priority: 1\r\nX-Empty:\r\n"
     b"Date: Thu, 9 Jun 2022 23:00:00 -0700\r\nMIME-Version: 1.0\r\n"
     b"Content-Type: multipart/mixed; boundary=\"b1\"\r\n\r\n--b1\r\n"
     b"Content-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"
     b"Gr=FC=DFe aus K=F6ln, und Schl=\r\nu=DF.\r\n--b1\r\nContent-Type: application/octet-stream\r\n\r\n"
     b"binary needle\r\n--b1--\r\n"),
    ("", "31-Dec-2023 23:59:59 +0000",
     b"From: Bob <bob@remote.test>\r\nTo: Alice <alice@remote.test>\r\nSubject: Big one\r\n"
     b"Date: Sun, 31 Dec 2023 10:00:00 +0000\r\n\r\n" + b"x" * 70 + b"\r\n" * 1 + (b"filler " * 10 + b"\r\n") * 80
     + b"tail word\r\n"),
]


def append_raw(r, name: str, flags: str, date: str, message: bytes):
    r.send(f'A APPEND {name} ({flags}) "{date}" {{{len(message)}+}}\r\n'.encode() + message + b"\r\n")
    responses = r.until(b"A")
    assert responses[-1].startswith(b"A OK"), responses


def search_folder() -> str:
    name = unique("S")
    with Raw() as r:
        r.login()
        r.ok(b"c", b"CREATE " + name.encode())
        for flags, date, message in SEARCH_MESSAGES:
            append_raw(r, name, flags, date, message)
    return name


def search_result(responses, word: bytes = b"SEARCH") -> list:
    lines = [x for x in responses if x.startswith(b"* " + word)]
    assert len(lines) == 1, responses
    return [int(n) for n in lines[0][len(word) + 2:].split()]


class Search(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.name = search_folder()
        cls.uids = db_uids(USER, cls.name)
        cls.r = Raw()
        cls.r.login()
        cls.r.ok(b"s", b"SELECT " + cls.name.encode())

    @classmethod
    def tearDownClass(cls):
        cls.r.close()

    def seqs(self, keys: bytes) -> list:
        responses = self.r.cmd(b"t", b"SEARCH " + keys)
        self.assertTrue(responses[-1].startswith(b"t OK SEARCH completed"), responses)
        return search_result(responses)

    def check(self, cases):
        for keys, want in cases:
            with self.subTest(keys=keys):
                keys = keys.encode() if isinstance(keys, str) else keys
                if want is None:
                    self.assertEqual(self.r.cmd(b"t", b"SEARCH " + keys)[-1], b"t BAD invalid character\r\n")
                else:
                    self.assertEqual(self.seqs(keys), want)

    def test_flags(self):
        self.check([("ALL", [1, 2, 3, 4]), ("SEEN", [1]), ("UNSEEN", [2, 3, 4]), ("ANSWERED", [1]),
                    ("UNANSWERED", [2, 3, 4]), ("FLAGGED", [2]), ("UNFLAGGED", [1, 3, 4]), ("DELETED", [3]),
                    ("UNDELETED", [1, 2, 4]), ("DRAFT", [3]), ("UNDRAFT", [1, 2, 4]),
                    # \Recent is not kept: nothing is recent or new, everything is old.
                    ("RECENT", []), ("NEW", []), ("OLD", [1, 2, 3, 4]),
                    ("KEYWORD $Work", [1]), ("KEYWORD $work", [1]), ("KEYWORD later", [3]), ("KEYWORD $Wor", []),
                    ("UNKEYWORD $Work", [2, 3, 4])])

    def test_dates_and_sizes(self):
        size4 = len(SEARCH_MESSAGES[3][2])
        self.check([("BEFORE 5-Mar-2021", [2]), ("ON 5-Mar-2021", [1]), ("SINCE 5-Mar-2021", [1, 3, 4]),
                    ('ON "31-Dec-2023"', [4]), ("SINCE 1-Jan-2024", []),
                    # The Date header's day in its own zone: 23:30 -0500 is 5 March there (6 March in UTC).
                    ("SENTON 5-Mar-2021", [1]), ("SENTON 6-Mar-2021", []), ("SENTON 9-Jun-2022", [3]),
                    # No Date header reads as 1 January 1970, as in Dovecot.
                    ("SENTBEFORE 1-Jan-2000", [2]), ("SENTON 1-Jan-1970", [2]), ("SENTSINCE 9-Jun-2022", [3, 4]),
                    (f"LARGER {size4 - 1}", [4]), (f"LARGER {size4}", []), (f"SMALLER {size4}", [1, 2, 3]),
                    ("SMALLER 1", [])])

    def test_headers(self):
        self.check([("FROM alice", [1]), ("FROM ALICE", [1]), ('FROM "andré"'.encode(), [2]),
                    ("FROM @remote.test", [1, 2, 3, 4]), ("TO bob", [1, 3]), ("CC dave", [3]), ("BCC eve", [3]),
                    ("BCC remote", [3]), ('SUBJECT "quarterly REPORT"', [1]), ('SUBJECT "café"'.encode(), [2]),
                    ("SUBJECT \"\"", [1, 2, 3, 4]), ("HEADER X-Priority 1", [3]), ('HEADER x-empty ""', [3]),
                    ('HEADER X-Missing ""', []), ('HEADER Message-ID "<q1@"', [1]), ("HEADER Date -0700", [3])])

    def test_body_and_text(self):
        self.check([("BODY numbers", [1]), ("BODY Quarterly", []), ("TEXT Quarterly", [1]),
                    ('BODY "crème brûlée"'.encode(), [2]), ("BODY <b>", []),
                    ('BODY "Grüße aus köln"'.encode(), [3]), ('BODY "Schluß"'.encode(), [3]),
                    ("BODY needle", []), ("BODY \"tail word\"", [4]), ("TEXT alice", [1, 2, 4]),
                    ("TEXT x-priority", [3]), ("BODY \"\"", [1, 2, 3, 4])])

    def test_sets_and_logic(self):
        u = self.uids
        self.check([("2", [2]), ("2:*", [2, 3, 4]), ("*", [4]), ("*:3", [3, 4]), ("1,3", [1, 3]),
                    (f"UID {u[1]}", [2]), (f"UID {u[2]}:*", [3, 4]), (f"UID {u[3] + 100}:*", [4]),
                    ("NOT SEEN", [2, 3, 4]), ("NOT NOT SEEN", [1]), ("OR SEEN FLAGGED", [1, 2]),
                    ("OR OR SEEN FLAGGED DRAFT", [1, 2, 3]), ("OR (SEEN ANSWERED) (DRAFT DELETED)", [1, 3]),
                    ("NOT (OR SEEN FLAGGED)", [3, 4]), ("(FROM bob)", [4]), ("((((FROM bob))))", [4]),
                    ("SINCE 1-Jan-2021 NOT (OR BODY numbers SUBJECT big)", [3]),
                    ('OR NOT BODY "grüße" UNDRAFT 2:3', [2]),
                    # An 8-bit atom is not an atom: it must be quoted or a literal.
                    ("BODY grüße", None),
                    ("UNSEEN OR TEXT bob (NOT 4 FROM andre)", [2, 3, 4]), ("NOT (SEEN) NOT 4 TEXT bob", [3])])

    def test_charset_literals_and_errors(self):
        r = self.r
        self.assertEqual(self.seqs(b"CHARSET UTF-8 FROM alice"), [1])
        self.assertEqual(self.seqs(b"charset us-ascii SUBJECT report"), [1])
        self.assertEqual(r.cmd(b"b", b"SEARCH CHARSET ISO-8859-1 FROM alice"),
                         [b"b NO [BADCHARSET (UTF-8 US-ASCII)] Unsupported charset\r\n"])
        # A synchronizing literal, UTF-8.
        word = "brûlée".encode()
        r.send(b"l1 SEARCH CHARSET UTF-8 BODY {" + str(len(word)).encode() + b"}\r\n")
        self.assertTrue(r.line().startswith(b"+ "))
        r.send(word + b" FLAGGED\r\n")
        self.assertEqual(search_result(r.until(b"l1")), [2])
        # LITERAL+, and two literals in one command.
        k = "Köln".encode()
        r.send(b"l2 SEARCH OR BODY {" + str(len(k)).encode() + b"+}\r\n" + k + b" SUBJECT {3+}\r\nBIG\r\n")
        self.assertEqual(search_result(r.until(b"l2")), [3, 4])
        for bad, reason in [(b"FOO", b"unknown search key"), (b"", b"missing argument"),
                            (b"OR SEEN", b"missing argument"), (b"SINCE 31-Feb-2020", b"invalid date"),
                            (b"LARGER x", b"expected a number"), (b"(SEEN", b"unbalanced parentheses"),
                            (b"0", b"invalid sequence set"), (b"UID x", b"invalid sequence set")]:
            with self.subTest(bad=bad):
                got = r.cmd(b"e", b"SEARCH " + bad if bad else b"SEARCH")
                self.assertEqual(got[-1], b"e BAD " + reason + b"\r\n")
        self.assertEqual(r.cmd(b"x", b"SEARCH 9")[-1], b"x OK SEARCH completed\r\n")

    def test_uid_search(self):
        u = self.uids
        responses = self.r.cmd(b"u", b"UID SEARCH OR SEEN DRAFT")
        self.assertTrue(responses[-1].startswith(b"u OK UID SEARCH completed"), responses)
        self.assertEqual(search_result(responses), [u[0], u[2]])
        self.assertEqual(search_result(self.r.cmd(b"v", b"UID SEARCH 2:3 UID " + str(u[2]).encode() + b":*")), [u[2]])
        self.assertEqual(search_result(self.r.cmd(b"w", b"UID SEARCH ALL")), u)
        with imaps() as c:
            c.select(self.name, readonly=True)
            typ, data = c.uid("SEARCH", "CHARSET", "UTF-8", "BODY", "numbers")
            self.assertEqual((typ, data), ("OK", [str(u[0]).encode()]))
            typ, data = c.search(None, "(OR FROM alice FROM bob)")
            self.assertEqual(data, [b"1 4"])

    def test_after_expunge(self):
        name = search_folder()
        uids = db_uids(USER, name)
        with Raw() as a, Raw() as b:
            a.login()
            b.login()
            a.ok(b"s", b"SELECT " + name.encode())
            b.ok(b"s", b"SELECT " + name.encode())
            # Another session expunges message 2: SEARCH must not announce it, and keeps the numbers a knows.
            b.ok(b"d", b"UID STORE " + str(uids[1]).encode() + b" +FLAGS.SILENT (\\Deleted)")
            b.ok(b"e", b"UID EXPUNGE " + str(uids[1]).encode())
            got = a.cmd(b"t", b"SEARCH ALL")
            self.assertFalse([x for x in got if b"EXPUNGE" in x], got)
            self.assertEqual(search_result(got), [1, 3, 4])
            self.assertEqual(search_result(a.cmd(b"u", b"SEARCH FROM carol")), [3])
            # UID SEARCH may announce it.
            got = a.cmd(b"v", b"UID SEARCH FROM carol")
            self.assertIn(b"* 2 EXPUNGE\r\n", got)
            self.assertEqual(search_result(got), [uids[2]])
            # Now renumbered.
            self.assertEqual(search_result(a.cmd(b"w", b"SEARCH FROM carol")), [2])
            self.assertEqual(search_result(a.cmd(b"x", b"SEARCH 3")), [3])
            self.assertEqual(search_result(a.cmd(b"y", b"SEARCH UNDELETED")), [1, 3])
            # Its own EXPUNGE, then SEARCH.
            a.ok(b"z", b"EXPUNGE")
            self.assertEqual(search_result(a.cmd(b"z2", b"SEARCH ALL")), [1, 2])
            self.assertEqual(search_result(a.cmd(b"z3", b"SEARCH SUBJECT big")), [2])
            # A delivery to the mailbox shows after SEARCH, as an EXISTS.
            append_raw(b, name, "", "01-Jan-2024 00:00:00 +0000", simple("late"))
            got = a.cmd(b"z4", b"SEARCH SUBJECT late")
            self.assertEqual(search_result(got), [])
            self.assertIn(b"* 3 EXISTS\r\n", got)
            self.assertEqual(search_result(a.cmd(b"z5", b"SEARCH SUBJECT late")), [3])

    def test_smtp_delivered_and_many(self):
        # Messages delivered through SMTP (meta stored by SMTP), more than one batch's worth of numbers.
        name = folder_with([simple(f"many{i}", f"Body number {i}.\r\n") for i in range(1, 13)])
        with Raw() as r:
            r.login()
            r.ok(b"s", b"EXAMINE " + name.encode())
            self.assertEqual(search_result(r.cmd(b"a", b"SEARCH BODY \"number 1\"")), [1, 10, 11, 12])
            self.assertEqual(search_result(r.cmd(b"b", b"SEARCH SUBJECT many1 NOT BODY \"number 11\"")), [1, 10, 12])
            self.assertEqual(search_result(r.cmd(b"c", b"SEARCH SENTON 5-Nov-2026 7:8")), [7, 8])


# A large multipart message built from known pieces: a text part, a 10 MB base64 attachment, and an attached message
# with a 1 MB body. Its sections are long enough to be streamed from the blob (more than 64 KiB).
BIG_P1_HDR = b"Content-Type: text/plain; charset=us-ascii\r\n\r\n"
BIG_P1_BODY = b"See the attachment.\r\n"
BIG_P2_HDR = b"Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n"
BIG_P3_HDR = b"Content-Type: message/rfc822\r\n\r\n"
BIG_INNER_HDR = b"From: Inner <inner@remote.test>\r\nSubject: inner big\r\nContent-Type: text/plain\r\n\r\n"


@functools.lru_cache(maxsize=None)
def big_pieces(seed: int) -> tuple:
    raw = bytes((i * 131 + seed * 7 + (i >> 9)) & 0xff for i in range(7_500_000))
    encoded = base64.encodebytes(raw).replace(b"\n", b"\r\n")
    inner_body = b"".join(b"Inner line %07d of the attached message.\r\n" % k for k in range(25_000))
    return encoded, inner_body


def big_message(subject: str, seed: int = 1) -> tuple:
    """(the message, its attachment's encoded body, the inner message's body)."""
    encoded, inner_body = big_pieces(seed)
    header = (f"From: Sender <sender@remote.test>\r\nTo: imap@example.org\r\nSubject: {subject}\r\n"
              f"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"BIG\"\r\n\r\n").encode()
    message = (header + b"--BIG\r\n" + BIG_P1_HDR + BIG_P1_BODY + b"\r\n--BIG\r\n" + BIG_P2_HDR + encoded +
               b"\r\n--BIG\r\n" + BIG_P3_HDR + BIG_INNER_HDR + inner_body + b"\r\n--BIG--\r\n")
    return message, encoded, inner_body


def append_big(r: Raw, tag: bytes, name: str, message: bytes, synchronizing: bool = True) -> int:
    """APPENDs `message` to `name` and gives its UID (APPENDUID)."""
    marker = b"{%d}" % len(message) if synchronizing else b"{%d+}" % len(message)
    r.send(tag + b" APPEND " + name.encode() + b" " + marker + b"\r\n")
    if synchronizing:
        line = r.line()
        assert line.startswith(b"+ "), line
    r.send(message + b"\r\n")
    done = r.until(tag)[-1]
    m = re.match(tag + rb" OK \[APPENDUID \d+ (\d+)\] APPEND completed\r\n", done)
    assert m, done
    return int(m.group(1))


def blob_files(name: str) -> bytes:
    blob = sql(f"SELECT encode(m.blob, 'hex') FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id "
               f"WHERE b.name = '{name}' ORDER BY m.uid LIMIT 1")
    with open(os.path.join(os.environ["MAILSERVER_BLOBS"], blob[0:2], blob[2:4], blob), "rb") as f:
        return f.read()


def temporary_blobs() -> set:
    tmp = os.path.join(os.environ["MAILSERVER_BLOBS"], "tmp")
    return {n for n in os.listdir(tmp) if n.endswith(".part")}


class LargeMessages(unittest.TestCase):
    """Slice 4: FETCH streams sections from the blob (sendfile on plaintext, pieces over TLS) and APPEND streams its
    literal into the blob, so neither holds a message in memory. A 10 MB message, fetched whole, in partials at its
    start, middle and end, and by part, over plaintext and TLS, compared byte for byte with what was appended."""

    @classmethod
    def setUpClass(cls):
        cls.name = unique("Big")
        cls.message, cls.encoded, cls.inner_body = big_message(cls.name)
        assert len(cls.message) > 10_000_000 and len(cls.message) < MAX_APPEND, len(cls.message)
        with Raw() as r:
            r.login()
            r.ok(b"a", b"CREATE " + cls.name.encode())
            cls.uid = append_big(r, b"b", cls.name, cls.message)

    def fetch_all(self, r: Raw):
        m, size = self.message, len(self.message)
        header = m[:m.index(b"\r\n\r\n") + 4]
        r.ok(b"s", b"SELECT " + self.name.encode())
        (_, items), = fetches(r.cmd(b"f1", b"FETCH 1 (UID RFC822.SIZE BODY.PEEK[] BODY.PEEK[]<0.1000> "
                                           b"BODY.PEEK[]<5000000.100000> BODY.PEEK[]<%d.1000000> "
                                           b"BODY.PEEK[]<%d.10>)" % (size - 200_000, size + 5)))
        self.assertEqual(int(items["UID"]), self.uid)
        self.assertEqual(int(items["RFC822.SIZE"]), size)
        self.assertEqual(items["BODY[]"], m, "whole")
        self.assertEqual(items["BODY[]<0>"], m[:1000], "the start")
        self.assertEqual(items["BODY[]<5000000>"], m[5_000_000:5_100_000], "the middle")
        self.assertEqual(items["BODY[]<%d>" % (size - 200_000)], m[-200_000:], "the end, clipped")
        self.assertEqual(items["BODY[]<%d>" % (size + 5)], b"", "past the end")
        (_, items), = fetches(r.cmd(b"f2", b"FETCH 1 (BODY.PEEK[HEADER] BODY.PEEK[TEXT] BODY.PEEK[1] BODY.PEEK[2] "
                                           b"BODY.PEEK[2.MIME] BODY.PEEK[3] BODY.PEEK[3.HEADER] BODY.PEEK[3.TEXT] "
                                           b"BODY.PEEK[3.1] BODY.PEEK[2]<1000.200000> BODY.PEEK[3.TEXT]<900000.1000> "
                                           b"BODY.PEEK[HEADER.FIELDS (Subject)] BODYSTRUCTURE)"))
        self.assertEqual(items["BODY[HEADER]"], header)
        self.assertEqual(items["BODY[TEXT]"], m[len(header):])
        self.assertEqual(items["BODY[1]"], BIG_P1_BODY)
        self.assertEqual(items["BODY[2]"], self.encoded)
        self.assertEqual(items["BODY[2.MIME]"], BIG_P2_HDR)
        self.assertEqual(items["BODY[3]"], BIG_INNER_HDR + self.inner_body)
        self.assertEqual(items["BODY[3.HEADER]"], BIG_INNER_HDR)
        self.assertEqual(items["BODY[3.TEXT]"], self.inner_body)
        self.assertEqual(items["BODY[3.1]"], self.inner_body)
        self.assertEqual(items["BODY[2]<1000>"], self.encoded[1000:201_000])
        self.assertEqual(items["BODY[3.TEXT]<900000>"], self.inner_body[900_000:901_000])
        self.assertEqual(items["BODY[HEADER.FIELDS (Subject)]"], b"Subject: " + self.name.encode() + b"\r\n\r\n")
        attachment = items["BODYSTRUCTURE"][1]
        self.assertEqual(attachment[:2], [b"application", b"octet-stream"])
        self.assertEqual(int(attachment[6]), len(self.encoded))
        # RFC822 and BODY[] set \Seen once, in the same response, after the items asked for, as for small messages.
        out = r.cmd(b"f3", b"FETCH 1 (RFC822.SIZE BODY[2]<0.100000> RFC822)")
        (_, items), = fetches(out)
        self.assertEqual(list(items), ["RFC822.SIZE", "BODY[2]<0>", "RFC822", "FLAGS"])
        self.assertEqual(items["BODY[2]<0>"], self.encoded[:100_000])
        self.assertEqual(items["RFC822"], m)
        self.assertEqual(items["FLAGS"], [b"\\Seen"])
        r.ok(b"u", b"STORE 1 -FLAGS.SILENT (\\Seen)")
        r.ok(b"z", b"UNSELECT")

    def test_stored_as_appended(self):
        self.assertEqual(blob_files(self.name), self.message)
        self.assertEqual(sql(f"SELECT meta IS NOT NULL FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id "
                             f"WHERE b.name = '{self.name}'"), "t", "indexed as it was written")

    def test_fetch_over_tls(self):
        with Raw() as r:
            r.login()
            self.fetch_all(r)

    @unittest.skipUnless(PLAINTEXT_AUTH, "logging in over plaintext needs IMAP_PLAINTEXT_AUTH=true")
    def test_fetch_over_plaintext(self):
        with Raw(tls=False) as r:
            r.login()
            self.fetch_all(r)

    def test_fetch_many_with_imaplib(self):
        """Two large literals per message and small ones between, for an independent client's parser."""
        c = imaps()
        c.select(self.name, readonly=True)
        typ, data = c.fetch("1", "(BODY.PEEK[1] BODY.PEEK[2] UID BODY.PEEK[3.TEXT])")
        self.assertEqual(typ, "OK")
        literals = [part[1] for part in data if isinstance(part, tuple)]
        self.assertEqual(literals, [BIG_P1_BODY, self.encoded, self.inner_body])
        c.logout()

    def append_back(self, tls: bool, synchronizing: bool):
        name = unique("BigApp")
        message, encoded, _ = big_message(name, seed=3 if tls else 4)
        with Raw(tls=tls) as r:
            r.login()
            r.ok(b"a", b"CREATE " + name.encode())
            uid = append_big(r, b"b", name, message, synchronizing)
            self.assertEqual([uid], db_uids(USER, name))
            r.ok(b"c", b"EXAMINE " + name.encode())
            (_, items), = fetches(r.cmd(b"d", b"FETCH 1 (BODY.PEEK[] BODY.PEEK[2])"))
            self.assertEqual(items["BODY[]"], message)
            self.assertEqual(items["BODY[2]"], encoded, "the part index made while streaming")
        self.assertEqual(blob_files(name), message)

    def test_append_large_tls(self):
        self.append_back(tls=True, synchronizing=True)

    def test_append_large_literal_plus(self):
        self.append_back(tls=True, synchronizing=False)

    @unittest.skipUnless(PLAINTEXT_AUTH, "logging in over plaintext needs IMAP_PLAINTEXT_AUTH=true")
    def test_append_large_plaintext(self):
        self.append_back(tls=False, synchronizing=True)

    def test_append_aborted_mid_literal(self):
        """The client goes away halfway through the literal: no blob row, no temporary file, and the session ends."""
        blobs, temporary = sql("SELECT count(*) FROM blobs"), temporary_blobs()
        messages = len(db_uids(USER, "INBOX"))
        logged = len(watches_logged())
        message, _, _ = big_message(unique("Abort"), seed=5)
        r = Raw()
        r.login()
        r.ok(b"a", b"SELECT INBOX")
        r.send(b"b APPEND INBOX {%d}\r\n" % len(message))
        self.assertTrue(r.line().startswith(b"+ "))
        r.send(message[:len(message) // 2])
        time.sleep(0.3)
        r.sock.close()
        # The session ends (it had selected INBOX, so its end is logged), and has removed its temporary file.
        deadline = time.time() + 10
        while len(watches_logged()) == logged and time.time() < deadline:
            time.sleep(0.05)
        self.assertGreater(len(watches_logged()), logged, "the session is gone")
        self.assertEqual(sql("SELECT count(*) FROM blobs"), blobs, "no blob row")
        self.assertEqual(temporary_blobs() - temporary, set(), "no temporary file")
        self.assertEqual(len(db_uids(USER, "INBOX")), messages)

    def test_too_big_refused_before_reading(self):
        with Raw() as r:
            r.login()
            # Synchronizing: refused at once, no "+", nothing read.
            started = time.time()
            r.send(b"a APPEND INBOX {%d}\r\n" % (MAX_APPEND + 1))
            self.assertTrue(r.line().startswith(b"a NO [TOOBIG]"))
            self.assertLess(time.time() - started, 2)
            r.ok(b"b", b"NOOP")
            # A refused synchronizing literal of an acceptable size (no such mailbox): no "+" either.
            r.send(b"c APPEND NoSuchBox%d {5000000}\r\n" % int(time.time()))
            self.assertTrue(r.line().startswith(b"c NO [TRYCREATE]"))
            r.ok(b"d", b"NOOP")
            # More after the message is a BAD, and the message is not kept.
            blobs = sql("SELECT count(*) FROM blobs")
            r.send(b"e APPEND INBOX {5}\r\n")
            self.assertTrue(r.line().startswith(b"+ "))
            r.send(b"hello extra\r\n")
            self.assertTrue(r.until(b"e")[-1].startswith(b"e BAD"))
            self.assertEqual(sql("SELECT count(*) FROM blobs"), blobs)
            r.ok(b"f", b"NOOP")


def exists_of(responses) -> int:
    for line in responses:
        m = re.match(rb"\* (\d+) EXISTS\r\n", line)
        if m:
            return int(m.group(1))
    raise AssertionError(f"no EXISTS in {responses!r}")


def watches_logged() -> list:
    """The server's `imap: mailbox watches N` lines (run.sh's SERVER_LOG), as numbers."""
    with open(os.environ["SERVER_LOG"]) as f:
        return [int(m.group(1)) for m in re.finditer(r"imap: mailbox watches (\d+)", f.read())]


class NotifyBus(unittest.TestCase):
    """Slice 2: IDLE learns of changes from the in-process notify bus at once, not by polling. Each test measures the
    time from the change's command returning to the idling client reading the update, and asserts it is well under
    the old 2-second poll (IDLE_LATENCY)."""

    wait_for = Concurrent.wait_for

    def idle(self, client: Raw, tag: bytes = b"i"):
        client.send(tag + b" IDLE\r\n")
        self.assertEqual(client.line(), b"+ idling\r\n")

    def done(self, client: Raw, tag: bytes = b"i"):
        client.sock.settimeout(10)
        client.send(b"DONE\r\n")
        self.assertEqual(client.until(tag)[-1], tag + b" OK IDLE terminated\r\n")

    def latency(self, client: Raw, pattern: bytes, since: float, what: str) -> float:
        self.wait_for(client, pattern, seconds=10)
        took = time.time() - since
        print(f"\n    IDLE latency, {what}: {took * 1000:.1f} ms", file=sys.stderr, end="")
        self.assertLess(took, IDLE_LATENCY, what)
        return took

    def quiet(self, client: Raw, seconds: float):
        """Nothing arrives within `seconds`."""
        client.sock.settimeout(seconds)
        try:
            data = client.sock.recv(65536)
        except (socket.timeout, TimeoutError):
            return
        self.fail(f"unexpected {data!r}")

    def test_smtp_delivery_wakes_idle(self):
        with Raw() as a:
            a.login(USER2, PASSWORD2)
            n = exists_of(a.ok(b"a1", b"SELECT INBOX"))
            self.idle(a)
            deliver(USER2, simple(unique("bus")))
            self.latency(a, rb"\* %d EXISTS\r\n" % (n + 1), time.time(), "SMTP delivery")
            self.done(a)

    def test_store_and_expunge_wake_idle(self):
        name = folder_with([simple("s1"), simple("s2"), simple("s3")])
        n = name.encode()
        with Raw() as a, Raw() as b:
            a.login()
            b.login()
            a.ok(b"a1", b"SELECT " + n)
            b.ok(b"b1", b"SELECT " + n)
            self.idle(a)
            b.ok(b"b2", b"STORE 1 +FLAGS.SILENT (\\Flagged)")
            self.latency(a, rb"\* 1 FETCH \(FLAGS \(\\Flagged\)\)\r\n", time.time(), "STORE")
            b.ok(b"b3", b"STORE 2 +FLAGS.SILENT (\\Deleted)")
            self.latency(a, rb"\* 2 FETCH \(FLAGS \(\\Deleted\)\)\r\n", time.time(), "STORE \\Deleted")
            b.ok(b"b4", b"EXPUNGE")
            self.latency(a, rb"\* 2 EXPUNGE\r\n", time.time(), "EXPUNGE")
            self.done(a)
            self.assertEqual(a.cmd(b"a2", b"NOOP"), [b"a2 OK NOOP completed\r\n"], "nothing reported twice")

    def test_move_out_wakes_idle(self):
        name = folder_with([simple("m1"), simple("m2")])
        n = name.encode()
        other = unique("Out").encode()
        with Raw() as a, Raw() as b:
            a.login()
            b.login()
            b.ok(b"b0", b"CREATE " + other)
            a.ok(b"a1", b"SELECT " + n)
            b.ok(b"b1", b"SELECT " + n)
            self.idle(a)
            b.ok(b"b2", b"MOVE 1 " + other)
            self.latency(a, rb"\* 1 EXPUNGE\r\n", time.time(), "MOVE out")
            self.done(a)
            got = fetches(a.cmd(b"a2", b"FETCH 1:* UID"))
            self.assertEqual([int(i["UID"]) for _, i in got], db_uids(USER, name))

    def test_other_mailbox_does_not_wake_idle(self):
        quiet_box = folder_with([simple("q1")])
        busy_box = folder_with([simple("b1"), simple("b2")])
        with Raw() as a, Raw() as b:
            a.login()
            b.login()
            a.ok(b"a1", b"SELECT " + quiet_box.encode())
            b.ok(b"b1", b"SELECT " + busy_box.encode())
            self.idle(a)
            b.ok(b"b2", b"STORE 1:* +FLAGS.SILENT (\\Flagged)")
            b.ok(b"b3", b"STORE 1 +FLAGS.SILENT (\\Deleted)")
            b.ok(b"b4", b"EXPUNGE")
            msg = simple("b3")
            b.ok(b"b5", b"APPEND " + busy_box.encode() + b" {" + str(len(msg)).encode() + b"+}\r\n" + msg)
            self.quiet(a, 1.0)
            # Still idling, and still woken by its own mailbox.
            b.ok(b"b6", b"SELECT " + quiet_box.encode())
            b.ok(b"b7", b"STORE 1 +FLAGS.SILENT (\\Seen)")
            self.latency(a, rb"\* 1 FETCH \(FLAGS \(\\Seen\)\)\r\n", time.time(), "STORE after quiet")
            self.done(a)

    def test_relay_bounce_wakes_idle(self):
        """A bounce reaches relay@example.org's INBOX through the relay's settle (a local delivery from the queue,
        not from a session). The time is from the row showing in the database (polled with psql) to the EXISTS."""
        with Raw() as a:
            a.login("relay@example.org", "relay-pw")
            n = exists_of(a.ok(b"a1", b"SELECT INBOX"))
            self.idle(a)
            arrived = []

            def read():
                try:
                    self.wait_for(a, rb"\* %d EXISTS\r\n" % (n + 1), seconds=30)
                    arrived.append(time.time())
                except BaseException as e:  # noqa: B036
                    arrived.append(e)

            reader = threading.Thread(target=read)
            reader.start()
            marker = f"bus-bounce-{time.time()}"
            with smtplib.SMTP(HOST, SUBMISSION) as c:
                c.starttls(context=tls_context())
                c.login("relay@example.org", "relay-pw")
                # A new address each run: one that bounced recently is refused at once (the suppression list).
                c.sendmail("relay@example.org", [f"reject-{int(time.time() * 1000)}@remote.test"],
                           f"From: relay@example.org\r\nSubject: {marker}\r\n\r\nbounce me\r\n")
            stored = None
            deadline = time.time() + 30
            while time.time() < deadline and stored is None:
                if int(sql("SELECT b.messages FROM mailboxes b JOIN users u ON u.id = b.user_id "
                           "WHERE u.email = 'relay@example.org' AND b.name = 'INBOX'")) > n:
                    stored = time.time()
                elif not arrived:
                    time.sleep(0.02)
                else:
                    stored = time.time()
            reader.join(35)
            self.assertTrue(arrived and isinstance(arrived[0], float), arrived)
            took = arrived[0] - stored
            print(f"\n    IDLE latency, relay bounce: {took * 1000:.1f} ms after psql saw the row "
                  f"(negative: before)", file=sys.stderr, end="")
            self.assertLess(took, IDLE_LATENCY)
            self.done(a)

    def test_many_idlers_and_the_registry_empties(self):
        count = int(os.environ.get("IDLERS", "50"))
        clients = []
        try:
            for i in range(count):
                c = Raw()
                c.login(USER2, PASSWORD2)
                n = exists_of(c.ok(b"a1", b"SELECT INBOX"))
                self.idle(c)
                clients.append(c)
            arrived = [None] * count

            def read(i):
                try:
                    self.wait_for(clients[i], rb"\* %d EXISTS\r\n" % (n + 1), seconds=15)
                    arrived[i] = time.time()
                except BaseException as e:  # noqa: B036
                    arrived[i] = e

            readers = [threading.Thread(target=read, args=(i,)) for i in range(count)]
            for r in readers:
                r.start()
            deliver(USER2, simple(unique("many")))
            sent = time.time()
            for r in readers:
                r.join(20)
            failed = [a for a in arrived if not isinstance(a, float)]
            self.assertEqual(failed, [])
            took = sorted(a - sent for a in arrived)
            print(f"\n    IDLE latency, {count} idlers, one delivery: median {took[count // 2] * 1000:.1f} ms, "
                  f"max {took[-1] * 1000:.1f} ms", file=sys.stderr, end="")
            self.assertLess(took[-1], IDLE_LATENCY * 2)
            for c in clients:
                self.done(c)
                c.ok(b"z", b"LOGOUT")
        finally:
            for c in clients:
                c.close()
        if "SERVER_LOG" not in os.environ:
            return
        # Every watch has ended: a last session's count (after its own watch is gone) is 0. Sessions of other tests
        # that the server has not yet seen close may still count, so this retries briefly.
        deadline, last = time.time() + 10, None
        while time.time() < deadline:
            before = len(watches_logged())
            with Raw() as p:
                p.login()
                p.ok(b"p1", b"SELECT INBOX")
                p.ok(b"p2", b"LOGOUT")
            while len(watches_logged()) == before and time.time() < deadline:
                time.sleep(0.05)
            last = watches_logged()[-1]
            if last == 0:
                break
            time.sleep(0.3)
        self.assertEqual(last, 0, "the watch registry is empty")


if __name__ == "__main__":
    unittest.main(verbosity=2)
