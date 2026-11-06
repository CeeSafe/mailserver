#!/usr/bin/env python3
"""Black-box tests of `mailserver import-cosmomail` (run.sh --import): a CosmoMailServer database (its own schema,
cosmomail_schema.sql) in the test Postgres as cosmomail_src, with message content in it and in a strict fake S3
(fakes3.py, port 52950), copied into the running server's store; then checked over SQL, IMAP and the admin API, and
copied again after the source changed (new, re-flagged and expunged messages); calendars and contacts, read back over
CalDAV and CardDAV, and copied again after an event changed and another was deleted."""
import hashlib, http.client, imaplib, json, os, re, subprocess, sys, unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from smtp_test import admin, sql, tls_context  # noqa: E402
from dav_test import dav, ok, responses  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
S3_ROOT = os.environ["S3_ROOT"]
S3_LOG = os.environ["S3_LOG"]
# bcrypt of "import-pw-1" (htpasswd -bnBC 10), as CosmoMail stores them.
HASH = "$2y$10$4FRjTtsMibGCA.MzxRr8iuph9erqpXATL78jEUpxqOiw/VVNFpiuO"


def source(query: str, stdin: str = None) -> str:
    out = subprocess.run(["docker", "exec", "-i", "ceesafe-pg-test", "psql", "-v", "ON_ERROR_STOP=1", "-At", "-q",
                          "-U", "cee", "-d", "cosmomail_src", *(["-c", query] if query else [])],
                         input=stdin, capture_output=True, check=True, text=True)
    return out.stdout.strip()


def put(locator: str, content: bytes):
    path = os.path.join(S3_ROOT, locator)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(content)


def literal(b: bytes) -> str:
    return "'\\x" + b.hex() + "'::bytea"


def message(subject: str) -> bytes:
    return (f"From: someone@remote.test\r\nTo: ann@legacy.example\r\nSubject: {subject}\r\n"
            f"Date: Mon, 2 Jun 2025 10:00:00 +0000\r\nMessage-ID: <{subject.replace(' ', '.')}@remote.test>\r\n\r\n"
            f"Body of {subject}.\r\n").encode()


# Bare LF line ends, as some old imports stored them.
LF_MESSAGE = b"From: a@remote.test\nSubject: bare lf\n\nline one\nline two\n"
S3_MESSAGE = message("from s3")
KV_MESSAGE = message("from cosmokvd")
ARCHIVE_MESSAGE = message("archived")


def ics(uid: str, summary: str, start: str = "DTSTART:20261110T090000Z") -> str:
    return ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VTIMEZONE\r\nTZID:Europe/Paris\r\nEND:VTIMEZONE\r\n"
            f"BEGIN:VEVENT\r\nUID:{uid}\r\n{start}\r\nDTEND:20261110T100000Z\r\nSUMMARY:{summary}\r\n"
            "END:VEVENT\r\nEND:VCALENDAR\r\n")


def etag(data: str) -> str:
    """The C# server's etag: the first 32 hex digits of the SHA-256."""
    return hashlib.sha256(data.encode()).hexdigest()[:32]


def quoted(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


# Events: one with a TZID start (whose facts the import reads), one plain, one deleted; one vCard.
EVENT_TZ = ics("ev-tz@legacy", "Team lunch", "DTSTART;TZID=Europe/Paris:20261110T120000")
EVENT_PLAIN = ics("ev-plain@legacy", "Dentist")
EVENT_GONE = ics("ev-gone@legacy", "Cancelled")
VCARD = "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:card-1\r\nFN:Carl Contact\r\nEND:VCARD\r\n"


def seed():
    subprocess.run(["docker", "exec", "ceesafe-pg-test", "psql", "-q", "-U", "cee", "-d", "ceetest",
                    "-c", "DROP DATABASE IF EXISTS cosmomail_src WITH (FORCE)", "-c", "CREATE DATABASE cosmomail_src"],
                   capture_output=True, check=True)
    with open(os.path.join(HERE, "cosmomail_schema.sql")) as f:
        source(None, f.read())
    openssl = "/opt/homebrew/opt/openssl@3/bin/openssl"
    if not os.path.exists(openssl):
        openssl = "openssl"
    pem = subprocess.run([openssl, "genrsa", "-traditional", "2048"], capture_output=True, check=True, text=True).stdout
    assert "BEGIN RSA PRIVATE KEY" in pem
    pem_sql = pem.replace("'", "''")
    source(f"""
        INSERT INTO domains (id, name, dkim_selector, dkim_private_key, dkim_signing_enabled, spf_enabled,
                             mta_sts_mode, mta_sts_mx_patterns, catchall_email)
        VALUES (1, 'Legacy.Example', 'mail', '{pem_sql}', true, true, 'enforce', 'mx1.legacy.example', NULL),
               (2, 'quiet.example', NULL, NULL, false, false, 'none', NULL, 'ann@legacy.example');
        INSERT INTO domain_aliases (alias_domain, target_domain_id) VALUES ('legacy-alias.example', 1);
        INSERT INTO users (id, email, password_hash, domain_id, quota, forward_to)
        VALUES (1, 'ann@legacy.example', '{HASH}', 1, 1073741824, 'ann@elsewhere.test'),
               (2, 'Bob@Legacy.Example', '{HASH}', 1, 0, NULL);
        INSERT INTO admin_users (username, password_hash, role, domain_id)
        VALUES ('legacyadmin', '{HASH}', 'server', NULL), ('legacyorg', '{HASH}', 'domain', 1),
               ('stranger', '{HASH}', 'super', NULL);
        INSERT INTO aliases (domain_id, email, destination) VALUES (1, 'Info@legacy.example', 'ann@legacy.example');
        INSERT INTO mailboxes (id, user_id, name, special_use, uid_validity, uid_next)
        VALUES (1, 1, 'INBOX', NULL, 1700000000, 10), (2, 1, 'Archive/2024', '\\Archive', 1700000001, 3),
               (3, 1, 'Bad//Name', NULL, 1700000002, 1), (4, 2, 'INBOX', NULL, 1700000003, 1),
               (5, 1, 'Spam', '\\Junk', 1700000004, 1);
        INSERT INTO messages (user_id, mailbox_id, uid, received_at, internal_date, size, flags, is_seen, is_deleted,
                              content, content_path, storage_type)
        VALUES (1, 1, 1, now(), '2025-06-02 10:00:00+00', {len(LF_MESSAGE)}, '["\\\\Seen","$Label1"]', true, false,
                {literal(LF_MESSAGE)}, NULL, 'database'),
               (1, 1, 2, now(), '2025-06-03 10:00:00+00', {len(S3_MESSAGE)}, '["\\\\Flagged","bad(kw"]', false,
                false, NULL, 'mailstore/1/1/0000000002.eml', 's3'),
               (1, 1, 5, now(), '2025-06-04 10:00:00+00', {len(KV_MESSAGE)}, '[]', false, true,
                NULL, '1/1/0000000005.eml', 'cosmokvd'),
               (1, 1, 7, now(), '2025-06-05 10:00:00+00', 100, '[]', false, false,
                NULL, 'mailstore/1/1/0000000007.eml', 's3'),
               (1, 2, 1, now(), '2024-01-01 10:00:00+00', {len(ARCHIVE_MESSAGE)}, '["\\\\Seen","\\\\Answered"]',
                true, false, {literal(ARCHIVE_MESSAGE)}, NULL, 'database');
        INSERT INTO sieve_scripts (user_id, name, content, active)
        VALUES (1, 'filters', 'require "fileinto";\nif header :contains "Subject" "offer" {{ fileinto "Spam"; }}', true),
               (1, 'second', 'keep;', true);
    """)
    put("mailstore/1/1/0000000002.eml", S3_MESSAGE)
    put("mailstore/1/1/0000000005.eml", KV_MESSAGE)  # CosmoKvD's locator has no bucket: the configured one
    source(f"""
        INSERT INTO calendars (id, user_id, name, description, color, sync_token)
        VALUES (1, 1, 'Default', 'Default Calendar', '#0078D4', 4), (2, 1, 'Work', NULL, '#FF0000', 0);
        INSERT INTO calendar_events (calendar_id, uid, ics_data, etag, deleted)
        VALUES (1, 'ev-tz', {quoted(EVENT_TZ)}, '{etag(EVENT_TZ)}', false),
               (1, 'ev-plain', {quoted(EVENT_PLAIN)}, '{etag(EVENT_PLAIN)}', false),
               (1, 'ev-gone', {quoted(EVENT_GONE)}, '{etag(EVENT_GONE)}', true);
        INSERT INTO address_books (id, user_id, name, description) VALUES (1, 1, 'Default', 'Default Address Book');
        INSERT INTO contacts (address_book_id, uid, v_card_data, etag)
        VALUES (1, 'card-1', {quoted(VCARD)}, '{etag(VCARD)}');
    """)


def run_import() -> str:
    out = admin("import-cosmomail")
    if out.returncode != 0:
        raise AssertionError("import-cosmomail failed:\n" + out.stdout + out.stderr)
    return out.stderr


def imap():
    c = imaplib.IMAP4_SSL("127.0.0.1", 2993, ssl_context=tls_context())
    c.login("ann@legacy.example", "import-pw-1")
    return c


def flags_by_uid(c) -> dict:
    typ, data = c.uid("FETCH", "1:*", "(FLAGS)")
    out = {}
    for line in data:
        m = re.search(rb"UID (\d+) FLAGS \(([^)]*)\)|FLAGS \(([^)]*)\) UID (\d+)", line)
        if m:
            uid = int(m.group(1) or m.group(4))
            out[uid] = set((m.group(2) if m.group(1) else m.group(3)).decode().split())
    return out


class Import(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        seed()
        cls.first = run_import()

    def test_1_accounts(self):
        self.assertIn("domains: 2 added of 2", self.first)
        self.assertEqual(sql("SELECT active, mta_sts_mode, mta_sts_mx, settings->>'spf_enabled', "
                             "settings ? 'dkim_private_key' FROM domains WHERE name = 'legacy.example'"),
                         "t|enforce|mx1.legacy.example|true|f")
        self.assertEqual(sql("SELECT catchall FROM domains WHERE name = 'quiet.example'"), "ann@legacy.example")
        self.assertEqual(sql("SELECT d.name FROM domain_aliases a JOIN domains d ON d.id = a.domain_id "
                             "WHERE a.alias = 'legacy-alias.example'"), "legacy.example")
        self.assertEqual(sql("SELECT email, forward_to, quota FROM users WHERE email LIKE '%legacy.example' "
                             "ORDER BY email"),
                         "ann@legacy.example|ann@elsewhere.test|1073741824\nbob@legacy.example||0")
        self.assertEqual(sql("SELECT destination FROM aliases WHERE address = 'info@legacy.example'"),
                         "ann@legacy.example")
        # A role CosmoMail does not have is left out, not made a server admin.
        self.assertEqual(sql("SELECT username || ':' || role FROM admin_users WHERE username IN "
                             "('legacyadmin', 'legacyorg', 'stranger') ORDER BY username"),
                         "legacyadmin:server\nlegacyorg:domain")
        self.assertIn("admin logins: 2 added of 3", self.first)

    def test_2_dkim_and_sieve(self):
        # The PKCS #1 PEM is stored as PKCS #8 DER, and signs as it did.
        self.assertEqual(sql("SELECT selector, active, length(private_key) > 1000 FROM dkim_keys "
                             "WHERE domain = 'legacy.example'"), "mail|t|t")
        self.assertEqual(sql("SELECT sieve_active FROM users WHERE email = 'ann@legacy.example'"), "filters")
        self.assertIn("has another active script", self.first)

    def test_3_mailboxes_keep_uidvalidity(self):
        self.assertEqual(sql("SELECT b.name || ':' || b.uid_validity || ':' || coalesce(b.special_use, '') "
                             "FROM mailboxes b JOIN users u ON u.id = b.user_id "
                             "WHERE u.email = 'ann@legacy.example' ORDER BY b.name"),
                         "Archive/2024:1700000001:\\Archive\nINBOX:1700000000:\nSpam:1700000004:\\Junk")
        self.assertGreaterEqual(int(sql("SELECT last_value FROM mstore_uid_validity")), 1700000004)

    def test_4_messages_over_imap(self):
        self.assertIn("messages whose content is missing at the source (skipped): 1", self.first)
        c = imap()
        typ, data = c.select("INBOX")
        self.assertEqual(int(data[0]), 3)
        self.assertEqual(c.response("UIDVALIDITY")[1], [b"1700000000"])
        self.assertEqual(c.response("UIDNEXT")[1], [b"10"])
        self.assertEqual(flags_by_uid(c), {1: {"\\Seen", "$Label1"}, 2: {"\\Flagged"}, 5: {"\\Deleted"}})
        typ, data = c.uid("FETCH", "1", "(BODY.PEEK[])")
        self.assertEqual(data[0][1], LF_MESSAGE.replace(b"\n", b"\r\n"))
        typ, data = c.uid("FETCH", "2", "(BODY.PEEK[] ENVELOPE)")
        self.assertEqual(data[0][1], S3_MESSAGE)
        typ, data = c.uid("FETCH", "5", "(BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
        self.assertIn(b"from cosmokvd", data[0][1])
        typ, data = c.select("Archive/2024")
        self.assertEqual(int(data[0]), 1)
        self.assertEqual(flags_by_uid(c), {1: {"\\Seen", "\\Answered"}})
        c.logout()
        with open(S3_LOG) as f:
            log = f.read()
        self.assertNotIn("403", log)
        self.assertIn("200 /mailstore/1/1/0000000002.eml", log)
        self.assertIn("200 /mailstore/1/1/0000000005.eml", log)
        self.assertIn("404 /mailstore/1/1/0000000007.eml", log)
        self.assertEqual(sql("SELECT used FROM users WHERE email = 'ann@legacy.example'"),
                         str(len(LF_MESSAGE.replace(b"\n", b"\r\n")) + len(S3_MESSAGE) + len(KV_MESSAGE)
                             + len(ARCHIVE_MESSAGE)))

    def test_5_admin_login(self):
        c = http.client.HTTPConnection("127.0.0.1", 2918, timeout=30)
        c.request("POST", "/api/auth/login", body=json.dumps({"username": "legacyadmin", "password": "import-pw-1"}),
                  headers={"Content-Type": "application/json", "Host": "127.0.0.1:2918"})
        r = c.getresponse()
        self.assertEqual(r.status, 200, r.read())
        c.close()

    def test_6_second_run_copies_the_changes(self):
        again = run_import()
        self.assertIn("domains: 0 added of 2", again)
        self.assertIn("messages copied: 0", again)
        modseq = ("SELECT b.highest_modseq FROM mailboxes b JOIN users u ON u.id = b.user_id "
                  "WHERE u.email = 'ann@legacy.example' AND b.name = 'INBOX'")
        before = int(sql(modseq))
        late = message("arrived late")
        source(f"""
            INSERT INTO messages (user_id, mailbox_id, uid, received_at, internal_date, size, flags, content,
                                  storage_type)
            VALUES (1, 1, 8, now(), now(), {len(late)}, '["\\\\Recent"]', {literal(late)}, 'database');
            UPDATE messages SET flags = '["$Label2"]', is_seen = false WHERE mailbox_id = 1 AND uid = 1;
            DELETE FROM messages WHERE mailbox_id = 1 AND uid = 2;
        """)
        third = run_import()
        self.assertIn("messages copied: 1", third)
        self.assertIn("messages expunged since an earlier run: 1", third)
        c = imap()
        typ, data = c.select("INBOX")
        self.assertEqual(int(data[0]), 3)
        self.assertEqual(flags_by_uid(c), {1: {"$Label2"}, 5: {"\\Deleted"}, 8: set()})
        typ, data = c.status("INBOX", "(UNSEEN)")
        self.assertIn(b"UNSEEN 3", data[0])
        self.assertGreater(int(sql(modseq)), before)
        c.logout()

    def test_7_compare_tool(self):
        # deploy/compare-imap.py, our server against itself: it reads every mailbox and finds nothing different.
        tool = os.path.join(HERE, "..", "..", "deploy", "compare-imap.py")
        out = subprocess.run([sys.executable, tool, "127.0.0.1:2993", "127.0.0.1:2993", "ann@legacy.example",
                              "--content", "--insecure"], env={**os.environ, "IMAP_PASSWORD": "import-pw-1"},
                             capture_output=True, text=True)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("INBOX: 3 messages compared", out.stderr)
        self.assertIn("Archive/2024: 1 messages compared", out.stderr)
        self.assertIn("3 mailboxes, 0 differences", out.stderr)


    def test_8_calendars_and_contacts(self):
        self.assertIn("calendars and address books: 3 added of 3", self.first)
        self.assertIn("events and contacts: 3 added of 4", self.first)
        self.assertIn("calendar objects indexed: 2", self.first)
        user, password = "ann@legacy.example", "import-pw-1"
        home = f"/dav/calendars/{user}/"
        cal = home + "Default/"
        allprop = """<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>"""
        r, data = dav("PROPFIND", home, allprop, {"Depth": "1"}, user=user, password=password)
        self.assertEqual(r.status, 207)
        listed = responses(data)
        self.assertIn(cal, listed)
        self.assertEqual(ok(listed[home + "Work/"], "{http://apple.com/ns/ical/}calendar-color").text, "#FF0000")
        # Same URLs, same content, same etags as the C# server served: clients do not download again.
        r, body = dav("GET", cal + "ev-tz.ics", user=user, password=password)
        self.assertEqual(r.status, 200)
        self.assertEqual(body.decode(), EVENT_TZ)
        self.assertEqual(r.getheader("ETag"), f'"{etag(EVENT_TZ)}"')
        r, _ = dav("GET", cal + "ev-gone.ics", user=user, password=password)
        self.assertEqual(r.status, 404)
        r, body = dav("GET", f"/dav/contacts/{user}/Default/card-1.vcf", user=user, password=password)
        self.assertEqual((r.status, body.decode()), (200, VCARD))
        self.assertEqual(sql("SELECT uid, component, dtstart IS NOT NULL FROM dav_objects WHERE href = 'ev-tz.ics'"),
                         "ev-tz@legacy|VEVENT|t")
        query = """<?xml version="1.0"?><C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
            <D:prop><D:getetag/></D:prop><C:filter><C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT">
            <C:time-range start="20261110T000000Z" end="20261111T000000Z"/></C:comp-filter></C:comp-filter>
            </C:filter></C:calendar-query>"""
        r, data = dav("REPORT", cal, query, {"Depth": "1"}, user=user, password=password)
        self.assertEqual(set(responses(data)), {cal + "ev-tz.ics", cal + "ev-plain.ics"})
        sync = """<?xml version="1.0"?><D:sync-collection xmlns:D="DAV:"><D:sync-token>{}</D:sync-token>
            <D:sync-level>1</D:sync-level><D:prop><D:getetag/></D:prop></D:sync-collection>"""
        r, data = dav("REPORT", cal, sync.format(""), user=user, password=password)
        token = ET.fromstring(data).find("{DAV:}sync-token").text
        # The source changes: an event edited, another deleted; the next run brings both.
        changed = ics("ev-plain@legacy", "Dentist, moved")
        source(f"""
            UPDATE calendar_events SET ics_data = {quoted(changed)}, etag = '{etag(changed)}' WHERE uid = 'ev-plain';
            UPDATE calendar_events SET deleted = true, deleted_at = now() WHERE uid = 'ev-tz';
        """)
        again = run_import()
        self.assertIn("events and contacts: 2 added of 4", again)
        r, data = dav("REPORT", cal, sync.format(token), user=user, password=password)
        self.assertEqual(r.status, 207)
        delta = responses(data)
        self.assertEqual(set(delta), {cal + "ev-plain.ics", cal + "ev-tz.ics"})
        self.assertIn("404", delta[cal + "ev-tz.ics"]["status"])
        self.assertEqual(ok(delta[cal + "ev-plain.ics"], "{DAV:}getetag").text, f'"{etag(changed)}"')
        r, body = dav("GET", cal + "ev-plain.ics", user=user, password=password)
        self.assertEqual(body.decode(), changed)
        self.assertIn("events and contacts: 0 added of 4", run_import())


if __name__ == "__main__":
    unittest.main(verbosity=2)
