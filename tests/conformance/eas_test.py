#!/usr/bin/env python3
"""ActiveSync black-box tests (tests/conformance/run.sh --eas): a device's flows over HTTPS, with a WBXML codec of
this file's own (MS-ASWBXML's tag numbers typed in here, independently of pkgs/meas). Mail arrives over SMTP and is
checked over IMAP; calendar and contact objects are checked in the database."""
import base64, imaplib, os, re, smtplib, ssl, struct, subprocess, sys, threading, time, unittest
import http.client

HOST = "127.0.0.1"
HTTPS = 2443
MX = 2525
IMAPS = 2993
USER, PASSWORD = "eas@example.org", "eas-pw-1234"
OTHER, OTHER_PASSWORD = "eas2@example.org", "eas2-pw-1234"

# ---- WBXML (MS-ASWBXML §2.1.2.1), the pages these tests use ----

PAGES = {
    0: ("AirSync", {
        "Sync": 0x05, "Responses": 0x06, "Add": 0x07, "Change": 0x08, "Delete": 0x09, "Fetch": 0x0A,
        "SyncKey": 0x0B, "ClientId": 0x0C, "ServerId": 0x0D, "Status": 0x0E, "Collection": 0x0F, "Class": 0x10,
        "CollectionId": 0x12, "GetChanges": 0x13, "MoreAvailable": 0x14, "WindowSize": 0x15, "Commands": 0x16,
        "Options": 0x17, "FilterType": 0x18, "Collections": 0x1C, "ApplicationData": 0x1D,
        "DeletesAsMoves": 0x1E, "MIMESupport": 0x22, "Wait": 0x24, "HeartbeatInterval": 0x29}),
    1: ("Contacts", {
        "Birthday": 0x08, "BusinessPhoneNumber": 0x13, "CompanyName": 0x19, "Email1Address": 0x1B,
        "FileAs": 0x1E, "FirstName": 0x1F, "HomeCity": 0x21, "HomeStreet": 0x25, "JobTitle": 0x28,
        "LastName": 0x29, "MobilePhoneNumber": 0x2B}),
    2: ("Email", {
        "Attachment": 0x05, "Attachments": 0x06, "Body": 0x0C, "DateReceived": 0x0F, "DisplayTo": 0x11,
        "Importance": 0x12, "MessageClass": 0x13, "Subject": 0x14, "Read": 0x15, "To": 0x16, "Cc": 0x17,
        "From": 0x18, "ReplyTo": 0x19, "ThreadTopic": 0x35, "InternetCPID": 0x39, "Flag": 0x3A,
        "FlagStatus": 0x3B, "ContentClass": 0x3C, "FlagType": 0x3D}),
    4: ("Calendar", {
        "TimeZone": 0x05, "AllDayEvent": 0x06, "Attendees": 0x07, "Attendee": 0x08, "Email": 0x09, "Name": 0x0A,
        "BusyStatus": 0x0D, "DTStamp": 0x11, "EndTime": 0x12, "Exception": 0x13, "Exceptions": 0x14,
        "Deleted": 0x15, "ExceptionStartTime": 0x16, "Location": 0x17, "MeetingStatus": 0x18,
        "OrganizerEmail": 0x19, "OrganizerName": 0x1A, "Recurrence": 0x1B, "Type": 0x1C, "Until": 0x1D,
        "Occurrences": 0x1E, "Interval": 0x1F, "DayOfWeek": 0x20, "Reminder": 0x24, "Sensitivity": 0x25,
        "Subject": 0x26, "StartTime": 0x27, "UID": 0x28, "AttendeeStatus": 0x29, "AttendeeType": 0x2A}),
    5: ("Move", {"MoveItems": 0x05, "Move": 0x06, "SrcMsgId": 0x07, "SrcFldId": 0x08, "DstFldId": 0x09,
                 "Response": 0x0A, "Status": 0x0B, "DstMsgId": 0x0C}),
    6: ("GetItemEstimate", {"GetItemEstimate": 0x05, "Collections": 0x07, "Collection": 0x08,
                            "CollectionId": 0x0A, "Estimate": 0x0C, "Response": 0x0D, "Status": 0x0E}),
    7: ("FolderHierarchy", {
        "DisplayName": 0x07, "ServerId": 0x08, "ParentId": 0x09, "Type": 0x0A, "Status": 0x0C, "Changes": 0x0E,
        "Add": 0x0F, "Delete": 0x10, "Update": 0x11, "SyncKey": 0x12, "FolderCreate": 0x13, "FolderDelete": 0x14,
        "FolderUpdate": 0x15, "FolderSync": 0x16, "Count": 0x17}),
    8: ("MeetingResponse", {"CalendarId": 0x05, "CollectionId": 0x06, "MeetingResponse": 0x07, "RequestId": 0x08,
                            "Request": 0x09, "Result": 0x0A, "Status": 0x0B, "UserResponse": 0x0C}),
    10: ("ResolveRecipients", {"ResolveRecipients": 0x05, "Response": 0x06, "Status": 0x07, "Type": 0x08,
                               "Recipient": 0x09, "DisplayName": 0x0A, "EmailAddress": 0x0B, "To": 0x10,
                               "RecipientCount": 0x12}),
    13: ("Ping", {"Ping": 0x05, "Status": 0x07, "HeartbeatInterval": 0x08, "Folders": 0x09, "Folder": 0x0A,
                  "Id": 0x0B, "Class": 0x0C}),
    14: ("Provision", {"Provision": 0x05, "Policies": 0x06, "Policy": 0x07, "PolicyType": 0x08, "PolicyKey": 0x09,
                       "Data": 0x0A, "Status": 0x0B, "EASProvisionDoc": 0x0D}),
    15: ("Search", {"Search": 0x05, "Store": 0x07, "Name": 0x08, "Query": 0x09, "Options": 0x0A, "Range": 0x0B,
                    "Status": 0x0C, "Response": 0x0D, "Result": 0x0E, "Properties": 0x0F, "Total": 0x10,
                    "And": 0x13, "FreeText": 0x15, "LongId": 0x18}),
    16: ("GAL", {"DisplayName": 0x05, "Alias": 0x0A, "EmailAddress": 0x0F}),
    17: ("AirSyncBase", {"BodyPreference": 0x05, "Type": 0x06, "TruncationSize": 0x07, "Body": 0x0A,
                         "Data": 0x0B, "EstimatedDataSize": 0x0C, "Truncated": 0x0D, "Attachments": 0x0E,
                         "Attachment": 0x0F, "DisplayName": 0x10, "FileReference": 0x11, "ContentType": 0x17,
                         "NativeBodyType": 0x16}),
    18: ("Settings", {"Settings": 0x05, "Status": 0x06, "Get": 0x07, "Set": 0x08, "DeviceInformation": 0x16,
                      "Model": 0x17, "FriendlyName": 0x19, "OS": 0x1A, "UserInformation": 0x1D,
                      "EmailAddresses": 0x1E, "SMTPAddress": 0x1F, "PrimarySmtpAddress": 0x23, "Accounts": 0x24,
                      "Account": 0x25}),
    20: ("ItemOperations", {"ItemOperations": 0x05, "Fetch": 0x06, "Store": 0x07, "Options": 0x08,
                            "Properties": 0x0B, "Data": 0x0C, "Status": 0x0D, "Response": 0x0E}),
    21: ("ComposeMail", {"SendMail": 0x05, "SmartForward": 0x06, "SmartReply": 0x07, "SaveInSentItems": 0x08,
                         "Source": 0x0B, "FolderId": 0x0C, "ItemId": 0x0D, "Mime": 0x10, "ClientId": 0x11,
                         "Status": 0x12}),
}
BY_NAME = {name: (page, tags) for page, (name, tags) in PAGES.items()}


class Node:
    def __init__(self, ns, name):
        self.ns, self.name, self.children, self.data = ns, name, [], b""

    def all(self, name):
        out = []
        for c in self.children:
            if c.name == name:
                out.append(c)
            out.extend(c.all(name))
        return out

    def find(self, name):
        found = self.all(name)
        return found[0] if found else None

    def child(self, name):
        return next((c for c in self.children if c.name == name), None)

    def text(self, name=None):
        node = self if name is None else self.find(name)
        return node.data.decode() if node is not None else None

    def kids(self, name):
        return [c for c in self.children if c.name == name]


def mb(value: int) -> bytes:
    out = [value & 0x7F]
    value >>= 7
    while value:
        out.append(0x80 | (value & 0x7F))
        value >>= 7
    return bytes(reversed(out))


def encode(tree) -> bytes:
    """tree: ("Page:Name", content), content a str, bytes (opaque), None (empty) or a list of trees."""
    out = bytearray(b"\x03\x01\x6a\x00")
    page = [None]

    def put(node):
        qualified, content = node
        ns, name = qualified.split(":")
        p, tags = BY_NAME[ns]
        if page[0] != p:
            out.extend([0x00, p])
            page[0] = p
        tag = tags[name]
        if content is None or content == [] or content == "":
            out.append(tag)
            return
        out.append(tag | 0x40)
        if isinstance(content, str):
            out.append(0x03)
            out.extend(content.encode() + b"\x00")
        elif isinstance(content, bytes):
            out.append(0xC3)
            out.extend(mb(len(content)) + content)
        else:
            for c in content:
                put(c)
        out.append(0x01)

    put(tree)
    return bytes(out)


def decode(data: bytes) -> Node:
    assert data[:1] == b"\x03", data[:8]
    pos = 1

    def read_mb():
        nonlocal pos
        v = 0
        while True:
            b = data[pos]
            pos += 1
            v = (v << 7) | (b & 0x7F)
            if not b & 0x80:
                return v

    read_mb()  # public id
    read_mb()  # charset
    table = read_mb()  # string table
    pos += table
    page = 0
    stack = []
    root = None
    while pos < len(data):
        b = data[pos]
        pos += 1
        if b == 0x00:
            page = data[pos]
            pos += 1
        elif b == 0x01:
            done = stack.pop()
            if not stack:
                root = done
                break
        elif b == 0x03:
            end = data.index(b"\x00", pos)
            stack[-1].data += data[pos:end]
            pos = end + 1
        elif b == 0xC3:
            n = read_mb()
            stack[-1].data += data[pos:pos + n]
            pos += n
        else:
            ns, tags = PAGES[page]
            names = {v: k for k, v in tags.items()}
            node = Node(ns, names.get(b & 0x3F, "Unknown%02X" % (b & 0x3F)))
            if stack:
                stack[-1].children.append(node)
            if b & 0x40:
                stack.append(node)
            elif not stack:
                root = node
                break
    return root


# ---- The device ----

def tls():
    c = ssl.create_default_context(cafile=os.environ["CA"])
    c.check_hostname = False
    return c


def post(cmd, body=None, user=USER, password=PASSWORD, device="DEV1", version="14.1", extra="",
         content_type="application/vnd.ms-sync.wbxml", raw=None, timeout=30):
    c = http.client.HTTPSConnection(HOST, HTTPS, context=tls(), timeout=timeout)
    auth = base64.b64encode(f"{user}:{password}".encode()).decode()
    headers = {"Authorization": "Basic " + auth, "MS-ASProtocolVersion": version, "User-Agent": "eas-test/1.0"}
    payload = raw if raw is not None else (encode(body) if body is not None else b"")
    if payload:
        headers["Content-Type"] = content_type
    c.request("POST", f"/Microsoft-Server-ActiveSync?Cmd={cmd}&User={user}&DeviceId={device}&DeviceType=TestPhone{extra}",
              body=payload, headers=headers)
    r = c.getresponse()
    data = r.read()
    c.close()
    if os.environ.get("EAS_DUMP"):
        print("\n", cmd, r.status, data[:300].hex(), file=sys.stderr)
    doc = decode(data) if data[:1] == b"\x03" else None
    return r.status, doc, r


def deliver(to, subject, body="Hello there.\r\n", extra_headers="", raw=None):
    message = raw or (f"From: Sender <sender@remote.test>\r\nTo: {to}\r\nSubject: {subject}\r\n"
                      f"Message-ID: <{subject.replace(' ', '.')}.{time.time()}@remote.test>\r\n"
                      f"Date: Thu, 05 Nov 2026 10:00:00 +0000\r\n{extra_headers}\r\n{body}").encode()
    with smtplib.SMTP(HOST, MX) as c:
        c.ehlo("remote.test")
        assert c.sendmail("sender@remote.test", [to], message) == {}


def submit_as(user, password, to, raw):
    with smtplib.SMTP(HOST, 2587) as c:
        c.starttls(context=tls())
        c.login(user, password)
        assert c.sendmail(user, [to], raw.encode()) == {}


def imap(user=USER, password=PASSWORD):
    c = imaplib.IMAP4_SSL(HOST, IMAPS, ssl_context=tls())
    c.login(user, password)
    return c


def sql(statement):
    out = subprocess.run(["docker", "exec", "ceesafe-pg-test", "psql", "-At", "-U", "cee", "-d", "mailserver_test",
                          "-c", statement], capture_output=True, text=True, check=True)
    return out.stdout.strip()


def folder_sync(device, key="0", **kw):
    status, doc, _ = post("FolderSync", ("FolderHierarchy:FolderSync", [("FolderHierarchy:SyncKey", key)]),
                          device=device, **kw)
    assert status == 200, status
    return doc


def folders_of(doc):
    return {a.text("DisplayName"): (a.text("ServerId"), int(a.text("Type"))) for a in doc.all("Add")}


def sync(device, collection, key, window=None, options=None, commands=None, extra=None, **kw):
    col = [("AirSync:SyncKey", key), ("AirSync:CollectionId", collection)]
    if extra:
        col.extend(extra)
    if window:
        col.append(("AirSync:WindowSize", str(window)))
    if options is not None:
        col.append(("AirSync:Options", options))
    if commands:
        col.append(("AirSync:Commands", commands))
    status, doc, _ = post("Sync", ("AirSync:Sync", [("AirSync:Collections", [("AirSync:Collection", col)])]),
                          device=device, **kw)
    assert status == 200, status
    return doc


HTML_OPTIONS = [("AirSyncBase:BodyPreference", [("AirSyncBase:Type", "2"), ("AirSyncBase:TruncationSize", "200000")])]


def commands_of(doc):
    cmds = doc.find("Commands")
    return [] if cmds is None else cmds.children


def fresh_sync(device, collection, options=None):
    """A folder synced to the end: its key, and every item sent (ServerId -> ApplicationData)."""
    doc = sync(device, collection, "0", options=options)
    key = doc.text("SyncKey")
    items = {}
    while True:
        doc = sync(device, collection, key, window=50, options=options)
        key = doc.text("SyncKey")
        for c in commands_of(doc):
            if c.name == "Add":
                items[c.text("ServerId")] = c.child("ApplicationData")
        if doc.find("MoreAvailable") is None:
            return key, items


class Discovery(unittest.TestCase):
    def test_options(self):
        c = http.client.HTTPSConnection(HOST, HTTPS, context=tls())
        c.request("OPTIONS", "/Microsoft-Server-ActiveSync")
        r = c.getresponse()
        r.read()
        self.assertEqual(r.status, 200)
        self.assertIn("14.1", r.getheader("MS-ASProtocolVersions"))
        self.assertIn("FolderSync", r.getheader("MS-ASProtocolCommands"))
        bad = base64.b64encode(b"eas@example.org:wrong").decode()
        c.request("OPTIONS", "/Microsoft-Server-ActiveSync", headers={"Authorization": "Basic " + bad})
        r = c.getresponse()
        r.read()
        self.assertEqual(r.status, 401)
        self.assertIn("Basic", r.getheader("WWW-Authenticate"))

    def test_wrong_password(self):
        status, _, _ = post("FolderSync", ("FolderHierarchy:FolderSync", [("FolderHierarchy:SyncKey", "0")]),
                            password="nope")
        self.assertEqual(status, 401)

    def test_provision_two_steps(self):
        status, doc, _ = post("Provision", ("Provision:Provision", [("Provision:Policies", [("Provision:Policy", [
            ("Provision:PolicyType", "MS-EAS-Provisioning-WBXML")])])]), device="PROV1")
        self.assertEqual(status, 200)
        temporary = doc.text("PolicyKey")
        self.assertIsNotNone(doc.find("EASProvisionDoc"))
        status, doc, _ = post("Provision", ("Provision:Provision", [("Provision:Policies", [("Provision:Policy", [
            ("Provision:PolicyType", "MS-EAS-Provisioning-WBXML"), ("Provision:PolicyKey", temporary),
            ("Provision:Status", "1")])])]), device="PROV1")
        final = doc.text("PolicyKey")
        self.assertNotEqual(final, temporary)
        self.assertIsNone(doc.find("EASProvisionDoc"))
        self.assertEqual(sql("SELECT policy_key FROM eas_devices WHERE device_id = 'PROV1'"), final)

    def test_settings(self):
        status, doc, _ = post("Settings", ("Settings:Settings", [
            ("Settings:DeviceInformation", [("Settings:Set", [("Settings:Model", "Phone 15"),
                                                               ("Settings:FriendlyName", "Test phone"),
                                                               ("Settings:OS", "TestOS 1")])]),
            ("Settings:UserInformation", [("Settings:Get", None)])]), device="SET1")
        self.assertEqual(status, 200)
        self.assertEqual(doc.text("SMTPAddress"), USER)
        self.assertEqual(sql("SELECT model || '/' || friendly_name FROM eas_devices WHERE device_id = 'SET1'"),
                         "Phone 15/Test phone")


class Hierarchy(unittest.TestCase):
    def test_folder_sync_and_changes(self):
        doc = folder_sync("FOLD1")
        self.assertEqual(doc.text("Status"), "1")
        self.assertEqual(doc.text("SyncKey"), "1")
        folders = folders_of(doc)
        self.assertEqual(folders["INBOX"][1], 2)
        self.assertEqual(folders["Sent"][1], 5)
        self.assertEqual(folders["Trash"][1], 4)
        self.assertEqual(folders["Calendar"][1], 8)
        self.assertEqual(folders["Contacts"][1], 9)
        # Nothing changed: the same key, no changes.
        doc = folder_sync("FOLD1", "1")
        self.assertEqual(doc.text("SyncKey"), "1")
        self.assertEqual(doc.text("Count"), "0")
        # A wrong key: status 9.
        self.assertEqual(folder_sync("FOLD1", "7").text("Status"), "9")
        # A folder made over IMAP shows up.
        c = imap()
        c.create("Projects")
        c.logout()
        doc = folder_sync("FOLD1", "1")
        self.assertEqual(doc.text("SyncKey"), "2")
        self.assertIn("Projects", folders_of(doc))
        # FolderCreate, FolderUpdate and FolderDelete from the device.
        status, doc, _ = post("FolderCreate", ("FolderHierarchy:FolderCreate", [
            ("FolderHierarchy:SyncKey", "2"), ("FolderHierarchy:ParentId", "0"),
            ("FolderHierarchy:DisplayName", "Receipts"), ("FolderHierarchy:Type", "12")]), device="FOLD1")
        self.assertEqual(doc.text("Status"), "1")
        receipts = doc.text("ServerId")
        self.assertEqual(doc.text("SyncKey"), "3")
        status, doc, _ = post("FolderUpdate", ("FolderHierarchy:FolderUpdate", [
            ("FolderHierarchy:SyncKey", "3"), ("FolderHierarchy:ServerId", receipts),
            ("FolderHierarchy:ParentId", "0"), ("FolderHierarchy:DisplayName", "Invoices")]), device="FOLD1")
        self.assertEqual(doc.text("Status"), "1")
        c = imap()
        _, listed = c.list()
        c.logout()
        self.assertTrue(any(b"Invoices" in line for line in listed), listed)
        # The device knows of the rename already: the next FolderSync has nothing.
        doc = folder_sync("FOLD1", "4")
        self.assertEqual(doc.text("Count"), "0")
        status, doc, _ = post("FolderDelete", ("FolderHierarchy:FolderDelete", [
            ("FolderHierarchy:SyncKey", "4"), ("FolderHierarchy:ServerId", receipts)]), device="FOLD1")
        self.assertEqual(doc.text("Status"), "1")
        inbox = folders["INBOX"][0]
        status, doc, _ = post("FolderDelete", ("FolderHierarchy:FolderDelete", [
            ("FolderHierarchy:SyncKey", "5"), ("FolderHierarchy:ServerId", inbox)]), device="FOLD1")
        self.assertEqual(doc.text("Status"), "3", "INBOX cannot be deleted")


class Mail(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folders = folders_of(folder_sync("MAIL1"))
        cls.inbox = cls.folders["INBOX"][0]

    def test_1_initial_sync_in_windows(self):
        for i in range(3):
            deliver(USER, f"Window {i}", body=f"<p>Body {i}</p>\r\n",
                    extra_headers="Content-Type: text/html; charset=utf-8\r\n")
        doc = sync("MAIL1", self.inbox, "0")
        self.assertEqual(doc.text("SyncKey"), "1")
        self.assertEqual(commands_of(doc), [], "no items with the first key")
        doc = sync("MAIL1", self.inbox, "1", window=2, options=HTML_OPTIONS)
        self.assertEqual(doc.text("SyncKey"), "2")
        adds = [c for c in commands_of(doc) if c.name == "Add"]
        self.assertEqual(len(adds), 2)
        self.assertIsNotNone(doc.find("MoreAvailable"))
        # Newest first.
        self.assertEqual(adds[0].text("Subject"), "Window 2")
        data = adds[0].child("ApplicationData")
        self.assertEqual(data.text("From"), "Sender <sender@remote.test>")
        self.assertEqual(data.text("Read"), "0")
        self.assertEqual(data.find("Body").text("Type"), "2")
        self.assertIn("<p>Body 2</p>", data.find("Body").text("Data"))
        self.assertTrue(data.text("DateReceived").endswith(".000Z"))
        doc = sync("MAIL1", self.inbox, "2", window=2)
        # Then the oldest of the three (and what other tests delivered before).
        self.assertEqual([c.text("Subject") for c in commands_of(doc)][0], "Window 0")
        self.assertIsNone(doc.find("MoreAvailable"))
        Mail.key = doc.text("SyncKey")
        Mail.ids = {a.text("Subject"): a.text("ServerId") for a in adds}

    def test_2_lost_response_is_sent_again(self):
        deliver(USER, "Replayed")
        doc = sync("MAIL1", self.inbox, Mail.key)
        new_key = doc.text("SyncKey")
        self.assertEqual([c.text("Subject") for c in commands_of(doc)], ["Replayed"])
        # The device never got that: it asks again with the old key, and gets the same.
        again = sync("MAIL1", self.inbox, Mail.key)
        self.assertEqual(again.text("SyncKey"), new_key)
        self.assertEqual([c.text("Subject") for c in commands_of(again)], ["Replayed"])
        # Confirmed: nothing more.
        doc = sync("MAIL1", self.inbox, new_key)
        self.assertEqual(commands_of(doc), [])
        self.assertEqual(doc.text("SyncKey"), new_key)
        # A key from nowhere: status 3.
        self.assertEqual(sync("MAIL1", self.inbox, "999").text("Status"), "3")
        doc = sync("MAIL1", self.inbox, "0")
        Mail.key, items = fresh_sync("MAIL1", self.inbox)
        Mail.ids = {d.text("Subject"): sid for sid, d in items.items()}

    def test_3_flags_both_ways(self):
        sid = Mail.ids["Window 1"]
        doc = sync("MAIL1", self.inbox, Mail.key, commands=[("AirSync:Change", [
            ("AirSync:ServerId", sid), ("AirSync:ApplicationData", [("Email:Read", "1")])])])
        Mail.key = doc.text("SyncKey")
        self.assertEqual([c for c in commands_of(doc) if c.text("ServerId") == sid], [], "not echoed back")
        uid = sid.split(":")[1]
        c = imap()
        c.select("INBOX")
        _, data = c.uid("FETCH", uid, "(FLAGS)")
        self.assertIn(b"\\Seen", data[0])
        c.uid("STORE", uid, "+FLAGS", "(\\Flagged)")
        c.logout()
        doc = sync("MAIL1", self.inbox, Mail.key)
        Mail.key = doc.text("SyncKey")
        changes = [c for c in commands_of(doc) if c.name == "Change"]
        self.assertEqual([c.text("ServerId") for c in changes], [sid])
        self.assertEqual(changes[0].find("Flag").text("FlagStatus"), "2")

    def test_4_deletes_both_ways(self):
        sid = Mail.ids["Window 0"]
        doc = sync("MAIL1", self.inbox, Mail.key, commands=[("AirSync:Delete", [("AirSync:ServerId", sid)])])
        Mail.key = doc.text("SyncKey")
        c = imap()
        c.select("Trash")
        _, data = c.search(None, "SUBJECT", '"Window 0"')
        self.assertTrue(data[0], "moved to Trash")
        c.select("INBOX")
        _, data = c.uid("SEARCH", None, "SUBJECT", '"Window 2"')
        uid = data[0].decode()
        c.uid("STORE", uid, "+FLAGS", "(\\Deleted)")
        c.expunge()
        c.logout()
        doc = sync("MAIL1", self.inbox, Mail.key)
        Mail.key = doc.text("SyncKey")
        deletes = [c.text("ServerId") for c in commands_of(doc) if c.name == "Delete"]
        self.assertEqual(deletes, [Mail.ids["Window 2"]])

    def test_5_estimate_and_ping(self):
        deliver(USER, "Estimated")
        status, doc, _ = post("GetItemEstimate", ("GetItemEstimate:GetItemEstimate", [
            ("GetItemEstimate:Collections", [("GetItemEstimate:Collection", [
                ("AirSync:SyncKey", Mail.key), ("GetItemEstimate:CollectionId", self.inbox)])])]), device="MAIL1")
        self.assertEqual(doc.text("Estimate"), "1")
        doc = sync("MAIL1", self.inbox, Mail.key)
        Mail.key = doc.text("SyncKey")
        result = {}

        def ping():
            result["started"] = time.time()
            status, doc, _ = post("Ping", ("Ping:Ping", [("Ping:HeartbeatInterval", "120"), ("Ping:Folders", [
                ("Ping:Folder", [("Ping:Id", self.inbox), ("Ping:Class", "Email")])])]), device="MAIL1",
                timeout=150)
            result["doc"] = doc
            result["took"] = time.time() - result["started"]

        t = threading.Thread(target=ping)
        t.start()
        time.sleep(1.5)
        self.assertTrue(t.is_alive(), "the Ping waits")
        deliver(USER, "Wakes the ping")
        t.join(30)
        self.assertFalse(t.is_alive())
        self.assertEqual(result["doc"].text("Status"), "2")
        self.assertEqual([f.text() for f in result["doc"].all("Folder")], [self.inbox])
        self.assertLess(result["took"], 30)
        # A Ping without folders repeats the last one's; there are changes waiting, so it answers at once.
        status, doc, _ = post("Ping", None, device="MAIL1")
        self.assertEqual(doc.text("Status"), "2")
        doc = sync("MAIL1", self.inbox, Mail.key)
        Mail.key = doc.text("SyncKey")

    def test_6_fetch_mime_and_attachments(self):
        raw = (b"From: Sender <sender@remote.test>\r\nTo: eas@example.org\r\nSubject: With attachment\r\n"
               b"Message-ID: <att@remote.test>\r\nMIME-Version: 1.0\r\n"
               b"Content-Type: multipart/mixed; boundary=XYZ\r\n\r\n--XYZ\r\nContent-Type: text/plain\r\n\r\n"
               b"See attached.\r\n--XYZ\r\nContent-Type: application/pdf; name=report.pdf\r\n"
               b"Content-Disposition: attachment; filename=report.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\n"
               + base64.b64encode(b"%PDF-1.4 fake pdf bytes") + b"\r\n--XYZ--\r\n")
        deliver(USER, None, raw=raw.decode())
        doc = sync("MAIL1", self.inbox, Mail.key)
        Mail.key = doc.text("SyncKey")
        add = next(c for c in commands_of(doc) if c.text("Subject") == "With attachment")
        sid = add.text("ServerId")
        attachment = add.find("Attachment")
        self.assertEqual(attachment.text("DisplayName"), "report.pdf")
        reference = attachment.text("FileReference")
        status, doc, _ = post("ItemOperations", ("ItemOperations:ItemOperations", [("ItemOperations:Fetch", [
            ("ItemOperations:Store", "Mailbox"), ("AirSyncBase:FileReference", reference)])]), device="MAIL1")
        self.assertEqual(doc.find("Fetch").text("Status"), "1")
        self.assertEqual(base64.b64decode(doc.find("Properties").text("Data")), b"%PDF-1.4 fake pdf bytes")
        self.assertEqual(doc.find("Properties").text("ContentType"), "application/pdf")
        status, doc, _ = post("ItemOperations", ("ItemOperations:ItemOperations", [("ItemOperations:Fetch", [
            ("ItemOperations:Store", "Mailbox"), ("AirSync:CollectionId", self.inbox), ("AirSync:ServerId", sid),
            ("ItemOperations:Options", [("AirSync:MIMESupport", "2"), ("AirSyncBase:BodyPreference", [
                ("AirSyncBase:Type", "4")])])])]), device="MAIL1")
        body = doc.find("Body")
        self.assertEqual(body.text("Type"), "4")
        # The stored message: the server's Received and Authentication-Results fields, then what was sent.
        self.assertTrue(body.find("Data").data.endswith(raw))
        # GetAttachment, as 12.1 devices fetch them.
        status, _, r = post("GetAttachment", None, device="MAIL1", version="12.1",
                            extra="&AttachmentName=" + reference)
        self.assertEqual(status, 200)

    def test_7_move_items(self):
        c = imap()
        c.create("Archive2")
        c.logout()
        folders = folders_of(folder_sync("MAIL2"))
        target = folders["Archive2"][0]
        deliver(USER, "To be moved")
        key, items = fresh_sync("MAIL2", self.inbox)
        sid = next(s for s, d in items.items() if d.text("Subject") == "To be moved")
        status, doc, _ = post("MoveItems", ("Move:MoveItems", [("Move:Move", [
            ("Move:SrcMsgId", sid), ("Move:SrcFldId", self.inbox), ("Move:DstFldId", target)])]), device="MAIL2")
        self.assertEqual(doc.text("Status"), "3")
        self.assertTrue(doc.text("DstMsgId").startswith(target + ":"))
        c = imap()
        c.select("Archive2")
        _, data = c.search(None, "SUBJECT", '"To be moved"')
        self.assertTrue(data[0])
        c.logout()
        # The device made the move: the next Sync of the inbox does not delete it again.
        doc = sync("MAIL2", self.inbox, key)
        self.assertNotIn(sid, [c.text("ServerId") for c in commands_of(doc)])

    def test_8_search(self):
        deliver(USER, "Quarterly kumquat report")
        status, doc, _ = post("Search", ("Search:Search", [("Search:Store", [
            ("Search:Name", "Mailbox"),
            ("Search:Query", [("Search:And", [("AirSync:Class", "Email"), ("Search:FreeText", "kumquat")])]),
            ("Search:Options", [("Search:Range", "0-9")])])]), device="MAIL1")
        self.assertEqual(doc.text("Status"), "1")
        results = doc.all("Result")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].text("Subject"), "Quarterly kumquat report")
        self.assertEqual(doc.text("Total"), "1")
        status, doc, _ = post("Search", ("Search:Search", [("Search:Store", [
            ("Search:Name", "GAL"), ("Search:Query", "eas2"), ("Search:Options", [("Search:Range", "0-9")])])]),
            device="MAIL1")
        self.assertEqual(doc.text("Total"), "1")

    def test_9_resolve_recipients(self):
        status, doc, _ = post("ResolveRecipients", ("ResolveRecipients:ResolveRecipients", [
            ("ResolveRecipients:To", OTHER), ("ResolveRecipients:To", "nobody-at-all")]), device="MAIL1")
        responses = doc.all("Response")
        self.assertEqual(responses[0].text("Status"), "1")
        self.assertEqual(responses[0].text("EmailAddress"), OTHER)
        self.assertEqual(responses[1].text("Status"), "4")


class Sending(unittest.TestCase):
    def test_sendmail_wbxml_and_mime(self):
        mime = (f"From: {USER}\r\nTo: {OTHER}\r\nBcc: hidden@example.org\r\nSubject: Sent from the phone\r\n"
                "MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nHi from ActiveSync.\r\n").encode()
        status, doc, _ = post("SendMail", ("ComposeMail:SendMail", [
            ("ComposeMail:ClientId", "c1"), ("ComposeMail:SaveInSentItems", None), ("ComposeMail:Mime", mime)]),
            device="SEND1")
        self.assertEqual(status, 200)
        self.assertIsNone(doc, "success is an empty body")
        c = imap(OTHER, OTHER_PASSWORD)
        c.select("INBOX")
        _, data = c.search(None, "SUBJECT", '"Sent from the phone"')
        self.assertTrue(data[0])
        _, fetched = c.fetch(data[0].split()[0], "(BODY.PEEK[HEADER])")
        self.assertNotIn(b"Bcc:", fetched[0][1], "Bcc is not delivered")
        c.logout()
        c = imap()
        c.select("Sent")
        _, data = c.search(None, "SUBJECT", '"Sent from the phone"')
        self.assertTrue(data[0], "a copy in Sent")
        c.logout()
        # 12.1: the body is the MIME message itself.
        mime2 = f"From: {USER}\r\nTo: {OTHER}\r\nSubject: Old style\r\n\r\nPlain MIME body.\r\n".encode()
        status, _, _ = post("SendMail", None, device="SEND1", version="12.1", extra="&SaveInSent=F",
                            content_type="message/rfc822", raw=mime2)
        self.assertEqual(status, 200)
        c = imap(OTHER, OTHER_PASSWORD)
        c.select("INBOX")
        _, data = c.search(None, "SUBJECT", '"Old style"')
        self.assertTrue(data[0])
        c.logout()

    def test_smart_forward(self):
        deliver(USER, "Forward me", body="Original text.\r\n")
        folders = folders_of(folder_sync("SEND2"))
        inbox = folders["INBOX"][0]
        key, items = fresh_sync("SEND2", inbox)
        sid = next(s for s, d in items.items() if d.text("Subject") == "Forward me")
        mime = f"From: {USER}\r\nTo: {OTHER}\r\nSubject: Fwd: Forward me\r\n\r\nHave a look.\r\n".encode()
        status, _, _ = post("SmartForward", ("ComposeMail:SmartForward", [
            ("ComposeMail:ClientId", "f1"),
            ("ComposeMail:Source", [("ComposeMail:FolderId", inbox), ("ComposeMail:ItemId", sid)]),
            ("ComposeMail:Mime", mime)]), device="SEND2")
        self.assertEqual(status, 200)
        c = imap(OTHER, OTHER_PASSWORD)
        c.select("INBOX")
        _, data = c.search(None, "SUBJECT", '"Fwd: Forward me"')
        _, fetched = c.fetch(data[0].split()[0], "(BODY.PEEK[])")
        whole = fetched[0][1]
        self.assertIn(b"Have a look.", whole)
        self.assertIn(b"message/rfc822", whole)
        self.assertIn(b"Original text.", whole)
        c.logout()
        c = imap()
        c.select("INBOX")
        _, data = c.uid("FETCH", sid.split(":")[1], "(FLAGS)")
        self.assertIn(b"$Forwarded", data[0])
        c.logout()


ZONE_PARIS = base64.b64encode(struct.pack("<i64s8Hi64s8Hi", -60, b"", 0, 10, 0, 5, 3, 0, 0, 0, 0,
                                          b"", 0, 3, 0, 5, 2, 0, 0, 0, -60)).decode()


class Groupware(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        folders = folders_of(folder_sync("CAL1"))
        cls.calendar = folders["Calendar"][0]
        cls.contacts = folders["Contacts"][0]

    def test_1_event_from_the_device(self):
        key = sync("CAL1", self.calendar, "0").text("SyncKey")
        doc = sync("CAL1", self.calendar, key, commands=[("AirSync:Add", [
            ("AirSync:ClientId", "e1"), ("AirSync:ApplicationData", [
                ("Calendar:TimeZone", ZONE_PARIS), ("Calendar:AllDayEvent", "0"),
                ("Calendar:StartTime", "20261110T090000Z"), ("Calendar:EndTime", "20261110T100000Z"),
                ("Calendar:Subject", "Standup"), ("Calendar:Location", "Room 1"),
                ("Calendar:BusyStatus", "2"), ("Calendar:Reminder", "15"),
                ("Calendar:Recurrence", [("Calendar:Type", "1"), ("Calendar:Interval", "1"),
                                         ("Calendar:DayOfWeek", "62"), ("Calendar:Occurrences", "10")]),
                ("AirSyncBase:Body", [("AirSyncBase:Type", "1"), ("AirSyncBase:Data", "Daily standup.")])])])])
        Groupware.key = doc.text("SyncKey")
        response = doc.find("Responses").find("Add")
        self.assertEqual(response.text("Status"), "1")
        self.assertEqual(response.text("ClientId"), "e1")
        Groupware.event = response.text("ServerId")
        object_id = Groupware.event.split(":")[1]
        data = sql(f"SELECT data FROM dav_objects WHERE id = {object_id}")
        self.assertIn("SUMMARY:Standup", data)
        self.assertIn("DTSTART:20261110T090000Z", data)
        self.assertIn("RRULE:FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR;COUNT=10", data)
        self.assertIn("TRIGGER:-PT15M", data)
        self.assertIn("DESCRIPTION:Daily standup.", data)
        # Not sent back to the device that made it.
        doc = sync("CAL1", self.calendar, Groupware.key)
        self.assertEqual(commands_of(doc), [])

    def test_2_event_from_elsewhere(self):
        ics = ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VTIMEZONE\r\nTZID:Europe/Paris\r\nBEGIN:STANDARD\r\n"
               "DTSTART:19701025T030000\r\nTZOFFSETFROM:+0200\r\nTZOFFSETTO:+0100\r\n"
               "RRULE:FREQ=YEARLY;BYMONTH=10;BYDAY=-1SU\r\nEND:STANDARD\r\nBEGIN:DAYLIGHT\r\n"
               "DTSTART:19700329T020000\r\nTZOFFSETFROM:+0100\r\nTZOFFSETTO:+0200\r\n"
               "RRULE:FREQ=YEARLY;BYMONTH=3;BYDAY=-1SU\r\nEND:DAYLIGHT\r\nEND:VTIMEZONE\r\nBEGIN:VEVENT\r\n"
               "UID:server-made-1\r\nDTSTAMP:20261101T000000Z\r\nDTSTART;TZID=Europe/Paris:20260710T140000\r\n"
               "DTEND;TZID=Europe/Paris:20260710T150000\r\nSUMMARY:Summer meeting\r\n"
               "ORGANIZER;CN=Carol:mailto:carol@example.org\r\n"
               "ATTENDEE;CN=Eas;PARTSTAT=ACCEPTED:mailto:eas@example.org\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n")
        sql("WITH c AS (UPDATE dav_collections SET modseq = modseq + 1 WHERE user_id = "
            "(SELECT id FROM users WHERE email = 'eas@example.org') AND kind = 'calendar' AND name = 'Default' "
            "RETURNING id, modseq) INSERT INTO dav_objects (collection_id, href, uid, component, data, etag, "
            "dtstart, dtend, created_modseq, modseq) SELECT id, 'server-made-1.ics', 'server-made-1', 'VEVENT', "
            f"$${ics}$$, 'e1', '2026-07-10 12:00Z', '2026-07-10 13:00Z', modseq, modseq FROM c")
        doc = sync("CAL1", self.calendar, Groupware.key)
        Groupware.key = doc.text("SyncKey")
        adds = [c for c in commands_of(doc) if c.name == "Add"]
        self.assertEqual(len(adds), 1)
        data = adds[0].child("ApplicationData")
        self.assertEqual(data.text("Subject"), "Summer meeting")
        # 14:00 in Paris in July (UTC+2) is 12:00 UTC.
        self.assertEqual(data.text("StartTime"), "20260710T120000Z")
        self.assertEqual(data.text("OrganizerEmail"), "carol@example.org")
        self.assertEqual(data.find("Attendee").text("AttendeeStatus"), "3")
        zone = base64.b64decode(data.text("TimeZone"))
        self.assertEqual(struct.unpack("<i", zone[:4])[0], -60, "the bias of UTC+1")
        Groupware.server_event = adds[0].text("ServerId")

    def test_3_change_and_delete_from_the_device(self):
        doc = sync("CAL1", self.calendar, Groupware.key, commands=[("AirSync:Change", [
            ("AirSync:ServerId", Groupware.event), ("AirSync:ApplicationData", [
                ("Calendar:TimeZone", ZONE_PARIS), ("Calendar:StartTime", "20261110T091500Z"),
                ("Calendar:EndTime", "20261110T100000Z"), ("Calendar:Subject", "Standup (moved)")])])])
        Groupware.key = doc.text("SyncKey")
        object_id = Groupware.event.split(":")[1]
        data = sql(f"SELECT data FROM dav_objects WHERE id = {object_id}")
        self.assertIn("SUMMARY:Standup (moved)", data)
        uid = sql(f"SELECT uid FROM dav_objects WHERE id = {object_id}")
        self.assertIn(f"UID:{uid}", data, "the UID is kept")
        doc = sync("CAL1", self.calendar, Groupware.key, commands=[("AirSync:Delete", [
            ("AirSync:ServerId", Groupware.server_event)])])
        Groupware.key = doc.text("SyncKey")
        self.assertEqual(sql("SELECT deleted FROM dav_objects WHERE uid = 'server-made-1'"), "t")
        doc = sync("CAL1", self.calendar, Groupware.key)
        self.assertEqual(commands_of(doc), [])

    def test_4_contacts_both_ways(self):
        key = sync("CAL1", self.contacts, "0").text("SyncKey")
        doc = sync("CAL1", self.contacts, key, commands=[("AirSync:Add", [
            ("AirSync:ClientId", "k1"), ("AirSync:ApplicationData", [
                ("Contacts:FirstName", "Jane"), ("Contacts:LastName", "Doe"), ("Contacts:FileAs", "Doe, Jane"),
                ("Contacts:Email1Address", "jane@example.net"), ("Contacts:MobilePhoneNumber", "+1 555 0100"),
                ("Contacts:CompanyName", "Acme"), ("Contacts:HomeCity", "Springfield"),
                ("Contacts:Birthday", "1990-05-01T00:00:00.000Z")])])])
        key = doc.text("SyncKey")
        sid = doc.find("Responses").find("Add").text("ServerId")
        vcard = sql(f"SELECT data FROM dav_objects WHERE id = {sid.split(':')[1]}")
        for expected in ("N:Doe;Jane;;;", "FN:Doe\\, Jane", "EMAIL;TYPE=INTERNET:jane@example.net",
                         "TEL;TYPE=CELL:+1 555 0100", "ORG:Acme;", "ADR;TYPE=HOME:;;;Springfield;;;",
                         "BDAY:1990-05-01"):
            self.assertIn(expected, vcard)
        card = ("BEGIN:VCARD\r\nVERSION:3.0\r\nUID:card-from-dav\r\nFN:Bob Builder\r\nN:Builder;Bob;;;\r\n"
                "EMAIL:bob@example.net\r\nTEL;TYPE=WORK:+1 555 0199\r\nTITLE:Builder\r\nEND:VCARD\r\n")
        sql("WITH c AS (UPDATE dav_collections SET modseq = modseq + 1 WHERE user_id = "
            "(SELECT id FROM users WHERE email = 'eas@example.org') AND kind = 'addressbook' AND name = 'Default' "
            "RETURNING id, modseq) INSERT INTO dav_objects (collection_id, href, uid, component, data, etag, "
            "created_modseq, modseq) SELECT id, 'card-from-dav.vcf', 'card-from-dav', 'VCARD', "
            f"$${card}$$, 'k2', modseq, modseq FROM c")
        doc = sync("CAL1", self.contacts, key)
        adds = [c for c in commands_of(doc) if c.name == "Add"]
        self.assertEqual(len(adds), 1)
        data = adds[0].child("ApplicationData")
        self.assertEqual((data.text("FirstName"), data.text("LastName")), ("Bob", "Builder"))
        self.assertEqual(data.text("Email1Address"), "bob@example.net")
        self.assertEqual(data.text("BusinessPhoneNumber"), "+1 555 0199")
        self.assertEqual(data.text("JobTitle"), "Builder")

    def test_5_meeting_response(self):
        invite = ("From: Carol <carol@example.org>\r\nTo: eas@example.org\r\nSubject: Planning\r\n"
                  "Message-ID: <planning@example.org>\r\nMIME-Version: 1.0\r\n"
                  "Content-Type: text/calendar; method=REQUEST; charset=utf-8\r\n\r\n"
                  "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nUID:planning-1\r\n"
                  "DTSTAMP:20261101T000000Z\r\nDTSTART:20261120T150000Z\r\nDTEND:20261120T160000Z\r\n"
                  "SUMMARY:Planning\r\nORGANIZER;CN=Carol:mailto:carol@example.org\r\n"
                  "ATTENDEE;RSVP=TRUE;PARTSTAT=NEEDS-ACTION:mailto:eas@example.org\r\nEND:VEVENT\r\n"
                  "END:VCALENDAR\r\n")
        submit_as("carol@example.org", "carol-pw", USER, invite)
        folders = folders_of(folder_sync("CAL2"))
        inbox = folders["INBOX"][0]
        key, items = fresh_sync("CAL2", inbox)
        sid = next(s for s, d in items.items() if d.text("Subject") == "Planning")
        status, doc, _ = post("MeetingResponse", ("MeetingResponse:MeetingResponse", [("MeetingResponse:Request", [
            ("MeetingResponse:UserResponse", "1"), ("MeetingResponse:CollectionId", inbox),
            ("MeetingResponse:RequestId", sid)])]), device="CAL2")
        self.assertEqual(doc.text("Status"), "1")
        self.assertTrue(doc.text("CalendarId"))
        stored = sql("SELECT data FROM dav_objects WHERE uid = 'planning-1' AND NOT deleted")
        self.assertIn("PARTSTAT=ACCEPTED", stored)
        self.assertNotIn("METHOD", stored)
        time.sleep(0.5)
        c = imap("carol@example.org", "carol-pw")
        c.select("INBOX")
        for _ in range(20):
            _, data = c.search(None, "SUBJECT", '"Accepted: Planning"')
            if data[0]:
                break
            time.sleep(0.2)
            c.noop()
        self.assertTrue(data[0], "the organizer got the reply")
        _, fetched = c.fetch(data[0].split()[0], "(BODY.PEEK[])")
        self.assertIn(b"METHOD:REPLY", fetched[0][1])
        c.logout()


if __name__ == "__main__":
    unittest.main(verbosity=2)
