#!/usr/bin/env python3
"""Black-box EWS tests (pkgs/mews) against a running mailserver (see run.sh --ews): raw SOAP 1.1 over HTTPS on 2443,
checked with xml.etree, and the effects checked over IMAP, SMTP and the fake remote MX. ews@example.org and
ews2@example.org are made by run.sh for these tests."""
import base64, http.client, imaplib, os, re, smtplib, socket, ssl, sys, time, unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from smtp_test import relayed, sql, tls_context  # noqa: E402

HOST = "127.0.0.1"
HTTPS, MX, IMAPS = 2443, 2525, 2993
USER, PASSWORD = "ews@example.org", "ews-pw-1234"
OTHER, OTHER_PASSWORD = "ews2@example.org", "ews2-pw-1234"
S = "http://schemas.xmlsoap.org/soap/envelope/"
T = "http://schemas.microsoft.com/exchange/services/2006/types"
M = "http://schemas.microsoft.com/exchange/services/2006/messages"
NS = {"s": S, "t": T, "m": M}


def basic(user=USER, password=PASSWORD) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def post(body: str, auth=None, path="/EWS/Exchange.asmx"):
    c = http.client.HTTPSConnection(HOST, HTTPS, context=tls_context(), timeout=20)
    headers = {"Host": "mail.example.org", "Content-Type": "text/xml; charset=utf-8"}
    if auth is not False:
        headers["Authorization"] = auth or basic()
    c.request("POST", path, body=body.encode(), headers=headers)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r, data


def envelope(operation: str) -> str:
    return (f'<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="{S}" xmlns:t="{T}" xmlns:m="{M}">'
            f'<soap:Header><t:RequestServerVersion Version="Exchange2013"/></soap:Header>'
            f'<soap:Body>{operation}</soap:Body></soap:Envelope>')


def call(operation: str, auth=None) -> ET.Element:
    r, data = post(envelope(operation), auth)
    assert r.status == 200, (r.status, data[:500])
    # No white space between elements: Apple's parser drops items that have it.
    assert b">\n<" not in data.split(b"?>", 1)[-1] and b">  <" not in data, data[:300]
    return ET.fromstring(data)


def messages(root: ET.Element) -> list:
    rm = root.find("s:Body/*/m:ResponseMessages", NS)
    return list(rm)


def ok(root: ET.Element) -> ET.Element:
    ms = messages(root)
    assert ms and ms[0].get("ResponseClass") == "Success", ET.tostring(root)[:800]
    return ms[0]


def folder_ref(distinguished=None, folder_id=None) -> str:
    if distinguished:
        return f'<t:DistinguishedFolderId Id="{distinguished}"/>'
    return f'<t:FolderId Id="{folder_id}"/>'


def find_items(folder="inbox", offset=0, maximum=100) -> list:
    root = call(f'<m:FindItem Traversal="Shallow"><m:ItemShape><t:BaseShape>Default</t:BaseShape></m:ItemShape>'
                f'<m:IndexedPageItemView MaxEntriesReturned="{maximum}" Offset="{offset}" BasePoint="Beginning"/>'
                f'<m:ParentFolderIds>{folder_ref(folder)}</m:ParentFolderIds></m:FindItem>')
    return ok(root).findall("m:RootFolder/t:Items/t:Message", NS)


def get_item(item_id: str, shape="Default") -> ET.Element:
    return call(f'<m:GetItem><m:ItemShape><t:BaseShape>{shape}</t:BaseShape></m:ItemShape>'
                f'<m:ItemIds><t:ItemId Id="{item_id}"/></m:ItemIds></m:GetItem>')


def sync_items(folder="inbox", state="", maximum=100):
    st = f"<m:SyncState>{state}</m:SyncState>" if state else ""
    root = call(f'<m:SyncFolderItems><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape></m:ItemShape>'
                f'<m:SyncFolderId>{folder_ref(folder)}</m:SyncFolderId>{st}'
                f'<m:MaxChangesReturned>{maximum}</m:MaxChangesReturned></m:SyncFolderItems>')
    return messages(root)[0]


def changes(msg: ET.Element) -> list:
    out = []
    for c in msg.find("m:Changes", NS):
        kind = c.tag.split("}")[1]
        item = c.find("t:Message/t:ItemId", NS)
        if item is None:
            item = c.find("t:ItemId", NS)
        out.append((kind, item.get("Id")))
    return out


def item_uid(item_id: str) -> int:
    return int(base64.b64decode(item_id).decode().split(":")[1])


def deliver(subject: str, to=USER, extra="") -> None:
    with smtplib.SMTP(HOST, MX) as c:
        c.ehlo("remote.test")
        c.sendmail("sender@remote.test", [to],
                   f"From: Sender Name <sender@remote.test>\r\nTo: {to}\r\nSubject: {subject}\r\n"
                   f"Message-ID: <{subject}@remote.test>\r\nDate: Thu, 05 Nov 2026 10:00:00 +0100\r\n{extra}\r\n"
                   f"Body of {subject}.\r\n")


def imap(user=USER, password=PASSWORD) -> imaplib.IMAP4_SSL:
    c = imaplib.IMAP4_SSL(HOST, IMAPS, ssl_context=tls_context())
    c.login(user, password)
    return c


def wait_for(subject: str, folder="inbox", seconds=5) -> ET.Element:
    deadline = time.time() + seconds
    while time.time() < deadline:
        for m in find_items(folder):
            if m.findtext("t:Subject", namespaces=NS) == subject:
                return m
        time.sleep(0.1)
    raise AssertionError(f"{subject} not in {folder}")


class Auth(unittest.TestCase):
    def test_challenge(self):
        r, _ = post(envelope("<m:GetFolder/>"), auth=False)
        self.assertEqual(r.status, 401)
        self.assertIn('Basic realm="CosmoMail"', r.getheader("WWW-Authenticate"))
        r, _ = post(envelope("<m:GetFolder/>"), auth=basic(USER, "wrong"))
        self.assertEqual(r.status, 401)

    def test_get_and_fault(self):
        c = http.client.HTTPSConnection(HOST, HTTPS, context=tls_context(), timeout=10)
        c.request("GET", "/EWS/Exchange.asmx", headers={"Host": "mail.example.org"})
        r = c.getresponse()
        self.assertEqual((r.status, r.read()), (200, b"CosmoMail EWS endpoint"))
        r, data = post("<not-soap")
        self.assertEqual(r.status, 500)
        fault = ET.fromstring(data).find("s:Body/s:Fault", NS)
        self.assertEqual(fault.findtext("faultcode"), "soap:Client")

    def test_plain_http_refused(self):
        c = http.client.HTTPConnection(HOST, 2080, timeout=10)
        c.request("POST", "/EWS/Exchange.asmx", body=envelope("<m:GetFolder/>"),
                  headers={"Host": "mail.example.org", "Authorization": basic()})
        self.assertEqual(c.getresponse().status, 403)

    def test_unknown_operation_succeeds_empty(self):
        msg = ok(call("<m:ResolveNames ReturnFullContactData=\"true\"><m:UnresolvedEntry>x</m:UnresolvedEntry></m:ResolveNames>"))
        self.assertEqual(msg.tag, f"{{{M}}}ResolveNamesResponseMessage")


class Folders(unittest.TestCase):
    def test_get_folder(self):
        root = call('<m:GetFolder><m:FolderShape><t:BaseShape>Default</t:BaseShape></m:FolderShape><m:FolderIds>'
                    '<t:DistinguishedFolderId Id="inbox"/><t:DistinguishedFolderId Id="msgfolderroot"/>'
                    '<t:DistinguishedFolderId Id="nonsense"/><t:DistinguishedFolderId Id="calendar"/>'
                    '</m:FolderIds></m:GetFolder>')
        ms = messages(root)
        self.assertEqual([m.get("ResponseClass") for m in ms], ["Success", "Success", "Error", "Success"])
        inbox = ms[0].find("m:Folders/t:Folder", NS)
        self.assertEqual([c.tag.split("}")[1] for c in inbox],
                         ["FolderId", "ParentFolderId", "FolderClass", "DisplayName", "TotalCount",
                          "ChildFolderCount", "UnreadCount"])
        self.assertEqual(inbox.findtext("t:DisplayName", namespaces=NS), "INBOX")
        rootf = ms[1].find("m:Folders/t:Folder", NS)
        self.assertEqual(base64.b64decode(rootf.find("t:FolderId", NS).get("Id")).decode()[:5], "root:")
        self.assertGreaterEqual(int(rootf.findtext("t:ChildFolderCount", namespaces=NS)), 5)
        self.assertEqual(ms[2].findtext("m:ResponseCode", namespaces=NS), "ErrorItemNotFound")
        self.assertEqual(ms[3].find("m:Folders/t:Folder/t:FolderClass", NS).text, "IPF.Appointment")
        # By opaque id, and another user's folder is not found.
        fid = inbox.find("t:FolderId", NS).get("Id")
        again = ok(call(f"<m:GetFolder><m:FolderIds>{folder_ref(folder_id=fid)}</m:FolderIds></m:GetFolder>"))
        self.assertEqual(again.findtext("m:Folders/t:Folder/t:DisplayName", namespaces=NS), "INBOX")
        theirs = messages(call(f"<m:GetFolder><m:FolderIds>{folder_ref(folder_id=fid)}</m:FolderIds></m:GetFolder>",
                               auth=basic(OTHER, OTHER_PASSWORD)))[0]
        self.assertEqual(theirs.findtext("m:ResponseCode", namespaces=NS), "ErrorItemNotFound")

    def test_roots_are_per_user(self):
        # macOS takes the id of the distinguished folder `root` as the account's identity: with one id for every
        # user, adding a second account of the same server fails with "This account already exists".
        def roots(auth):
            got = call('<m:GetFolder><m:FolderShape><t:BaseShape>IdOnly</t:BaseShape></m:FolderShape><m:FolderIds>'
                       '<t:DistinguishedFolderId Id="root"/><t:DistinguishedFolderId Id="msgfolderroot"/>'
                       '</m:FolderIds></m:GetFolder>', auth=auth)
            return [m.find("m:Folders/t:Folder", NS) for m in messages(got)]
        mine, theirs = roots(None), roots(basic(OTHER, OTHER_PASSWORD))
        top, store = (f.find("t:FolderId", NS).get("Id") for f in mine)
        self.assertNotEqual(top, theirs[0].find("t:FolderId", NS).get("Id"))
        self.assertNotEqual(store, theirs[1].find("t:FolderId", NS).get("Id"))
        self.assertEqual(mine[1].find("t:ParentFolderId", NS).get("Id"), top)
        # By its opaque id, the root is found again and holds the top of the information store.
        again = ok(call(f"<m:GetFolder><m:FolderShape><t:BaseShape>Default</t:BaseShape></m:FolderShape>"
                        f"<m:FolderIds>{folder_ref(folder_id=top)}</m:FolderIds></m:GetFolder>"))
        self.assertEqual(again.find("m:Folders/t:Folder/t:FolderId", NS).get("Id"), top)
        found = ok(call(f"<m:FindFolder Traversal=\"Shallow\"><m:FolderShape><t:BaseShape>IdOnly</t:BaseShape>"
                        f"</m:FolderShape><m:ParentFolderIds>{folder_ref(folder_id=top)}</m:ParentFolderIds>"
                        f"</m:FindFolder>"))
        self.assertEqual([f.get("Id") for f in found.iterfind(".//t:FolderId", NS)], [store])

    def test_apple_mail_hierarchy(self):
        # Apple Mail 16's sequence (captured from a crash): GetFolder IdOnly for the distinguished folders, then
        # SyncFolderHierarchy asking for ParentFolderId, FolderClass, PR_ENTRYID and PR_ATTR_HIDDEN. It asserts that
        # every distinguished folder is in the synced tree, so the tree must hold them all, be rooted (no folder is
        # its own parent) and carry the properties asked for.
        names = ["msgfolderroot", "inbox", "drafts", "sentitems", "deleteditems", "junkemail", "outbox", "notes",
                 "tasks", "journal"]
        got = call('<m:GetFolder><m:FolderShape><t:BaseShape>IdOnly</t:BaseShape></m:FolderShape><m:FolderIds>'
                   + "".join(f'<t:DistinguishedFolderId Id="{n}"/>' for n in names) + '</m:FolderIds></m:GetFolder>')
        ms = messages(got)
        self.assertEqual([m.get("ResponseClass") for m in ms], ["Success"] * len(names))
        ids = {n: m.find("m:Folders/t:Folder/t:FolderId", NS).get("Id") for n, m in zip(names, ms)}
        root = ms[0].find("m:Folders/t:Folder", NS)
        self.assertNotEqual(root.find("t:ParentFolderId", NS).get("Id"), ids["msgfolderroot"], "root is its own parent")
        sync = ok(call(
            '<m:SyncFolderHierarchy><m:FolderShape><t:BaseShape>Default</t:BaseShape><t:AdditionalProperties>'
            '<t:FieldURI FieldURI="folder:ParentFolderId"/><t:FieldURI FieldURI="folder:FolderClass"/>'
            '<t:ExtendedFieldURI PropertyTag="0xfff" PropertyType="Binary"/>'
            '<t:ExtendedFieldURI PropertyTag="0x10f4" PropertyType="Boolean"/>'
            '</t:AdditionalProperties></m:FolderShape></m:SyncFolderHierarchy>'))
        folders = sync.findall("m:Changes/t:Create/t:Folder", NS)
        synced = {f.find("t:FolderId", NS).get("Id") for f in folders}
        for n in names[1:]:
            self.assertIn(ids[n], synced, f"{n} is not in the synced hierarchy")
        for f in folders:
            self.assertEqual(f.find("t:ParentFolderId", NS).get("Id"), ids["msgfolderroot"])
            props = {p.find("t:ExtendedFieldURI", NS).get("PropertyTag"): p.findtext("t:Value", namespaces=NS)
                     for p in f.findall("t:ExtendedProperty", NS)}
            self.assertTrue(props.get("0xfff"), "PR_ENTRYID")
            self.assertEqual(props.get("0x10f4"), "false")
            self.assertEqual([c.tag.split("}")[1] for c in f][-3:], ["ExtendedProperty", "ExtendedProperty",
                                                                      "UnreadCount"])
        # The virtual folders resolve by the ids handed out, and are empty.
        for n in ("notes", "outbox"):
            again = ok(call(f"<m:GetFolder><m:FolderIds>{folder_ref(folder_id=ids[n])}</m:FolderIds></m:GetFolder>"))
            self.assertEqual(again.findtext("m:Folders/t:Folder/t:TotalCount", namespaces=NS), "0")

    def test_find_folder_and_hierarchy_sync(self):
        found = ok(call('<m:FindFolder Traversal="Deep"><m:FolderShape><t:BaseShape>Default</t:BaseShape>'
                        '</m:FolderShape><m:ParentFolderIds><t:DistinguishedFolderId Id="msgfolderroot"/>'
                        '</m:ParentFolderIds></m:FindFolder>'))
        names = [f.findtext("t:DisplayName", namespaces=NS) for f in found.findall("m:RootFolder/t:Folders/t:Folder", NS)]
        for n in ("INBOX", "Sent", "Drafts", "Trash"):
            self.assertIn(n, names)
        first = ok(call('<m:SyncFolderHierarchy><m:FolderShape><t:BaseShape>Default</t:BaseShape></m:FolderShape>'
                        '</m:SyncFolderHierarchy>'))
        created = first.findall("m:Changes/t:Create/t:Folder", NS)
        self.assertEqual(len(created), len(names))
        state = first.findtext("m:SyncState", namespaces=NS)
        quiet = ok(call(f"<m:SyncFolderHierarchy><m:SyncState>{state}</m:SyncState></m:SyncFolderHierarchy>"))
        self.assertEqual(len(quiet.find("m:Changes", NS)), 0)
        c = imap()
        c.create("EwsProjects")
        added = ok(call(f"<m:SyncFolderHierarchy><m:SyncState>{state}</m:SyncState></m:SyncFolderHierarchy>"))
        self.assertEqual([f.findtext("t:DisplayName", namespaces=NS)
                          for f in added.findall("m:Changes/t:Create/t:Folder", NS)], ["EwsProjects"])
        state2 = added.findtext("m:SyncState", namespaces=NS)
        c.delete("EwsProjects")
        c.logout()
        removed = ok(call(f"<m:SyncFolderHierarchy><m:SyncState>{state2}</m:SyncState></m:SyncFolderHierarchy>"))
        self.assertEqual(len(removed.findall("m:Changes/t:Delete/t:FolderId", NS)), 1)
        bad = messages(call("<m:SyncFolderHierarchy><m:SyncState>bm9wZQ==</m:SyncState></m:SyncFolderHierarchy>"))[0]
        self.assertEqual(bad.findtext("m:ResponseCode", namespaces=NS), "ErrorInvalidSyncStateData")


class Items(unittest.TestCase):
    def test_find_and_get(self):
        deliver("ews-find", extra="Cc: Carol <carol@example.org>\r\n")
        m = wait_for("ews-find")
        self.assertEqual(m.findtext("t:IsRead", namespaces=NS), "false")
        self.assertEqual(m.findtext("t:From/t:Mailbox/t:Name", namespaces=NS), "Sender Name")
        self.assertEqual(m.findtext("t:From/t:Mailbox/t:EmailAddress", namespaces=NS), "sender@remote.test")
        self.assertEqual(m.findtext("t:CcRecipients/t:Mailbox/t:EmailAddress", namespaces=NS), "carol@example.org")
        self.assertEqual(m.findtext("t:DateTimeSent", namespaces=NS), "2026-11-05T09:00:00Z")
        self.assertEqual(m.findtext("t:InternetMessageId", namespaces=NS), "<ews-find@remote.test>")
        item = m.find("t:ItemId", NS).get("Id")
        got = ok(get_item(item)).find("m:Items/t:Message", NS)
        tags = [c.tag.split("}")[1] for c in got]
        self.assertEqual(tags[:4], ["MimeContent", "ItemId", "ParentFolderId", "ItemClass"])
        mime = base64.b64decode(got.findtext("t:MimeContent", namespaces=NS))
        self.assertIn(b"Subject: ews-find\r\n", mime)
        self.assertIn(b"Body of ews-find.", mime)
        self.assertEqual(int(got.findtext("t:Size", namespaces=NS)), len(mime))
        bare = ok(get_item(item, "IdOnly")).find("m:Items/t:Message", NS)
        self.assertIsNone(bare.find("t:MimeContent", NS))
        # Someone else's id, a malformed one, and one that does not exist.
        theirs = messages(call(f'<m:GetItem><m:ItemShape><t:BaseShape>Default</t:BaseShape></m:ItemShape>'
                               f'<m:ItemIds><t:ItemId Id="{item}"/></m:ItemIds></m:GetItem>',
                               auth=basic(OTHER, OTHER_PASSWORD)))[0]
        self.assertEqual(theirs.findtext("m:ResponseCode", namespaces=NS), "ErrorItemNotFound")
        self.assertEqual(messages(get_item("!!"))[0].get("ResponseClass"), "Error")

    def test_paging(self):
        for i in range(3):
            deliver(f"ews-page-{i}")
        wait_for("ews-page-2")
        first = find_items(maximum=2)
        self.assertEqual(len(first), 2)
        self.assertEqual(first[0].findtext("t:Subject", namespaces=NS), "ews-page-2", "newest first")
        root = call('<m:FindItem Traversal="Shallow"><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape></m:ItemShape>'
                    '<m:IndexedPageItemView MaxEntriesReturned="2" Offset="0" BasePoint="Beginning"/>'
                    '<m:ParentFolderIds><t:DistinguishedFolderId Id="inbox"/></m:ParentFolderIds></m:FindItem>')
        view = ok(root).find("m:RootFolder", NS)
        self.assertEqual(view.get("IncludesLastItemInRange"), "false")
        self.assertEqual(view.get("IndexedPagingOffset"), "2")
        self.assertEqual(find_items("calendar"), [])

    def test_sync_items(self):
        c = imap()
        c.create("EwsSync")
        c.select("EwsSync")
        for i in range(3):
            c.append("EwsSync", None, None, f"Subject: sync-{i}\r\n\r\nbody {i}\r\n".encode())
        fid = None
        found = ok(call('<m:FindFolder><m:ParentFolderIds><t:DistinguishedFolderId Id="msgfolderroot"/>'
                        '</m:ParentFolderIds></m:FindFolder>'))
        for f in found.findall("m:RootFolder/t:Folders/t:Folder", NS):
            if f.findtext("t:DisplayName", namespaces=NS) == "EwsSync":
                fid = f.find("t:FolderId", NS).get("Id")

        def sync(state="", maximum=100):
            root = call(f'<m:SyncFolderItems><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape></m:ItemShape>'
                        f'<m:SyncFolderId>{folder_ref(folder_id=fid)}</m:SyncFolderId>'
                        f'{"<m:SyncState>" + state + "</m:SyncState>" if state else ""}'
                        f'<m:MaxChangesReturned>{maximum}</m:MaxChangesReturned></m:SyncFolderItems>')
            return messages(root)[0]

        # Two rounds of at most two changes.
        a = sync(maximum=2)
        self.assertEqual([k for k, _ in changes(a)], ["Create", "Create"])
        self.assertEqual(a.findtext("m:IncludesLastItemInRange", namespaces=NS), "false")
        b = sync(a.findtext("m:SyncState", namespaces=NS), 2)
        self.assertEqual([k for k, _ in changes(b)], ["Create"])
        self.assertEqual(b.findtext("m:IncludesLastItemInRange", namespaces=NS), "true")
        state = b.findtext("m:SyncState", namespaces=NS)
        self.assertEqual(changes(sync(state)), [])
        # A flag change, a new message and an expunge.
        c.store("1", "+FLAGS", "\\Seen")
        c.append("EwsSync", None, None, b"Subject: sync-new\r\n\r\nnew\r\n")
        c.store("2", "+FLAGS", "\\Deleted")
        c.expunge()
        d = sync(state)
        got = changes(d)
        self.assertEqual(sorted(k for k, _ in got), ["Create", "Delete", "Update"])
        self.assertEqual([item_uid(i) for k, i in got if k == "Delete"], [2])
        self.assertEqual([item_uid(i) for k, i in got if k == "Update"], [1])
        updated = d.find("m:Changes/t:Update/t:Message", NS)
        self.assertEqual(updated.findtext("t:IsRead", namespaces=NS), "true")
        state = d.findtext("m:SyncState", namespaces=NS)
        self.assertEqual(changes(sync(state)), [])
        # One STORE over every message (one modseq for all, possibly), read one change at a time: none is lost.
        c.store("1:*", "+FLAGS", "\\Flagged")
        seen = set()
        for _ in range(10):
            r = sync(state, 1)
            seen |= {item_uid(i) for k, i in changes(r) if k == "Update"}
            state = r.findtext("m:SyncState", namespaces=NS)
            if r.findtext("m:IncludesLastItemInRange", namespaces=NS) == "true":
                break
        _, data = c.uid("SEARCH", "ALL")
        self.assertEqual(seen, {int(u) for u in data[0].split()})
        bad = sync("bm9wZQ==")
        self.assertEqual(bad.findtext("m:ResponseCode", namespaces=NS), "ErrorInvalidSyncStateData")
        c.logout()

    def test_update(self):
        deliver("ews-update")
        item = wait_for("ews-update").find("t:ItemId", NS)
        uid = item_uid(item.get("Id"))
        root = call(f'<m:UpdateItem ConflictResolution="AlwaysOverwrite" MessageDisposition="SaveOnly"><m:ItemChanges>'
                    f'<t:ItemChange><t:ItemId Id="{item.get("Id")}" ChangeKey="{item.get("ChangeKey")}"/><t:Updates>'
                    f'<t:SetItemField><t:FieldURI FieldURI="message:IsRead"/><t:Message><t:IsRead>true</t:IsRead>'
                    f'</t:Message></t:SetItemField>'
                    f'<t:SetItemField><t:FieldURI FieldURI="item:Flag"/><t:Message><t:Flag>'
                    f'<t:FlagStatus>Flagged</t:FlagStatus></t:Flag></t:Message></t:SetItemField>'
                    f'<t:SetItemField><t:FieldURI FieldURI="item:Categories"/><t:Message><t:Categories>'
                    f'<t:String>Red Category</t:String><t:String>Work</t:String></t:Categories></t:Message>'
                    f'</t:SetItemField></t:Updates></t:ItemChange></m:ItemChanges></m:UpdateItem>')
        new = ok(root).find("m:Items/t:Message/t:ItemId", NS)
        self.assertNotEqual(new.get("ChangeKey"), item.get("ChangeKey"))
        c = imap()
        c.select("INBOX", readonly=True)
        _, data = c.uid("FETCH", str(uid), "(FLAGS)")
        flags = data[0].decode()
        self.assertIn("\\Seen", flags)
        self.assertIn("\\Flagged", flags)
        self.assertIn("Red_Category", flags)
        self.assertIn("Work", flags)
        c.logout()
        got = ok(get_item(item.get("Id"), "IdOnly")).find("m:Items/t:Message", NS)
        self.assertEqual([s.text for s in got.findall("t:Categories/t:String", NS)], ["Red_Category", "Work"])
        self.assertEqual(got.findtext("t:IsRead", namespaces=NS), "true")

    def test_move_copy_delete(self):
        deliver("ews-move")
        item = wait_for("ews-move").find("t:ItemId", NS).get("Id")
        moved = ok(call(f'<m:MoveItem><m:ToFolderId><t:DistinguishedFolderId Id="archive"/></m:ToFolderId>'
                        f'<m:ItemIds><t:ItemId Id="{item}"/></m:ItemIds></m:MoveItem>'))
        archived = moved.find("m:Items/t:Message/t:ItemId", NS).get("Id")
        self.assertNotIn("ews-move", [m.findtext("t:Subject", namespaces=NS) for m in find_items()])
        wait_for("ews-move", "archive")
        # The old id is gone: a replayed move gets ErrorItemNotFound, which makes Apple Mail drop it.
        again = messages(call(f'<m:MoveItem><m:ToFolderId><t:DistinguishedFolderId Id="archive"/></m:ToFolderId>'
                              f'<m:ItemIds><t:ItemId Id="{item}"/></m:ItemIds></m:MoveItem>'))[0]
        self.assertEqual(again.findtext("m:ResponseCode", namespaces=NS), "ErrorItemNotFound")
        copied = ok(call(f'<m:CopyItem><m:ToFolderId><t:DistinguishedFolderId Id="inbox"/></m:ToFolderId>'
                         f'<m:ItemIds><t:ItemId Id="{archived}"/></m:ItemIds></m:CopyItem>'))
        copy = copied.find("m:Items/t:Message/t:ItemId", NS).get("Id")
        wait_for("ews-move")
        ok(call(f'<m:DeleteItem DeleteType="MoveToDeletedItems"><m:ItemIds><t:ItemId Id="{copy}"/></m:ItemIds>'
                f'</m:DeleteItem>'))
        trashed = wait_for("ews-move", "deleteditems").find("t:ItemId", NS).get("Id")
        ok(call(f'<m:DeleteItem DeleteType="HardDelete"><m:ItemIds><t:ItemId Id="{trashed}"/></m:ItemIds>'
                f'</m:DeleteItem>'))
        self.assertNotIn("ews-move", [m.findtext("t:Subject", namespaces=NS) for m in find_items("deleteditems")])
        both = messages(call(f'<m:DeleteItem DeleteType="HardDelete"><m:ItemIds><t:ItemId Id="{archived}"/>'
                             f'<t:ItemId Id="{trashed}"/></m:ItemIds></m:DeleteItem>'))
        self.assertEqual([m.get("ResponseClass") for m in both], ["Success", "Error"])


class Send(unittest.TestCase):
    def test_send_and_save_copy(self):
        mime = ("From: EWS User <ews@example.org>\r\nTo: ews2@example.org, far@remote.test\r\n"
                "Bcc: hidden@remote.test\r\nSubject: ews-sent\r\nMessage-ID: <ews-sent@example.org>\r\n\r\n"
                "Sent through EWS.\r\n")
        root = call(f'<m:CreateItem MessageDisposition="SendAndSaveCopy"><m:SavedItemFolderId>'
                    f'<t:DistinguishedFolderId Id="sentitems"/></m:SavedItemFolderId><m:Items><t:Message>'
                    f'<t:MimeContent CharacterSet="UTF-8">{base64.b64encode(mime.encode()).decode()}</t:MimeContent>'
                    f'</t:Message></m:Items></m:CreateItem>')
        saved = ok(root).find("m:Items/t:Message/t:ItemId", NS)
        self.assertIsNotNone(saved, "the saved copy's id")
        sent = ok(get_item(saved.get("Id"))).find("m:Items/t:Message", NS)
        self.assertEqual(sent.findtext("t:Subject", namespaces=NS), "ews-sent")
        self.assertEqual(sent.findtext("t:IsRead", namespaces=NS), "true")
        stored = base64.b64decode(sent.findtext("t:MimeContent", namespaces=NS))
        self.assertNotIn(b"Bcc:", stored)
        # The local recipient has it; the remote ones (Bcc too) got it through the relay.
        root2 = call('<m:FindItem Traversal="Shallow"><m:ItemShape><t:BaseShape>IdOnly</t:BaseShape></m:ItemShape>'
                     '<m:ParentFolderIds><t:DistinguishedFolderId Id="inbox"/></m:ParentFolderIds></m:FindItem>',
                     auth=basic(OTHER, OTHER_PASSWORD))
        self.assertIn("ews-sent", [m.findtext("t:Subject", namespaces=NS)
                                   for m in ok(root2).findall("m:RootFolder/t:Items/t:Message", NS)])
        far = relayed("far@remote.test", "ews@example.org")
        self.assertEqual(len(far), 1)
        self.assertIn("Subject: ews-sent", far[0])
        self.assertNotIn("Bcc:", far[0])
        self.assertEqual(len(relayed("hidden@remote.test", "ews@example.org")), 1)

    def test_save_draft_and_compose(self):
        root = call('<m:CreateItem MessageDisposition="SaveOnly"><m:Items><t:Message>'
                    '<t:Subject>ews-draft été</t:Subject><t:Body BodyType="Text">Draft body</t:Body>'
                    '<t:ToRecipients><t:Mailbox><t:EmailAddress>far@remote.test</t:EmailAddress></t:Mailbox>'
                    '</t:ToRecipients></t:Message></m:Items></m:CreateItem>')
        saved = ok(root).find("m:Items/t:Message/t:ItemId", NS).get("Id")
        draft = ok(get_item(saved)).find("m:Items/t:Message", NS)
        self.assertEqual(draft.findtext("t:Subject", namespaces=NS), "ews-draft été")
        self.assertEqual(draft.findtext("t:IsDraft", namespaces=NS), "true")
        self.assertIn(b"To: far@remote.test", base64.b64decode(draft.findtext("t:MimeContent", namespaces=NS)))
        self.assertIn("ews-draft été", [m.findtext("t:Subject", namespaces=NS) for m in find_items("drafts")])

    def test_no_recipients(self):
        mime = base64.b64encode(b"Subject: nobody\r\n\r\nx\r\n").decode()
        msg = messages(call(f'<m:CreateItem MessageDisposition="SendOnly"><m:Items><t:Message><t:MimeContent>'
                            f'{mime}</t:MimeContent></t:Message></m:Items></m:CreateItem>'))[0]
        self.assertEqual(msg.findtext("m:ResponseCode", namespaces=NS), "ErrorInvalidRecipients")


class Notifications(unittest.TestCase):
    def test_subscribe_and_get_events(self):
        pull = ok(call('<m:Subscribe><m:PullSubscriptionRequest><t:FolderIds><t:DistinguishedFolderId Id="inbox"/>'
                       '</t:FolderIds><t:EventTypes><t:EventType>NewMailEvent</t:EventType></t:EventTypes>'
                       '<t:Timeout>10</t:Timeout></m:PullSubscriptionRequest></m:Subscribe>'))
        self.assertIsNotNone(pull.findtext("m:Watermark", namespaces=NS))
        streaming = ok(call('<m:Subscribe><m:StreamingSubscriptionRequest><t:FolderIds>'
                            '<t:DistinguishedFolderId Id="inbox"/></t:FolderIds><t:EventTypes>'
                            '<t:EventType>NewMailEvent</t:EventType></t:EventTypes></m:StreamingSubscriptionRequest>'
                            '</m:Subscribe>'))
        self.assertIsNone(streaming.find("m:Watermark", NS))
        sid = streaming.findtext("m:SubscriptionId", namespaces=NS)
        events = ok(call(f'<m:GetEvents><m:SubscriptionId>{sid}</m:SubscriptionId><m:Watermark>x</m:Watermark>'
                         f'</m:GetEvents>'))
        self.assertIsNotNone(events.find("m:Notification/t:StatusEvent", NS))

    def test_streaming_events(self):
        body = envelope('<m:GetStreamingEvents><m:SubscriptionIds><t:SubscriptionId>sub-test</t:SubscriptionId>'
                        '</m:SubscriptionIds><m:ConnectionTimeout>1</m:ConnectionTimeout></m:GetStreamingEvents>')
        raw = socket.create_connection((HOST, HTTPS), timeout=20)
        s = tls_context().wrap_socket(raw, server_hostname="localhost")
        s.sendall((f"POST /EWS/Exchange.asmx HTTP/1.1\r\nHost: mail.example.org\r\nAuthorization: {basic()}\r\n"
                   f"Content-Type: text/xml\r\nContent-Length: {len(body.encode())}\r\n\r\n").encode() + body.encode())
        buffer = b""

        def read_part():
            nonlocal buffer
            while True:
                m = re.match(rb"([0-9a-f]+)\r\n", buffer)
                if m:
                    n = int(m.group(1), 16)
                    start = m.end()
                    if len(buffer) >= start + n + 2:
                        part = buffer[start:start + n]
                        buffer = buffer[start + n + 2:]
                        return part
                chunk = s.recv(65536)
                if not chunk:
                    raise AssertionError("closed")
                buffer += chunk

        while b"\r\n\r\n" not in buffer:
            buffer += s.recv(65536)
        head, buffer = buffer.split(b"\r\n\r\n", 1)
        self.assertIn(b"200 OK", head.split(b"\r\n")[0])
        self.assertIn(b"Transfer-Encoding: chunked", head)
        first = ET.fromstring(read_part())
        self.assertEqual(first.findtext(".//m:ConnectionStatus", namespaces=NS), "OK")
        deliver("ews-stream")
        event = ET.fromstring(read_part())
        new = event.find(".//m:Notifications/m:Notification/t:NewMailEvent", NS)
        self.assertIsNotNone(new, ET.tostring(event)[:600])
        self.assertEqual(event.findtext(".//t:SubscriptionId", namespaces=NS), "sub-test")
        item = new.find("t:ItemId", NS).get("Id")
        got = ok(get_item(item, "IdOnly")).find("m:Items/t:Message", NS)
        self.assertEqual(got.findtext("t:Subject", namespaces=NS), "ews-stream")
        s.close()


class Autodiscover(unittest.TestCase):
    def test_v2_json_ews(self):
        c = http.client.HTTPSConnection(HOST, HTTPS, context=tls_context(), timeout=10)
        c.request("GET", "/autodiscover/autodiscover.json/v1.0/ews@example.org?Protocol=EWS",
                  headers={"Host": "autodiscover.example.org"})
        r = c.getresponse()
        import json
        self.assertEqual(r.status, 200)
        self.assertEqual(json.loads(r.read()), {"Protocol": "EWS", "Url": "https://mail.example.org/EWS/Exchange.asmx"})

    def test_pox_expr_when_enabled(self):
        body = ('<?xml version="1.0"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/'
                'outlook/requestschema/2006"><Request><EMailAddress>ews@example.org</EMailAddress>'
                '<AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/'
                'responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>')
        c = http.client.HTTPSConnection(HOST, HTTPS, context=tls_context(), timeout=10)
        import base64
        auth = "Basic " + base64.b64encode(b"ews@example.org:ews-pw-1234").decode()
        c.request("POST", "/autodiscover/autodiscover.xml", body=body,
                  headers={"Host": "autodiscover.example.org", "Content-Type": "text/xml", "Authorization": auth})
        data = c.getresponse().read().decode()
        # run.sh --ews turns advertise_exchange on.
        self.assertIn("<Type>EXPR</Type>", data)
        self.assertIn("<EwsUrl>https://mail.example.org/EWS/Exchange.asmx</EwsUrl>", data)
        self.assertIn("<LoginName>ews@example.org</LoginName>", data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
