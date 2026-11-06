#!/usr/bin/env python3
"""Black-box CalDAV (RFC 4791) and CardDAV (RFC 6352) tests against a running mailserver (see run.sh --dav), over
HTTPS on 2443 with Python's http.client and ElementTree: discovery as Apple's and Thunderbird's clients do it, PUT and
GET with etags and preconditions, the reports (multiget, query with a time range, sync-collection), MKCALENDAR, MKCOL,
PROPPATCH and DELETE."""
import base64, http.client, os, subprocess, sys, unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from smtp_test import sql, tls_context  # noqa: E402

HOST = "127.0.0.1"
HTTP, HTTPS = 2080, 2443
USER, PASSWORD = "dav@example.org", "dav-pw-1234"
OTHER, OTHER_PASSWORD = "dav2@example.org", "dav2-pw-1234"
NS = {"D": "DAV:", "C": "urn:ietf:params:xml:ns:caldav", "CARD": "urn:ietf:params:xml:ns:carddav",
      "CS": "http://calendarserver.org/ns/", "IC": "http://apple.com/ns/ical/"}
CAL = f"/dav/calendars/{USER}/Default/"
BOOK = f"/dav/contacts/{USER}/Default/"


def dav(method, path, body=None, headers=None, user=USER, password=PASSWORD, port=HTTPS):
    if port == HTTPS:
        c = http.client.HTTPSConnection(HOST, port, context=tls_context(), timeout=10)
    else:
        c = http.client.HTTPConnection(HOST, port, timeout=10)
    h = {"Host": "localhost"}
    if user is not None:
        h["Authorization"] = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
    if body is not None and "Content-Type" not in (headers or {}):
        h["Content-Type"] = "application/xml; charset=utf-8"
    h.update(headers or {})
    c.request(method, path, body=body.encode() if isinstance(body, str) else body, headers=h)
    r = c.getresponse()
    data = r.read()
    c.close()
    return r, data


def xml(data: bytes):
    return ET.fromstring(data)


def responses(data: bytes) -> dict:
    """href -> {"status": the response's own status or None, "props": {clark name: (status, element)}}."""
    out = {}
    for resp in xml(data).findall("D:response", NS):
        href = resp.find("D:href", NS).text
        own = resp.find("D:status", NS)
        props = {}
        for ps in resp.findall("D:propstat", NS):
            status = ps.find("D:status", NS).text
            for p in ps.find("D:prop", NS):
                props[p.tag] = (status, p)
        out[href] = {"status": own.text if own is not None else None, "props": props}
    return out


def ok(entry, tag):
    status, el = entry["props"][tag]
    assert "200" in status, (tag, status)
    return el


def event(uid: str, summary: str, start: str = "20261110T090000Z", end: str = "20261110T100000Z") -> str:
    return ("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\n"
            f"UID:{uid}\r\nDTSTAMP:20261101T000000Z\r\nDTSTART:{start}\r\nDTEND:{end}\r\nSUMMARY:{summary}\r\n"
            "END:VEVENT\r\nEND:VCALENDAR\r\n")


def card(uid: str, name: str) -> str:
    return f"BEGIN:VCARD\r\nVERSION:3.0\r\nUID:{uid}\r\nFN:{name}\r\nN:{name};;;;\r\nEND:VCARD\r\n"


PROPFIND_ALL = """<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>"""

D = "{DAV:}"
C = "{urn:ietf:params:xml:ns:caldav}"
CARD = "{urn:ietf:params:xml:ns:carddav}"


class Dav(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for who, pw in ((USER, PASSWORD), (OTHER, OTHER_PASSWORD)):
            subprocess.run([os.environ["MAILSERVER_BIN"], "--config", os.environ["MAILSERVER_CONFIG"], "add-user",
                            who, pw], check=False, capture_output=True)

    def test_01_options_and_well_known(self):
        r, _ = dav("OPTIONS", "/dav/", user=None)
        self.assertEqual(r.status, 200)
        self.assertIn("calendar-access", r.getheader("DAV"))
        self.assertIn("addressbook", r.getheader("DAV"))
        self.assertIn("REPORT", r.getheader("Allow"))
        for path in ("/.well-known/caldav", "/.well-known/carddav"):
            r, _ = dav("PROPFIND", path, user=None)
            self.assertEqual(r.status, 301, path)
            self.assertEqual(r.getheader("Location"), "/dav/")

    def test_02_logins(self):
        r, _ = dav("PROPFIND", "/dav/", user=None)
        self.assertEqual(r.status, 401)
        self.assertTrue(r.getheader("WWW-Authenticate").startswith("Basic realm="))
        r, _ = dav("PROPFIND", "/dav/", password="wrong")
        self.assertEqual(r.status, 401)
        r, _ = dav("PROPFIND", f"/dav/calendars/{OTHER}/", headers={"Depth": "0"})
        self.assertEqual(r.status, 403)
        r, _ = dav("PROPFIND", "/dav/", port=HTTP)
        self.assertEqual(r.status, 403, "never over plain HTTP")
        r, _ = dav("PROPFIND", "/dav/", user=USER.upper(), headers={"Depth": "0"})
        self.assertEqual(r.status, 207, "the address in any case")

    def test_03_discovery(self):
        body = """<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop><D:current-user-principal/>
            <D:resourcetype/></D:prop></D:propfind>"""
        r, data = dav("PROPFIND", "/dav/", body, {"Depth": "0"})
        self.assertEqual(r.status, 207)
        entry = responses(data)["/dav/"]
        principal = ok(entry, D + "current-user-principal").find("D:href", NS).text
        self.assertEqual(principal, f"/dav/principals/{USER}/")
        body = """<?xml version="1.0"?><D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"
            xmlns:CARD="urn:ietf:params:xml:ns:carddav" xmlns:A="http://example.com/ns/"><D:prop>
            <C:calendar-home-set/><CARD:addressbook-home-set/><C:calendar-user-address-set/><D:displayname/>
            <D:resourcetype/><A:unknown-thing/></D:prop></D:propfind>"""
        r, data = dav("PROPFIND", principal, body, {"Depth": "0"})
        self.assertEqual(r.status, 207)
        entry = responses(data)[principal]
        self.assertEqual(ok(entry, C + "calendar-home-set").find("D:href", NS).text, f"/dav/calendars/{USER}/")
        self.assertEqual(ok(entry, CARD + "addressbook-home-set").find("D:href", NS).text, f"/dav/contacts/{USER}/")
        addresses = [h.text for h in ok(entry, C + "calendar-user-address-set").findall("D:href", NS)]
        self.assertIn(f"mailto:{USER}", addresses)
        self.assertIsNotNone(ok(entry, D + "resourcetype").find("D:principal", NS))
        status, _ = entry["props"]["{http://example.com/ns/}unknown-thing"]
        self.assertIn("404", status)

    def test_04_calendar_home(self):
        r, data = dav("PROPFIND", f"/dav/calendars/{USER}/", PROPFIND_ALL, {"Depth": "1"})
        self.assertEqual(r.status, 207)
        all_ = responses(data)
        self.assertIn(f"/dav/calendars/{USER}/", all_)
        entry = all_[CAL]
        rt = ok(entry, D + "resourcetype")
        self.assertIsNotNone(rt.find("C:calendar", NS))
        self.assertIsNotNone(rt.find("D:collection", NS))
        self.assertTrue(ok(entry, D + "sync-token").text.startswith("http://cosmomail/sync/"))
        self.assertTrue(ok(entry, "{http://calendarserver.org/ns/}getctag").text.isdigit())
        comps = [c.get("name") for c in ok(entry, C + "supported-calendar-component-set")]
        self.assertEqual(comps, ["VEVENT", "VTODO"])
        reports = ok(entry, D + "supported-report-set")
        self.assertIsNotNone(reports.find(".//C:calendar-multiget", NS))
        self.assertIsNotNone(reports.find(".//D:sync-collection", NS))
        r, data = dav("PROPFIND", CAL, """<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:propname/></D:propfind>""",
                      {"Depth": "0"})
        self.assertIn("{http://apple.com/ns/ical/}calendar-color", responses(data)[CAL]["props"])

    def test_05_put_get_and_preconditions(self):
        path = CAL + "put-1.ics"
        r, _ = dav("PUT", path, event("put-1@test", "First"), {"Content-Type": "text/calendar"})
        self.assertEqual(r.status, 201)
        etag = r.getheader("ETag")
        self.assertTrue(etag.startswith('"') and etag.endswith('"'))
        r, data = dav("GET", path)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.getheader("ETag"), etag)
        self.assertTrue(r.getheader("Content-Type").startswith("text/calendar"))
        self.assertEqual(data.decode(), event("put-1@test", "First"))
        r, _ = dav("GET", path, headers={"If-None-Match": etag})
        self.assertEqual(r.status, 304)
        r, data = dav("HEAD", path)
        self.assertEqual((r.status, data), (200, b""))
        r, _ = dav("PUT", path, event("put-1@test", "Second"), {"If-Match": '"nope"'})
        self.assertEqual(r.status, 412)
        r, _ = dav("PUT", path, event("put-1@test", "Second"), {"If-None-Match": "*"})
        self.assertEqual(r.status, 412)
        r, _ = dav("PUT", path, event("put-1@test", "Second"), {"If-Match": etag})
        self.assertEqual(r.status, 204)
        self.assertNotEqual(r.getheader("ETag"), etag)
        r, data = dav("PUT", CAL + "other-name.ics", event("put-1@test", "Clash"))
        self.assertEqual(r.status, 409)
        self.assertIsNotNone(xml(data).find("C:no-uid-conflict", NS))
        r, data = dav("PUT", CAL + "bad.ics", "not a calendar")
        self.assertEqual(r.status, 403)
        self.assertIsNotNone(xml(data).find("C:valid-calendar-data", NS))
        r, data = dav("PUT", CAL + "card.ics", card("c-in-cal", "Card"))
        self.assertEqual(r.status, 403)
        r, _ = dav("PUT", CAL + "new.ics", event("new@test", "New"), {"If-Match": "*"})
        self.assertEqual(r.status, 412, "If-Match: * on nothing")
        r, _ = dav("DELETE", path, headers={"If-Match": '"nope"'})
        self.assertEqual(r.status, 412)
        r, _ = dav("DELETE", path)
        self.assertEqual(r.status, 204)
        r, _ = dav("GET", path)
        self.assertEqual(r.status, 404)
        r, _ = dav("DELETE", path)
        self.assertEqual(r.status, 404)
        r, _ = dav("PUT", path, event("put-1@test", "Again"), {"If-None-Match": "*"})
        self.assertEqual(r.status, 201, "a deleted name can be made again")

    def test_06_reports(self):
        for uid, start, end in (("nov-10", "20261110T090000Z", "20261110T100000Z"),
                                ("dec-24", "20261224T090000Z", "20261224T100000Z")):
            r, _ = dav("PUT", CAL + uid + ".ics", event(uid, uid, start, end))
            self.assertIn(r.status, (201, 204))
        multiget = f"""<?xml version="1.0"?><C:calendar-multiget xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
            <D:prop><D:getetag/><C:calendar-data/></D:prop><D:href>{CAL}nov-10.ics</D:href>
            <D:href>{CAL}missing.ics</D:href></C:calendar-multiget>"""
        r, data = dav("REPORT", CAL, multiget, {"Depth": "1"})
        self.assertEqual(r.status, 207)
        all_ = responses(data)
        self.assertIn("UID:nov-10", ok(all_[CAL + "nov-10.ics"], C + "calendar-data").text)
        self.assertIn("404", all_[CAL + "missing.ics"]["status"])
        query = """<?xml version="1.0"?><C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
            <D:prop><D:getetag/></D:prop><C:filter><C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT">
            <C:time-range start="20261201T000000Z" end="20270101T000000Z"/></C:comp-filter></C:comp-filter>
            </C:filter></C:calendar-query>"""
        r, data = dav("REPORT", CAL, query, {"Depth": "1"})
        self.assertEqual(r.status, 207)
        hrefs = set(responses(data))
        self.assertIn(CAL + "dec-24.ics", hrefs)
        self.assertNotIn(CAL + "nov-10.ics", hrefs)
        r, data = dav("REPORT", CAL, """<?xml version="1.0"?><D:foo xmlns:D="DAV:"/>""")
        self.assertEqual(r.status, 403)

    def test_07_sync_collection(self):
        def sync(token):
            body = f"""<?xml version="1.0"?><D:sync-collection xmlns:D="DAV:"><D:sync-token>{token}</D:sync-token>
                <D:sync-level>1</D:sync-level><D:prop><D:getetag/></D:prop></D:sync-collection>"""
            return dav("REPORT", CAL, body)
        r, data = sync("")
        self.assertEqual(r.status, 207)
        first = xml(data).find("D:sync-token", NS).text
        everything = responses(data)
        self.assertTrue(all(e["status"] is None for e in everything.values()), "no deletions in a first sync")
        r, _ = dav("PUT", CAL + "sync-a.ics", event("sync-a", "A"))
        self.assertEqual(r.status, 201)
        r, _ = dav("DELETE", CAL + "nov-10.ics")
        self.assertEqual(r.status, 204)
        r, data = sync(first)
        self.assertEqual(r.status, 207)
        changed = responses(data)
        self.assertEqual(set(changed), {CAL + "sync-a.ics", CAL + "nov-10.ics"})
        self.assertIn("404", changed[CAL + "nov-10.ics"]["status"])
        ok(changed[CAL + "sync-a.ics"], D + "getetag")
        second = xml(data).find("D:sync-token", NS).text
        self.assertNotEqual(first, second)
        r, data = sync(second)
        self.assertEqual(responses(data), {})
        for bad in ("http://cosmomail/sync/999999", "urn:other:1", "http://cosmomail/sync/x"):
            r, data = sync(bad)
            self.assertEqual(r.status, 403, bad)
            self.assertIsNotNone(xml(data).find("D:valid-sync-token", NS))
        # The CTag moved with the changes.
        r, data = dav("PROPFIND", CAL, """<?xml version="1.0"?><D:propfind xmlns:D="DAV:"
            xmlns:CS="http://calendarserver.org/ns/"><D:prop><CS:getctag/><D:sync-token/></D:prop></D:propfind>""",
                      {"Depth": "0"})
        self.assertEqual(ok(responses(data)[CAL], D + "sync-token").text, second)

    def test_08_depth_one_lists_objects(self):
        body = """<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop><D:getetag/><D:getcontenttype/>
            </D:prop></D:propfind>"""
        r, data = dav("PROPFIND", CAL, body, {"Depth": "1"})
        self.assertEqual(r.status, 207)
        all_ = responses(data)
        self.assertIn(CAL + "dec-24.ics", all_)
        self.assertTrue(ok(all_[CAL + "dec-24.ics"], D + "getetag").text.startswith('"'))
        self.assertIn("404", all_[CAL]["props"][D + "getetag"][0], "a collection has no etag")
        r, data = dav("PROPFIND", CAL, body, {"Depth": "0"})
        self.assertEqual(set(responses(data)), {CAL})

    def test_09_mkcalendar_proppatch_delete(self):
        path = f"/dav/calendars/{USER}/work%20stuff/"
        body = """<?xml version="1.0"?><C:mkcalendar xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav"
            xmlns:IC="http://apple.com/ns/ical/"><D:set><D:prop><D:displayname>Work</D:displayname>
            <C:calendar-description>Office hours</C:calendar-description><IC:calendar-color>#FF0000FF</IC:calendar-color>
            </D:prop></D:set></C:mkcalendar>"""
        r, _ = dav("MKCALENDAR", path, body)
        self.assertEqual(r.status, 201)
        r, _ = dav("MKCALENDAR", path, body)
        self.assertEqual(r.status, 405)
        r, data = dav("PROPFIND", path, PROPFIND_ALL, {"Depth": "0"})
        entry = responses(data)[path]
        self.assertEqual(ok(entry, D + "displayname").text, "Work")
        self.assertEqual(ok(entry, "{http://apple.com/ns/ical/}calendar-color").text, "#FF0000FF")
        self.assertEqual(ok(entry, C + "calendar-description").text, "Office hours")
        patch = """<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:A="http://example.com/ns/">
            <D:set><D:prop><D:displayname>Renamed</D:displayname><A:mine>x</A:mine></D:prop></D:set>
            </D:propertyupdate>"""
        r, data = dav("PROPPATCH", path, patch)
        self.assertEqual(r.status, 207)
        entry = responses(data)[path]
        self.assertIn("424", entry["props"][D + "displayname"][0])
        self.assertIn("403", entry["props"]["{http://example.com/ns/}mine"][0])
        patch = """<?xml version="1.0"?><D:propertyupdate xmlns:D="DAV:" xmlns:IC="http://apple.com/ns/ical/">
            <D:set><D:prop><D:displayname>Renamed</D:displayname><IC:calendar-order>3</IC:calendar-order>
            </D:prop></D:set></D:propertyupdate>"""
        r, data = dav("PROPPATCH", path, patch)
        self.assertIn("200", responses(data)[path]["props"][D + "displayname"][0])
        r, data = dav("PROPFIND", path, PROPFIND_ALL, {"Depth": "0"})
        self.assertEqual(ok(responses(data)[path], D + "displayname").text, "Renamed")
        r, _ = dav("PUT", path + "e.ics", event("in-work", "W"))
        self.assertEqual(r.status, 201)
        r, _ = dav("DELETE", path)
        self.assertEqual(r.status, 204)
        r, _ = dav("PROPFIND", path, PROPFIND_ALL, {"Depth": "0"})
        self.assertEqual(r.status, 404)
        self.assertEqual(sql("SELECT count(*) FROM dav_objects WHERE uid = 'in-work'"), "0")

    def test_10_carddav(self):
        r, data = dav("PROPFIND", f"/dav/contacts/{USER}/", PROPFIND_ALL, {"Depth": "1"})
        self.assertEqual(r.status, 207)
        entry = responses(data)[BOOK]
        self.assertIsNotNone(ok(entry, D + "resourcetype").find("CARD:addressbook", NS))
        r, _ = dav("PUT", BOOK + "jane.vcf", card("jane", "Jane Doe"), {"Content-Type": "text/vcard"})
        self.assertEqual(r.status, 201)
        r, data = dav("GET", BOOK + "jane.vcf")
        self.assertTrue(r.getheader("Content-Type").startswith("text/vcard"))
        r, data = dav("PUT", BOOK + "event.vcf", event("ev-in-book", "E"))
        self.assertEqual(r.status, 403)
        self.assertIsNotNone(xml(data).find("CARD:valid-address-data", NS))
        multiget = f"""<?xml version="1.0"?><CARD:addressbook-multiget xmlns:D="DAV:"
            xmlns:CARD="urn:ietf:params:xml:ns:carddav"><D:prop><D:getetag/><CARD:address-data/></D:prop>
            <D:href>{BOOK}jane.vcf</D:href></CARD:addressbook-multiget>"""
        r, data = dav("REPORT", BOOK, multiget)
        self.assertIn("FN:Jane Doe", ok(responses(data)[BOOK + "jane.vcf"], CARD + "address-data").text)
        query = """<?xml version="1.0"?><CARD:addressbook-query xmlns:D="DAV:"
            xmlns:CARD="urn:ietf:params:xml:ns:carddav"><D:prop><D:getetag/></D:prop></CARD:addressbook-query>"""
        r, data = dav("REPORT", BOOK, query, {"Depth": "1"})
        self.assertIn(BOOK + "jane.vcf", responses(data))
        r, _ = dav("REPORT", BOOK, """<?xml version="1.0"?><C:calendar-query xmlns:C="urn:ietf:params:xml:ns:caldav"/>""")
        self.assertEqual(r.status, 403, "a calendar report on an address book")
        mkcol = """<?xml version="1.0"?><D:mkcol xmlns:D="DAV:" xmlns:CARD="urn:ietf:params:xml:ns:carddav"><D:set>
            <D:prop><D:resourcetype><D:collection/><CARD:addressbook/></D:resourcetype><D:displayname>Team</D:displayname>
            </D:prop></D:set></D:mkcol>"""
        r, _ = dav("MKCOL", f"/dav/contacts/{USER}/team/", mkcol)
        self.assertEqual(r.status, 201)
        r, _ = dav("MKCOL", f"/dav/contacts/{USER}/plain/")
        self.assertEqual(r.status, 201, "a plain MKCOL makes an address book, as before")
        r, data = dav("PROPFIND", f"/dav/contacts/{USER}/", PROPFIND_ALL, {"Depth": "1"})
        names = {ok(e, D + "displayname").text for h, e in responses(data).items() if h != f"/dav/contacts/{USER}/"}
        self.assertTrue({"Team", "plain", "Contacts"} <= names, names)
        r, data = dav("MKCOL", f"/dav/contacts/{USER}/wrong/", mkcol.replace("CARD:addressbook", "D:principal"))
        self.assertEqual(r.status, 403)

    def test_11_isolation(self):
        r, _ = dav("PUT", f"/dav/calendars/{OTHER}/Default/x.ics", event("x", "x"))
        self.assertEqual(r.status, 403)
        r, data = dav("PROPFIND", f"/dav/calendars/{OTHER}/", PROPFIND_ALL, {"Depth": "1"},
                      user=OTHER, password=OTHER_PASSWORD)
        self.assertEqual(r.status, 207)
        self.assertNotIn(f"/dav/calendars/{OTHER}/work%20stuff/", responses(data))
        r, _ = dav("GET", f"/dav/calendars/{OTHER}/Default/dec-24.ics", user=OTHER, password=OTHER_PASSWORD)
        self.assertEqual(r.status, 404, "the other user's calendar does not have the first user's events")


if __name__ == "__main__":
    unittest.main(verbosity=2)
