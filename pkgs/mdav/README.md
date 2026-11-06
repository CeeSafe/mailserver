# mdav

CalDAV (RFC 4791) and CardDAV (RFC 6352) under `/dav`, at the C# server's URLs, so clients set up against
CosmoMailServer keep working after the cutover:

    /dav/principals/<email>/                       the account's principal
    /dav/calendars/<email>/[<calendar>/[<href>]]   calendars and their iCalendar objects
    /dav/contacts/<email>/[<book>/[<href>]]        address books and their vCards
    /.well-known/caldav, /.well-known/carddav      301 to /dav/ (RFC 6764)

mweb routes these paths here on HTTPS, the admin listener and `[http] proxied`, never on plain port 80. The store is
pkgs/mpim's (`dav_collections`, `dav_objects`), shared with ActiveSync and EWS.

- **Logins:** HTTP Basic on every request but OPTIONS, through mpim's `basicLogin` (the failed-login guard, and
  the cache of recent logins, so clients that poll do not cost a bcrypt check each time). The address in the path
  must be the account's (403 otherwise).
- **Discovery:** `current-user-principal` everywhere; on the root and the principal, `principal-URL`,
  `calendar-home-set`, `addressbook-home-set`, `calendar-user-address-set` (`mailto:`) and
  `principal-collection-set`. The principal searches (`principal-property-search`,
  `principal-search-property-set`) answer empty: there is no directory.
- **PROPFIND:** the properties asked for, with unknown ones under a 404 propstat; `allprop` (all but the object
  data) and `propname`; Depth 0, 1 and infinity (taken as 1: homes list their collections, collections their
  objects). Collections have `getctag` and `sync-token` (their modseq, as `http://cosmomail/sync/<n>`),
  `supported-report-set`, `current-user-privilege-set`, `owner`, the display name, color and description, and the
  supported components and data types.
- **REPORT:** `calendar-multiget`, `calendar-query` (by component, and by time range through `objectsInRange`,
  which widens ranges by 14 hours each way for times with a TZID), `addressbook-multiget`, `addressbook-query` (the
  whole book; filters are not applied), and `sync-collection` (RFC 6578: what changed since the token, deletions
  as 404 responses; a token from elsewhere or from the future is refused with `valid-sync-token`). Other reports
  get 403 `supported-report`.
- **Objects:** GET and HEAD with `ETag` (and 304 for a matching `If-None-Match`); PUT with `If-Match` (an etag or
  `*`) and `If-None-Match: *`, 201 or 204 and the new etag, 412 when a precondition fails, 409 `no-uid-conflict`
  when another object has the UID, 403 `valid-calendar-data`/`valid-address-data` for anything else (a vCard in a
  calendar too). A PUT into a calendar that does not exist makes it, as the C# server did. DELETE leaves a
  tombstone for sync.
- **Collections:** MKCALENDAR and MKCOL (plain, which makes an address book as before, or RFC 5689's extended form,
  whose resource type must match the path) with a display name, description and color; the name is the URL
  segment. PROPPATCH keeps the display name, color and description; Apple's and CalendarServer's other properties
  (`calendar-order` and the like) are accepted and not kept; others are refused, and then nothing changes. DELETE
  removes a collection with its objects.
- **Etags** are the C# server's: the first 32 hex digits of the object's SHA-256, so imported objects keep theirs.

Not done: scheduling (RFC 6638: no inbox or outbox, iMIP invitations are the client's), LOCK (the DAV header
says class 1 and 3), COPY and MOVE, `expand-property` (empty), `free-busy-query`, text-match and param filters,
calendar-data subsets (`<C:comp>` in a request: the whole object is returned), and a size limit below the upload
limit (50 MiB).

Tests: `ceesafec test` (paths, hrefs, property names, requests and etag headers), and `tests/conformance/run.sh
--dav` (11 black-box tests over HTTPS) and `--import` (the calendars and contacts of a CosmoMail database, read
back over CalDAV and CardDAV, and a second run after an event changed and another was deleted).
