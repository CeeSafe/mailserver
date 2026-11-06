# meas

Exchange ActiveSync (MS-ASHTTP, MS-ASCMD, MS-ASWBXML; protocol versions 12.1, 14.0, 14.1, 16.0, 16.1) at
`/Microsoft-Server-ActiveSync`, which mweb routes here on HTTPS, the admin listener and `[http] proxied`. It covers
mail from mstore, and calendars and contacts from mpim's collections, which CalDAV/CardDAV share.

```ceesafe
let response = await serveActiveSync(mailContext, request)?;
```

## Requests

- **Logins:** HTTP Basic, checked through mpim (`basicLogin`): the failed-login guard, and a cache of recent logins,
  so a phone's Ping does not cost a bcrypt check every time.
  - `DOMAIN\user` is accepted.
  - OPTIONS needs no login, but credentials that are sent are checked.
- **Queries:** plain (`Cmd=Sync&DeviceId=…`) or base64-encoded (MS-ASHTTP §2.2.1.1.1.1).
- **Devices:** each device has a row in `eas_devices`:
  - its id, type, model, OS, user agent and protocol version;
  - its policy key, and its status (`allowed`, `blocked`, `wipe`, `wiped`);
  - its FolderSync key, and its last Ping.

  A `blocked` device gets 403. A `wipe` one gets 449 until it provisions, then a RemoteWipe.
- **WBXML** (`wbxml.cee`, `codepages.cee`) decodes into mxml's `XmlDocument`, with each code page's name as the
  namespace. The tag tables are MS-ASWBXML's. The C# server's tables had several wrong numbers (Email from 0x31 on,
  Calendar, Contacts, Provision, Settings, MeetingResponse); `knowsThePages` pins the right ones.

## Commands

- **Provision:** both steps. The first gets a temporary key with the policy; the acknowledgement gets the final
  key. The policy restricts nothing, as the C# server's did. Keys are not enforced on other commands.
- **FolderSync, FolderCreate, FolderUpdate, FolderDelete:**
  - Folders keep the C# server's ServerIds: mailboxes `m<id>`, calendars `c<id>` and address books `a<id>`.
  - `Work/Projects` appears inside `Work`.
  - Types: INBOX 2, Drafts 3, Trash 4, Sent 5, mail 12; the default calendar 8 (others 13); the default address
    book 9 (others 14).
  - `eas_folders` records what the device was given, so a FolderSync sends only the changes.
  - INBOX, special-use mailboxes and the default collections cannot be deleted.
- **Sync** (`sync.cee`): mail, calendars and contacts.
  - **The record:** `eas_items` holds what the device has: each item (a uid, or a dav_objects id), and the version
    (modseq) it was sent.
  - **Each round:** applies the client's commands, then sends deletes, changes and adds, newest first, a
    WindowSize at a time (MoreAvailable).
  - **A lost response:** each row keeps what the last response replaced. A device that repeats its previous key
    gets the same changes again, and the new key confirms them; any other key is status 3.
  - **Locking:** the folder's row is locked for the round, so overlapping Syncs of one folder (iOS sends them)
    take turns.
  - **Options:** FilterType, BodyPreference (plain text, HTML, or MIME with MIMESupport), TruncationSize. They are
    remembered, as the protocol allows a Sync to omit them.
  - **Long polls:** Wait and HeartbeatInterval (14.0), answered on the first change or with an empty 200.
- **Mail:**
  - A message carries its header fields (RFC 2047 decoded), DateReceived, DisplayTo, Importance, Read and Flag,
    the body in the type asked for, and its attachments, by FileReference `m<id>:<uid>:<part>`.
  - A changed message is sent as its flags only.
  - A device's Change sets `\Seen` and `\Flagged`. Its Delete moves the message to Trash (DeletesAsMoves), or
    expunges it from Trash.
  - The device's own changes are recorded, so they are not sent back to it.
- **Calendar** (`calendar.cee`, `timezone.cee`):
  - **From iCalendar:** times go to the device in UTC, with the event's VTIMEZONE as the TimeZone blob. RRULE
    becomes Recurrence (daily, weekly, monthly by day or by nth weekday, yearly), EXDATE deleted exceptions,
    ATTENDEE and ORGANIZER the attendees and organizer, and VALARM the reminder. TRANSP and CLASS give
    BusyStatus and Sensitivity; CATEGORIES and DESCRIPTION go across too.
  - **From the device:** the event is rewritten from its fields, keeping its UID. All-day events become dates in
    the device's zone.
- **Contacts** (`contacts.cee`): vCard 3.0 and 4.0 in, vCard 3.0 out. Carried over:
  - the name parts and FN;
  - three addresses and the phones by kind;
  - home, work and other postal addresses;
  - company, department, title, web page, birthday and anniversary;
  - notes, nickname, categories and photo.
- **GetItemEstimate and Ping:**
  - Ping waits on the notify bus's whole-user watch (`watch(userId, 0)`) and answers the folders that have
    changes.
  - A Ping without a body repeats the last one's folders.
  - A folder the device does not know gets status 7.
- **SendMail, SmartReply, SmartForward** (`compose.cee`): the device's MIME goes where submission sends it.
  - Delivery: local recipients' INBOXes and the queue, in one transaction; the Sent copy when asked.
  - The message: the envelope sender is the account, Bcc is removed, and From, Date and Message-ID are added when
    missing.
  - A SmartForward attaches the original (unless ReplaceMime).
  - The original is flagged `\Answered` or `$Forwarded`.
  - Both the 14.x WBXML form and 12.1's raw MIME body are accepted.
- **MoveItems:** between mailboxes, with the device's records following the message.
- **ItemOperations:**
  - Fetch of an item (by ServerId or Search's LongId), or of an attachment by FileReference, with Range;
  - EmptyFolderContents.
- **GetAttachment** (12.1).
- **Search and Find:**
  - Mailbox: free text over the envelope (subject and addresses), optionally in one folder, with
    DateReceived bounds and Range.
  - GAL: the accounts of the user's domain.
- **ResolveRecipients:** the domain's accounts and the user's contacts.
- **MeetingResponse:** answers an invitation in the inbox (its text/calendar part), or an event in a calendar.
  - Accepted and tentative events go into the default calendar with the account's PARTSTAT.
  - The organizer gets an iTIP REPLY.
- **Settings:** UserInformation (the account's address); DeviceInformation (stored); Oof (the account's
  auto-reply, `users.auto_reply_*`); DevicePassword and RightsManagementInformation acknowledged.
- **Autodiscover:** mweb answers the mobilesync schema with `mobileSyncAutodiscover`, and the v2 JSON's
  `Protocol=ActiveSync`.

## Not yet

- Tasks and Notes folders. VTODOs stay in calendars, for CalDAV only.
- Drafts from the device (a Sync Add to a mail folder gets status 6). Conversation views. The GAL through Find.
- Events: overridden instances (RECURRENCE-ID) go to the device only as the series. A device's edit replaces
  what ActiveSync cannot carry: X- properties, and attendees' parameters other than CN, ROLE, CUTYPE and
  PARTSTAT. A TZID without a VTIMEZONE is read as UTC.
- Messages are read whole for rendering, so a big attachment costs its size on each Sync of it. Search reads only
  the envelope of the newest 5,000 messages.
- Policies are not enforced, as with the C# server.

## Tests

- `ceesafec test`: 9 tests.
  - WBXML: MS-ASWBXML's example, round trips, refusals, and the tag numbers.
  - Time zones, VTIMEZONE and the TimeZone blob.
  - Events and contacts both ways, all-day dates, and the encoded query.
- `tests/conformance/run.sh --eas`: `eas_test.py`, with its own WBXML codec.
  - Discovery: OPTIONS, a wrong password, two-step Provision, Settings.
  - Hierarchy: FolderSync changes, FolderCreate, Update and Delete.
  - Mail:
    - the initial sync in windows, and a lost response sent again;
    - flags and deletes both ways;
    - GetItemEstimate, and a Ping woken by a delivery;
    - attachment and MIME fetches;
    - MoveItems, Search and the GAL, ResolveRecipients.
  - Sending: SendMail (WBXML and 12.1 MIME, Bcc removed, the Sent copy), SmartForward.
  - Groupware:
    - events and contacts from the device and from elsewhere, with time zones and recurrence;
    - changes and deletes;
    - a MeetingResponse whose REPLY reaches the organizer.
