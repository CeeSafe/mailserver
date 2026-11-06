# mews

Exchange Web Services (SOAP 1.1) at `/EWS/Exchange.asmx`, as the C# server served it (`EwsController`). It covers
what macOS Mail and Outlook need to sync folders and messages, read, flag, move, delete and send.

```ceesafe
// mweb routes to it (HTTPS, the admin listener and [http] proxied; plain HTTP is refused):
let response = await serveEws(mail, request);
// GetStreamingEvents writes its own chunked response, before routing:
if (isStreamingRequest(request)) { await streamEvents(mail, request, mut wire); }
```

## Requests and responses

- **Logins:** every request carries HTTP Basic credentials, checked by mpim's `basicLogin` (the shared login guard
  and its cache). A missing or wrong login gets 401 with `WWW-Authenticate: Basic realm="CosmoMail"`.
- **Requests:** SOAP 1.1 and 1.2 envelopes are both read (pkgs/mxml), and elements are found by local name, as the
  C# server found them. A request that is not XML, or not an envelope, gets a SOAP fault (`soap:Client`, HTTP 500).
- **Responses:** each operation's `ResponseMessages` hold one message per folder or item asked for, in request
  order. They are written without indentation, because Apple's SOAP parser drops items that have white space
  between their elements. Members appear in schema order, because Apple's deserializer aborts on anything else.

## Ids, as the C# server made them

All ids are base64 of the following:
- folder: `f:<mailbox id>`;
- virtual root: `root:<user id>`, one per user, since Apple's accountsd takes it as the account's identity;
- message: `<mailbox id>:<uid>`;
- change key: `ck:` plus 16 hex digits of a SHA-256 over the flags, sorted.

Mailbox ids are this store's, so ids that clients cached against the C# server are not found after the cutover.
Clients then sync again: a C# SyncFolderItems state gets `ErrorInvalidSyncStateData`, and the folders of a C#
hierarchy state are reported deleted.

## Operations

- **Folders:** `GetFolder`, `FindFolder` and `SyncFolderHierarchy`.
  - Mail folders are the user's mailboxes, all children of the virtual root (a flat hierarchy, as before).
  - Distinguished ids map to special-use mailboxes: inbox, sentitems, drafts, deleteditems, junkemail, archive.
  - calendar, contacts, tasks, notes, journal and outbox are virtual, empty folders.
- **`FindItem`:** a folder's messages, newest first, paged by `IndexedPageItemView`. Restrictions and sort orders
  are not read (nor were they there).
- **`GetItem`:** each message with its MIME content (unless `IdOnly` without `IncludeMimeContent`) and its summary.
  The summary comes from the ENVELOPE in the store's meta, so listings never open message files: subject, sender,
  To, Cc, dates, size, categories, draft and read state, and attachments. A message whose content file is missing
  gets a short stub, because macOS Mail aborts on a message with no content.
- **`SyncFolderItems`:** the state is base64 of `s2:<uidvalidity>:<modseq>:<uid ranges>`.
  - Creates are the uids the client lacks, deletes are the uids it has that are gone, and updates are the messages
    it has whose modseq is newer.
  - Each round sends at most `MaxChangesReturned` changes: deletes, then updates by modseq, then creates.
  - Every change is reported, however large the folder. The C# server stopped tracking deletes and flag changes
    past 5000 messages.
  - A new UIDVALIDITY starts the sync over.
- **`UpdateItem`:** `message:IsRead`, `item:Flag` (`\Flagged`) and `item:Categories` (keywords; characters IMAP
  atoms cannot hold become `_`), through Set, Append and Delete field changes. The new change key is returned.
- **`DeleteItem`:** `MoveToDeletedItems` moves the message to Trash; in Trash, and for `SoftDelete` and
  `HardDelete`, it is expunged by uid, only that one.
- **`MoveItem` and `CopyItem`:** the new item id is returned. An id that is gone gets `ErrorItemNotFound`, which
  makes Apple Mail drop a replayed action.
- **`CreateItem`:** the message is the request's MIME content, or one made from Subject, Body and the recipients.
  - `SaveOnly` stores it in Drafts (or `SavedItemFolderId`) as `\Draft`.
  - `SendOnly` and `SendAndSaveCopy` do what SMTP submission does, in one transaction:
    - local recipients get the message in their INBOX;
    - remote recipients get it through the queue, which signs it with DKIM at relay time;
    - the copy goes to Sent (or `SavedItemFolderId`), and its id is returned, because without it macOS Mail sends
      again.
  - Recipients come from To, Cc, Bcc and the request's lists, and Bcc is removed from the content. Sieve is not run
    for local recipients of mail sent this way.
- **`Subscribe` and `GetEvents`:** as the C# server answered (an id and a watermark, and a status event).
- **`GetStreamingEvents`:** one chunked response that stays open for `ConnectionTimeout` (1 to 10 minutes,
  default 2). It carries whole SOAP envelopes, as Apple's EWS client requires:
  - a keep-alive at once and every 20 seconds;
  - a `NewMailEvent` (with the newest message) or `ModifiedEvent` when a mailbox changes, woken by the store's
    notify bus;
  - a last part with `ConnectionStatus` set to `Closed`.
- **Everything else** (GetServiceConfiguration, ResolveNames, GetUserAvailability, FindPeople, ConvertId and the
  rest) gets an empty success, as before.

## Autodiscover

- **v2 JSON:** `Protocol=ews` gets `{Protocol, Url}`.
- **Outlook's POX response:** names EWS in an `EXPR` block while `[http] advertise_exchange` is true (the
  default); its presence makes macOS Mail set the account up as Exchange, so set it false for IMAP-only setups. The block carries `LoginName`; without it, macOS Mail
  logs in with the bare local part.

## Tests

- `ceesafec test`: ids against the C# server's values, sync states, the ENVELOPE reader, dates, and SOAP framing.
- `tests/conformance/run.sh --ews`: 18 end-to-end tests, raw SOAP over HTTPS. They check:
  - logins, faults, and the refusal over plain HTTP;
  - folders, and hierarchy sync with created and deleted folders;
  - find, get and paging;
  - item sync with flag changes, new messages, expunges, paging and modseq ties;
  - updates, moves, copies and deletes;
  - sending to local and remote recipients, Bcc, drafts, and an error;
  - subscriptions, and streaming woken by a delivery;
  - Autodiscover.

## Not done

- Calendar, contact and task items: their folders are empty, as on the C# server.
- Restrictions, sorting and grouping in FindItem; `t:Body` and attachments as separate items in GetItem (clients
  use the MIME content); `ResolveNames` against the directory.
- Push subscriptions, and real events for pull subscriptions.
