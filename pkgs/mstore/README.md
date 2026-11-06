# mstore

The mail server's storage: accounts, mailboxes and messages in Postgres (through the `postgres` package's pool),
and message content in content-addressed files.

```ceesafe
let store = await MailStore.open(PgConfig.parse(url)?, 16, "/var/lib/mail/blobs")?;  // migrates the schema

// SMTP: where does mail for this address go?
var to = Recipient.create();
await store.resolve("Info@Example.net", mut to)?;   // domain aliases, aliases, catch-all

// Write the content once (on a worker thread), deliver it to every local recipient in one transaction.
var content = store.blobs().begin()?;
content.write(chunk)?;  …  content.finish()?;
var targets = Vector<Delivery>.create();
targets.push(Delivery.to(to.userId, inboxId, Clock.unixMillis()))?;
var done = Vector<Delivered>.create();
await store.deliver(mut content, targets, mut done)?;  // done[i].uid, done[i].modseq

// IMAP
await store.mailboxById(userId, mailboxId, mut boxes)?;                // the selected mailbox's counters, UIDVALIDITY
await store.messages(userId, mailboxId, 0, mut list)?;                 // SELECT; changedSince > 0 for CONDSTORE
await store.fetchMessages(userId, mailboxId, uids, true, mut list)?;   // FETCH; true adds list.meta(i, mut meta)
await store.setFlags(userId, mailboxId, uids, change, mut changed)?;   // STORE, with UNCHANGEDSINCE
await store.expunge(userId, mailboxId, mut gone)?;                     // also expungeUids
await store.copy(userId, from, to, uids, true, mut moved)?;            // COPY/MOVE, with COPYUID's data

// IDLE: wake when the mailbox changes
let watch = (await store.notifications().watch(userId, mailboxId))!;   // dropping it ends the watch
await watch.changed()?;                                                // coalesced; a raise before the wait is kept
```

## Design

- **One round trip per operation.** Every message operation is one SQL statement. Deliver, STORE, EXPUNGE, COPY
  and MOVE each change the messages, allocate UIDs, bump `HIGHESTMODSEQ`, and keep the mailbox's counters
  (messages, unseen, size) and the user's quota in that one statement, under the mailbox row's lock. SELECT and
  STATUS read counters and never count rows.
- **Isolation.** Every call that names a mailbox takes the user's id too, and finds nothing when the mailbox is
  someone else's.
- **Content.** A message's content is stored once, at `<root>/ab/cd/<sha-256>`.
  - A message delivered to many recipients, or copied, shares one file.
  - Triggers keep each blob's reference count, whatever adds or removes messages: deliveries, copies, moves,
    expunges, and cascades from deleting a mailbox or a user.
  - `collectBlobs` removes blobs nothing has referenced for a grace period.
  - A delivery locks its blob's row before moving the file into place, and the collector removes a file only while
    holding that lock, so the two cannot race.
- **Flags.** System flags are a bit set (`FLAG_SEEN` …); keywords are a sorted `text[]`. Each change gets a new
  MODSEQ (RFC 7162), and `messages(…, changedSince)` gives what changed after a given one.
- **UID sets** travel as one `int8multirange` parameter, so a STORE over `1:500,600:*` is one statement.
  - The caller resolves `*` to a uid first: IMAP's `*` is the mailbox's highest uid.
  - `fetchMessages` joins each range as an index range scan: a FETCH of `1:*` is one statement and one result,
    with each message's meta in its row when asked; a FETCH of a few uids reads only their rows.
- **Schema.** The migrations are in `src/migrations.cee`, one raw `"""` literal per statement, and the statements
  in `src/queries.cee`, one function each. Add a migration as a new version; never change an applied one.
  `Migrations.apply` runs each new version in its own transaction under an advisory lock, and refuses a database
  newer than the build.
- **Imports** (`import-cosmomail`, the server's `src/import.cee`) deliver with `Delivery.uid` set: the message
  takes that uid instead of the next one, if it is above every uid in the mailbox, and `uid_next` moves past it.
  An import keeps the old server's uids this way, through the same statement, blob handling and triggers as SMTP.
- **Meta.** `messages.meta` holds `mmime`'s stored meta: each part's offsets and the rendered ENVELOPE,
  BODYSTRUCTURE and BODY. Put `encodeMeta`'s output in `Delivery.meta`.
- **The notify bus** (`src/notify.cee`). Every change the store makes to a mailbox wakes that mailbox's watchers
  once it is committed, so producers (SMTP, the relay's settle, IMAP) need do nothing:
  - `deliver`/`accept` and `settle` wake each target's mailbox; `setFlags` and `expunge`/`expungeUids` theirs when
    a message changed; `copy` the target, and the source too when moving;
  - `createMailbox`, `renameMailbox` and `deleteMailbox` wake all of the user's watchers (`raise(userId, 0)`).

  A `Watch` holds an `Arc` of its watcher (an `AsyncSignal` and a live flag), which the bus's list
  (`AsyncMutex<Vector<…>>`, shared by every worker thread) holds too. Raising takes the lock only to walk the list,
  never across an `await`. Dropping the `Watch` only clears the flag, with no lock and no `await`, so it happens
  however the session ends, cancellation included; the bus takes such watchers out at its next `watch`, `raise` or
  `count`. The bus is per process: another server on the same database does not wake it.
- **Requirements.** Postgres 14 or later, for multiranges.

## Not yet

- QRESYNC's expunged-UID history (VANISHED).
- The queue, failed-login and suppression tables, which arrive with SMTP (Phase 4/5).
- A sweep for orphaned blob files, written when a delivery's transaction failed after its file was placed.

## Tests

```sh
../../../PostgresClient/tests/setup-docker.sh   # once: Postgres 17 on 127.0.0.1:55432
PG_TEST_PORT=55432 ceesafec test                # each live test makes its own database, mstore_<test>
PG_TEST_PORT=55432 ceesafec test --sweep cancel
```
