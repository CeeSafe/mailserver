# mimap

The IMAP server: IMAP4rev1 (RFC 3501) with the capabilities the C# server advertised:
- IDLE (RFC 2177), MOVE (RFC 6851), NAMESPACE (RFC 2342), ID (RFC 2971), UIDPLUS (RFC 4315), UNSELECT (RFC 3691);
- SPECIAL-USE (RFC 6154), ENABLE (RFC 5161), LITERAL+ (RFC 7888), CHILDREN (RFC 3348).

It follows the RFCs, not the C# server's behaviour, which had several bugs:
- plain COPY and MOVE were unknown commands;
- there was no UID EXPUNGE;
- FETCH sent only one literal per response;
- LIST always answered `\HasNoChildren`;
- SEARCH ignored OR and parenthesised keys;
- other sessions' expunges and flag changes never reached IDLE.

## Design

- **Layers.**
  - `src/parser.cee`: commands from the wire, with no I/O. It reads one tagged command at a time, as tokens over the
    line and the literals that follow. It handles:
    - atoms, quoted strings with `\"` and `\\` escapes, literals `{n}` and `{n+}`, NIL, and parenthesised lists;
    - sequence sets (`1:3,5,7:*`);
    - FETCH attributes, with sections (`BODY.PEEK[1.2.HEADER.FIELDS (FROM TO)]<0.100>`);
    - flag lists and dates.
  - `src/response.cee`: writing responses. It writes astrings and quoted strings, choosing a literal for
    non-ASCII or CR/LF, the FETCH item syntax, and compressed UID sets for COPYUID and APPENDUID.
  - `src/session.cee`: the connection, reading commands and their literals, the state machine, and the commands of
    any state and of login, over msmtp's `Wire` (plain, STARTTLS on 143, implicit TLS on 993).
  - `src/mailbox.cee`: the authenticated state's commands (SELECT to APPEND); `src/selected.cee`: the selected
    state's (FETCH, STORE, COPY, MOVE, EXPUNGE, IDLE) and the updates after each command; `src/search.cee`:
    SEARCH (below).
  - `src/snapshot.cee` (sequence numbers and UIDs) and `src/listing.cee` (LIST patterns), pure and unit-tested.
  - `src/server.cee`: the accept loop, as msmtp's `serve`.
- **State.** Not authenticated, authenticated, selected (read-write, or read-only for EXAMINE), logout.
  - A selected mailbox keeps a snapshot of its UIDs in sequence order, which is the mapping between sequence numbers
    and UIDs. NOOP, IDLE and the end of each command bring it up to date. Expunges are announced as `* n EXPUNGE` from
    the highest sequence number down, and new messages as `* n EXISTS`.
  - `\Recent` is not kept: RECENT is always 0, as Dovecot does when there are many sessions. `\Recent` is not in FLAGS.
  - FLAGS at SELECT lists the system flags and every keyword the mailbox's messages have. A keyword the client has
    not been told of (another session's, or its own STORE's) gets a new `* FLAGS` and `PERMANENTFLAGS` before the
    first FETCH that shows it (RFC 3501 §7.2.6; imaptest checks it).
- **Store.** mstore does the work; mimap reads and formats. `messageMeta` gives ENVELOPE and BODYSTRUCTURE as IMAP
  text, and the part offsets for sections. Bodies are read from the blob by byte range, and streamed (Streaming,
  under Performance).
  - A MOVE to the selected mailbox itself (RFC 6851 allows it, Dovecot does it) gives the messages new UIDs in one
    statement: COPYUID, the old numbers' EXPUNGE, and EXISTS.
  - CREATE does not subscribe the mailbox, nor the parents it makes (as Dovecot); the mailboxes made for a new
    account are subscribed (the store's default).
- **Login.**
  - LOGIN and AUTHENTICATE PLAIN go through the same check and throttle as SMTP AUTH (msmtp's shared login function).
  - Over plaintext they are refused (`LOGINDISABLED`, `[PRIVACYREQUIRED]`) unless the configuration allows it.
- **Limits.**
  - A command line is at most 64 KiB, with `BYE` beyond.
  - A literal is at most the configured message size for APPEND's message and 64 KiB elsewhere (APPEND's mailbox
    name too).
  - The autologout timer is 30 minutes, and IDLE re-arms it.
- **IDLE and the notify bus** (slice 2). SELECT and EXAMINE take a `Watch` on the mailbox from mstore's `NotifyBus`
  (before reading the messages, so no change falls between), kept in the session.
  - IDLE races the read for `DONE` against the watch (`Async.race`). A raise runs `sync`, which sends the FETCH
    FLAGS, EXPUNGE and EXISTS the client has not been told, then IDLE waits again. A session's own changes raise its
    watch too, and `sync` then finds nothing to say.
  - The read loses the race safely, plain or TLS: everything is flushed first, so only the socket read is stopped,
    as a timed-out one is (the tls package's `fill` keeps such a read usable); a line read as the raise came is kept.
  - Raises coalesce: a burst wakes IDLE once, and a raise before IDLE starts waiting is kept until taken.
  - IDLE also syncs every 60 seconds (`IDLE_REFRESH`), for a missed raise. Changes made by another process on the
    same database (a second server) reach the bus of neither: they show by that refresh, and at NOOP or any command.
  - The watch is dropped by UNSELECT, CLOSE, a new SELECT, DELETE of the selected mailbox and LOGOUT, and with the
    session however it ends (an error, the client closing, cancellation). A session that selected logs
    `imap: mailbox watches N` when it ends, the bus's live count, which the tests check returns to 0.
  - NOOP and the other commands still bring the snapshot up to date with `sync` after each command.

## SEARCH

SEARCH and UID SEARCH (`src/search.cee`) take RFC 3501's whole grammar (§6.4.4, §9), keys in any combination.
- **Keys.**
  - Flags and their UN- forms, KEYWORD and UNKEYWORD (keywords in any case), LARGER and SMALLER, UID and bare
    sequence sets (`*` is the last message or UID the client knows; numbers past it match nothing), NOT, OR, and
    parenthesised lists, an AND. Nesting is at most 64 deep.
  - `\Recent` is not kept, so RECENT and NEW match nothing and OLD matches everything.
  - BEFORE, ON and SINCE compare the INTERNALDATE's day. The store keeps it in UTC (APPEND's zone is not kept), so
    its own zone is UTC, as in Dovecot on a UTC host. SENTBEFORE, SENTON and SENTSINCE compare the day the Date
    header names in its own zone (23:30 -0500 on 5 March is 5 March). The Date is read as RFC 5322 says, with the
    obsolete forms (two-digit years, zone names, comments); a missing or unreadable Date is 1 January 1970, as
    Dovecot does.
  - FROM, TO, CC, BCC, SUBJECT and HEADER match the decoded value (RFC 2047) of every field of that name, through
    mmime's `appendHeaderValues`. `HEADER name ""` matches messages that have the field.
  - BODY matches mmime's `appendSearchText` (every text/* leaf decoded to UTF-8, HTML as a reader sees it, and
    attached messages' headers and text); TEXT the message's decoded header too. Each is capped at
    `SEARCH_TEXT_LIMIT` (1 MiB) per message.
  - Strings are astrings (atoms, quoted strings, literals; UTF-8 needs a quoted string or a literal), matched as
    substrings ignoring case with mmime's `containsFolded` (ASCII and Latin-1 letters).
  - `CHARSET` may be UTF-8 or US-ASCII; another is `NO [BADCHARSET (UTF-8 US-ASCII)]` (Dovecot converts any charset
    iconv knows). A syntax error is `BAD` with the parser's reason (`unknown search key`, `invalid date`, …).
- **Evaluation.** The keys parse into a tree (`SearchQuery`). Each message is evaluated in stages, with three-valued
  logic: a key whose data is not loaded yet is unknown, and a message is decided as soon as what is known settles it.
  - Level 0, before any query: the sequence number and UID rule messages out by the sets.
  - Level 1: the rows, `fetchMessages` without meta, one query per batch of 1,000 messages: flags, keywords,
    INTERNALDATE and size.
  - Level 2, for the messages still undecided: their meta (one more query per batch) and the header block, read from
    the blob by the meta's offsets: the header keys and SENT dates.
  - Level 3, only when BODY or TEXT must still decide: the whole message, read and decoded inside `Async.blocking`.
  - AND and OR evaluate their cheaper operands first. What is loaded for a message is dropped before the next, and
    nothing is cached across commands, so memory is one batch's rows and one message's text, whatever the
    mailbox's size: a 50,000-message mailbox is 50 batches.
- **Responses.** `* SEARCH` with sequence numbers, or UIDs for UID SEARCH, ascending. As FETCH and STORE do, SEARCH
  sends no EXPUNGE (RFC 3501 §7.4.1): a message another session expunged keeps its number, and is not found, until
  a command that may announce it; UID SEARCH may. A message whose blob cannot be read is not found, and the command
  ends `NO [UNAVAILABLE]` after the results.
- **The Dovecot differential** (`tools/search-differential.py`). It appends mmime's corpus (244 messages) and 10
  crafted ones (HTML, base64 and quoted-printable Latin-1, encoded-word subjects, no Date, a bad Date, an obsolete
  Date, an attached message) with the same flags, keywords and internal dates (five zones) to our server and to
  Dovecot 2.4.5 (Docker, `tools/dovecot-search.conf`: no full-text index, so Dovecot searches substrings as RFC 3501
  says), runs 125 UID SEARCH queries on both, and compares the results by APPEND order.
  - One command, `pkgs/mimap/tools/search-differential.py [-v]` (with run.sh's Postgres up, and the corpus from
    `pkgs/mmime/tools/fetch-corpus.py`): it starts our server through tests/conformance/run.sh
    (`--search-differential`) and Dovecot (container `mimap-dovecot`). `--query Q` and `--show NAME,…` look closer.
  - The result: 31,496 message checks, 0 unexplained differences, and 199 listed in `tests/search-deviations.txt`
    by reason:
    - **embedded-header** (64): BODY searches an attached message's header, which is part of the outer body (as
      Dovecot's full-text index does); Dovecot's plain BODY skips every header line;
    - **address** (45): Dovecot's FROM/TO/CC/BCC search its re-written address list (`nsb` becomes
      `nsb@MISSING_DOMAIN`); ours search the field's text, as Dovecot's own `HEADER From` does, which agrees with
      ours;
    - **html** (38): we search HTML as it reads; Dovecot without full-text search, its source;
    - **message-leaf** (37): Dovecot searches message/partial, delivery-status and feedback-report bodies raw;
      mmime reads only text/* leaves;
    - **untyped** (10), **bad-encoding** (2), **two-types** (1): a part with an invalid Content-Type, an unknown
      transfer encoding, or two Content-Type fields, which mmime reads as text (the first type) and Dovecot skips;
    - **mime-header** (2): Dovecot's TEXT also searches parts' MIME headers.
  - Everything else agrees exactly: flags, keywords, dates in five zones, SENT dates (no Date, bad Date, obsolete
    forms), sizes, sets, NOT/OR/lists, HEADER, and BODY and TEXT over plain, base64 and QP text in many charsets.

## Testing

Each needs run.sh's Postgres (Docker `ceesafe-pg-test`); the last three need Docker for Dovecot 2.4.5 (container
`mimap-dovecot`) and mmime's corpus (`pkgs/mmime/tools/fetch-corpus.py`).
- **Unit tests** (`ceesafec test`): the parser, sessions, snapshots and SEARCH (tests/*.cee).
- **End-to-end** (`tests/conformance/run.sh --imap`, or with the SMTP tests, `run.sh`): Python's `imaplib` and raw
  sockets against the built server. `LargeMessages` (slice 4): a 10 MB message fetched whole, in partials at its
  start, middle and end, and by part, over TLS and (with `IMAP_PLAINTEXT_AUTH=true`) plaintext, byte for byte; large
  APPENDs fetched back; an APPEND dropped mid-literal (no blob row, no temporary file, the session gone); TOOBIG and
  other refusals made before the literal is read. run.sh's `MAX_APPEND_SIZE` is 16 MB for them.
- **The SEARCH differential** (`tools/search-differential.py`, above).
- **imaptest** (`tools/imaptest.py`, or `tests/conformance/run.sh --imaptest`): Dovecot's compliance and stress tool
  (Docker image `dovecot/imaptest`; its scripted tests are fetched from its source at a pinned commit into
  `out/imaptest`), with plaintext login allowed.
  - The scripted tests, against ours and against Dovecot (as of imaptest d66226a):
    ours 74 groups, 4 failed, 39 skipped; base protocol 11/460 commands failed, extensions 0/26; Dovecot 0 failed,
    6 skipped, 0/460 and 0/329. Our 11, by reason:
    - **recent** (10 commands in copy, search-flags and select): `\Recent` is not kept (above).
    - **address** (1, search-addresses): FROM searches the field's text, not Dovecot's address list (SEARCH, above).
  - Unlisted failures fail the run (tests/imaptest-deviations.txt), and so does any protocol error imaptest reports.
    The 39 groups for extensions we do not offer are skipped from our CAPABILITY: BINARY, CATENATE, CONDSTORE,
    CONTEXT, ESEARCH, ESORT, LIST-EXTENDED, MULTIAPPEND, NOTIFY, QRESYNC, SORT, THREAD, UIDBATCHES, URLAUTH.
  - It found and slice 4 fixed: keywords used in FETCH before FLAGS announced them; an empty `Sender:` or
    `Reply-To:` not read as the From in ENVELOPE (mmime); SENTON/SENTBEFORE/SENTSINCE a day late for late-evening
    dates east of UTC (the zone was added twice); MOVE to the same mailbox refused; CREATE subscribing.
  - The stress mode (`--secs`, `--clients`; 60 s and 10 clients by default): random commands on one mailbox with
    imaptest's state tracking, appending mmime's corpus with a Message-ID each
    (237 of its messages: those imaptest's checks can track). 0 errors from either; 60 s, 10 clients: ours 7,920
    commands (132/s), Dovecot 13,535 (226/s), on a loaded laptop (load 3 to 9; Dovecot did 835/s in a quieter
    30 s run, ours 172/s). Each client logs in and out every cycle, and our LOGIN checks bcrypt (about 300 ms);
    FETCH, STORE and EXPUNGE took 70 to 100 ms against Dovecot's 10 to 13 (imaptest's `ms/cmd`). That was the
    bcrypt checks taking every core (Performance, below); since they are limited, 19 to 22 ms.
  - The tool prints the run's `ms/cmd`; `--set name=value` passes imaptest settings (`--set logout=0`: the clients
    stay logged in), `--no-compliance` skips the scripted tests.
- **The FETCH differential** (`tools/fetch-differential.py`, or `tests/conformance/run.sh --fetch-differential`): the
  search differential's 254 messages on both servers, fetched item by item and compared byte for byte (the tool's
  header lists the items, partials and part numbers): 15,309 FETCH commands on each; of 16,833 items, 16,178 are
  identical bytes, 58 differ only as literal against quoted, and 597 differ, all explained (576 message-items).
  - Normalised, as both may choose: sequence numbers and UIDs (matched by APPEND position), a literal against a
    quoted string with the same bytes, an item name's case and quoting (Dovecot upper-cases HEADER.FIELDS names; we
    echo the client's), and the order of items in one response.
  - The deviations (tests/fetch-deviations.txt), by reason:
    - **missing-part**: a part past the last is NIL; Dovecot sends `""`. Both are nstrings.
    - **zero-partial**: `<5.0>` is BAD (the grammar's length is `nz-number`); Dovecot answers `""`.
    - **keyword-order**: a message's keywords in the store's order; Dovecot's in the order the mailbox met them.
    - mmime's own (pkgs/mmime/tests/deviations.txt): Dovecot rewrites NUL and bare CR (**stored-bytes**); an empty
      Content-Type parameter (**empty-parameter**); one charset's case (**charset-case**); malformed addresses
      (**bad-address**); and the blank line of HEADER.FIELDS in a message that is all header (**all-header**).

## Performance

Measured on 6 November 2026 on an 8-core Apple laptop shared with other work (the load average is given with each
run), our server built with `-O2` and 4 workers, Postgres 17 and Dovecot 2.4.5 in Docker Desktop. Dovecot is reached
through Docker's port forwarding, which costs it throughput and some latency that ours does not pay; its test login
is a plain static password, ours bcrypt (cost 12).

- **Command latency** (`tools/latency.py`, `tests/conformance/run.sh --imap-latency [-n N] [--background N]
  [--steady] [--smtp] [--tls]`): one plaintext session logged in once, a mailbox of the 254 differential messages,
  milliseconds as median / p99.

  | command | ours, alone | Dovecot, alone | ours, 10 clients logging in, before | after | Dovecot, 10 clients |
  |---|---|---|---|---|---|
  | NOOP | 0.41 / 1.98 | 0.34 / 0.44 | 0.71 / 3.15 | 0.77 / 1.01 | 0.59 / 3.48 |
  | SELECT | 1.51 / 4.73 | 0.90 / 1.24 | 12.6 / 112 | 3.29 / 14.5 | 1.67 / 11.2 |
  | FETCH 1 (FLAGS) | 1.01 / 1.61 | 0.37 / 0.52 | 11.0 / 51.5 | 2.31 / 5.80 | 0.68 / 1.59 |
  | FETCH 1 (BODY.PEEK[]) | 1.21 / 1.92 | 0.43 / 0.57 | 12.0 / 89.4 | 2.48 / 5.73 | 0.55 / 2.40 |
  | STORE 1 +FLAGS | 1.78 / 4.95 | 0.75 / 0.98 | 29.9 / 122 | 4.68 / 19.3 | 1.70 / 6.98 |
  | NOOP after another session's STORE | 0.70 / 0.94 | 0.36 / 0.52 | 10.8 / 52.7 | 1.56 / 2.65 | 0.66 / 1.77 |

  Load 3.4 to 4.9. Alone, a command costs its Postgres round trips (0.33 ms each through Docker's port, by pgbench):
  FETCH two (the rows, and `sync`'s HIGHESTMODSEQ), STORE three. SMTP commands answer in 0.03 to 0.1 ms, RCPT
  (a lookup) 0.64 and a whole small message on port 25 0.50.
- **The cause of imaptest's 70 to 100 ms** was not the network: both sockets set TCP_NODELAY (msmtp's `Wire` and
  PostgresClient), a reply goes out in one write at `flush`, and alone every command is about a millisecond. It was
  the bcrypt checks. Each runs on a thread of its own (`Async.blocking`), and nothing limited them: ten clients
  logging in at every cycle kept about ten 250 ms checks running on eight cores, beside Postgres's VM, and the
  workers waited for the scheduler (load 14; with the same clients logged in once, FETCH was 2.7 ms). msmtp's
  `LoginGuard` now runs at most 4 at once (`BCRYPT_AT_ONCE`; SMTP AUTH shares it); further logins wait their turn.
  imaptest's stress mode, 60 s and 10 clients (load 2.4 to 2.7): FETCH 19 ms, STORE 19, EXPUNGE 21 (Dovecot 8,
  11, 10); 91 commands/s against Dovecot's 298, now bound by logins (about 16 a second). With `--set logout=0`
  (no logins, load 8 to 12): 1,633 commands/s against Dovecot's 2,425, 33 to 39 ms/cmd against 8 to 33.
- **STORE** sets the snapshot's HIGHESTMODSEQ itself when its statement's MODSEQ is the next one (nothing else changed
  the mailbox), so the `sync` after it reads no rows: one round trip fewer.
- **Streaming** (slice 4). No message is held in memory whole, whatever its size.
  - FETCH: a section of more than 64 KiB (`INLINE_LITERAL`) is sent as `{n}\r\n`, then its byte range from the
    blob, then the rest of the response. On plaintext the kernel copies it (`Wire.sendFile`, std's
    `AsyncTcpStream.sendFileAll` over the blob opened as std's `File` by `BlobStore.pathOf`); over TLS it is read in
    64 KiB pieces (`STREAM_CHUNK`) and written as they come (`Wire.sendNow`). Partials are a range within the
    section's. Smaller literals are copied into the response, which is flushed at 256 KiB. HEADER.FIELDS and
    HEADER.FIELDS.NOT filter the header block in memory, at most 1 MiB of it (`HEADER_FIELDS_LIMIT`; a field past it
    is not found). A blob shorter than its meta says is an empty literal and `NO [UNAVAILABLE]`, as before; a read
    failing mid-literal ends the session, the literal being short. A message without stored meta is indexed from
    the blob in pieces.
  - APPEND: the session leaves the message literal on the wire (`CommandReader.deferLiteral`). APPEND checks the
    announced size (`NO [TOOBIG]`), the mailbox and the quota first, then sends `+` (not for LITERAL+) and copies the
    literal from the `Wire` into mstore's `BlobWriter` in 256 KiB pieces, feeding mmime's scanner as SMTP delivery
    does, so the meta is made in the same pass. A refused synchronizing literal is never sent; a refused
    LITERAL+ one is read and dropped by the session. A connection that drops mid-literal (or a disk error, or more
    after the message: `BAD`) discards the blob's temporary file; no blob row is made before `deliver`.
- **Memory** (`tools/bench.py --only memory --transports plain|tls`, a fresh server for each transport): the
  server's RSS before, and its peak during, one APPEND (LITERAL+) and one `FETCH 1 (BODY.PEEK[])` of a message,
  sampled with `ps` every few milliseconds. Before streaming (load 4.7 to 5.3), and after (load 2.5 to 2.8):

  | size | before: APPEND / FETCH peak, plain | TLS | after: APPEND / FETCH peak, plain | TLS |
  |---|---|---|---|---|
  | 1 MB | 9 / 12 MB | 10 / 13 MB | 8 / 8 MB | 9 / 9 MB |
  | 10 MB | 22 / 50 MB | 23 / 51 MB | 9 / 9 MB | 9 / 9 MB |
  | 50 MB | 98 / 241 MB | 99 / 242 MB | 9 / 9 MB | 10 / 10 MB |

  Before, the RSS stayed at its peak afterwards (241 MB after the 50 MB message); after, it stays at 9 to 10 MB.
- **FETCH throughput** (`tools/bench.py`, `run.sh --imap-bench`; `FETCH … (BODY.PEEK[])`, the best of 5 rounds,
  STARTTLS for TLS). Before streaming (load 3.0 to 4.7, and 3.1 to 3.9 for ours alone), and after (load 3.1):

  | what | ours plain, before | after | ours TLS, before | after | Dovecot plain | Dovecot TLS |
  |---|---|---|---|---|---|---|
  | 254 messages, 12.2 MB, one command | 345 MB/s | 336 to 391 MB/s | 107 to 114 MB/s | 109 to 112 MB/s | 217 MB/s | 154 MB/s |
  | one 1 MB message | 516 to 543 MB/s | 800 to 962 MB/s | 103 to 105 MB/s | 105 to 109 MB/s | 242 MB/s | 189 MB/s |
  | one 10 MB message | 837 to 924 MB/s | 3,444 to 3,617 MB/s | 113 to 117 MB/s | 120 to 124 MB/s | 216 MB/s | 169 MB/s |

  The corpus's messages are mostly under 64 KiB, so copied as before. TLS is bound by encryption and the tls
  package's records: it sends a record per socket write (its 16 KiB network buffer), so each 64 KiB piece is four
  records and four writes. APPEND (`--only memory`, one message, LITERAL+), before / after: plain 54 / 64 MB/s at
  1 MB, 128 / 148 at 10 MB, 150 / 168 at 50 MB; TLS 37 / 42, 60 / 93, 62 / 107.
- **SEARCH** over the 254 messages (median of 5): ours 41 to 50 ms for `BODY "the"`, `BODY "zqxjkvbw"` (no match),
  `TEXT "message"` and `BODY "fox"`; Dovecot 13, 23, 6 and 21. Ours decodes every text leaf of every undecided
  message (level 3), with three `Async.blocking` threads per message (open, header, text: about 17 µs each).
- **Idle connections** (2,000 that each LOGIN, SELECT INBOX and IDLE, then one APPEND by another session; load 4.7
  to 8.3; the run raises the open-files limit to 20,000 if lower, and Dovecot's per-user and process limits):

  | | ours | Dovecot |
  |---|---|---|
  | memory at 0 / 1,000 / 2,000 | 16 / 39 / 47 MB (RSS) | 27 / 732 / 789 MB (container) |
  | opening all 2,000 | 119 s (bcrypt, 4 at once) | 15 s |
  | the APPEND seen by: first / median / all | 25 / 228 / 363 ms | 511 / 2,464 / 3,423 ms (1,999 of 2,000) |

- **What remains.** SEARCH's level 3 still reads a whole message to decode it (its text is capped at 1 MiB, but
  not the read). Over TLS, larger records would save writes: the tls package (CeeSafeLibs, which needs its owner's
  approval to change) sends a record per 16 KiB buffer and a socket write per record. `sync` could skip its query
  when the notify bus has not been raised (it is still needed for other processes on the same database); SEARCH
  could use one blocking call per message, or a full-text index; a cache of verified logins (as Dovecot's
  `auth_cache`) would take bcrypt off reconnects.

## Slices

1. **The core.** The parser, the responses, and every command except SEARCH. It adds `[imap]` ports to the binary, and
   end-to-end tests with Python's `imaplib` and raw sockets.
2. **The notify bus.** Deliveries, flag changes and expunges from any session or the relay reach IDLE at once
   (done; see IDLE above). End-to-end tests measure the latency (`NotifyBus` in tests/conformance/imap_test.py).
3. **SEARCH** (done; see SEARCH above), the full RFC 3501 grammar: header and body keys over decoded text, unit tests
   (tests/search_tests.cee), end-to-end tests (`Search` in tests/conformance/imap_test.py), and the Dovecot
   differential.
4. **Conformance and speed.** Dovecot's imaptest and Dovecot 2.4.5 as a differential oracle for FETCH (done; see
   Testing above), and benchmarks. CONDSTORE if time allows.
