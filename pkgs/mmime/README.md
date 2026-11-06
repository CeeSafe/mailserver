# mmime

The mail server's MIME engine. A streaming scanner reads each message once, at delivery, and records every part's
byte ranges. The IMAP renderings (ENVELOPE, BODYSTRUCTURE and BODY) are made at the same time and stored, so
IMAP FETCH copies bytes and never parses MIME again.

```ceesafe
var scanner = MimeScanner.create();
scanner.feed(chunk)?;              // as SMTP DATA arrives, in chunks of any size
var index = MessageIndex.create();
scanner.finish(mut index)?;

var renderer = Renderer.create();
var meta = Vector<u8>.create();
encodeMeta(index, mut renderer, mut meta)?;   // for mstore's messages.meta column

// IMAP, later, from the stored bytes:
var m = MessageMeta.create();
if (m.read(stored)?) {
    metaBodyStructure(m, stored);              // FETCH BODYSTRUCTURE, ready to send
    let part = m.partAt([1u32, 2][..])?;       // BODY[1.2]: m.parts[part].bodyStart .. bodyEnd of the blob
    // BODY[HEADER.FIELDS (FROM TO)] (or .NOT, with true) from a part's headerStart .. bodyStart of the blob:
    appendHeaderFields(header, names, false, mut out)?;
}

// SEARCH, Sieve, display:
decodeHeader(headerOf(index, 0, "Subject")!, mut text)?;    // RFC 2047, any charset, to UTF-8
decodeParam(disposition.params, "filename", mut name)?;     // RFC 2231 and 2047 in parameters

// IMAP SEARCH, from the message blob and its meta:
appendSearchText(blob, m, false, SEARCH_TEXT_LIMIT, mut text)?;   // BODY; true for TEXT (decoded header first)
appendHeaderValues(header, "Subject", mut value)?;               // FROM, SUBJECT, HEADER name: every occurrence
if (containsFolded(text.view(), key)) { … }                       // case-insensitive substring
```

## How it reads mail

- **Dovecot is the reference.** For the IMAP views, mmime reads mail the way Dovecot 2.4 does: Dovecot is the most
  widely deployed IMAP server, so it is what clients already handle. That covers:
  - where a boundary's line break belongs, and which part it is taken from;
  - lines without a colon in a header block;
  - empty and missing boundaries;
  - a multipart with no parts, encoded message/rfc822 parts, and multipart/digest defaults;
  - lowercase hosts and the `MISSING_DOMAIN` placeholders in ENVELOPE;
  - adding a default charset to text parts;
  - folding and whitespace in ENVELOPE fields.
- **It never rejects a message.** Malformed mail is read as well as it can be.
- **Hostile input is bounded.**
  - Nesting deeper than 64 levels reads as a leaf.
  - Header lines over 16 KiB are cut, and at most 256 KiB of headers are kept per part, 4 MiB per message.
  - Body lines of any length use constant memory.
- **Stored meta** (`meta.cee`, a versioned varint format) holds each part's offsets and line counts plus the three
  renderings: a median of about 0.75 KB per message in the corpus, up to 133 KB for one with hundreds of parts. `MessageMeta.read` checks every offset and parent link, so a damaged
  row is refused rather than trusted.
- **Header decoding** is for people, not for IMAP's views, which carry the raw text.
  - It handles RFC 2047 words (Q and B), dropping the whitespace between adjacent words, and decodes leniently.
  - Charsets other than UTF-8, US-ASCII and Latin-1 go through iconv (`c/charset_shim.c`); ISO-2022-JP and KOI8-R
    both work.
  - Raw 8-bit text is read as UTF-8 if it is valid, else as Latin-1.
  - Bad input becomes U+FFFD; decoding never fails.

## Body text for SEARCH

`bodytext.cee` gives IMAP SEARCH (RFC 3501 §6.4.4) text to match against:

- **`appendPartText`** (or `appendLeafText`, by part index) decodes one leaf part to UTF-8:
  - only text/* parts (or parts with no type, which are text/plain); images, PDFs and the like are `Skipped`;
  - base64 and quoted-printable are undone leniently (`decodeTransfer`), as Dovecot does:
    - base64 skips every byte outside its alphabet, and goes on after `=`;
    - quoted-printable takes `=XX` in either case, drops whitespace at line ends, and keeps a malformed `=`;
    - other encodings, uuencode among them, are copied as they are;
  - the `charset` goes through `convertToUtf8`: Latin-1 and UTF-8 directly, the rest through iconv. An unknown
    charset reads as UTF-8 if it is valid, else as Latin-1, and invalid sequences become U+FFFD;
  - text/html is stripped crudely (`appendHtmlText`):
    - tags and comments are dropped, and so are `<script>` and `<style>` with their contents;
    - block tags leave a space;
    - `&amp; &lt; &gt; &quot; &apos; &nbsp; &#NN; &#xHH;` are decoded, `&nbsp;` to a plain space;
    - a charset named only in a `<meta>` tag is not read.
- **`appendSearchText`** walks every part of a message: for TEXT, the decoded header (`Name: value` lines) first;
  then each text leaf's text, then a line break. Embedded message/rfc822 messages are walked too. Each one's header
  is decoded whole (Subject, From and the rest), since it is part of the outer message's body. Parts' own MIME
  headers are left out.
- **`appendHeaderValues`** appends the decoded value (RFC 2047) of every field with a given name, for FROM, TO, CC,
  BCC, SUBJECT and HEADER.
- **`containsFolded`** is the substring match. It folds ASCII letters and the Latin-1 letters À–Þ to à–þ, which is
  cheap in UTF-8. It does not fold other scripts, ß or ÿ, nor accents (`e` does not find `é`), nor Unicode
  normalisation; Dovecot's i;unicode-casemap does more.
- **The cap.** The text is capped, at `SEARCH_TEXT_LIMIT` (1 MiB) per message for a typical caller:
  - every call takes a limit in bytes, cuts its output at a UTF-8 character boundary at or below it, and says so
    (`PartText.Cut`, or `false`);
  - SEARCH cannot find text past the cap;
  - work is bounded too: at most `limit` bytes are transfer-decoded per part, twice that for HTML, and iconv needs
    up to four times that, transiently.

## Testing

- **The differential** (`tools/differential.py`), against two oracles:
  - **Dovecot 2.4.5:** size, ENVELOPE, BODYSTRUCTURE and BODY, and the SHA-256 of every body section of every
    message (HEADER, TEXT, n, n.MIME, n.HEADER, n.TEXT, and HEADER.FIELDS and HEADER.FIELDS.NOT of seven common
    fields, for the message and each embedded message).
  - **Python's `email` package:** decoded subjects and display names.
- **The corpus** is 244 messages from MimeKit's test data, jwz's MIME torture collection among them.
- **The results** are 4,774 checks with no unexplained difference, and the same at every chunk size from 1 byte to
  64 KiB. Each check goes through the stored meta, so the meta's round trip is tested too.
- **The body differential** (`tools/body-differential.py`) checks decoded body text against Python's `email`
  package. `tools/body-oracle.py` writes `tests/body-oracle/` (checked in), and examples/inspect prints mmime's text.
  - Each text part is compared, HTML unstripped: `get_payload(decode=True)`, then decoding with the charset.
  - A part with no charset, or US-ASCII, is read as UTF-8 on both sides.
  - The corpus has QP, base64, 7bit and 8bit text parts in UTF-8, US-ASCII, ISO-8859-1, -2, -7 and -8, KOI8-R and
    ISO-2022-JP.
  - The results are 448 checks, no unexplained difference, and 23 allowed deviations (`tests/body-deviations.txt`):
    - 14 quoted-printable parts: mmime deletes whitespace at line ends (RFC 2045 §6.7, as Dovecot does), and Python
      keeps it;
    - 3 multiparts never closed, whose last part keeps its last line break as in Dovecot;
    - 5 messages that Python splits differently from Dovecot;
    - 1 mislabelled ISO-2022-JP part, where the U+FFFD land in different places.
  - When the part counts differ (33 messages), Python's texts are looked for among mmime's by content. Python's
    parts inside message/partial, message/delivery-status and the like (38) are not compared: IMAP reads those
    types as leaves.
- **`tests/deviations.txt`** lists 23 checks where mmime knowingly differs from Dovecot, each with its reason:
  - Dovecot rewrites NUL and bare-CR bytes;
  - mmime finds a boundary Dovecot loses to a `;;` in the header;
  - three malformed addresses;
  - Dovecot adds a blank line to HEADER.FIELDS of a message that is all header.

```sh
tools/fetch-corpus.py        # once: tests/corpus/ (not checked in)
# Only to regenerate tests/oracle/ (checked in):
docker run -d --name mmime-dovecot -e USER_PASSWORD=oracle -p 127.0.0.1:51143:31143 \
    -v "$PWD/tools/dovecot-oracle.conf:/etc/dovecot/conf.d/oracle.conf:ro" dovecot/dovecot:2.4.5
tools/dovecot-oracle.py
(cd examples/inspect && ceesafec build -o out/inspect) && tools/differential.py [-v] [--chunk N]
tools/body-oracle.py         # only to regenerate tests/body-oracle/ (checked in)
tools/body-differential.py [-v]
ceesafec test                # unit tests and a randomised test (1,500 generated messages, cut and chunked)
```

`ceesafec test --sweep alloc` fails each allocation in turn (1,483 runs). Every failure reaches the caller as
`AllocError`; nothing crashes or leaks. The sweep reports these as failures only because the tests unwrap with `!`.

## Speed

`examples/bench` scans the corpus from memory in 64 KiB chunks. Built with `-O3` on an M-series Mac:

- scanning alone runs at about 2.8 GB/s;
- scanning and building the stored meta runs at about 1.6 GB/s, or 31,700 messages/s.

At delivery, the SHA-256 of the blob (about 200 MB/s in pure CeeSafe) costs more than parsing.

## Not yet

- BINARY (RFC 3516): `decodeTransfer` undoes the encoding, but the FETCH BINARY and BINARY.SIZE views are not
  built yet.
- Unicode case folding beyond Latin-1 for SEARCH (i;unicode-casemap).
- The message builder (bounces, auto-replies).
- A cached form of the decoded headers for SEARCH, which arrives with IMAP SEARCH (Phase 6).
