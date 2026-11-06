# msieve

A Sieve interpreter (RFC 5228) with the extensions mail users actually write: `fileinto`, `envelope`, `copy`
(RFC 3894), `imap4flags` (RFC 5232), `vacation` (RFC 5230), and the `i;octet` and `i;ascii-casemap` comparators.
It replaces the C# server's two regular expressions, which understood one `header :contains` rule. msieve decides;
the delivery code (msmtp) carries the actions out.

```ceesafe
var script = Script.create();
if (!parseScript(source, mut script)?) {
    // script.error, script.errorLine
}
let message = SieveMessage { header: header, envelopeFrom: from, envelopeTo: to, size: size };
var result = SieveResult.create();
runScript(script, message, mut result)?;
// result.actions: ACTION_KEEP / ACTION_FILEINTO (target, flags), ACTION_REDIRECT (target), ACTION_VACATION
//   (days, subject, from, reason, handle, addresses, mime); result.implicitKeep with result.implicitFlags;
//   result.error after a runtime error (then the message is simply kept, RFC 5228 §2.10.6).
```

- **Parsing:**
  - A script compiles into a flat node tree with every string unescaped into one buffer, so a script costs a handful
    of allocations however long it is.
  - Validation happens at compile time: `require` before other commands, every extension declared, argument kinds and
    counts, tags, comparators, and redirect addresses. A broken script is refused before it is stored.
- **Limits** keep a hostile script cheap:
  - a 64 KB script, 4096 nodes, and nesting 32 deep;
  - 32 actions and 4 redirects;
  - `:matches` is iterative with one backtrack point, so it is O(n·m), never exponential (tested with 200 stars).
- **Headers** are decoded (RFC 2047) and unfolded for `header`. `address` uses mmime's address parser, and like
  Pigeonhole it compares the whole value when a field holds no valid address.
- **Vacation** (`src/vacation.cee`):
  - `vacationAllowed` applies RFC 5230 §4.5 and RFC 3834. There is no reply to:
    - the null sender, or the user themselves;
    - `MAILER-DAEMON`, `owner-*`, `*-request` or `noreply` addresses;
    - `Auto-Submitted` messages, or `Precedence: bulk/list/junk`;
    - mail with `List-*` fields or `X-Auto-Response-Suppress`;
    - mail where neither the user nor an `:addresses` entry is a recipient.
  - `buildVacation` writes the reply: an `Auto: ` subject by default, RFC 2047-encoded when needed, with
    `In-Reply-To`, `References` and `Auto-Submitted: auto-replied`. Strings from the script cannot add header
    fields.
  - The `:days` memory is the store's (`MailStore.vacationDue`): the check and the note are one SQL statement.

## In the server

- `mailserver set-sieve USER FILE [NAME]` compiles a script, stores it and activates it.
- `set-vacation USER DAYS SUBJECT MESSAGE` writes the vacation script for you.
- `clear-sieve USER` turns scripts off.
- RCPT's lookup returns the recipient's active script with the rest. At delivery, msmtp runs it against the header
  as it will be stored, so scripts can test `X-Spam-Status` and `Authentication-Results`. Then:
  - mailboxes become the message's copies, with flags as system flags and keywords; a missing mailbox means the
    INBOX, as Pigeonhole does without `:create`;
  - redirects join the outbound queue, in the same transaction;
  - vacation replies are queued from the null sender after the message is stored.
- **Quarantined mail** (DMARC quarantine, or spam at the junk score) goes to Junk without running the script, so a
  script can neither forward spam nor answer it.

## Tests

`tests/run.sh` runs two kinds of test:
- **Unit tests:** hostile patterns, limits, every prefix of a script, bad UTF-8, and vacation's rules and reply.
- **Differential test** (`tests/differential/compare.py`): 100 cases in `cases.py`, each run through
  `examples/run` and through Pigeonhole's `sieve-test` in `dovecot/dovecot:2.4.5`, one long-lived container. The
  cases cover:
  - every test, match type, comparator and action;
  - if/elsif/else and stop;
  - flags;
  - vacation's handle and reason;
  - encoded, folded, group and broken headers;
  - syntax errors.

All 100 agree. The end-to-end tests are the `Sieve` class in `tests/conformance/smtp_test.py`.
