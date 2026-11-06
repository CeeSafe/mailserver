# msmtp

The mail server's SMTP side: MX (port 25), submission (587, AUTH after STARTTLS) and submission over implicit TLS
(465). The outbound relay client arrives with Phase 5.

## What a session does

- **Commands:** EHLO/HELO, STARTTLS, AUTH PLAIN and LOGIN, MAIL, RCPT, DATA, RSET, NOOP, VRFY/EXPN (252: who exists
  is not revealed), HELP and QUIT.
- **Extensions advertised:** PIPELINING, SIZE, 8BITMIME, ENHANCEDSTATUSCODES, SMTPUTF8, plus STARTTLS and AUTH where
  they apply. Pipelined replies go out in one write.
- **Recipients are checked at RCPT,** through `MailStore.resolve`: domain aliases, aliases, and catch-alls.
  - Unknown local users get `550 5.1.1` at once, rather than a later bounce that sends backscatter to forged
    senders.
  - A user over quota gets `452 4.2.2`, judged against the SIZE the client declared.
  - Relaying is refused (`550 5.7.1`) unless the client has logged in.
  - Two aliases of one user give one copy.
- **Mail is stored before the 250.** DATA streams through one pass:
  - dot-unstuffing;
  - the blob file, written in 256 KiB batches on a worker thread and fsynced;
  - the MIME scanner, whose index and renderings are stored as `messages.meta`.

  Then a single `MailStore.accept` transaction stores every local copy, the sender's Sent copy (on submission,
  flagged `\Seen`) and the queued remote copy. So a 250 means the message is on disk and committed.
- **A `Received:` header** starts every message (RFC 5321 §4.4), with RFC 3848's ESMTP/ESMTPS/ESMTPA/ESMTPSA. It
  has `for <rcpt>` only for a single recipient.

## Security choices

- **SMTP smuggling:** only `<CRLF>.<CRLF>` ends DATA. A bare LF is data, so `<LF>.<LF>` cannot end a message early
  and smuggle a second one past another server. This is the 2023 class of attacks.
- **STARTTLS:**
  - Bytes the client pipelined after STARTTLS are thrown away, not run inside the TLS session (CVE-2011-0411).
  - The session starts fresh after the handshake.
  - Handshakes time out after 30 s (`TlsStream.acceptWithin`).
- **Submission:**
  - AUTH is refused before TLS (`538 5.7.11`, RFC 8314) unless `plaintext_auth` is set for a TLS-terminating proxy.
  - Mail without AUTH is refused (`530 5.7.0`, RFC 6409); the C# server accepted it for local domains.
  - MAIL FROM must be in the user's domain, as the C# server checks.
- **Passwords:**
  - bcrypt, compatible with the existing `$2a$`/`$2b$`/`$2y$` hashes, checked on a worker thread.
  - An unknown user is checked against a dummy hash, so timing does not show who exists.
  - An AUTH PLAIN authzid naming another user is refused.
  - The password is wiped after the check.
- **Brute force:**
  - One check for every protocol: `checkLogin` (`src/login.cee`) does the guard, the bcrypt check (against the dummy
    hash for an unknown user), the `active` flag and the bookkeeping, for SMTP AUTH and IMAP alike. SMTP also asks
    `loginBlocked` before the SASL exchange, so a blocked address is refused before it sends a password.
  - Three failures end a session.
  - Addresses are counted as IPv4 addresses, or as IPv6 /64s, since one attacker holds a whole /64.
  - **In memory** (`AuthThrottle`, no round trip): 10 failures from one address within 15 minutes block it for 15
    minutes in this process.
  - **In the store** (`auth_failures`, shared by every server process and kept across restarts): 10 failures from
    one address within 15 minutes, or 30 against one login name from any number of addresses (a botnet spread
    thin), block the failing address for 2 hours.
    - The account is never locked, so nobody can lock its owner out.
    - A good login clears its address's count.
    - Counting and blocking are one upsert per failure; a check is one index lookup.
    - When the database cannot answer, memory alone decides.
  - `mailserver block-ip ADDRESS [HOURS]` and `unblock-ip ADDRESS` set and lift blocks by hand.
- **Limits:**
  - 8 KiB command lines. `Wire.readLineWithin` takes another limit (IMAP's is 64 KiB), and `Wire.readExact` reads
    an IMAP literal.
  - 500 recipients.
  - The configured message size: SIZE is checked at MAIL, the real size during DATA, and the session stays in
    step after a refused message.
  - Idle and DATA timeouts of 5 and 10 minutes.
  - Connections are capped per listener; a flood waits in the kernel's backlog.

## Tests

- `ceesafec test`: the DATA decoder (in every chunk size), path and parameter parsing, SASL decoding and dates, and
  `Wire` over a loopback connection (a line limit, and a literal begun in the buffer and ended by a later read).
- `tests/conformance/run.sh` (repository root): builds the server, starts it on a fresh database with TLS, and runs
  23 black-box tests (and one more, `REAL_SCANNERS=1`, against Docker's ClamAV and SpamAssassin) with Python's `smtplib`:
  - delivery and the stored bytes, unknown users and relaying, sequence errors, pipelining, quota and size limits;
  - SMTP smuggling, STARTTLS and its plaintext injection;
  - virus rejection on both ports, a hung scanner giving 451, spam routing by score, forged spam headers removed;
  - DMARC reject and quarantine, a dkimpy-signed message arriving byte-for-byte unchanged with `dkim=pass`, forged
    `Authentication-Results` removed, and a 1.8 MB message through the spool;
  - AUTH PLAIN, AUTH LOGIN over SMTPS, the sender check, and wrong passwords (timing included).
- `tests/conformance/run.sh --load 16 100`: 16 clients sending 100 messages each, about 750 messages/s on an M-series
  Mac against Postgres in Docker, the same with SPF, DKIM and DMARC on as off (their DNS answers are cached). All of them go to one INBOX, the worst case, since every delivery takes that
  mailbox's row lock.

## Behind a TCP proxy

`src/proxy.cee`: the PROXY protocol, versions 1 and 2, for a proxy (CosmoProxy, HAProxy) that streams the mail ports
to the server. IMAP uses it too, through `proxyPeer`.

- **Only from the proxies.** `SmtpSettings.proxyFrom` (`[proxy] from`) lists the proxies' networks. A connection
  from one of them must start with a header, or it is closed; from anywhere else no header is read, so no client
  can claim another address.
- **Before TLS.** The header is read from the TCP stream before the SMTPS or IMAPS handshake, in exact-length
  reads, so nothing after it is consumed; the address survives STARTTLS.
- **The client's address** is then the session's everywhere: logs, `Received:`, SPF, the failed-login guard.
  Version 2's LOCAL (the proxy's health checks) and version 1's UNKNOWN keep the proxy's own address.
- **Tests:** `tests/proxy_tests.cee` (parsing, networks, and a loopback read that leaves the next line intact);
  `tests/conformance/run.sh --proxy` (both versions, over SMTP, STARTTLS, submission and IMAPS).

## Inbound authentication (port 25)

- **Holding DATA.** DATA is held, in memory up to 1 MiB and beyond that in a spool file. Meanwhile mauth's DKIM
  verifier reads it. The final blob is then written in one pass, which also feeds the MIME scanner:
  1. `Authentication-Results`;
  2. `Received`;
  3. the original header, without forged `Authentication-Results` fields naming this host;
  4. the body.
- **DMARC dispositions:**
  - `reject` is refused with 550 5.7.1;
  - `quarantine` goes to each recipient's Junk folder.
- **Configuration:** `[dns] inbound_auth = false` turns all of this off.

## Content scanning

Through mscan, configured in `[scan]`:
- **Viruses (both ports):** clamd scans every message up to 25 MB. An infected message is refused (554 5.7.1, naming
  the signature), on submission too, so a user's infected machine cannot send through us.
- **When clamd cannot scan** (down, timed out, an error), the message is refused *temporarily* (451 4.7.1) and the
  sender retries. The C# server refused permanently (554), bouncing all mail while ClamAV was down.
  `clamd_unavailable = "accept"` delivers unscanned instead. A circuit breaker skips a failing clamd for 30 s.
- **Spam (port 25):**
  - spamd scores messages up to 512 KB, and the score goes in `X-Spam-Score` and `X-Spam-Status` headers;
  - at the junk score (5.0) the message goes to Junk, and at the reject score (10.0) it is refused (550);
  - a failing spamd leaves mail unscored, never refused;
  - the sender's own `X-Spam-*` headers are removed, so a spammer cannot pre-label mail as clean.

## Not yet

- Sieve, auto-reply and quarantine review.
- CHUNKING/BDAT, DSN and XOAUTH2.

## SRS and suppression

- **SRS** (`src/srs.cee`) applies to mail this server forwards on port 25: Sieve redirects, and aliases to remote
  addresses.
  - The forwarded message leaves with `SRS0=HHHHHHHH=TT=domain=local@<srs_domain>` as its envelope sender, so SPF at
    the destination checks this server.
  - A bounce to such an address is accepted at RCPT, checked, and queued on to the original sender:
    - HHHHHHHH is an HMAC-SHA256 under `[relay] srs_secret`, in base32 so lowercasing does not break it;
    - TT is the day it was made; addresses expire after 21 days.
  - A forged or expired address is just an unknown address (550).
  - Local senders, the null sender and addresses too long to rewrite are left alone. An empty secret turns SRS off.
- **Suppression:** on the submission ports, RCPT to an address on the relay's suppression list (it bounced with
  5.1.x recently) is refused with 550 and the reason, instead of being queued to bounce again.

