# mqueue

The outbound relay: workers that take messages off mstore's queue and deliver them. Remote recipients go through
their domain's MX hosts with msmtp's SMTP client; local ones go into their INBOX. What fails for good is bounced to the
sender as a delivery status notification, and what fails for now is retried on a schedule until the message is too
old.

```ceesafe
var settings = RelaySettings.create("mx.example.org")?;   // port 25, retries, 5-day limit, STARTTLS
let relay = Relay.create(settings, resolver)?;
// In a task scope, as many as wanted: rows are claimed with SKIP LOCKED, so workers never collide.
s.spawn(async () => await relayWorker(relay, store));
```

- **Claiming.**
  - A worker claims one due row with a random token, for 30 minutes. A crashed worker's claim runs out by itself, with
    no reaper.
  - The due row is chosen in a materialized CTE. As a subquery joined to `queue`, Postgres rescanned it in a nested
    loop, and each rescan could skip-lock another row: one claim took several, and all but one were left claimed and
    untouched for the 30 minutes. A worker also processes every row a claim returns.
  - Settling checks the token, so a worker that took too long cannot settle a row that another worker has since
    claimed.
  - Settling is one transaction: local recipients get the queued blob as it is (no copy), then the row is dropped, or
    rescheduled with only the recipients that are left.
- **Routing** (`src/mx.cee`):
  - MX hosts in preference order, with equal preferences shuffled (RFC 5321 §5.1);
  - the domain itself when it has no MX (the implicit MX);
  - a null MX (RFC 7505) bounces with 5.1.10, a domain that does not exist with 5.1.2, and a DNS failure is retried
    (4.4.3);
  - each host's addresses are looked up as it is tried, IPv4 first; up to 10 hosts and 20 addresses per domain.
- **Delivery** (msmtp's `deliverTo`): one transaction per domain, and every recipient keeps its own outcome and the
  server's reply.
  - The next MX host is tried only when a host is unusable: refused, silent, closing, or a 4xx/5xx greeting or EHLO.
  - A 4xx for a recipient is retried later; a 5xx is final.
  - STARTTLS is opportunistic (RFC 7435): the certificate is not checked, and a failed handshake is retried in the
    clear on the same host.
  - The client also handles:
    - PIPELINING;
    - SIZE: an oversized message is refused before MAIL, 5.3.4;
    - BODY=8BITMIME;
    - SMTPUTF8: internationalized addresses to a server without it fail with 5.6.7;
    - HELO for old servers;
    - RFC 5321's timeouts;
    - dot-stuffing, with bare LF sent as CRLF.
  - A recipient accepted at RCPT is not delivered until the server answers the message, so a connection lost during
    DATA means a retry, never a lost message.
- **Retries:**
  - 5 and 15 minutes, half an hour, then 1, 2, 4, 8, 16 and 24 hours, as the C# server had; the last delay repeats.
  - After 5 days in the queue (`max_age`), the rest bounces with 4.4.7 and the last reply.
- **Bounces** (`src/dsn.cee`):
  - one RFC 3464 `multipart/report` per message, from `MAILER-DAEMON` with the null sender and
    `Auto-Submitted: auto-replied`;
  - a part for people, then per recipient: Final-Recipient, Action, Status (the enhanced code from the reply),
    Remote-MTA and Diagnostic-Code;
  - then the original header (`text/rfc822-headers`), never the body;
  - a bounce that fails is dropped, never bounced again.
  - The C# server's bounce was plain text with one reason for every recipient.

- **DKIM signing:**
  - Each attempt signs the message once, for all its domains, with the active key of its From domain (mauth's
    `DkimSigner`: relaxed/relaxed, RSA-SHA256 or Ed25519-SHA256, the display and threading fields signed, and From,
    To, Cc, Subject, Date and Reply-To oversigned).
  - The signature is sent ahead of the stored blob, which is never rewritten. A message without a key, or whose
    signing fails, goes out unsigned.
  - Keys are kept in mstore (`dkim_keys`, PKCS #8) and managed with `mailserver dkim-generate`, `dkim-import`,
    `dkim-activate` and `dkim-show`. A new key is inactive until its DNS record is published and it is activated.

- **Delay notices:** after `delay_notice` (4 hours) undelivered, the sender gets one report with `Action: delayed`
  and `Will-Retry-Until`, saying there is no need to send again. The queue row remembers that it went.
- **The suppression list** (mstore's `suppression`):
  - A recipient that fails with 5.1.x (no such mailbox, no such domain, null MX) is suppressed for `suppress_days`
    (30), with the reply that failed it.
  - Policy and content rejections are not recorded: they say nothing about the address.
  - A local user writing to a suppressed address gets 550 at RCPT, with the old reply; the relay fails it without
    connecting.
  - `mailserver unsuppress ADDRESS` lifts a suppression, and housekeeping drops expired ones.
- **Per-domain breakers** (`src/breaker.cee`):
  - A domain whose MX hosts were all unusable `breaker_threshold` (3) times in a row is not tried for
    `breaker_seconds` (60), doubling each time it trips again, up to an hour.
  - Its mail waits instead of holding a worker for a connect timeout per message.
  - Only whole-host failures count. The C# server closed a whole domain for 15 minutes after any single 5xx, so one
    mistyped address could block all mail to a large provider.
- **SRS:** see msmtp's README. Forwarded mail leaves with an SRS sender.
- **Connection reuse** (`src/pool.cee`): idle sessions are kept per MX address and name (`pool_size`, `pool_idle`,
  100 messages each). A reused session starts with RSET, and a stale one costs nothing: a new one is opened. A session
  serves only hosts that need no more TLS than it has.
- **Strict TLS** (`src/tlspolicy.cee`, `[relay] tls_policy`):
  - `opportunistic`: STARTTLS when offered, the certificate unchecked, plaintext when the handshake fails
    (RFC 7435).
  - `published` (the default): what each recipient domain publishes. DANE takes precedence (RFC 8461 §2).
    - **DANE (RFC 7672).** It applies when the resolver validated the MX answer, the host's addresses and its
      `_25._tcp` TLSA records with DNSSEC (the AD bit; mdns asks for it). Usable DANE-TA or DANE-EE records
      authenticate the server through OpenSSL's DANE, in tls. Records that are all unusable still require TLS,
      unauthenticated. A failed TLSA lookup skips the host.
    - **MTA-STS (RFC 8461).** The `_mta-sts` TXT record's id says whether the cached policy is current; otherwise
      `https://mta-sts.<domain>/.well-known/mta-sts.txt` is fetched (`src/stsfetch.cee`). It needs a certificate valid
      for that name, a 200 `text/plain` response, at most 64 KiB, and follows no redirects.
      - Policies are cached in memory and in Postgres (`mta_sts_policies`, migration 8) for their `max_age`, so they
        outlive restarts and a blocked lookup.
      - A domain without one, or whose fetch failed, is not asked again for 5 minutes, and a cached policy stays in
        force meanwhile.
      - In `enforce` mode, only listed MX hosts are used, over TLS with a certificate valid for the host's name under
        the system's roots and `tls_trust_file`. In `testing` mode, mail goes as without a policy (no TLSRPT reports
        are sent).
  - `verified`: as `published`, and every other domain also needs TLS with a certificate valid for the MX name.
  - **Failures.** A host that cannot give what its domain asks is skipped, never used in the clear (4.7.10 when it
    offers no STARTTLS, 4.7.5 when its certificate fails, 4.7.0 for an unlisted host). The mail is retried, and
    bounces only when it is too old.
  - **Cost.** Under the relay load test (1,000 messages, STARTTLS, pooled), `published` relays 320 messages/s
    against 341 for `opportunistic`.

## Tests

- **`tests/run.sh`:** the client against `tools/fakemx.py`, a fake MX with one failure mode per port:
  - a 421 greeting, a server that is only HELO, silence, and a drop during DATA;
  - a broken STARTTLS, and no PIPELINING;
  - per-recipient 550 and 451, and 554 at the final dot.
  It also tests the bounce builder.
- **`tests/conformance` (`Relay`):** end to end through the server, against fakemx and the zone's MX records:
  - a dead first MX, the implicit MX, a null MX and a domain that does not exist;
  - retries, then expiry;
  - bounces parsed with Python's `email` package;
  - a bounce that fails is not bounced;
  - DKIM: no signature before a key is activated, then RSA and Ed25519 signatures that dkimpy verifies;
  - one delay notice, then the bounce;
  - suppression after 5.1.1 (and none after 5.6.0), then `unsuppress`;
  - the breaker opening for a dead domain;
  - SRS out and back, with a forged address refused.
- **`tests/conformance` (`StrictTls`):** DANE and MTA-STS against fakemx (`localhost.pem`).
  - DNSSEC is simulated: fakedns sets AD for names marked `SECURE`, only when the query asks for it.
  - MTA-STS policies are served by `tools/fakests.py` over HTTPS, with a certificate made at run time and trusted
    through `tls_trust_file`.
  - The cases:
    - a matching DANE-EE record;
    - a mismatching one, never sent in the clear;
    - a wrong record that is ignored without DNSSEC;
    - an `enforce` policy, fetched once and then cached in Postgres;
    - an unlisted MX host;
    - an MX certificate for another name;
    - `testing` mode.
- **`tests/sts_tests.cee`:** the MTA-STS record and policy parsers and MX patterns, with RFC 8461's examples.
- **`tests/interop/run.sh`:** against a real Postfix in Docker. It checks STARTTLS, the stored bytes
  (dots, 8-bit text, long lines), Postfix's own 550 in the bounce, its SIZE limit, and SMTPUTF8.
