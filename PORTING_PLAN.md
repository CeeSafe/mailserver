# CosmoMailServer → CeeSafe porting plan

- **Source:** `~/dev/CosmoMail/CosmoMailServer` (.NET 10, about 40k LOC of C# excluding tests, plus 18k LOC of tests and a Nuxt admin UI).
- **Target:** `~/dev/CeeSafeApps/mailserver`, CeeSafe with `ceesafec` 0.14.0.
- **Approach:** a performance-first redesign. The C# is not translated line by line. The C# code serves as the spec for behaviour, and its tests and `.eml` corpus serve as the oracle.

---

## 1. What we are porting (and what we are not)

### What is actually in the C# code

| Area | C# home | Notes |
|---|---|---|
| SMTP: MX on 25, submission on 587, SMTPS on 465 | `CosmoMail.Server/Smtp` | STARTTLS, AUTH PLAIN/LOGIN/XOAUTH2, SIZE, 8BITMIME, PIPELINING, SMTPUTF8, ENHANCEDSTATUSCODES, PROXY protocol. No BDAT or DSN. |
| IMAP on 143 and 993 | `ImapSession.cs` (2.8k lines) | IMAP4rev1, IDLE, MOVE, UIDPLUS, NAMESPACE, ID, UNSELECT, SPECIAL-USE, ENABLE, LITERAL+, CHILDREN. No CONDSTORE, QRESYNC or COMPRESS. |
| Outbound relay and queue | `RelayWorker.cs` (1.1k lines), `QueueService` | DB-backed queue with backoff and circuit breakers, 8 parallel workers, pooled sessions. Uses the external `CosmoMailClient` project. |
| Inbound authentication | `CosmoMail.Security` | Custom SPF and DMARC. DKIM verification and signing go through MimeKit. |
| Content scanning | `ScannerService` | ClamAV (zINSTREAM) and spamd over TCP, plus a reputation breaker. |
| Accounts | `UserService` | BCrypt with dummy-hash timing protection, `BruteForceGuard` with failure counts kept in SQL. Domains, aliases, catch-all, domain aliases, auto-reply, Sieve subset (regex based). |
| TLS and ACME | Certes (vendored, 5.4k lines), `CertificateProvider` | HTTP-01 challenges, hot reload. |
| DNS | `CosmoMailServer.Utils` (vendored DnsClient) | MX, TXT, PTR, TLSA, A, AAAA records, with a cache. |
| Storage | `CosmoMail.Data` and `CosmoMail.Storage` | Raw SQL through CosmoSQLClient against MsSql, Postgres or CosmoKv, with dialect shims. 36 tables. Blobs in S3, CosmoKv or the DB. |
| HTTP API | `CosmoMail.Api` (8.7k lines) | ActiveSync 16.1 (WBXML), EWS (SOAP), CalDAV/CardDAV, Autodiscover, MTA-STS publishing, OAuth2/OIDC server, Postmark-compatible and transactional APIs, webhooks, Liquid templates. |
| Admin | `CosmoMailAdmin` | CLI plus a 72-route JSON API, used by the Nuxt frontend. |

### Scope cuts

The README advertises several features the code does not implement: enforcement of greylisting and rate limits, ARC, DANE and MTA-STS enforcement, and full Sieve. These are new features, not porting work, so they are tracked separately. We are also dropping things that exist only for .NET or for supporting several databases:
- Dialect-translation shims (`Postgres/CosmoKvCompatibilitySqlDatabase`), EF Core, and MsSql support.
- System.IO.Pipelines, Channels and DI/Hosting plumbing.
- OpenTelemetry (for now), and `Cosmo.Transport`, which nothing uses.

---

## 2. CeeSafe reality check (0.14.0)

**Strengths for this job:**
- Structured async (`Async.tasks`, `race`, `timeout`, cancellation).
- A work-stealing multi-core executor (`Async.runWorkers`).
- Reactor backends: kqueue, epoll and io_uring.
- Async TCP and UDP, `writeVectored` and `sendFile`.
- Arenas, pools and scratch allocators.
- Ownership-based safety with no GC.
- Fixed-size async frames, so idle connections cost little memory.
- C FFI (`extern "C"`, `links = [...]`, `c = [...]`) that was verified to work with sqlite3.

**Gaps we must fill ourselves:**

| Gap | Plan |
|---|---|
| TLS | A thin OpenSSL 3 shim using memory BIOs, our own C file of about 600 lines. CeeSafe.Web's `web_tls` is the reference, but it is **GPLv2** while this project is MIT. Do not depend on it unless you accept GPL. |
| Crypto: SHA-1/256, HMAC, RSA, Ed25519, ECDSA, X.509/CSR, random | The same OpenSSL shim. |
| bcrypt | Port it to CeeSafe (Blowfish EksBlowfish, about 300 lines) so existing hashes keep working. New hashes use argon2id from OpenSSL 3.2+. |
| DNS records beyond getaddrinfo: MX, TXT, PTR, TLSA | Our own async stub resolver over `AsyncUdpSocket`, falling back to TCP. |
| MIME | Our own streaming parser. This is the largest single component. |
| String utilities: find, split, trim, case folding, number parsing | A `bytes` utility module, the first thing we write. |
| JSON, base64, quoted-printable, TOML/config | Small modules of our own. |
| SQL | An sqlite3 binding through FFI. libpq is optional later. |
| HTTP server for admin, ACME and MTA-STS | Our own minimal HTTP/1.1 server. CeeSafe.Web's `web_server` is an option, with the same GPL caveat. |

**Constraints:**
- The language is days old (0.10 to 0.14 shipped on the same day).
- **Pin the compiler version** and keep a `docs/compiler-issues.md` log. CeeSafe.Web logged 15 upstream bugs.
- Code that calls C cannot run in the `--interp` interpreter, so FFI-heavy tests must run natively.
- There is no ordered map, so sorted UID sets need our own structure.
- Note: the CLI is `ceesafec new`, not `csafec`.

---

## 3. Target architecture

```
                ┌─────────────── mailserver (single exe) ───────────────┐
 25/587/465 ──► │ smtp_in ──► pipeline(auth, scan, sieve, deliver) ──┐  │
 143/993    ──► │ imap      ◄──── notify bus (in-proc) ◄─────────────┤  │
 80/443     ──► │ http (admin API, ACME http-01, MTA-STS, autoconfig)│  │
                │ queue/relay workers ──► smtp_out (MX, STARTTLS, DKIM)  │
                │ background: retention, blob GC, ACME renew, stats   │  │
                │ ─────────────────────────────────────────────────── │  │
                │ store: SQLite (WAL) metadata + content-addressed     │  │
                │        message files on disk (+ optional S3 later)   │  │
                └────────────────────────────────────────────────────────┘
```

**Runtime model.** There is one process. `Async.runWorkers(nCores)` runs one task per connection, launched from `Async.tasks(limit, …)` so each listener has an enforced connection cap. Timeouts on every read use `Async.deadline`. Shutdown happens through cancellation, with `Async.shield` protecting the commit/fsync steps.

### Performance design decisions

1. **Zero-copy protocol parsing.**
   - Each connection gets a fixed read buffer of 16–64 KB.
   - The SMTP and IMAP parsers produce `StringView`s into that buffer, and command state goes into a per-command `Arena` that is reset after each command. Nothing in the steady state calls the heap.
2. **Parse each message once, at ingest.**
   - While the SMTP DATA stream arrives, it is dot-unstuffed and fed in a single pass to:
     - the file writer, writing to a temp file that is later renamed to `blobs/ab/cdef…`, named by SHA-256;
     - the DKIM body hasher, so verification needs no second pass;
     - the streaming MIME scanner, which builds a **part index** of byte offsets, header ranges, encodings and charsets.
   - ENVELOPE, BODYSTRUCTURE, the header cache and the search tokens are computed once and stored. IMAP FETCH then never re-parses MIME. The C# version caches BODYSTRUCTURE but still parses through MimeKit.
3. **IMAP FETCH serves byte ranges.**
   - `BODY[n.m]`, `BINARY` and `RFC822` become offset/length reads from the blob, sent with `sendFile` on plaintext sessions and as read+write through TLS.
   - kTLS on Linux, which would allow `sendFile` under TLS too, is a later optimisation.
4. **One round trip per operation.**
   - *As built on Postgres:* each message operation is one statement. It changes the messages, allocates UIDs and MODSEQ, and keeps the mailbox's counters, all under the mailbox row's lock.
   - It runs over a pool of async connections shared by all workers.
   - This removes the C# `stats_pending` and drain machinery.
   - *Superseded SQLite design:* a single writer with group commit, and readers through `Async.blocking`.
5. **An in-process notify bus.** IDLE and push use per-mailbox `AsyncSignal`/`Channel` fan-out instead of DB polling.
6. **The DNS resolver** has a sharded in-memory cache and coalesces concurrent identical queries into a single request. SPF evaluation is bounded by the RFC limit of 10 lookups and 2 void lookups.
7. **Outbound relay.**
   - Workers are per destination domain, with connection reuse (several messages per session) and pipelining.
   - DKIM signatures are computed once per message, not once per recipient.
8. **Build:** `--cflag -O3`, with `-g` in profiling builds. Profile with Instruments on macOS and perf on Linux, using `--line-directives`.

**Opportunistic additions** (cheap once the redesign exists): CHUNKING/BDAT, CONDSTORE/QRESYNC, real Sieve (RFC 5228 subset with a proper parser), REQUIRETLS, and outbound MTA-STS/DANE enforcement.

---

## 4. Repository layout

Each component is a package connected by `path` dependencies, so packages have separate scopes and tests and can be compiled independently.

```
mailserver/
  ceesafe.toml            # exe package "mailserver" (from `ceesafec new`)
  AGENTS.md CLAUDE.md .mcp.json
  src/main.cee            # config load, listeners, runWorkers
  pkgs/
    mbytes/    # find/split/trim/ascii-casefold/int parse, base64, QP, hex, UTF-8 helpers, ByteBuf
    mconfig/   # TOML-subset parser + typed config, env overrides
    mlog/      # structured logging (JSON lines), levels, per-conn ids
    mjson/     # streaming JSON writer + small DOM reader (admin API, ACME)
    mcrypto/   # c/ossl_shim.c: SHA*, HMAC, RSA/Ed25519 sign/verify, ECDSA, CSR, X.509, random, argon2; bcrypt.cee
    mtls/      # c/tls_shim.c: memory-BIO TLS, SNI, ALPN, hot-reload ctx, STARTTLS upgrade of AsyncTcpStream
    mdns/      # async stub resolver: MX/TXT/PTR/TLSA/A/AAAA, cache, coalescing
    mmime/     # streaming MIME scanner, header/encoded-word/RFC2231 decoding, iconv FFI charsets, part index,
               # ENVELOPE/BODYSTRUCTURE builders, message builder (bounces, auto-replies)
    mauth/     # SPF, DKIM verify/sign (canonicalization over part index), DMARC, Received-SPF/Auth-Results
    mstore/    # sqlite FFI, schema/migrations, writer thread, repos, blob store (fs; S3 later)
    msmtp/     # server session state machine + client (outbound), PROXY protocol
    mimap/     # parser (literals, seq-sets, search keys), session, FETCH renderer, IDLE
    mqueue/    # queue scheduler, relay workers, backoff, circuit breakers, DSN generation
    mhttp/     # minimal HTTP/1.1 server: admin JSON API, ACME http-01, MTA-STS, autoconfig
    macme/     # ACME v2 client (JWS ES256, orders, ARI, EAB), renewal task
    mscan/     # clamd + spamd clients
  tools/
    migrate-pg/            # one-shot import from the existing Postgres/CosmoKv DB
  tests/conformance/       # black-box protocol tests (see §6)
  bench/                   # load generators + baseline numbers vs C#
```

---

## 5. Phases

Each phase ends with something that runs, plus its tests.

### Phase 0: Bootstrap
- In `~/dev/CeeSafeApps/mailserver`, run `ceesafec new mailserver --agent claude`. It creates AGENTS.md, CLAUDE.md and `.mcp.json` for the `ceesafec mcp` tools. Then move the generated files to this root if the command made a subdirectory.
- `git init`. Pin the compiler by recording `ceesafec 0.14.0` in the README and in a CI check. Add a Makefile or script for `check`, `fmt --check`, `test` and `build -O3`.
- **Spikes**, each of which is a go/no-go gate for the language:
  1. An OpenSSL shim plus a TLS echo server under `Async.runWorkers`, including a **STARTTLS upgrade** of a live `AsyncTcpStream`.
  2. The sqlite3 FFI, called from `Async.blocking`.
  3. An echo server with 10k concurrent idle connections: measure the RSS per connection.
  4. iconv through FFI.
- Record baseline numbers for the C# server, reusing `benchmarks/`: SMTP msgs/s, IMAP FETCH MB/s, and RSS with 10k IDLE connections.

### Phase 1: Foundations
- Packages: `mbytes`, `mconfig`, `mlog`, `mjson`, `mcrypto` (including the bcrypt port, verified against hashes from the C# DB) and `mdns`.
- Port DnsClient's behaviour rather than its structure: about 1k lines of CeeSafe against 3k lines of C#.

### Phase 2: The MIME engine
- **Status (2026-11-05):** done; see `pkgs/mmime/README.md`. Still to come: decoding part bodies (for SEARCH TEXT
  and BINARY) and the message builder.
- `mmime`: a streaming scanner and part index, header decoding (RFC 2047/2231, charsets through iconv), and
  ENVELOPE/BODYSTRUCTURE rendered once and stored as `messages.meta`.
- **Differential oracle (as built):**
  - The "4,205 `.eml` fixtures" in the C# repo turned out to be identical synthetic benchmark messages with no MIME
    structure, so the corpus is MimeKit's test data instead: 244 messages, jwz's torture collection among them.
  - The oracle is **Dovecot 2.4.5** in Docker for the IMAP views and every section's bytes, and Python's `email`
    package for decoded headers.
  - The result is 4,010 checks with no unexplained difference; the 21 known deviations are documented.
- Fuzzed with randomised and truncated messages and every chunk size, and swept with `ceesafec test --sweep alloc`.

### Phase 3: Storage
- **Status (2026-11-05):** started, on **Postgres** rather than SQLite (decision 1 below).
  - `pkgs/mstore` holds the schema, migrations, the blob store, accounts, address resolution, mailboxes, and
    delivery, flags, expunge and copy/move, with live tests; see its README.
  - It is built on `~/dev/CeeSafeApps/PostgresClient` (pool included) and `~/dev/CeeSafeLibs/diskio`.
- `mstore`: a new, lean schema.
  - Tables: domains, users, aliases, domain_aliases, mailboxes, messages (including the part-index blob), queue, failed_logins, sieve_scripts, dkim_keys, audit_log, suppression, and blob refcounts.
  - Blobs are reference-counted and content-addressed. This replaces `blob_cleanup_queue`, `blob_copy_pins` and the two-strike audit with refcount plus a GC sweep.
- `tools/migrate-pg` imports users (keeping their bcrypt hashes), mailboxes with UIDVALIDITY/UID preserved so clients don't resync, messages and blobs.

### Phase 4: Inbound SMTP and delivery
- **Status (2026-11-05):** first slice done; see `pkgs/msmtp/README.md` and `tests/conformance/`.
  - **Done:** the SMTP server on all three ports with STARTTLS, AUTH, recipient checks, quota, delivery and queueing;
    `CeeSafeLibs/bcrypt`; and the `mailserver` binary with `serve`, `add-domain`, `add-user` and `set-password`.
  - **Second slice done:** `pkgs/mdns`, the resolver; `pkgs/mauth`, with SPF passing RFC 7208's suite of 203 tests,
    DKIM matching dkimpy on 78 cases, and DMARC on the full Public Suffix List; `CeeSafeLibs/pkey`; and inbound
    authentication in msmtp (Authentication-Results, DMARC reject and quarantine).
  - **Third slice done:** `pkgs/mscan`, with ClamAV and SpamAssassin scanning in msmtp, checked against the real
    scanners in Docker.
  - **Fourth slice done:** `pkgs/msieve`, a Sieve interpreter (fileinto, envelope, copy, imap4flags, vacation)
    that agrees with Pigeonhole on 100 differential cases; vacation replies following RFC 3834; mstore's
    sieve_scripts and vacation_sent tables; delivery through scripts in msmtp; and the `set-sieve`, `set-vacation`
    and `clear-sieve` commands.
  - **Fifth slice done:** the persisted brute-force guard: mstore's `auth_failures`, one upsert per failure,
    per-address and per-login-name thresholds as the C# guard had, IPv6 counted by /64, and `block-ip` and
    `unblock-ip`. Phase 4 is complete.
  - **Next:** Phase 5, the queue's relay workers, which also send the vacation replies and redirects now queued.
- `msmtp` server, `mauth` (SPF, DKIM verify, DMARC), `mscan`, brute-force guard (kept in memory and persisted), local delivery, aliases and catch-all, the Sieve subset, auto-reply, quarantine.
- **Conformance:** point the C# `SmtpSocketTests` and the relevant `MailServerIntegrationTests` at the new binary by setting the host and port through environment variables. MailKit serves as an independent client.

### Phase 5: Queue and outbound relay
- `mqueue` and the `msmtp` client: MX resolution, per-domain connection pools, opportunistic STARTTLS (strict mode is configurable), DKIM signing, backoff and circuit breakers, DSN bounces, suppression list, reputation breaker.
- **Status (2026-11-05):** first slice done; see `pkgs/mqueue/README.md`.
  - **Done:**
    - the msmtp SMTP client: per-recipient outcomes, pipelining, opportunistic STARTTLS with plaintext fallback,
      SIZE, 8BITMIME and SMTPUTF8;
    - MX routing with the implicit MX and null MX;
    - relay workers claiming rows with tokens, and settling atomically, local recipients included;
    - the C# retry schedule with a 5-day limit;
    - RFC 3464 bounces;
    - `[relay]` settings.
  - **Tested** against a fake MX and against a real Postfix (`tests/interop`). The vacation replies and redirects that
    Phase 4 queued now go out.
  - **DKIM signing done:**
    - `CeeSafeLibs/pkey` signs and makes keys, byte-identical to openssl;
    - mauth's `DkimSigner` matches dkimpy on 170 signed messages;
    - the relay signs with the From domain's active key;
    - the `dkim-*` commands manage keys.
  - **Done since:**
    - delay notices;
    - the suppression list (5.1.x only, refused at RCPT);
    - per-domain breakers on whole-host failures (replacing the C# breaker, which tripped on any 5xx);
    - SRS for forwarded mail, with bounces routed back.
  - **Connection reuse done:** idle sessions pooled per MX host. Over STARTTLS, 1,000 messages relay at about 330/s
    with the pool, against about 250/s without it.
  - **Strict TLS done** (`[relay] tls_policy`, default `published`):
    - DANE (RFC 7672), through OpenSSL's DANE in `CeeSafeLibs/tls`, with mdns asking for the AD bit;
    - MTA-STS (RFC 8461), with HTTPS policy fetches and policies cached in Postgres (migration 8);
    - a host that cannot meet its domain's policy is never used in the clear.

    See `pkgs/mqueue/README.md`. Tested end to end (`StrictTls`, 7 cases) with fakedns's simulated DNSSEC and a fake
    policy server.
  - **Fixed on the way:** the queue's claim query could claim several rows under concurrency and leave all but one
    stuck for 30 minutes (a rescanned `SKIP LOCKED` subquery); it is now a materialized CTE.
  - **Not done:** TLSRPT reports (RFC 8460), so MTA-STS `testing` mode delivers as if there were no policy.
  - **Phase 5 is complete.** Next: Phase 6, IMAP.

### Phase 6: IMAP
- `mimap` with the full current capability set, IDLE through the notify bus, and SEARCH over stored header tokens.
- **Conformance:** MailKit-driven tests ported from the C# suite. Also run imaptest (Dovecot's stress and compliance tool) against both servers.
- **Status (2026-11-06):** all four slices done; see `pkgs/mimap/README.md`. CONDSTORE (the stretch goal) is not
  started.
  - **Approach.** The C# server's IMAP turned out buggy, and its tests mostly re-test copied algorithms, so mimap
    follows RFC 3501 for the same capability set instead.
  - **Slice 1, every command:**
    - LOGIN and AUTHENTICATE PLAIN use SMTP's login check;
    - LIST has real `\HasChildren`; APPEND gives APPENDUID; FETCH takes any number of sections;
    - COPY and MOVE give COPYUID, including MOVE within the same mailbox; UID EXPUNGE;
    - 143 with STARTTLS, and 993.
  - **Slice 2, the notify bus in mstore.** Every change wakes the IDLE sessions on its mailbox:
    - about 1 ms after an SMTP delivery, 0.2 ms after a STORE;
    - 2,000 idlers all saw one delivery within 363 ms, against Dovecot's 3.4 s.

    The tls package's read now survives a timeout, for this.
  - **Slice 3, SEARCH:** the full RFC 3501 grammar, evaluated in stages (rows, then headers, then decoded bodies, with
    mmime's new body decoding). Against Dovecot 2.4.5, 31,496 checks gave 0 unexplained differences.
  - **Slice 4, conformance and speed:**
    - **imaptest:** 11 failures out of 460, all documented deviations (`\Recent`, address search); the stress run gave
      0 errors. Five bugs it found were fixed.
    - **FETCH against Dovecot:** 16,833 items with 0 unexplained differences.
    - **Login:** a cap of 4 concurrent bcrypt checks ended the starvation that made commands take 70–100 ms. They now
      take about 2–5 ms under load, about 1 ms alone.
    - **Streaming:** FETCH and APPEND stream, so RSS is 9–10 MB for 50 MB messages (241 MB before).
  - **Benchmarks against Dovecot:**
    - FETCH, plaintext: 345–3,600 MB/s here, about 220 MB/s for Dovecot;
    - FETCH, TLS: 110–124 MB/s here, about 170 MB/s for Dovecot;
    - 2,000 idle connections: 47 MB RSS here, 789 MB for Dovecot.
  - **Open:**
    - Logins top out at about 16/s with cost-12 bcrypt and 4 at once (an owner decision: a setting, an auth cache, or the
      cost).
    - TLS throughput is limited by the tls package's 16 KiB writes.
    - SEARCH BODY holds one message's text in memory.
    - Address search (FROM/TO) matches the header text, not Dovecot's address list.
    - CONDSTORE.

### Phase 7: Operations surface
- `mtls` hot reload, `macme` (ACME HTTP-01 plus the renewal task), and `mhttp` serving MTA-STS, autoconfig/autodiscover, and the **admin JSON API**. Its routes keep the same `/api/*` shapes so the **existing Nuxt frontend works unchanged**; serve the prebuilt static files.
- Admin CLI subcommands: setup-domain, create-user, dns records/TLSA, purge.

**Status (2026-11-06):** all four slices done. See `pkgs/mweb/README.md`.
- **7a, HTTP:** `pkgs/mhttp` (HTTP/1.1 requests and responses, JSON writer and tape reader, an HTTP(S) client, the
  ACME challenge store) and `pkgs/mweb` (listeners `[http] http`, `https`, `admin`).
  - Endpoints: MTA-STS policies on `mta-sts.<domain>` over HTTPS (migration 9's `domains.mta_sts_*` columns),
    Thunderbird autoconfig, Outlook autodiscover (POX and v2 JSON; no ActiveSync/EWS advertised), ACME HTTP-01
    challenges, `/api/health`.
  - Conformance: `run.sh --web`, 20 tests (persistent connections, HEAD, chunked bodies, 100-continue, limits,
    smuggling-shaped framing refused).
- **7b, certificates:** the TLS configuration is replaceable (`SharedTlsConfig`).
  - The certificate files are polled (`[tls] reload_interval`) and a change is installed for new connections on
    every TLS listener; a broken change is refused and the old certificate stays.
  - `pkgs/macme`: an ACME client (RFC 8555: RS256 JWS, badNonce retry, HTTP-01, finalize, polling with Retry-After),
    with DER, CSR and self-signed certificate building in CeeSafe (checked with OpenSSL).
  - Renewal (`[acme]`): twice a day by default; renews 30 days before expiry, or when a name is missing. Names are
    the configured ones plus `mta-sts.<domain>` for each domain publishing a policy. With no certificate at first
    start, a self-signed placeholder lets TLS start until the first order completes.
  - Conformance: `run.sh --acme` against `pkgs/macme/tools/fakeacme.py`, a strict fake CA (it checks signatures,
    nonces and URLs, does real HTTP-01 fetches and issues real certificates); 4 tests. Pebble was not used: installing
    it needs a download of outside code.
  - Renewals keep the certificate's key, so a DANE `3 1 1` record stays right.
- **7c, admin API** (`pkgs/mweb/src/admin*.cee`): the C# CosmoMailAdmin routes the Nuxt frontend calls, with the same
  shapes and mixed casing.
  - Auth: HS256 JWTs with the C# claims (`[admin] jwt_secret`), the static token, server and domain admins
    (`admin_users`, migration 10), and mail users (users.role `admin` is a domain admin).
  - Areas: domains (including the setup wizard and DKIM regeneration), aliases, users, mailboxes, Sieve scripts,
    profile, stats, queue (with the retry the UI calls but C# never had) and audit logs.
  - Domain settings the server does not act on (SPF/DMARC/spam/greylist/rate-limit/auth-policy fields) are kept in
    `domains.settings` and round-trip; C# silently dropped them.
  - No secrets in responses: the C# server sent password hashes, TOTP secrets and DKIM private keys.
  - Differences from C#: domain admins see only their domain everywhere, and other domains' rows are 404.
    Duplicates are 409, not 500. A wrong current password is 400, not a 401 that logged the user out. New DKIM keys
    stay off until signing is turned on (after DNS).
  - Not supported: greylist, IP blacklist, retention rules, webhooks, PGP keys, OAuth clients (list empty, writes
    501), `/api/tools/*` DNS diagnostics, sync-dns/sync-proxy (Cloudflare/CosmoProxy) and TOTP (all 501).
  - Conformance: `run.sh --admin`, 16 tests.
- **7d, CLI:** `add-admin USERNAME PASSWORD [DOMAIN]`, and `dns-records DOMAIN` (MX, SPF, DMARC, DKIM, MTA-STS,
  autoconfig and TLSA). These join the existing add-domain, add-user, set-password, dkim-*, sieve, block-ip and
  unsuppress commands. Purge is not needed: blobs are collected automatically.
- **Open:**
  - Not tried with the real Nuxt UI in a browser. The tests call the API as its Nitro server does.
  - The `forward_to`, auto-reply, mailbox retention and quota settings are stored and shown but not enforced.
  - The DNS tools.

### Phase 8: Cutover
- Run the new server shadowed on alternate ports against a migrated copy of the data, and replay production traffic.
- Then DNS/MX cutover, Docker image (two-stage: ceesafec build, then a distroless image with libssl and libsqlite3), compose and fresh-vps scripts.

**Status (2026-11-06): the tooling is done; the shadow run and the cutover itself are the operator's (deploy/CUTOVER.md).**
- **PROXY protocol** v1/v2 (`pkgs/msmtp/src/proxy.cee`, `[proxy] from`): production runs behind CosmoProxy, which
  sends v2 on every mail port. Required from the configured networks, never read from others; read before TLS;
  kept across STARTTLS. `run.sh --proxy`: 6 tests.
- **`import-cosmomail`** (`src/import.cee`, `src/import_sql.cee`, `[import]`): domains (settings kept), domain aliases,
  users (bcrypt hashes), admin logins, aliases, DKIM keys (PKCS #1 PEM to PKCS #8), Sieve, mailboxes with UIDVALIDITY,
  and messages with their uids (`Delivery.uid`), flags and keywords, from the database, S3 (SigV4) or CosmoKvD
  locators. Re-runs copy only what changed, and bring flags and expunges up to date. `run.sh --import`: 7 tests,
  against the C# schema (`tests/conformance/cosmomail_schema.sql`) and a strict SigV4 fake S3.
- **Image and deploy:** `Dockerfile` (ceesafec from its release, checksum-checked; distroless nonroot),
  `deploy/build-image.sh`, the admin UI's image, `deploy/docker-compose.yml` (+ `.cosmoproxy.yml`),
  `deploy/mailserver.toml.example`, `deploy/compare-imap.py` (old vs new, read-only), `deploy/CUTOVER.md`.
- **Instead of replaying production traffic:** shadow ports plus `compare-imap.py` over real accounts; replaying SMTP
  would deliver duplicates to real recipients.
- **Linux build:** needs two CeeSafeLibs fixes, tested on a copy, not yet applied (CEESAFE_FINDINGS.md §2.5). The image
  built with them is 46.5 MB and passed an SMTP-to-IMAPS smoke test.
- **Open:** not yet tried against a real CosmoMailServer database (only its schema). ActiveSync, EWS and DAV are
  covered by Phase 9.

### Phase 9: Groupware before cutover (CalDAV/CardDAV, ActiveSync, EWS)
*Decided (2026-11-06): port all three before the cutover (open decision 2).* The C# sources are
`WebDavController.cs` (600 lines), `ActiveSyncController.cs` plus `ActiveSync/` (3.4k) and `EwsController.cs` plus
`Ews/` (1.7k); their integration tests (`ActiveSyncProtocolTests`, `ActiveSyncTests`, `EwsAndSecurityTests`,
`LiveActiveSyncTests`, about 5k lines) describe the expected behaviour.

- **9a. Shared groundwork:**
  - `pkgs/mxml`: an XML reader into a tree with namespaces, plus a writer. WBXML decodes into the same tree.
  - Schema version 11: calendars, events, address books, contacts (with a change log for sync tokens), ActiveSync
    devices and folder state.
  - `pkgs/mpim`: HTTP Basic login on the shared login guard. A short-lived cache of verified credentials means a
    phone's Ping or Sync does not cost a bcrypt check each time. Also the calendar and contact store, and iCalendar
    and vCard helpers.
  - mweb routes `/dav`, `/.well-known/caldav|carddav`, `/Microsoft-Server-ActiveSync` and `/EWS/Exchange.asmx` on
    HTTPS, on the admin listener, and on a new `[http] proxied` listener (plain HTTP for a TLS-terminating proxy such
    as CosmoProxy, without the admin API).
  - `import-cosmomail` copies calendars, events, address books and contacts. Devices are not copied: they resync.
- **9b. `pkgs/mdav`:** CalDAV and CardDAV as the C# server serves them (same URLs), plus incremental
  sync-collection and If-Match/If-None-Match.
- **9c. `pkgs/meas`:** ActiveSync 14.1/16.1 over WBXML, covering every command the C# server handles.
- **9d. `pkgs/mews`:** EWS SOAP, covering every operation the C# server handles.
- Autodiscover advertises ActiveSync and EWS. Each track gets a conformance mode in `run.sh`.

**Status (2026-11-06): all three are ported and tested; none has been tried with a real client yet.**
- **9a:**
  - `pkgs/mxml`: 5 tests.
  - `pkgs/mpim`: 4 tests. It has Basic login through msmtp's `checkRepeatedLogin`, a 15-minute cache of verified
    credentials that is dropped when the stored hash changes.
  - Schema version 11.
  - A watch on mailbox 0 hears every change of the user's.
  - `[http] proxied`.
  - `import-cosmomail` copies calendars and contacts, keeping their URLs and etags.
- **9b, `pkgs/mdav`:** CalDAV/CardDAV with the C# URLs, plus incremental sync-collection, If-Match and
  If-None-Match, uid conflicts, calendar-query time ranges, MKCALENDAR, extended MKCOL and PROPPATCH. Tests: 5 unit,
  `run.sh --dav` 11, and the import's calendar test (`--import` now has 8).
  - Open: scheduling (RFC 6638), LOCK, COPY and MOVE, free-busy, and addressbook-query filters.
- **9c, `pkgs/meas`:** ActiveSync 12.1 to 16.1, covering every command the C# server handled. It uses MS-ASWBXML's
  code pages, because the C# table had wrong tags. Sync replays a lost response, and Ping uses the notify bus.
  Calendar and contacts are converted to and from iCalendar and vCard (time zones, recurrences, attendees).
  SendMail, SmartReply and SmartForward go through the store in one transaction. Autodiscover answers mobilesync.
  Tests: 9 unit, `run.sh --eas` 21.
  - Open: Tasks and Notes, drafts from the device, recurrence exceptions beyond deletions, and policy enforcement.
- **9d, `pkgs/mews`:** EWS with every operation the C# server handled, keeping the C# id format. SyncFolderItems
  reports deletions without server state, GetStreamingEvents streams chunked, and CreateItem sends. Autodiscover
  names EWS (`[http] advertise_exchange`, on by default). Tests: 5 unit, `run.sh --ews` 18.
  - Open: calendar and contact folders are empty, as in C#; FindItem ignores restrictions and sort; ResolveNames
    answers empty.

### Phase 10: Deferred feature tracks
These are optional and should be prioritised by actual usage:
- OAuth2/OIDC server and XOAUTH2 validation (JWT through mcrypto).
- Webhooks (HMAC), the transactional/Postmark API and Liquid-lite templates.
- S3 blob backend (SigV4), Postgres backend, OpenTelemetry.

---

## 6. Testing strategy

1. **Unit tests:** `@test` in each package, run natively, with `--sweep alloc` and `--sweep cancel` on the parsers and sessions.
2. **Differential tests:** MIME against MimeKit (§Phase 2), plus SPF/DKIM/DMARC verdicts against the C# implementation for a corpus of headers and DNS fixtures.
3. **Black-box protocol tests:** reuse the C# integration tests (693 tests, about 18k lines) as an external client suite wherever they talk over sockets. Port the tests that use the in-memory fakes into CeeSafe tests.
4. **Compliance and load:** imaptest, `smtp-source`/`smtp-sink` (Postfix tools), and the `bench/` generators. Compare against the Phase 0 baselines in CI. Regressions over 10% fail the build.

---

## 7. Key risks

| Risk | Mitigation |
|---|---|
| Compiler immaturity and breaking releases | Pin the version, log issues, keep reduced repros, and upgrade deliberately. |
| MIME edge cases (broken messages, charsets) | The differential corpus, fuzzing, and lenient parsing that never rejects. |
| TLS/STARTTLS through memory BIOs and async | The Phase 0 spike is a hard gate. |
| SQLite write contention at scale | The single-writer group commit; keep the store behind an interface so Postgres can be added later. |
| Feature regression for EAS/EWS/DAV users | Decide before cutover: either port those first, or keep the C# Api running until they are ported. Keeping it requires the Postgres backend. |
| GPL contamination via CeeSafe.Web | Own the TLS and HTTP code, about 1.5k lines total. |

---

## 8. Open decisions for the user

1. **Metadata store.** *Decided: Postgres.* The native Postgres client was built as the gate.
   - SQLite: fastest and simplest for a single node.
   - Postgres: keeps multi-node operation possible and lets the C# Api/Admin coexist during the transition.
2. **ActiveSync/EWS/CalDAV:** *Decided: needed at cutover; ported in Phase 9.*
3. **Blobs:** local filesystem only at first (recommended), or S3 from day one?
4. **CeeSafe.Web (GPLv2):** acceptable as a dependency, or build our own TLS and HTTP (recommended)?
