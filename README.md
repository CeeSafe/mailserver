# mailserver

A complete mail server written in [CeeSafe](https://ceesafe.github.io/CeeSafe/), a memory-safe systems language
that compiles to C. It replaces CosmoMailServer (C#/.NET) with one native process. Postgres holds accounts,
mailboxes and indexes; message content lives in content-addressed files on disk.

It speaks SMTP (MX, submission), IMAP, ActiveSync, EWS and CalDAV/CardDAV, and it publishes autoconfig,
autodiscover and MTA-STS. It manages its own TLS certificates and has a JSON admin API, which the existing Nuxt
admin UI uses.

- [Features](#features)
- [How it is built](#how-it-is-built)
- [Building and running locally](#building-and-running-locally)
- [Configuration](#configuration)
- [Command line](#command-line)
- [Deployment guide](#deployment-guide)
- [Operations](#operations)
- [Testing](#testing)
- [Status and known gaps](#status-and-known-gaps)

---

## Features

### SMTP: receiving and submission (`pkgs/msmtp`)
- **Ports:** MX on 25, submission on 587 (STARTTLS, AUTH only after TLS), and submission over implicit TLS on 465.
- **Extensions:** PIPELINING, SIZE, 8BITMIME, ENHANCEDSTATUSCODES, SMTPUTF8, STARTTLS, and AUTH (PLAIN and LOGIN).
- **Recipients are checked at RCPT** against domain aliases, aliases and catch-alls. VRFY and EXPN never reveal who
  exists.
- **Inbound authentication on port 25** (`pkgs/mauth`): SPF (RFC 7208), DKIM (RFC 6376 and 8463, including
  Ed25519) and DMARC (RFC 7489), recorded in an `Authentication-Results` field. A DMARC `reject` is refused at DATA,
  and a `quarantine` is filed in Junk.
  - SPF is checked against the 203 cases of the RFC 7208 test suite.
  - DKIM is checked against 78 cases signed by dkimpy.
- **Content scanning** (`pkgs/mscan`): ClamAV (clamd INSTREAM) and SpamAssassin (spamd), streamed. Viruses are
  rejected; spam is filed in Junk above one score and rejected above another.
- **Sieve filtering** (`pkgs/msieve`): RFC 5228 with `fileinto`, `envelope`, `copy`, `imap4flags` and `vacation`
  (auto-reply, once per sender per period).
- **PROXY protocol** v1 and v2 from trusted networks (`[proxy] from`), so the server can sit behind a TCP proxy and
  still see clients' addresses.
- **Brute-force guard:** failed logins are counted per address, in memory and in Postgres, and repeat offenders are
  blocked. bcrypt checks run on a bounded pool of threads.

### Outbound relay (`pkgs/mqueue`)
- **Queue:** messages queue in Postgres, and workers claim them with `SKIP LOCKED`.
- **Retries and bounces:** retries follow a configurable schedule, with a delay notice and a DSN bounce after 5 days.
- **Routing:** MX hosts in RFC 5321 order, with the implicit MX and null MX (RFC 7505) handled. Connections are pooled
  and reused per host.
- **TLS:** opportunistic STARTTLS, or a `published` policy that honours DANE (TLSA) and MTA-STS (RFC 8461) with
  policy caching.
- **Signing and forwarding:** outgoing mail is DKIM-signed with the From domain's active key (RSA or Ed25519).
  Forwarded mail gets SRS, and addresses that do not exist are suppressed for a while.
- **Circuit breaker:** a domain that keeps failing is backed off.

### IMAP (`pkgs/mimap`)
- **Protocol:** IMAP4rev1 (RFC 3501), with IDLE, MOVE, UIDPLUS, UNSELECT, NAMESPACE, ID, SPECIAL-USE, ENABLE,
  LITERAL+ and CHILDREN.
- **Fast FETCH:** messages are indexed once, at delivery (`pkgs/mmime`), so FETCH copies stored bytes and never
  parses MIME again.
- **Checked against Dovecot:** FETCH and SEARCH are differentially tested against Dovecot 2.4, and the server is
  checked with imaptest.
- **IDLE** wakes on every change, through an in-process notify bus.

### Groupware
- **CalDAV and CardDAV** (`pkgs/mdav`), at the C# server's URLs (`/dav/principals|calendars|contacts/<email>/…`):
  - PROPFIND with the requested properties, and every REPORT clients use: multiget, calendar-query with time
    ranges, and incremental sync-collection.
  - Conditional PUT and DELETE, MKCALENDAR, extended MKCOL, PROPPATCH, and `/.well-known` redirects.
- **Exchange ActiveSync 12.1–16.1** (`pkgs/meas`), for phones and Outlook:
  - Provision, FolderSync and Sync for mail, calendar and contacts. A client that repeats a lost sync key gets the
    same changes again.
  - Ping push, SendMail, SmartReply, SmartForward, MoveItems, ItemOperations (attachments), Search, Settings,
    MeetingResponse, ResolveRecipients and Find.
  - iCalendar and vCard are converted to and from ActiveSync, including time zones, recurrences and attendees.
- **Exchange Web Services** (`pkgs/mews`), for macOS Mail and Outlook:
  - Folder and item sync (deletions included), FindItem, GetItem with MIME, UpdateItem, CreateItem (sends), and
    Delete, Move and Copy.
  - Push through streaming notifications.
- **Logins for all three:** HTTP Basic on the IMAP login path. Verified credentials are cached for 15 minutes, so a
  phone's Ping does not cost a bcrypt check every time.

### Web endpoints (`pkgs/mweb`, `pkgs/mhttp`)
- **Client setup:** Thunderbird autoconfig, and Outlook/Apple autodiscover (POX for Outlook and mobilesync, plus the
  v2 JSON).
- **MTA-STS:** policies at `mta-sts.<domain>`, generated from each domain's settings.
- **Certificates:** ACME (Let's Encrypt, HTTP-01, `pkgs/macme`) for the host name and every `mta-sts.` name, renewed
  on time and reloaded without a restart. You can instead give it certificate files that another proxy renews.
- **Admin API:** `/api/*`, with the same routes and JSON shapes as the C# server, for the CosmoMailAdmin Nuxt UI.
  It covers domains, users, aliases, mailboxes, Sieve, DKIM keys, the queue, statistics and the audit log.
- **Transactional email:** `/postmark/*` on HTTPS and the proxied listener, as the C# server's Postmark-compatible
  API, for applications. It takes `X-Postmark-Server-Token` (`[admin] postmark_token`). It covers:
  - `POST /postmark/email`: one message with To, Cc, Bcc, Reply-To, a tag, text and HTML bodies, and attachments up to
    25 MB;
  - templates per domain, written in Liquid (if, unless, case, for, assign, filters), with create, read, update,
    list, delete, send by id or name, and batch send to up to 500 recipients;
  - each message's events (`queued`, `sent`, `deferred`, `failed`, `delivered`) and status, kept 45 days;
  - each domain's suppression list, which these sends check.
- **Hardened HTTP/1.1 parser:** request-smuggling shapes are refused, and body sizes are limited per path.

### Storage (`pkgs/mstore`)
- **Postgres:** the schema is migrated on start, 12 versions so far. Mailbox counters and UIDs are allocated in the
  mailbox row, so a delivery takes one row lock.
- **Message files:** content is stored once per distinct message, by SHA-256, and reference-counted and collected
  automatically.
- **Changes:** every change carries a modseq. Calendar and contact changes keep tombstones, so sync tokens are exact.

### Migration from CosmoMailServer
- **`import-cosmomail`:** copies a running C# installation, and on re-runs copies only what changed. It carries:
  - domains, users (with their bcrypt hashes) and admin logins;
  - aliases, DKIM keys and Sieve scripts;
  - mailboxes with their UIDVALIDITY;
  - every message with its uid and flags, from the database, S3 (SigV4) or CosmoKvD;
  - calendars and contacts, with their URLs and etags;
  - transactional email templates and suppression lists.
- **`deploy/compare-imap.py`** compares an account on the old and new servers, read-only.
- **[`deploy/CUTOVER.md`](deploy/CUTOVER.md)** is the runbook for the switch.

---

## How it is built

| Package | What it is |
|---|---|
| `src/` | The executable: configuration, listeners, the command line, and `import-cosmomail`. |
| `pkgs/msmtp` | SMTP server sessions, the PROXY protocol, logins, the SMTP client, Sieve delivery. |
| `pkgs/mimap` | The IMAP server. |
| `pkgs/mqueue` | The outbound relay: queue workers, MX routing, MTA-STS/DANE, DSNs, SRS. |
| `pkgs/mstore` | Postgres store, schema migrations, content files, the notify bus. |
| `pkgs/mmime` | Streaming MIME scanner and IMAP renderings. |
| `pkgs/mauth` | SPF, DKIM (verify and sign), DMARC, the Public Suffix List. |
| `pkgs/mdns` | Async DNS stub resolver with caching. |
| `pkgs/mscan` | clamd and spamd clients. |
| `pkgs/msieve` | Sieve interpreter. |
| `pkgs/mhttp` | HTTP/1.1 server and client, JSON. |
| `pkgs/mweb` | HTTP listeners, well-known endpoints, certificates and ACME renewal, the admin API. |
| `pkgs/macme` | ACME client. |
| `pkgs/mxml` | XML reader and writer with namespaces; WBXML decodes into the same document. |
| `pkgs/mpim` | Groupware basics: HTTP Basic logins, the calendar and contact store, iCalendar and vCard. |
| `pkgs/mdav` | CalDAV and CardDAV. |
| `pkgs/meas` | Exchange ActiveSync. |
| `pkgs/mews` | Exchange Web Services. |

Most packages have a README with design notes and test details.

**Dependencies:**
- `../PostgresClient`, a native Postgres client written in CeeSafe;
- from `../../CeeSafeLibs`: `tls` (OpenSSL 3), `pkey`, `bcrypt`, `sha256`, `encoding` and `diskio`.

[PORTING_PLAN.md](PORTING_PLAN.md) records the port phase by phase.

---

## Building and running locally

The build uses two sibling repositories through relative paths, so clone all three side by side:

```sh
mkdir dev && cd dev
git clone https://github.com/CeeSafe/CeeSafeLibs.git                    # dev/CeeSafeLibs
mkdir CeeSafeApps && cd CeeSafeApps
git clone https://github.com/CeeSafe/PostgresClient.git                 # dev/CeeSafeApps/PostgresClient
git clone https://github.com/CeeSafe/mailserver.git                     # dev/CeeSafeApps/mailserver
cd mailserver
```

**You need:**
- `ceesafec`; the Dockerfile pins v0.21.0;
- a C compiler and OpenSSL 3 (on macOS, Homebrew's `openssl@3`);
- Postgres 14 or later;
- the sibling checkouts `../PostgresClient` and `../../CeeSafeLibs` (above).

```sh
ceesafec build -o out/mailserver --cflag -O2

createdb mail
cat > mailserver.toml <<'EOF'
hostname = "mail.example.org"
database = "postgres://mail:secret@127.0.0.1/mail"
blobs = "/tmp/mail-blobs"
[smtp]
mx = "127.0.0.1:2525"
submission = "127.0.0.1:2587"
submissions = ""
[imap]
imap = "127.0.0.1:2143"
imaps = ""
allow_plaintext_auth = true
[http]
http = "127.0.0.1:8080"
admin = "127.0.0.1:9184"
EOF

out/mailserver add-domain example.org
out/mailserver add-user alice@example.org 'a-long-password'
out/mailserver serve
```

The schema is created on first start. Without `[tls]`, STARTTLS is not offered. Use plaintext logins only on
loopback, for testing.

---

## Configuration

The configuration is a TOML subset: `[section]`, `key = "string"`, `key = 123`, `key = true`, and `#` comments.
**Every key, with its default, is documented at the top of [`src/config.cee`](src/config.cee).**
[`deploy/mailserver.toml.example`](deploy/mailserver.toml.example) is a production starting point.

| Section | What it sets |
|---|---|
| (top) | `hostname` (HELO, banners, certificates), `database`, `blobs` (content directory), `workers` (threads) |
| `[smtp]` | `mx`, `submission`, `submissions` listen addresses, `max_message_size`, `max_connections` |
| `[imap]` | `imap` (STARTTLS), `imaps`, `max_append_size`, `max_connections` |
| `[http]` | `http`, `https`, `admin` (the admin API; never expose it), and `proxied` (plain HTTP for a TLS-terminating proxy, without the admin API) |
| `[http]` (advertising) | `imap_port` and `submission_port` (advertised to clients), and `advertise_exchange` (autodiscover names EWS) |
| `[admin]` | `jwt_secret` (or `COSMOMAIL_JWT_SECRET`), `token` for scripts, `token_hours`, `postmark_token` for the transactional API (or `COSMOMAIL_POSTMARK_TOKEN`) |
| `[tls]` | `certificate`, `key` (PEM files, polled for changes), `reload_interval` |
| `[acme]` | `directory` (empty: no ACME), `email`, `account_key`, `names`, `mta_sts_names`, renewal timing |
| `[proxy]` | `from`: networks whose SMTP and IMAP connections start with a PROXY header |
| `[dns]` | `servers` (default `/etc/resolv.conf`), `inbound_auth` (SPF, DKIM and DMARC on port 25) |
| `[scan]` | `clamd`, `spamd` (IP:port), spam scores, what to do when clamd is down, size limits |
| `[relay]` | workers, TLS policy, retry schedule, `max_age`, delay notices, suppression, SRS, connection pool |
| `[import]` | the CosmoMailServer database and S3 store for `import-cosmomail` |

> **Addresses are IP addresses.** `database`, `[scan] clamd` and `[scan] spamd` take IP addresses, not host names.
> The server has no system resolver for them. In Docker, give those containers fixed addresses, as
> `deploy/docker-compose.yml` does.

---

## Command line

```
mailserver [--config FILE] serve                         the server (the default; FILE defaults to ./mailserver.toml)
mailserver [--config FILE] add-domain example.org
mailserver [--config FILE] add-user alice@example.org PASSWORD [QUOTA_BYTES]
mailserver [--config FILE] set-password alice@example.org PASSWORD
mailserver [--config FILE] add-admin USERNAME PASSWORD [DOMAIN]     admin UI login: the whole server, or one domain
mailserver [--config FILE] set-sieve alice@example.org SCRIPT_FILE [NAME]
mailserver [--config FILE] set-vacation alice@example.org DAYS SUBJECT MESSAGE
mailserver [--config FILE] clear-sieve alice@example.org
mailserver [--config FILE] block-ip ADDRESS [HOURS] | unblock-ip ADDRESS
mailserver [--config FILE] unsuppress ADDRESS
mailserver [--config FILE] dkim-generate DOMAIN SELECTOR [rsa|ed25519]   prints the DNS record; the key starts inactive
mailserver [--config FILE] dkim-import DOMAIN SELECTOR KEY.pem
mailserver [--config FILE] dkim-activate DOMAIN SELECTOR                 once the record is published
mailserver [--config FILE] dkim-show DOMAIN [SELECTOR]
mailserver [--config FILE] dns-records DOMAIN       the zone records to publish (MX, SPF, DMARC, DKIM, MTA-STS, TLSA…)
mailserver [--config FILE] import-cosmomail         copy a CosmoMailServer installation (see deploy/CUTOVER.md)
```

In Docker, run these as
`docker compose exec mailserver mailserver --config /etc/mailserver/mailserver.toml <command>`.

---

## Deployment guide

This guide installs the server with Docker Compose on a Debian or Ubuntu host. The examples use the domain
`example.com`, the mail host `mail.example.com`, and the public address `203.0.113.10`.

### 1. Choose a layout

| Layout | When | Files |
|---|---|---|
| **A. Standalone** | The host is the mail server's alone; it takes ports 25, 465, 587, 993, 143, 80 and 443 and gets its own certificates. | `docker-compose.yml` |
| **B. Behind an HTTPS proxy** | Another reverse proxy (CosmoProxy, Caddy, nginx) already owns 80 and 443. The mail ports are still published straight to the server; the proxy forwards HTTPS for the mail host names to the `proxied` listener, and its certificate is copied over. | `docker-compose.yml` + `docker-compose.https-proxy.yml` |
| **C. Replacing CosmoMailServer** | Moving an existing C# installation, behind CosmoProxy, with its data. | `docker-compose.yml` + `docker-compose.cosmoproxy.yml`, and [CUTOVER.md](deploy/CUTOVER.md) |

ceesafe.com runs layout B, on a host shared with other services behind CosmoProxy.

### 2. Check the host

```sh
# The mail ports must be free on the public address. 127.0.0.1:25 may be held by exim or postfix; then bind to
# the public address only (PUBLIC_IP, step 5).
ss -ltnp | grep -E ':(25|465|587|993|143|80|443)\b'

# Outbound port 25 must be open (many clouds and ISPs block it).
timeout 8 bash -c '</dev/tcp/gmail-smtp-in.l.google.com/25' && echo open || echo blocked

docker --version && docker compose version     # Docker 24+ with the compose plugin
```

**Reverse DNS:** set the PTR record of the public address to `mail.example.com` in your hosting provider's panel.
Without it, Gmail and Outlook are likely to put mail in spam or refuse it. It is not set in your DNS zone, but by
whoever owns the address.

### 3. Build the images

Build on any machine with Docker buildx. From an arm64 Mac for an x86 server, set `PLATFORM=linux/amd64`.

```sh
PLATFORM=linux/amd64 ADMIN_UI_SOURCE="" deploy/build-image.sh 1.0.0   # mailserver:1.0.0
PLATFORM=linux/amd64 deploy/build-admin-ui.sh 1.0.0                    # mailserver-admin-ui:1.0.0
```

- **Mail server image:** `Dockerfile` downloads `ceesafec` from its GitHub release, checks it against
  `SHA256SUMS`, and builds against OpenSSL. The runtime image is distroless and runs as non-root (uid 65532), at about
  40 MB.
- **Admin UI image:** `build-admin-ui.sh` builds the Nuxt frontend with vite+ (`vp install && vp run build`) in a
  temporary copy. Only the Nitro output goes into a `node:22-slim` image.

Copy the images to the server without a registry:

```sh
docker save mailserver:1.0.0 | gzip | ssh root@SERVER 'gunzip | docker load'
docker save mailserver-admin-ui:1.0.0 | gzip | ssh root@SERVER 'gunzip | docker load'
```

### 4. Lay out the server

```sh
mkdir -p /data/mailserver && cd /data/mailserver
# Copy from deploy/: docker-compose.yml (and the layout's override), mailserver.toml.example as mailserver.toml,
# .env.example as .env; for layout B also certsync.sh and the two mailserver-certsync.* units.
mkdir -p tls && chown 65532:65532 tls && chmod 700 tls
```

Write **`.env`**, with every secret random:

```sh
umask 077
cat > .env <<EOF
SERVER_HOSTNAME=mail.example.com
MAILSERVER_IMAGE=mailserver:1.0.0
ADMIN_UI_IMAGE=mailserver-admin-ui:1.0.0
POSTGRES_PASSWORD=$(openssl rand -hex 24)
COSMOMAIL_JWT_SECRET=$(openssl rand -hex 32)
COSMOMAIL_POSTMARK_TOKEN=$(openssl rand -hex 32)
NUXT_SESSION_PASSWORD=$(openssl rand -hex 32)
PUBLIC_IP=203.0.113.10
EOF
```

`PUBLIC_IP` is for layout B when a local MTA holds 127.0.0.1:25; leave it out otherwise.
`COSMOMAIL_POSTMARK_TOKEN` is the token applications send to the transactional API. Leave it empty to turn the API
off (it then answers 503). When moving from CosmoMailServer, use its `ApiAccess.PostmarkToken` here, so applications
keep working.

Edit **`mailserver.toml`**:
- `hostname = "mail.example.com"`;
- `database` with the Postgres password, at the fixed address `172.30.53.5`;
- `[relay] srs_secret` (`openssl rand -hex 32`);
- `[scan] clamd = "172.30.53.10:3310"` and `spamd = "172.30.53.11:783"`.

Then the layout's settings:
- **Layout A:** `[http] http = "0.0.0.0:8080"` and `https = "0.0.0.0:8443"`, and `[acme] directory =
  "https://acme-v02.api.letsencrypt.org/directory"` with `email`. A self-signed placeholder serves until the first
  certificate arrives.
- **Layout B:**
  - `[http] http = ""`, `https = ""`, `proxied = "0.0.0.0:9185"`;
  - `[tls] certificate = "/etc/mailserver/tls/fullchain.pem"`, `key = "/etc/mailserver/tls/key.pem"`;
  - `[acme] directory = ""`.

The file holds secrets and must be readable by the container only:

```sh
chown 65532:65532 mailserver.toml && chmod 600 mailserver.toml .env
```

### 5. DNS records

All records point straight at the server. With Cloudflare, every record must be **DNS only** (grey cloud): mail
cannot pass Cloudflare's proxy.

| Name | Type | Value |
|---|---|---|
| `mail.example.com` | A | `203.0.113.10` |
| `mta-sts.example.com` | CNAME | `mail.example.com` |
| `autodiscover.example.com` | CNAME | `mail.example.com` |
| `autoconfig.example.com` | CNAME | `mail.example.com` |
| `admin.example.com` (optional) | CNAME | `mail.example.com` |
| `example.com` | MX | `10 mail.example.com` |
| `example.com` | TXT | `v=spf1 mx -all` |
| `_dmarc.example.com` | TXT | `v=DMARC1; p=quarantine; rua=mailto:postmaster@example.com` |
| `<selector>._domainkey.example.com` | TXT | from `dkim-generate` (step 7) |
| `_mta-sts.example.com` | TXT | `v=STSv1; id=<from dns-records>` |
| `_smtp._tls.example.com` | TXT | `v=TLSRPTv1; rua=mailto:postmaster@example.com` |
| `_imaps._tcp.example.com` | SRV | `0 1 993 mail.example.com` |
| `_submissions._tcp.example.com` | SRV | `0 1 465 mail.example.com` |
| `_submission._tcp.example.com` | SRV | `0 1 587 mail.example.com` |
| `_autodiscover._tcp.example.com` | SRV | `0 1 443 mail.example.com` |

Publish the A and CNAME records first, since certificates need them. Publish the rest once the server prints its
DKIM and MTA-STS values.

`mailserver dns-records example.com` prints the zone lines for your domain. It also prints a DANE TLSA record. Leave
that out unless the zone has DNSSEC and the certificate key stays the same across renewals; a proxy's ACME often
makes a new key each time.

**Cloudflare by script:** `deploy/cf-dns.py` creates and updates records from a JSON list, always DNS-only. It is
idempotent, so running it twice changes nothing. Create an API token with *Zone → DNS → Edit* for the zone only, and
save it without echoing it:

```sh
mkdir -p ~/.config/cloudflare && (umask 077; pbpaste > ~/.config/cloudflare/example.token)
cat > records.json <<'EOF'
[{"type": "A", "name": "mail.example.com", "content": "203.0.113.10"},
 {"type": "CNAME", "name": "mta-sts.example.com", "content": "mail.example.com"},
 {"type": "MX", "name": "example.com", "content": "mail.example.com", "priority": 10},
 {"type": "TXT", "name": "example.com", "content": "\"v=spf1 mx -all\""},
 {"type": "SRV", "name": "_imaps._tcp.example.com",
  "data": {"priority": 0, "weight": 1, "port": 993, "target": "mail.example.com"}}]
EOF
CF_ZONE=example.com deploy/cf-dns.py records.json --dry-run
CF_ZONE=example.com deploy/cf-dns.py records.json
```

### 6. Certificates

**Layout A:** nothing to do. The server orders a certificate for `hostname` and every `mta-sts.<domain>`, answers
HTTP-01 on port 80, renews 30 days before expiry, and reloads without a restart.

**Layout B:** the proxy gets the certificate, and the mail server uses the same one for SMTP and IMAP.

1. Add host blocks to the proxy for `mail`, `mta-sts`, `autodiscover` and `autoconfig.example.com`, all forwarding to
   `127.0.0.1:9185` and passing the `Host` header. For CosmoProxy:

   ```
   mail.example.com {
   	tls_certificate_name mail.example.com
   	tls_key_type rsa2048
   	header_up Host=$host
   	reverse_proxy 127.0.0.1:9185
   }
   ```

   Repeat it for `mta-sts`, `autodiscover` and `autoconfig`, each with `tls_certificate_name mail.example.com`, so
   one certificate covers all four names.
2. Reload the proxy. CosmoProxy does not watch its file: run `docker restart cosmoproxy`. Back the file up first; a
   restart drops its in-flight requests for a moment.
3. Copy the certificate to the mail server, now and hourly:

   ```sh
   cp certsync.sh /data/mailserver/ && chmod 755 /data/mailserver/certsync.sh
   # In mailserver-certsync.service: CERT_SRC=<the proxy's directory for mail.example.com>
   #   (CosmoProxy: <its conf>/certs/mail.example.com), CERT_DST=/data/mailserver/tls
   install -m 644 mailserver-certsync.service mailserver-certsync.timer /etc/systemd/system/
   systemctl daemon-reload && systemctl enable --now mailserver-certsync.timer
   systemctl start mailserver-certsync.service && ls -l /data/mailserver/tls
   ```

### 7. Start, then create the domain, accounts and DKIM key

```sh
cd /data/mailserver
docker compose -f docker-compose.yml -f docker-compose.https-proxy.yml up -d   # layout B; layout A: no -f
docker compose logs -f mailserver          # "mailserver: listening"
```

ClamAV loads its signatures for a minute or two after its first start. Until then, mail it cannot scan gets a
temporary 451.

```sh
ms() { docker compose exec -T mailserver mailserver --config /etc/mailserver/mailserver.toml "$@"; }

ms add-domain example.com
ms add-user postmaster@example.com "$(openssl rand -base64 18)"   # receives DMARC and TLS reports
ms add-user you@example.com 'a long password'
ms add-admin admin "$(openssl rand -base64 18)"                    # the admin UI's login (whole server)

ms dkim-generate example.com s2026 rsa      # prints the TXT record: publish it (step 5) and wait until it resolves
dig +short TXT s2026._domainkey.example.com
ms dkim-activate example.com s2026          # outgoing mail is signed from now on

ms dns-records example.com                  # the remaining records: MX, SPF, DMARC, MTA-STS
```

Keep the generated passwords somewhere safe, such as a root-only file.

**MTA-STS:**
1. Start in testing mode, in the admin UI's domain settings (MTA-STS mode) or with SQL. Then publish the `_mta-sts` TXT record that
   `dns-records` prints.

   ```sh
   docker compose exec -T postgres psql -U mailserver -d mailserver -c \
     "UPDATE domains SET mta_sts_mode = 'testing', mta_sts_mx = 'mail.example.com' WHERE name = 'example.com'"
   ```
2. After a few weeks of clean TLS reports, switch to `enforce`. The policy id changes by itself, so senders fetch the
   policy again.

### 8. The admin UI (optional)

The admin UI is CosmoMailAdmin's Nuxt frontend. It calls the admin API on the compose network, and the API itself is
never published.

```sh
docker compose up -d admin-ui                # listens on 127.0.0.1:9183
```

Put it behind your HTTPS proxy as `admin.example.com`, forwarding to `127.0.0.1:9183`, or reach it through an SSH
tunnel (`ssh -L 9183:127.0.0.1:9183 root@SERVER`). Log in with the `add-admin` account.

> The UI's `nuxt.config.ts` reads `COSMOMAIL_ADMIN_API_BASE` only when the UI is built. At run time Nuxt takes
> `NUXT_API_BASE`, which the compose file sets. Without it, every login fails with 401.

### 9. Verify

From a machine whose outbound port 25 is not blocked (home ISPs often intercept it; test inbound SMTP from the
server itself or another host if so):

```sh
# TLS with a valid certificate on every mail port
openssl s_client -connect mail.example.com:993 -servername mail.example.com </dev/null | grep 'Verify return'
openssl s_client -connect mail.example.com:465 </dev/null | grep 'Verify return'
openssl s_client -starttls smtp -connect mail.example.com:587 </dev/null | grep 'Verify return'
openssl s_client -starttls smtp -connect mail.example.com:25 </dev/null | grep 'Verify return'

curl -s https://mta-sts.example.com/.well-known/mta-sts.txt                              # mode, mx
curl -s "https://autoconfig.example.com/mail/config-v1.1.xml?emailaddress=you@example.com" | head
curl -s -o /dev/null -w '%{http_code}\n' -X OPTIONS https://mail.example.com/Microsoft-Server-ActiveSync  # 200
curl -s -H "X-Postmark-Server-Token: $TOKEN" "https://mail.example.com/postmark/templates?domain=example.com"  # []
```

Then add the account to a mail client. Thunderbird, Outlook, iOS and macOS Mail find the settings from the address
alone. Send a message to an outside mailbox and check its headers for `dkim=pass`, `spf=pass` and `dmarc=pass`.

Manual settings, if a client asks:

| | Server | Port | Security | User name |
|---|---|---|---|---|
| IMAP | mail.example.com | 993 | SSL/TLS | the full address |
| SMTP | mail.example.com | 465 (or 587) | SSL/TLS (or STARTTLS) | the full address |
| ActiveSync / EWS | mail.example.com | 443 | HTTPS | the full address |
| CalDAV / CardDAV | `https://mail.example.com/dav/` | 443 | HTTPS | the full address |

With `[http] advertise_exchange = true` (the default), autodiscover names EWS, and macOS Mail sets accounts up as
Exchange, which gives mail, push and folders. Set it to `false` if you want IMAP-only setups.

---

## Operations

**Upgrading:**

```sh
# Build and load the new image (step 3). A new schema version cannot be undone, so back up first (below). Then:
sed -i 's/^MAILSERVER_IMAGE=.*/MAILSERVER_IMAGE=mailserver:1.0.4/' .env
docker compose up -d mailserver              # schema migrations run on start; connections reconnect
```

An install from before 1.0.4 has no transactional API token. Add `COSMOMAIL_POSTMARK_TOKEN=…` to `.env`, and
`COSMOMAIL_POSTMARK_TOKEN: ${COSMOMAIL_POSTMARK_TOKEN:-}` to the mailserver service's `environment` in
`docker-compose.yml`, as in `deploy/`.

**Transactional email:** applications send through `https://mail.example.com/postmark/…` with the token. The From
address must be in one of the server's domains; the message is DKIM-signed with that domain's key.

```sh
curl -s -H "X-Postmark-Server-Token: $TOKEN" -H 'Content-Type: application/json' \
    -d '{"From": "noreply@example.com", "To": "someone@example.net", "Subject": "Hi", "TextBody": "Hello"}' \
    https://mail.example.com/postmark/email                     # {"messageID": "…", "errorCode": 0, …}
curl -s -H "X-Postmark-Server-Token: $TOKEN" https://mail.example.com/postmark/messages/MESSAGE_ID/status
```

Templates, batch sends and suppression lists are under `/postmark/templates` and `/postmark/suppressions`. Their
routes and JSON are those of CosmoMailServer's Postmark-compatible API. Behind CosmoProxy, send a browser
User-Agent, because its bot filter refuses `curl`'s.

**Backups:** back up the database and the content files together. A message's row and its file are both needed.

```sh
docker compose exec -T postgres pg_dump -U mailserver -Fc mailserver > mail-$(date +%F).dump
tar czf blobs-$(date +%F).tgz -C /data/mailserver/data blobs
```

**Logs:** `docker compose logs mailserver`. It logs one line per accepted or refused message
(`smtp [client] accepted …`), relay outcomes, certificate reloads, and renewals.

**Certificates:**
- **Layout A:** renewal runs twice a day.
- **Layout B:** the timer copies a renewed certificate within the hour, and the server picks it up within
  `[tls] reload_interval`.
- **Either layout:** the certificate in use is shown by
  `openssl s_client -connect mail.example.com:993 </dev/null | openssl x509 -noout -dates`.

**Rotating DKIM:**
1. Generate a new selector and publish its record.
2. Run `dkim-activate` once the record resolves.
3. Remove the old record a few days later.

**Accounts and security:**
- **Failed logins:** a blocked address can be unblocked with `unblock-ip ADDRESS`.
- **Passwords:** users can change their own in the admin UI, and admins can set them there or with `set-password`.

### Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `mailserver: invalid argument` at start | A host name where an IP address is needed (`database`, `[scan] clamd`/`spamd`). Use the compose file's fixed addresses. |
| `failed to bind host port 0.0.0.0:25: address already in use` | A local MTA (exim, postfix) holds 127.0.0.1:25. Set `PUBLIC_IP` (layout B) to bind the mail ports to the public address only. |
| Port 25 connects but no greeting arrives from your laptop | Your ISP intercepts outbound port 25. Test from the server or another network. |
| HTTPS answers 403 to scripts | CosmoProxy's bot filter blocks User-Agents such as `python-urllib` and `curl`. Send a browser User-Agent. |
| Admin UI logins always fail (401) | `NUXT_API_BASE` is missing from the admin-ui service (step 8). |
| Mail lands in recipients' spam | No reverse DNS (PTR) for the public address, or DKIM is not active (`dkim-show`). |
| Mail rejected with `5.7.1 … DMARC policy` | Working as intended: the sender's domain asks for rejection and the message failed SPF and DKIM. |
| A phone keeps resyncing | Normal once after a migration or a server-side folder change; ActiveSync device state is per server. |

---

## Testing

```sh
# Unit tests, per package
for p in pkgs/*; do (cd $p && ceesafec test); done

# Black-box conformance suites against a built server and a Postgres in Docker
# (../PostgresClient/tests/setup-docker.sh starts one on port 55432)
tests/conformance/run.sh            # SMTP (55), IMAP (56), HTTP (20) and admin API (16)
tests/conformance/run.sh --dav      # CalDAV/CardDAV (11)
tests/conformance/run.sh --eas      # ActiveSync, with its own WBXML codec (21)
tests/conformance/run.sh --ews      # EWS, including Apple Mail's folder sequence (19)
tests/conformance/run.sh --import   # import-cosmomail from the C# schema and a strict fake S3 (9)
tests/conformance/run.sh --postmark # the transactional email API (13)
tests/conformance/run.sh --proxy    # PROXY protocol (6)
tests/conformance/run.sh --acme     # certificate issuance and renewal against a fake CA (4)
```

The conformance runs share fixed ports and one database, so `run.sh` takes a lock and later runs wait their turn.

Other checks:
- `pkgs/mauth/tests/spf/run.py` and `tests/dkim/run.py`: SPF and DKIM against their reference suites;
- `run.sh --search-differential` and `--fetch-differential`: IMAP against Dovecot;
- `run.sh --imaptest`: imaptest's stress mode;
- `run.sh --load`: load.

---

## Status and known gaps

The server runs in production for ceesafe.com. What is not done yet:

- **Calendar and contacts protocols:**
  - **CalDAV:** no scheduling (RFC 6638) or free-busy; addressbook-query ignores its filters.
  - **ActiveSync:** no Tasks or Notes folders, and no drafts from the device. Recurrence exceptions are sent only as
    deletions. Device policies are reported, not enforced.
  - **EWS:** calendar and contact folders are listed but empty. FindItem ignores restrictions and sort order;
    ResolveNames answers empty.
- **Account settings:** `forward_to`, quotas and retention are stored and shown, but not enforced. Auto-replies go
  through Sieve (`set-vacation`).
- **Not ported from CosmoMailServer:** the OAuth2/OIDC server, webhooks (so delivery events are not pushed; poll
  `/postmark/messages/{id}/status`) and TOTP.
- **Transactional email:** message events are not imported from CosmoMailServer, so a message sent before the
  cutover has no status here. Liquid is a subset of Fluid's: no `capture`, `cycle`, `include`, math or date filters.
  A template that uses them falls back to the C# server's `{{name}}`-only rendering.
- **Storage:** the S3 content backend; content is on local disk only.
- **Not yet tested:** against a real CosmoMailServer database; so far only against its schema.

[PORTING_PLAN.md](PORTING_PLAN.md) has the full history and the open decisions.

## License

The mail server is licensed under the GNU General Public License, version 2 only ([COPYING](COPYING)),
with an exception that permits linking with OpenSSL ([COPYING.OPENSSL](COPYING.OPENSSL)).
Data from other projects keeps its own license; see [THIRD_PARTY.md](THIRD_PARTY.md).
