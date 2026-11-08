# Cutover from CosmoMailServer

Replacing a running CosmoMailServer (server, api and admin containers, Postgres, CosmoS3, behind CosmoProxy) with
this server, on the same host, without users noticing: same passwords, same mailboxes and UIDs (IMAP clients
do not download everything again), same DKIM keys, same admin logins.

## What carries over, and what does not

| Carries over (import-cosmomail) | Does not |
|---|---|
| Domains and their settings, domain aliases, catch-alls | ActiveSync device state: devices provision again and resync (status 9 / new sync keys), without being set up again |
| Users with their bcrypt hashes, quotas, forwarding and auto-reply settings (stored; not yet acted on) | EWS item and folder ids: clients resync once (their SyncState is refused) |
| Calendars, events, address books and contacts, at the same CalDAV/CardDAV URLs and with the same etags | |
| Admin logins (`server` and `domain` roles) | Webhooks, PGP keys, OAuth clients, greylist and IP blacklist entries |
| Aliases | The outbound queue: drain it first (step 3) |
| DKIM keys, signing as before | TOTP secrets (TOTP is not supported yet) |
| Sieve scripts (one active per user; others reported) | Audit log, statistics |
| Mailboxes with UIDVALIDITY, UIDNEXT, special use, subscriptions | |
| Messages with uids, flags, keywords, internal dates; content from the database, S3 or CosmoKvD | |

## 1. Build and stage (days before)

```sh
deploy/build-image.sh 1.0.0                     # mailserver:1.0.0 and mailserver-admin-ui:1.0.0
PLATFORM=linux/amd64 deploy/build-image.sh 1.0.0   # from an arm64 Mac for an x86 VPS
```

On the VPS, in `/opt/mailserver-new`: `docker-compose.yml`, `docker-compose.cosmoproxy.yml`, `.env` (from
`.env.example`), and `mailserver.toml` (from `mailserver.toml.example`) with:

- `[proxy] from = "172.16.0.0/12"`, `[tls]` at CosmoProxy's files, `[acme] directory = ""`;
- `[import]` pointing at the old database and CosmoS3 (the old compose network's names, or published ports);
- for the shadow run only, the mail ports moved off the ones CosmoProxy uses (edit the cosmoproxy override's
  loopback ports to, say, 26025/26587/26465/26993/26143), so both servers run side by side.

## 2. Shadow run

```sh
docker compose -f docker-compose.yml -f docker-compose.cosmoproxy.yml up -d postgres
docker compose run --rm mailserver import-cosmomail      # the long copy: every message
docker compose -f docker-compose.yml -f docker-compose.cosmoproxy.yml up -d
```

The import prints each table's counts and each mailbox it copied, and at the end the messages it could not copy:

- **missing at the source**: CosmoMail's row points at content its store does not have. The old server cannot
  serve these either; they are skipped.
- **could not be copied**: a transient failure (S3, the network). Run the import again: it retries them.

Then check, on the shadow ports:

- `deploy/compare-imap.py 127.0.0.1:25993 127.0.0.1:26993 user@domain --content --insecure` (with
  `IMAP_PASSWORD` set) for a few real accounts, yours first: no differences expected but sizes of messages
  stored with bare LFs (which `--content` checks properly).
- Log in to the admin UI (127.0.0.1:9183) with an existing admin login.
- Send through the shadow submission port and read the message over the shadow IMAP port.
- `docker compose exec mailserver mailserver --config /etc/mailserver/mailserver.toml dns-records DOMAIN` matches
  what is published (DKIM selector and key, MTA-STS id).

Run the import again whenever you like: each run copies only what changed. The new database is a mirror until the
cutover: do not deliver real mail to it.

## 3. Cutover (minutes)

1. Stop the old mail paths, keeping their data up:
   `docker compose -p <old> stop mailserver-server mailserver-api mailserver-admin` (Postgres and CosmoS3 stay).
2. Check the old queue is empty, or note what is in it:
   `SELECT count(*), min(created_at) FROM smtp_queue WHERE status NOT IN ('sent', 'delivered', 'failed');`
   Messages left there were accepted but never sent; resend them from the old server before stopping it, or tell
   their senders.
3. The final copy: `docker compose run --rm mailserver import-cosmomail` (only what changed since the last run).
4. Move the new server onto the ports CosmoProxy proxies to: restore `docker-compose.cosmoproxy.yml`'s
   25025/25587/25465/25993/25143 and `docker compose ... up -d`. The CosmoProxyfile does not change for the mail
   ports. Point what the C# api took (autodiscover/autoconfig, `mta-sts.<domain>`, `/Microsoft-Server-ActiveSync`,
   `/EWS/*`, `/dav/*`, `/.well-known/caldav`, `/.well-known/carddav`, and the transactional API's `/postmark/*`) at
   127.0.0.1:9185 (`[http] proxied`). Applications keep their `X-Postmark-Server-Token`: copy the C# server's
   `ApiAccess.PostmarkToken` (or `COSMOMAIL_POSTMARK_TOKEN`) to `[admin] postmark_token`. Autodiscover names EWS
   (`[http] advertise_exchange`, on by default). Point the admin UI's
   host at 127.0.0.1:9183.
5. Watch `docker compose logs -f mailserver`: `smtp [<client>] accepted` lines with real client addresses (not
   172.x: if they are, the PROXY header is not being sent or `[proxy] from` is wrong).

DNS does not change: the same host, the same names, the same DKIM keys.

## 4. Rollback

Until mail has arrived at the new server, rolling back is: stop it, start the old containers again. After that,
mail the new server accepted is only in the new store. The old server cannot import it; copy it back over IMAP
(imapsync from new to old, per account) before switching back. So decide within the first hours, and keep the old
stack (stopped, with its data) for a week.

## Without CosmoProxy

Use `docker-compose.yml` alone: the server binds 25, 587, 465, 993, 143, 80 and 443 itself, does its own ACME
(`[acme]`), and sees clients' addresses directly. Leave `[proxy]` out.
