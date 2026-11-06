-- CosmoMailServer's Postgres schema (CosmoMail.Data/Schema/postgres.sql), copied as the source of the importer's tests
-- (import_test.py). Refresh it when that schema changes.
-- CosmoMailServer schema for PostgreSQL
-- Idempotent: safe to run on every startup

-- ── Schema migrations ledger ────────────────────────────────────────────
-- Records one-time data backfills so they run exactly once instead of
-- re-scanning large tables on every boot. Cheap idempotent DDL is NOT gated
-- (it is self-guarding and fast); only the expensive one-shot backfills
-- below consult this ledger. NB: the schema splitter cuts on ";\n", which
-- shreds multi-line DO $$ … $$ blocks (see the ux_users_email block), so the
-- backfills are gated with a single-statement `WHERE NOT EXISTS (… ledger …)`
-- predicate instead of a procedural DO block. The uncorrelated NOT EXISTS is
-- hoisted to a one-time filter, so once the marker exists the table scan is
-- skipped entirely; if it isn't skipped the divergence predicate still makes
-- the write a no-op, so correctness never depends on the optimisation.
CREATE TABLE IF NOT EXISTS schema_migrations (
    id         BIGSERIAL PRIMARY KEY,
    name       VARCHAR(256) NOT NULL,
    applied_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ── Domains ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS domains (
    id                              BIGSERIAL PRIMARY KEY,
    name                            VARCHAR(256) NOT NULL,
    status                          VARCHAR(64)  NOT NULL DEFAULT 'active',
    max_users                       INT          NOT NULL DEFAULT 100,
    max_mailbox_size                BIGINT       NOT NULL DEFAULT 1073741824,
    default_quota                   BIGINT       NOT NULL DEFAULT 536870912,
    catchall_email                  VARCHAR(256) NULL,
    backup_mx                       BOOLEAN      NOT NULL DEFAULT FALSE,
    -- DKIM
    dkim_selector                   VARCHAR(128) NULL,
    dkim_private_key                TEXT         NULL,
    dkim_public_key                 TEXT         NULL,
    dkim_signing_enabled            BOOLEAN      NOT NULL DEFAULT FALSE,
    dkim_verify_enabled             BOOLEAN      NOT NULL DEFAULT FALSE,
    dkim_key_size                   INT          NOT NULL DEFAULT 2048,
    dkim_key_type                   VARCHAR(32)  NOT NULL DEFAULT 'rsa',
    dkim_headers_to_sign            VARCHAR(512) NOT NULL DEFAULT 'From,To,Subject,Date,Message-ID',
    -- SPF
    spf_record                      VARCHAR(512) NULL,
    spf_enabled                     BOOLEAN      NOT NULL DEFAULT FALSE,
    spf_dns_server                  VARCHAR(64)  NOT NULL DEFAULT '8.8.8.8',
    spf_dns_timeout                 INT          NOT NULL DEFAULT 5,
    spf_max_lookups                 INT          NOT NULL DEFAULT 10,
    spf_fail_action                 VARCHAR(32)  NOT NULL DEFAULT 'reject',
    spf_softfail_action             VARCHAR(32)  NOT NULL DEFAULT 'quarantine',
    -- DMARC
    dmarc_policy                    VARCHAR(32)  NULL,
    dmarc_enabled                   BOOLEAN      NOT NULL DEFAULT FALSE,
    dmarc_dns_server                VARCHAR(64)  NOT NULL DEFAULT '8.8.8.8',
    dmarc_dns_timeout               INT          NOT NULL DEFAULT 5,
    dmarc_report_enabled            BOOLEAN      NOT NULL DEFAULT FALSE,
    dmarc_report_email              VARCHAR(256) NULL,
    -- Security
    clam_av_enabled                 BOOLEAN      NOT NULL DEFAULT FALSE,
    clam_av_max_scan_size           BIGINT       NOT NULL DEFAULT 26214400,
    clam_av_virus_action            VARCHAR(32)  NOT NULL DEFAULT 'reject',
    clam_av_fail_action             VARCHAR(32)  NOT NULL DEFAULT 'allow',
    spam_enabled                    BOOLEAN      NOT NULL DEFAULT FALSE,
    spam_reject_score               DOUBLE PRECISION NOT NULL DEFAULT 10.0,
    spam_quarantine_score           DOUBLE PRECISION NOT NULL DEFAULT 5.0,
    spam_learning_enabled           BOOLEAN      NOT NULL DEFAULT FALSE,
    -- Greylisting
    greylist_enabled                BOOLEAN      NOT NULL DEFAULT FALSE,
    greylist_delay_minutes          INT          NOT NULL DEFAULT 15,
    greylist_expiry_days            INT          NOT NULL DEFAULT 30,
    greylist_cleanup_interval       INT          NOT NULL DEFAULT 24,
    greylist_whitelist_after        INT          NOT NULL DEFAULT 5,
    -- Rate limiting
    rate_limit_enabled              BOOLEAN      NOT NULL DEFAULT FALSE,
    rate_limit_smtp_per_ip          VARCHAR(32)  NOT NULL DEFAULT '100/1h',
    rate_limit_smtp_per_user        VARCHAR(32)  NOT NULL DEFAULT '500/1h',
    rate_limit_smtp_per_domain      VARCHAR(32)  NOT NULL DEFAULT '1000/1h',
    rate_limit_auth_per_ip          VARCHAR(32)  NOT NULL DEFAULT '20/15m',
    rate_limit_imap_per_user        VARCHAR(32)  NOT NULL DEFAULT '1000/1h',
    rate_limit_cleanup_interval     INT          NOT NULL DEFAULT 1,
    -- Auth policy
    auth_totp_enforced              BOOLEAN      NOT NULL DEFAULT FALSE,
    auth_brute_force_enabled        BOOLEAN      NOT NULL DEFAULT FALSE,
    auth_brute_force_threshold      INT          NOT NULL DEFAULT 5,
    auth_brute_force_window_minutes INT          NOT NULL DEFAULT 30,
    auth_brute_force_block_minutes  INT          NOT NULL DEFAULT 60,
    auth_ip_blacklist_enabled       BOOLEAN      NOT NULL DEFAULT FALSE,
    auth_cleanup_interval           INT          NOT NULL DEFAULT 24,
    -- Cloudflare
    cloudflare_zone_id              VARCHAR(128) NULL,
    -- When TRUE, the apex domain ({name}) is hosted elsewhere (e.g. user's
    -- website on a different IP) and only the mail-related subdomains
    -- (mail.{name}, autoconfig.{name}, autodiscover.{name}, mta-sts.{name})
    -- route through this server. Wizard skips the apex in proxy routes and
    -- ACME cert entries; MX still points to mail.{name} so inbound mail works.
    mail_only                       BOOLEAN      NOT NULL DEFAULT TRUE,
    -- MTA-STS (RFC 8461): "none" disables; "testing" / "enforce" advertise
    -- the policy via _mta-sts.{name} TXT + mta-sts.{name}/.well-known/mta-sts.txt.
    mta_sts_mode                    VARCHAR(16)  NOT NULL DEFAULT 'none',
    mta_sts_max_age                 INT          NOT NULL DEFAULT 86400,
    -- Whitespace/comma-separated list of mx patterns for the MTA-STS policy.
    -- Empty/NULL defaults to "mail.{name}" at policy-serve time.
    mta_sts_mx_patterns             VARCHAR(1024) NULL,
    created_at                      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at                      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ── Users ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id                 BIGSERIAL PRIMARY KEY,
    email              VARCHAR(256) NOT NULL,
    password_hash      VARCHAR(512) NOT NULL,
    domain_id          BIGINT       NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    role               VARCHAR(64)  NOT NULL DEFAULT 'user',
    status             VARCHAR(64)  NOT NULL DEFAULT 'active',
    quota              BIGINT       NOT NULL DEFAULT 536870912,
    used_quota         BIGINT       NOT NULL DEFAULT 0,
    language           VARCHAR(16)  NOT NULL DEFAULT 'en',
    totp_enabled       BOOLEAN      NOT NULL DEFAULT FALSE,
    totp_secret        VARCHAR(256) NULL,
    forward_to         VARCHAR(256) NULL,
    auto_reply_enabled BOOLEAN      NOT NULL DEFAULT FALSE,
    auto_reply_subject VARCHAR(512) NULL,
    auto_reply_body    TEXT         NULL,
    auth_method        VARCHAR(64)  NOT NULL DEFAULT 'password',
    last_login         TIMESTAMPTZ  NULL,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ── Admin Users ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS admin_users (
    id            BIGSERIAL PRIMARY KEY,
    username      VARCHAR(256) NOT NULL,
    password_hash VARCHAR(512) NOT NULL,
    display_name  VARCHAR(256) NULL,
    role          VARCHAR(64)  NOT NULL DEFAULT 'domain',
    domain_id     BIGINT       NULL REFERENCES domains(id),
    status        VARCHAR(64)  NOT NULL DEFAULT 'active',
    last_login    TIMESTAMPTZ  NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ── Aliases ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aliases (
    id          BIGSERIAL PRIMARY KEY,
    domain_id   BIGINT       NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    email       VARCHAR(256) NOT NULL,
    destination VARCHAR(256) NOT NULL,
    active      BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ── Domain Aliases ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS domain_aliases (
    id               BIGSERIAL PRIMARY KEY,
    alias_domain     VARCHAR(256) NOT NULL,
    target_domain_id BIGINT       NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    active           BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS ix_domain_aliases_alias_domain
    ON domain_aliases(alias_domain);

-- ── Mailboxes ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS mailboxes (
    id             BIGSERIAL PRIMARY KEY,
    user_id        BIGINT       NOT NULL,
    parent_id      BIGINT       NULL,
    name           VARCHAR(256) NOT NULL,
    subscribed     BOOLEAN      NOT NULL DEFAULT TRUE,
    special_use    VARCHAR(64)  NULL,
    uid_validity   BIGINT       NOT NULL,
    uid_next       BIGINT       NOT NULL,
    max_size       BIGINT       NOT NULL DEFAULT 0,
    current_size   BIGINT       NOT NULL DEFAULT 0,
    message_count  INT          NOT NULL DEFAULT 0,
    retention_days INT          NOT NULL DEFAULT 0,
    description    VARCHAR(512) NULL,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Idempotent ADD COLUMN for existing installs that predate the
-- denormalised-counters change. See mssql.sql for the rationale.
ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS unseen_count INT NOT NULL DEFAULT 0;
ALTER TABLE mailboxes ADD COLUMN IF NOT EXISTS recent_count INT NOT NULL DEFAULT 0;

-- ── Messages ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS messages (
    id             BIGSERIAL PRIMARY KEY,
    user_id        BIGINT        NOT NULL,
    mailbox_id     BIGINT        NOT NULL,
    uid            BIGINT        NOT NULL,
    thread_id      VARCHAR(256)  NULL,
    message_id     VARCHAR(512)  NULL,
    in_reply_to    VARCHAR(512)  NULL,
    refs           TEXT          NULL,
    "from"         VARCHAR(512)  NULL,
    "to"           TEXT          NULL,
    cc             TEXT          NULL,
    bcc            TEXT          NULL,
    reply_to       VARCHAR(512)  NULL,
    subject        VARCHAR(1024) NULL,
    date           TIMESTAMPTZ   NULL,
    received_at    TIMESTAMPTZ   NOT NULL,
    internal_date  TIMESTAMPTZ   NOT NULL,
    size           BIGINT        NOT NULL DEFAULT 0,
    flags          TEXT          NOT NULL DEFAULT '[]',
    is_seen        BOOLEAN       NOT NULL DEFAULT FALSE,
    is_recent      BOOLEAN       NOT NULL DEFAULT FALSE,
    is_deleted     BOOLEAN       NOT NULL DEFAULT FALSE,
    categories     TEXT          NOT NULL DEFAULT '[]',
    body_structure TEXT          NULL,
    headers        TEXT          NULL,
    content        BYTEA         NULL,
    content_path   VARCHAR(512)  NULL,
    storage_type   VARCHAR(32)   NOT NULL DEFAULT 'database',
    task_completed BOOLEAN       NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- ── Messages flag-state migration ───────────────────────────────────────
ALTER TABLE messages
    ADD COLUMN IF NOT EXISTS is_seen BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS is_recent BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS is_deleted BOOLEAN NOT NULL DEFAULT FALSE;

-- Backfill the flag bits from the stored JSON `flags` text (mirrors the MsSql
-- backfill). This repairs rows written while the Postgres translation used a
-- broken `LIKE '%\SEEN%'` pattern (Postgres treats '\' as the LIKE escape and
-- LIKE is case-sensitive, so it never matched the mixed-case ["\\Seen"] value).
-- Idempotent + guarded: only rows whose cached bit diverges are rewritten.
-- One-time flag-bit backfill, gated on the schema_migrations ledger. The
-- leading `NOT EXISTS (… ledger …)` is uncorrelated, so the planner runs it
-- once as a one-time filter and skips the messages scan after the first boot.
-- Computation unchanged.
UPDATE messages
SET is_seen    = (POSITION('SEEN' IN UPPER(COALESCE(flags, ''))) > 0),
    is_recent  = (POSITION('RECENT' IN UPPER(COALESCE(flags, ''))) > 0),
    is_deleted = (POSITION('DELETED' IN UPPER(COALESCE(flags, ''))) > 0)
WHERE NOT EXISTS (SELECT 1 FROM schema_migrations WHERE name = 'backfill_flag_bits_v1')
  AND (is_seen    <> (POSITION('SEEN' IN UPPER(COALESCE(flags, ''))) > 0)
   OR  is_recent  <> (POSITION('RECENT' IN UPPER(COALESCE(flags, ''))) > 0)
   OR  is_deleted <> (POSITION('DELETED' IN UPPER(COALESCE(flags, ''))) > 0));
INSERT INTO schema_migrations (name)
    SELECT 'backfill_flag_bits_v1'
    WHERE NOT EXISTS (SELECT 1 FROM schema_migrations WHERE name = 'backfill_flag_bits_v1');

-- Re-derive the denormalised mailbox counters from the now-correct flag bits.
-- Gated the same way: the NOT EXISTS lives inside the messages aggregate's
-- WHERE so the expensive per-mailbox GROUP BY scan is the thing skipped once
-- the marker is present. Guarded so only diverging mailbox rows are rewritten.
UPDATE mailboxes m
SET unseen_count = COALESCE(s.unseen, 0),
    recent_count = COALESCE(s.recent, 0)
FROM (
    SELECT mailbox_id,
           SUM(CASE WHEN is_seen   = FALSE THEN 1 ELSE 0 END) AS unseen,
           SUM(CASE WHEN is_recent = TRUE  THEN 1 ELSE 0 END) AS recent
    FROM messages
    WHERE NOT EXISTS (SELECT 1 FROM schema_migrations WHERE name = 'backfill_mailbox_counters_v1')
    GROUP BY mailbox_id
) s
WHERE s.mailbox_id = m.id
  AND (m.unseen_count <> COALESCE(s.unseen, 0) OR m.recent_count <> COALESCE(s.recent, 0));
INSERT INTO schema_migrations (name)
    SELECT 'backfill_mailbox_counters_v1'
    WHERE NOT EXISTS (SELECT 1 FROM schema_migrations WHERE name = 'backfill_mailbox_counters_v1');

-- ── Domains: mail_only migration (apex hosted elsewhere) ────────────────
ALTER TABLE domains
    ADD COLUMN IF NOT EXISTS mail_only BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE domains ALTER COLUMN mail_only SET DEFAULT TRUE;

-- ── Domains: MTA-STS migration (RFC 8461) ───────────────────────────────
ALTER TABLE domains
    ADD COLUMN IF NOT EXISTS mta_sts_mode VARCHAR(16) NOT NULL DEFAULT 'none',
    ADD COLUMN IF NOT EXISTS mta_sts_max_age INT NOT NULL DEFAULT 86400,
    ADD COLUMN IF NOT EXISTS mta_sts_mx_patterns VARCHAR(1024) NULL;

-- ── SMTP Queue ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS smtp_queue (
    id           BIGSERIAL PRIMARY KEY,
    message_id   VARCHAR(256)  NULL,
    sender       VARCHAR(256)  NOT NULL,
    recipients   TEXT          NOT NULL DEFAULT '[]',
    message_path VARCHAR(512)  NOT NULL,
    status       VARCHAR(32)   NOT NULL DEFAULT 'pending',
    retry_count  INT           NOT NULL DEFAULT 0,
    max_retries  INT           NOT NULL DEFAULT 5,
    next_retry   TIMESTAMPTZ   NULL,
    error_message TEXT         NULL,
    auto_save_user_id BIGINT   NULL,
    created_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);
-- v1.4.29 upgrade path for databases created before auto_save_user_id.
ALTER TABLE smtp_queue ADD COLUMN IF NOT EXISTS auto_save_user_id BIGINT NULL;

-- ── Stats Pending (deferred mailbox/user counter deltas) ────────────────
-- Append-only log replacing the in-line hot-row UPDATEs that previously
-- ran on every SMTP delivery (sp_Mailboxes_AdjustSize + sp_Users_AdjustQuota).
-- Per delivery: one INSERT here. A background worker batches deltas every
-- few seconds and applies the equivalent UPDATEs once per affected mailbox
-- /user. Eliminates hot-row contention on mailboxes + users under load.
-- (Added late to this file: shipped in mssql.sql/cosmokv long before —
-- Postgres deployments bootstrapped from the stale file lacked it; found
-- on jabal-shada 2026-07-06.)
CREATE TABLE IF NOT EXISTS stats_pending (
    id           BIGSERIAL PRIMARY KEY,
    mailbox_id   BIGINT       NOT NULL,
    user_id      BIGINT       NOT NULL,
    size_delta   BIGINT       NOT NULL DEFAULT 0,
    count_delta  BIGINT       NOT NULL DEFAULT 0,
    unseen_delta BIGINT       NOT NULL DEFAULT 0,
    recent_delta BIGINT       NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Cross-process mail-notification signal (M15). See mssql.sql for the model.
CREATE TABLE IF NOT EXISTS notification_events (
    id           BIGSERIAL   PRIMARY KEY,
    user_id      BIGINT      NOT NULL,
    mailbox_id   BIGINT      NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS ix_notification_events_created_at ON notification_events(created_at);

-- ── Webhooks ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS webhooks (
    id          BIGSERIAL PRIMARY KEY,
    name        VARCHAR(256) NOT NULL,
    url         VARCHAR(512) NOT NULL,
    event_types VARCHAR(256) NOT NULL DEFAULT '*',
    secret      VARCHAR(256) NULL,
    active      BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ── Webhook Deliveries ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id                 BIGSERIAL PRIMARY KEY,
    webhook_id         BIGINT      NOT NULL,
    event_type         VARCHAR(128) NOT NULL,
    payload            TEXT         NOT NULL,
    status             VARCHAR(32)  NOT NULL DEFAULT 'pending',
    status_code        INT          NULL,
    response_body      TEXT         NULL,
    error_message      TEXT         NULL,
    attempt_count      INT          NOT NULL DEFAULT 0,
    max_attempts       INT          NOT NULL DEFAULT 5,
    first_attempted_at TIMESTAMPTZ  NULL,
    last_attempted_at  TIMESTAMPTZ  NULL,
    next_retry_at      TIMESTAMPTZ  NULL,
    completed_at       TIMESTAMPTZ  NULL,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ── Security tables ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS greylist (
    id            BIGSERIAL PRIMARY KEY,
    ip            VARCHAR(64)  NOT NULL,
    sender        VARCHAR(256) NOT NULL,
    recipient     VARCHAR(256) NOT NULL,
    first_seen_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    attempt_count INT          NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rate_limits (
    id           BIGSERIAL PRIMARY KEY,
    key          VARCHAR(256) NOT NULL,
    count        INT          NOT NULL DEFAULT 0,
    window_start TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id            BIGSERIAL PRIMARY KEY,
    "timestamp"   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    user_id       BIGINT       NULL,
    username      VARCHAR(256) NULL,
    action        VARCHAR(128) NOT NULL,
    resource_type VARCHAR(128) NOT NULL,
    resource_id   VARCHAR(128) NULL,
    details       TEXT         NULL,
    ip_address    VARCHAR(64)  NULL,
    user_agent    VARCHAR(512) NULL,
    severity      VARCHAR(32)  NOT NULL DEFAULT 'info',
    success       BOOLEAN      NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS ip_blacklist (
    id         BIGSERIAL PRIMARY KEY,
    ip         VARCHAR(64)  NOT NULL,
    reason     VARCHAR(512) NULL,
    expires_at TIMESTAMPTZ  NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS spam_quarantine (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT       NOT NULL,
    "from"     VARCHAR(256) NOT NULL,
    subject    VARCHAR(512) NOT NULL,
    reason     VARCHAR(512) NOT NULL,
    content    BYTEA        NOT NULL,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS failed_logins (
    id        BIGSERIAL PRIMARY KEY,
    ip        VARCHAR(64)  NOT NULL,
    email     VARCHAR(256) NULL,
    success   BOOLEAN      NOT NULL DEFAULT FALSE,
    "timestamp" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS mtasts_policies (
    id         BIGSERIAL PRIMARY KEY,
    domain     VARCHAR(256) NOT NULL,
    policy     TEXT         NOT NULL,
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tls_reports (
    id          BIGSERIAL PRIMARY KEY,
    domain      VARCHAR(256) NOT NULL,
    report      TEXT         NOT NULL,
    received_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS pgp_keys (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT       NOT NULL,
    public_key  TEXT         NOT NULL,
    private_key TEXT         NULL,
    fingerprint VARCHAR(128) NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sieve_scripts (
    id         BIGSERIAL PRIMARY KEY,
    user_id    BIGINT       NOT NULL,
    name       VARCHAR(256) NOT NULL,
    content    TEXT         NOT NULL,
    active     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- ── CalDAV / CardDAV ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS calendars (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT       NOT NULL,
    name        VARCHAR(256) NOT NULL,
    description VARCHAR(512) NULL,
    color       VARCHAR(32)  NULL,
    sync_token  BIGINT       NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS calendar_events (
    id          BIGSERIAL PRIMARY KEY,
    calendar_id BIGINT       NOT NULL,
    uid         VARCHAR(256) NOT NULL,
    ics_data    TEXT         NOT NULL,
    etag        VARCHAR(64)  NOT NULL DEFAULT '',
    deleted     BOOLEAN      NOT NULL DEFAULT FALSE,
    deleted_at  TIMESTAMPTZ  NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS address_books (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT       NOT NULL,
    name        VARCHAR(256) NOT NULL,
    description VARCHAR(512) NULL,
    sync_token  BIGINT       NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS contacts (
    id              BIGSERIAL PRIMARY KEY,
    address_book_id BIGINT       NOT NULL,
    uid             VARCHAR(256) NOT NULL,
    v_card_data     TEXT         NOT NULL,
    etag            VARCHAR(64)  NOT NULL DEFAULT '',
    deleted         BOOLEAN      NOT NULL DEFAULT FALSE,
    deleted_at      TIMESTAMPTZ  NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS email_templates (
    id          BIGSERIAL PRIMARY KEY,
    domain_id   BIGINT        NOT NULL,
    name        VARCHAR(256)  NOT NULL,
    subject     VARCHAR(1024) NULL,
    html_body   TEXT          NULL,
    text_body   TEXT          NULL,
    active      BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS message_events (
    id          BIGSERIAL PRIMARY KEY,
    message_id  VARCHAR(256) NOT NULL,
    event_type  VARCHAR(64)  NOT NULL,
    details     TEXT         NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS suppression_list (
    id         BIGSERIAL PRIMARY KEY,
    domain_id  BIGINT        NOT NULL,
    email      VARCHAR(256)  NOT NULL,
    reason     VARCHAR(512)  NOT NULL,
    created_at TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id          BIGSERIAL PRIMARY KEY,
    user_id     BIGINT        NOT NULL,
    token       VARCHAR(512)  NOT NULL,
    client_id   VARCHAR(256)  NOT NULL,
    expires_at  TIMESTAMPTZ   NOT NULL,
    revoked     BOOLEAN       NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS activesync_devices (
    id              BIGSERIAL PRIMARY KEY,
    user_id         BIGINT        NOT NULL,
    device_id       VARCHAR(128)  NOT NULL,
    device_type     VARCHAR(64)   NOT NULL,
    model           VARCHAR(128)  NULL,
    friendly_name   VARCHAR(128)  NULL,
    os              VARCHAR(64)   NULL,
    policy_key      BIGINT        NOT NULL DEFAULT 0,
    status          VARCHAR(32)   NOT NULL DEFAULT 'allowed',
    protocol_version VARCHAR(8)    NOT NULL DEFAULT '14.1',
    last_sync_at    TIMESTAMPTZ    NULL,
    created_at      TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ    NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS activesync_folder_state (
    id             BIGSERIAL PRIMARY KEY,
    device_id      BIGINT        NOT NULL,
    collection_id  VARCHAR(64)   NOT NULL,
    folder_type    INT           NOT NULL,
    source_id      BIGINT        NOT NULL,
    source_type    VARCHAR(32)   NOT NULL DEFAULT 'mailbox',
    sync_key       VARCHAR(64)   NOT NULL DEFAULT '0',
    sync_state     TEXT          NULL,
    updated_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- ── Indexes ─────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS ix_domains_name ON domains(name);
CREATE INDEX IF NOT EXISTS ix_users_email ON users(email);
-- Enforce email uniqueness (M9). Guarded: if duplicate emails already exist the
-- unique index can't be built, so warn instead of aborting schema init. Resolve
-- the duplicates and the index self-applies on the next boot.
DO $$
BEGIN
    IF EXISTS (SELECT email FROM users GROUP BY email HAVING COUNT(*) > 1) THEN
        RAISE WARNING 'ux_users_email not created: duplicate user emails exist — resolve them, then re-run schema init';
    ELSE
        CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email ON users(email);
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS ix_users_domain_id ON users(domain_id);
CREATE UNIQUE INDEX IF NOT EXISTS ix_admin_users_username ON admin_users(username);
CREATE INDEX IF NOT EXISTS ix_admin_users_domain_id ON admin_users(domain_id);
CREATE INDEX IF NOT EXISTS ix_aliases_email ON aliases(email);
CREATE INDEX IF NOT EXISTS ix_aliases_domain_id ON aliases(domain_id);
CREATE UNIQUE INDEX IF NOT EXISTS ix_domain_aliases_alias_domain ON domain_aliases(alias_domain);
-- Enforce one mailbox per (user_id, name). The IMAP-delivery lookup
-- (GetOrCreateAsync) is not atomic, so a transient "not found" could insert a
-- SHADOW duplicate that hides the real folder's messages (the shadow-INBOX
-- incident). Self-heal any existing duplicates — keep the row with the most
-- messages (ties → lowest id) and rename the rest; NO mail is deleted — then
-- build the unique index. GetOrCreateAsync now treats the resulting
-- unique-violation as benign and re-fetches the existing row.
DO $$
BEGIN
    UPDATE mailboxes m
    SET name = m.name || '-dup-' || m.id, subscribed = false
    WHERE EXISTS (
        SELECT 1 FROM mailboxes k
        WHERE k.user_id = m.user_id AND k.name = m.name AND k.id <> m.id
          AND (k.message_count > m.message_count
               OR (k.message_count = m.message_count AND k.id < m.id))
    );
    CREATE UNIQUE INDEX IF NOT EXISTS ux_mailboxes_user_id_name ON mailboxes(user_id, name);
END $$;
-- The unique index above supersedes the old non-unique one for (user_id, name) lookups.
DROP INDEX IF EXISTS ix_mailboxes_user_id_name;
CREATE UNIQUE INDEX IF NOT EXISTS ix_messages_mailbox_id_uid ON messages(mailbox_id, uid);
CREATE INDEX IF NOT EXISTS ix_messages_mailbox_is_seen ON messages(mailbox_id, is_seen);
CREATE INDEX IF NOT EXISTS ix_messages_mailbox_is_recent ON messages(mailbox_id, is_recent);
CREATE INDEX IF NOT EXISTS ix_messages_mailbox_is_deleted_uid ON messages(mailbox_id, is_deleted, uid) INCLUDE (size);
-- M8: index content_path so CleanupOrphanedBlobs' per-blob COUNT(*) doesn't full-scan.
CREATE INDEX IF NOT EXISTS ix_messages_content_path ON messages(content_path);
CREATE INDEX IF NOT EXISTS ix_smtp_queue_status_next_retry ON smtp_queue(status, next_retry);
CREATE INDEX IF NOT EXISTS ix_webhook_deliveries_status_next_retry_at ON webhook_deliveries(status, next_retry_at);
CREATE UNIQUE INDEX IF NOT EXISTS ix_calendars_user_id_name ON calendars(user_id, name);
CREATE UNIQUE INDEX IF NOT EXISTS ix_calendar_events_calendar_id_uid ON calendar_events(calendar_id, uid);
CREATE UNIQUE INDEX IF NOT EXISTS ix_address_books_user_id_name ON address_books(user_id, name);
CREATE UNIQUE INDEX IF NOT EXISTS ix_contacts_address_book_id_uid ON contacts(address_book_id, uid);
CREATE INDEX IF NOT EXISTS ix_email_templates_domain_id_name ON email_templates(domain_id, name);
CREATE INDEX IF NOT EXISTS ix_message_events_message_id ON message_events(message_id);
CREATE UNIQUE INDEX IF NOT EXISTS ix_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX IF NOT EXISTS ix_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS ix_activesync_devices_user_id_device_id ON activesync_devices(user_id, device_id);
CREATE UNIQUE INDEX IF NOT EXISTS ix_activesync_folder_state_device_id_collection_id ON activesync_folder_state(device_id, collection_id);
CREATE UNIQUE INDEX IF NOT EXISTS ix_suppression_list_domain_id_email ON suppression_list(domain_id, email);

-- Mailbox retention rules (admin-managed; enforced by MailboxRetentionWorker)
CREATE TABLE IF NOT EXISTS mailbox_retention_rules (
    id         BIGSERIAL PRIMARY KEY,
    email      VARCHAR(256) NOT NULL,
    mailbox    VARCHAR(256) NOT NULL DEFAULT '*',
    days       INT          NOT NULL,
    enabled    BOOLEAN      NOT NULL DEFAULT TRUE,
    source     VARCHAR(16)  NOT NULL DEFAULT 'admin',
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

ALTER TABLE mailbox_retention_rules ADD COLUMN IF NOT EXISTS source VARCHAR(16) NOT NULL DEFAULT 'admin';

-- Durable blob-deletion intents: expunge enqueues locators BEFORE deleting
-- their message rows; BlobCleanupService sweeps the queue, deleting blobs no
-- row references any more and retrying entries a crash or storage outage
-- left behind.
-- mailbox_id/uid non-null marks a ROW-WITHDRAWAL intent instead: the sweep
-- removes that message row (its blob is already gone) and unwinds its stats.
CREATE TABLE IF NOT EXISTS blob_cleanup_queue (
    id           BIGSERIAL     PRIMARY KEY,
    content_path VARCHAR(512)  NOT NULL,
    storage_type VARCHAR(64)   NOT NULL,
    mailbox_id   BIGINT        NULL,
    uid          BIGINT        NULL,
    attempts     INT           NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

-- Short-lived pins COPY holds around its reference re-check + destination-row
-- insert so the cleanup sweep never deletes a blob a concurrent copy is about
-- to re-reference. Rows outliving BlobCleanupService.PinExpiry are from
-- crashed copies and are reaped by the sweep.
-- kind 'copy' = a COPY protecting its source blob; kind 'sweep' = the
-- cleanup sweep claiming the path for deletion. Each side inserts its row
-- BEFORE reading the other kind, so one of them always observes the other
-- (store-then-load mutual exclusion) and blob deletion never races a copy.
CREATE TABLE IF NOT EXISTS blob_copy_pins (
    id           BIGSERIAL     PRIMARY KEY,
    content_path VARCHAR(512)  NOT NULL,
    kind         VARCHAR(8)    NOT NULL DEFAULT 'copy',
    created_at   TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_blob_copy_pins_content_path ON blob_copy_pins(content_path);
