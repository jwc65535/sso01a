-- postgres/init/01-schema.sql
-- Core schema for the SSO application database.

\connect sso

-- Extension for UUID primary keys
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ── Certificate enrollment registry ──────────────────────────────────────
-- Tracks which x509 certificates are currently enrolled per user.
-- Source of truth for the Golang app; LDAP is a read-cache only.
CREATE TABLE IF NOT EXISTS enrolled_certs (
    id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    username        TEXT        NOT NULL,                -- matches PostgreSQL role name
    serial          TEXT        NOT NULL UNIQUE,         -- Vault PKI serial
    thumbprint      TEXT        NOT NULL UNIQUE,         -- x5t#S256 (SHA-256, base64url)
    public_cert_pem TEXT        NOT NULL,
    device_fp       TEXT,                               -- FingerprintJS visitor ID
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ,
    CONSTRAINT expires_after_issued CHECK (expires_at > issued_at)
);

CREATE INDEX idx_enrolled_certs_username   ON enrolled_certs (username);
CREATE INDEX idx_enrolled_certs_thumbprint ON enrolled_certs (thumbprint);
CREATE INDEX idx_enrolled_certs_expires_at ON enrolled_certs (expires_at)
    WHERE revoked_at IS NULL;

-- ── Audit log ─────────────────────────────────────────────────────────────
-- Append-only; never updated or deleted.
CREATE TABLE IF NOT EXISTS auth_events (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    event_time  TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_type  TEXT        NOT NULL,    -- 'login', 'logout', 'cert_issued', 'cert_revoked', 'denied'
    username    TEXT,
    serial      TEXT,
    thumbprint  TEXT,
    device_fp   TEXT,
    remote_addr TEXT,
    details     JSONB
);

CREATE INDEX idx_auth_events_username   ON auth_events (username);
CREATE INDEX idx_auth_events_event_time ON auth_events (event_time DESC);

-- Prevent any modification of audit records
CREATE RULE no_update_auth_events AS ON UPDATE TO auth_events DO INSTEAD NOTHING;
CREATE RULE no_delete_auth_events AS ON DELETE TO auth_events DO INSTEAD NOTHING;

-- ── Session store ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS sessions (
    session_id  TEXT        PRIMARY KEY,
    username    TEXT        NOT NULL,
    thumbprint  TEXT        NOT NULL REFERENCES enrolled_certs(thumbprint),
    device_fp   TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked     BOOLEAN     NOT NULL DEFAULT false
);

CREATE INDEX idx_sessions_username   ON sessions (username);
CREATE INDEX idx_sessions_expires_at ON sessions (expires_at) WHERE NOT revoked;
