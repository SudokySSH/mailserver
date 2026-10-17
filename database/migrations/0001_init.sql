-- AETHER MAIL — базовая схема PostgreSQL (миграция 0001)
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    INT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_events (
    id     BIGSERIAL PRIMARY KEY,
    ts     TIMESTAMPTZ NOT NULL DEFAULT now(),
    type   TEXT NOT NULL CHECK (char_length(type) <= 64),
    actor  TEXT NOT NULL DEFAULT '' CHECK (char_length(actor) <= 128),
    detail TEXT NOT NULL DEFAULT '' CHECK (char_length(detail) <= 1024),
    ip     TEXT NOT NULL DEFAULT '' CHECK (char_length(ip) <= 45),
    hmac   TEXT NOT NULL CHECK (char_length(hmac) = 64)
);
CREATE INDEX IF NOT EXISTS idx_audit_events_ts   ON audit_events (ts DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_type ON audit_events (type);

CREATE TABLE IF NOT EXISTS accounts (
    id            BIGSERIAL PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE CHECK (email ~ '^[a-z0-9._%+-]+@[a-z0-9.-]+$'),
    display_name  TEXT NOT NULL DEFAULT '',
    quota_bytes   BIGINT NOT NULL DEFAULT 104857600 CHECK (quota_bytes > 0),
    is_admin      BOOLEAN NOT NULL DEFAULT FALSE,
    is_blocked    BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
    id         BIGSERIAL PRIMARY KEY,
    account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    ip         TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_sessions_account ON sessions (account_id);

INSERT INTO schema_migrations (version) VALUES (1)
ON CONFLICT (version) DO NOTHING;
