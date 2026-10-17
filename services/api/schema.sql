-- AETHER MAIL — схема, которую применяет Go API при старте (go:embed).
-- Держать в синке с database/migrations/0001_init.sql.
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
