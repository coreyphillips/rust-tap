-- PostgreSQL port of migrations/005_mailbox.up.sql.

-- Address book: one row per generated TAP address.
CREATE TABLE IF NOT EXISTS addresses (
    id BIGSERIAL PRIMARY KEY,
    version BIGINT NOT NULL,
    asset_id BYTEA CHECK(asset_id IS NULL OR octet_length(asset_id) = 32),
    group_key BYTEA CHECK(group_key IS NULL OR octet_length(group_key) = 33),
    script_key BYTEA NOT NULL CHECK(octet_length(script_key) = 33),
    internal_key BYTEA NOT NULL CHECK(octet_length(internal_key) = 33),
    amount BIGINT NOT NULL,
    proof_courier_addr TEXT,
    -- The full bech32m-encoded address string.
    encoded TEXT NOT NULL,
    UNIQUE(script_key)
);

CREATE INDEX IF NOT EXISTS addresses_asset_id_idx
    ON addresses (asset_id);

-- Mailbox polling cursors: one row per receiver key, tracking the
-- last mailbox message ID (and its proof block height) that has been
-- processed, so polling can resume where it left off.
CREATE TABLE IF NOT EXISTS mailbox_cursors (
    receiver_key BYTEA PRIMARY KEY CHECK(octet_length(receiver_key) = 33),
    last_message_id BIGINT NOT NULL DEFAULT 0,
    last_block BIGINT NOT NULL DEFAULT 0
);

INSERT INTO schema_version (version) VALUES (5);
