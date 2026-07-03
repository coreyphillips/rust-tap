-- Address book: one row per generated TAP address. There was no
-- addresses table in migrations 001-003; V2 (authmailbox) receives
-- need one to map incoming mailbox messages back to an address.
CREATE TABLE IF NOT EXISTS addresses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version INTEGER NOT NULL,
    asset_id BLOB CHECK(asset_id IS NULL OR length(asset_id) = 32),
    group_key BLOB CHECK(group_key IS NULL OR length(group_key) = 33),
    script_key BLOB NOT NULL CHECK(length(script_key) = 33),
    internal_key BLOB NOT NULL CHECK(length(internal_key) = 33),
    amount INTEGER NOT NULL,
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
    receiver_key BLOB PRIMARY KEY CHECK(length(receiver_key) = 33),
    last_message_id INTEGER NOT NULL DEFAULT 0,
    last_block INTEGER NOT NULL DEFAULT 0
);

INSERT INTO schema_version (version) VALUES (5);
