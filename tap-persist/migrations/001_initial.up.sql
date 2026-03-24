-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);
INSERT INTO schema_version (version) VALUES (1);

-- Owned assets: tracks asset UTXOs
CREATE TABLE IF NOT EXISTS owned_assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id BLOB NOT NULL CHECK(length(asset_id) = 32),
    amount INTEGER NOT NULL,
    anchor_txid BLOB NOT NULL CHECK(length(anchor_txid) = 32),
    anchor_vout INTEGER NOT NULL,
    script_key BLOB NOT NULL CHECK(length(script_key) = 33),
    spent INTEGER NOT NULL DEFAULT 0,
    block_height INTEGER NOT NULL,
    UNIQUE(anchor_txid, anchor_vout)
);
CREATE INDEX IF NOT EXISTS idx_assets_asset_id ON owned_assets(asset_id);
CREATE INDEX IF NOT EXISTS idx_assets_spent ON owned_assets(spent);

-- Minting batches
CREATE TABLE IF NOT EXISTS minting_batches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_key BLOB NOT NULL UNIQUE CHECK(length(batch_key) = 33),
    batch_state INTEGER NOT NULL,
    key_family INTEGER NOT NULL,
    key_index INTEGER NOT NULL,
    genesis_psbt BLOB,
    signed_tx BLOB,
    genesis_outpoint_txid BLOB,
    genesis_outpoint_vout INTEGER,
    confirm_block_hash BLOB,
    confirm_block_height INTEGER,
    confirm_tx_index INTEGER,
    confirm_tx BLOB,
    mint_output_index INTEGER,
    height_hint INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Seedlings: one-to-many with minting_batches
CREATE TABLE IF NOT EXISTS seedlings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    batch_id INTEGER NOT NULL REFERENCES minting_batches(id) ON DELETE CASCADE,
    asset_name TEXT NOT NULL,
    asset_version INTEGER NOT NULL DEFAULT 0,
    asset_type INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    enable_emission INTEGER NOT NULL DEFAULT 0,
    UNIQUE(batch_id, asset_name)
);
CREATE INDEX IF NOT EXISTS idx_seedlings_batch ON seedlings(batch_id);

-- Proof files
CREATE TABLE IF NOT EXISTS proof_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    anchor_txid BLOB NOT NULL CHECK(length(anchor_txid) = 32),
    anchor_vout INTEGER NOT NULL,
    script_key BLOB NOT NULL CHECK(length(script_key) = 33),
    proof_data BLOB NOT NULL,
    UNIQUE(anchor_txid, anchor_vout, script_key)
);
