-- PostgreSQL port of migrations/001_initial.up.sql.
--
-- Dialect notes (applied consistently across all migrations_pg files):
--   * BLOB                        -> BYTEA
--   * INTEGER PRIMARY KEY AUTOINCREMENT -> BIGSERIAL PRIMARY KEY
--   * INTEGER                     -> BIGINT (every value column; the
--     Rust stores bind/read i64 uniformly, casting to the narrower
--     u8/u16/u32/u64 Rust types at the edges, exactly like the SQLite
--     backend does through SQLite's single INTEGER storage class)
--   * length(col)                 -> octet_length(col)
--   * datetime('now') TEXT default -> TIMESTAMPTZ DEFAULT now()
--
-- The UNIQUE(anchor_txid, anchor_vout) constraint is named explicitly
-- so migration 008 can widen it with ALTER TABLE instead of SQLite's
-- table rebuild.

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
    version BIGINT NOT NULL
);
INSERT INTO schema_version (version) VALUES (1);

-- Owned assets: tracks asset UTXOs
CREATE TABLE IF NOT EXISTS owned_assets (
    id BIGSERIAL PRIMARY KEY,
    asset_id BYTEA NOT NULL CHECK(octet_length(asset_id) = 32),
    amount BIGINT NOT NULL,
    anchor_txid BYTEA NOT NULL CHECK(octet_length(anchor_txid) = 32),
    anchor_vout BIGINT NOT NULL,
    script_key BYTEA NOT NULL CHECK(octet_length(script_key) = 33),
    spent BIGINT NOT NULL DEFAULT 0,
    block_height BIGINT NOT NULL,
    CONSTRAINT owned_assets_anchor_unique UNIQUE(anchor_txid, anchor_vout)
);
CREATE INDEX IF NOT EXISTS idx_assets_asset_id ON owned_assets(asset_id);
CREATE INDEX IF NOT EXISTS idx_assets_spent ON owned_assets(spent);

-- Minting batches
CREATE TABLE IF NOT EXISTS minting_batches (
    id BIGSERIAL PRIMARY KEY,
    batch_key BYTEA NOT NULL UNIQUE CHECK(octet_length(batch_key) = 33),
    batch_state BIGINT NOT NULL,
    key_family BIGINT NOT NULL,
    key_index BIGINT NOT NULL,
    genesis_psbt BYTEA,
    signed_tx BYTEA,
    genesis_outpoint_txid BYTEA,
    genesis_outpoint_vout BIGINT,
    confirm_block_hash BYTEA,
    confirm_block_height BIGINT,
    confirm_tx_index BIGINT,
    confirm_tx BYTEA,
    mint_output_index BIGINT,
    height_hint BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seedlings: one-to-many with minting_batches
CREATE TABLE IF NOT EXISTS seedlings (
    id BIGSERIAL PRIMARY KEY,
    batch_id BIGINT NOT NULL REFERENCES minting_batches(id) ON DELETE CASCADE,
    asset_name TEXT NOT NULL,
    asset_version BIGINT NOT NULL DEFAULT 0,
    asset_type BIGINT NOT NULL,
    amount BIGINT NOT NULL,
    enable_emission BIGINT NOT NULL DEFAULT 0,
    UNIQUE(batch_id, asset_name)
);
CREATE INDEX IF NOT EXISTS idx_seedlings_batch ON seedlings(batch_id);

-- Proof files
CREATE TABLE IF NOT EXISTS proof_files (
    id BIGSERIAL PRIMARY KEY,
    anchor_txid BYTEA NOT NULL CHECK(octet_length(anchor_txid) = 32),
    anchor_vout BIGINT NOT NULL,
    script_key BYTEA NOT NULL CHECK(octet_length(script_key) = 33),
    proof_data BYTEA NOT NULL,
    UNIQUE(anchor_txid, anchor_vout, script_key)
);
