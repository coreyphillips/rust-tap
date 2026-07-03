-- Migration 008: allow multiple assets per anchor outpoint.
--
-- A single anchor output's Taproot Asset commitment can carry several
-- assets (e.g. a multi-seedling mint batch anchors every minted asset
-- at the same outpoint). The original UNIQUE(anchor_txid, anchor_vout)
-- constraint made later inserts silently replace earlier ones,
-- dropping assets. Rebuild the table with the uniqueness widened to
-- (anchor_txid, anchor_vout, asset_id, script_key).

CREATE TABLE owned_assets_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id BLOB NOT NULL CHECK(length(asset_id) = 32),
    amount INTEGER NOT NULL,
    anchor_txid BLOB NOT NULL CHECK(length(anchor_txid) = 32),
    anchor_vout INTEGER NOT NULL,
    script_key BLOB NOT NULL CHECK(length(script_key) = 33),
    spent INTEGER NOT NULL DEFAULT 0,
    block_height INTEGER NOT NULL,
    script_key_family INTEGER,
    script_key_index INTEGER,
    script_key_raw BLOB
        CHECK(script_key_raw IS NULL OR length(script_key_raw) = 33),
    internal_key_family INTEGER,
    internal_key_index INTEGER,
    internal_key_raw BLOB
        CHECK(internal_key_raw IS NULL OR length(internal_key_raw) = 33),
    genesis_tag TEXT,
    genesis_meta_hash BLOB
        CHECK(genesis_meta_hash IS NULL OR length(genesis_meta_hash) = 32),
    genesis_output_index INTEGER,
    genesis_asset_type INTEGER,
    genesis_point_txid BLOB
        CHECK(genesis_point_txid IS NULL OR length(genesis_point_txid) = 32),
    genesis_point_vout INTEGER,
    UNIQUE(anchor_txid, anchor_vout, asset_id, script_key)
);

INSERT INTO owned_assets_new (
    id, asset_id, amount, anchor_txid, anchor_vout, script_key, spent,
    block_height, script_key_family, script_key_index, script_key_raw,
    internal_key_family, internal_key_index, internal_key_raw,
    genesis_tag, genesis_meta_hash, genesis_output_index,
    genesis_asset_type, genesis_point_txid, genesis_point_vout)
SELECT
    id, asset_id, amount, anchor_txid, anchor_vout, script_key, spent,
    block_height, script_key_family, script_key_index, script_key_raw,
    internal_key_family, internal_key_index, internal_key_raw,
    genesis_tag, genesis_meta_hash, genesis_output_index,
    genesis_asset_type, genesis_point_txid, genesis_point_vout
FROM owned_assets;

DROP TABLE owned_assets;
ALTER TABLE owned_assets_new RENAME TO owned_assets;

CREATE INDEX IF NOT EXISTS idx_assets_asset_id ON owned_assets(asset_id);
CREATE INDEX IF NOT EXISTS idx_assets_spent ON owned_assets(spent);

INSERT INTO schema_version (version) VALUES (8);
