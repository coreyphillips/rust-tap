-- Burn records: one row per completed asset burn.
CREATE TABLE IF NOT EXISTS asset_burns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    note TEXT,
    asset_id BLOB NOT NULL CHECK(length(asset_id) = 32),
    group_key BLOB CHECK(group_key IS NULL OR length(group_key) = 33),
    amount INTEGER NOT NULL,
    anchor_txid BLOB NOT NULL CHECK(length(anchor_txid) = 32),
    script_key BLOB NOT NULL CHECK(length(script_key) = 33),
    outpoint_txid BLOB NOT NULL CHECK(length(outpoint_txid) = 32),
    outpoint_vout INTEGER NOT NULL,
    block_height INTEGER NOT NULL,
    UNIQUE(outpoint_txid, outpoint_vout, script_key)
);

CREATE INDEX IF NOT EXISTS asset_burns_asset_id_idx
    ON asset_burns (asset_id);

INSERT INTO schema_version (version) VALUES (3);
