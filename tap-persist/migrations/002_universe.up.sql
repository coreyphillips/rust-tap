-- Universe roots: one row per (asset_id, group_key, proof_type) triple
CREATE TABLE IF NOT EXISTS universe_roots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id BLOB NOT NULL CHECK(length(asset_id) = 32),
    group_key BLOB,
    proof_type TEXT NOT NULL CHECK(proof_type IN ('issuance', 'transfer')),
    root_hash BLOB NOT NULL DEFAULT x'0000000000000000000000000000000000000000000000000000000000000000',
    root_sum INTEGER NOT NULL DEFAULT 0,
    UNIQUE(asset_id, proof_type)
);
CREATE INDEX IF NOT EXISTS idx_universe_roots_asset ON universe_roots(asset_id);

-- Universe leaves: keyed by (outpoint, script_key) within a universe root
CREATE TABLE IF NOT EXISTS universe_leaves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    universe_root_id INTEGER NOT NULL REFERENCES universe_roots(id) ON DELETE CASCADE,
    outpoint_txid BLOB NOT NULL CHECK(length(outpoint_txid) = 32),
    outpoint_vout INTEGER NOT NULL,
    script_key BLOB NOT NULL CHECK(length(script_key) = 33),
    asset_id BLOB NOT NULL CHECK(length(asset_id) = 32),
    amount INTEGER NOT NULL,
    proof_data BLOB NOT NULL,
    UNIQUE(universe_root_id, outpoint_txid, outpoint_vout, script_key)
);
CREATE INDEX IF NOT EXISTS idx_universe_leaves_root ON universe_leaves(universe_root_id);

-- Federation servers
CREATE TABLE IF NOT EXISTS universe_servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_host TEXT NOT NULL UNIQUE,
    server_id TEXT NOT NULL
);

INSERT INTO schema_version (version) VALUES (2);
