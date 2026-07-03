-- PostgreSQL port of migrations/002_universe.up.sql. The x'00...'
-- SQLite blob literal becomes PostgreSQL's '\x00...' bytea hex form.

-- Universe roots: one row per (asset_id, group_key, proof_type) triple
CREATE TABLE IF NOT EXISTS universe_roots (
    id BIGSERIAL PRIMARY KEY,
    asset_id BYTEA NOT NULL CHECK(octet_length(asset_id) = 32),
    group_key BYTEA,
    proof_type TEXT NOT NULL CHECK(proof_type IN ('issuance', 'transfer')),
    root_hash BYTEA NOT NULL DEFAULT '\x0000000000000000000000000000000000000000000000000000000000000000',
    root_sum BIGINT NOT NULL DEFAULT 0,
    UNIQUE(asset_id, proof_type)
);
CREATE INDEX IF NOT EXISTS idx_universe_roots_asset ON universe_roots(asset_id);

-- Universe leaves: keyed by (outpoint, script_key) within a universe root
CREATE TABLE IF NOT EXISTS universe_leaves (
    id BIGSERIAL PRIMARY KEY,
    universe_root_id BIGINT NOT NULL REFERENCES universe_roots(id) ON DELETE CASCADE,
    outpoint_txid BYTEA NOT NULL CHECK(octet_length(outpoint_txid) = 32),
    outpoint_vout BIGINT NOT NULL,
    script_key BYTEA NOT NULL CHECK(octet_length(script_key) = 33),
    asset_id BYTEA NOT NULL CHECK(octet_length(asset_id) = 32),
    amount BIGINT NOT NULL,
    proof_data BYTEA NOT NULL,
    UNIQUE(universe_root_id, outpoint_txid, outpoint_vout, script_key)
);
CREATE INDEX IF NOT EXISTS idx_universe_leaves_root ON universe_leaves(universe_root_id);

-- Federation servers
CREATE TABLE IF NOT EXISTS universe_servers (
    id BIGSERIAL PRIMARY KEY,
    server_host TEXT NOT NULL UNIQUE,
    server_id TEXT NOT NULL
);

INSERT INTO schema_version (version) VALUES (2);
