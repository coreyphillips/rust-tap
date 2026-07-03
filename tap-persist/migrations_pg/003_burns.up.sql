-- PostgreSQL port of migrations/003_burns.up.sql.

-- Burn records: one row per completed asset burn.
CREATE TABLE IF NOT EXISTS asset_burns (
    id BIGSERIAL PRIMARY KEY,
    note TEXT,
    asset_id BYTEA NOT NULL CHECK(octet_length(asset_id) = 32),
    group_key BYTEA CHECK(group_key IS NULL OR octet_length(group_key) = 33),
    amount BIGINT NOT NULL,
    anchor_txid BYTEA NOT NULL CHECK(octet_length(anchor_txid) = 32),
    script_key BYTEA NOT NULL CHECK(octet_length(script_key) = 33),
    outpoint_txid BYTEA NOT NULL CHECK(octet_length(outpoint_txid) = 32),
    outpoint_vout BIGINT NOT NULL,
    block_height BIGINT NOT NULL,
    UNIQUE(outpoint_txid, outpoint_vout, script_key)
);

CREATE INDEX IF NOT EXISTS asset_burns_asset_id_idx
    ON asset_burns (asset_id);

INSERT INTO schema_version (version) VALUES (3);
