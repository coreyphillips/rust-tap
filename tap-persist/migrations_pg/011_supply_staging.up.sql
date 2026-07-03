-- PostgreSQL port of migrations/011_supply_staging.up.sql: the staged
-- supply update queue plus the key/group metadata the authoring
-- pipeline needs across restarts. SQLite's strftime('%s','now')
-- unix-seconds default becomes EXTRACT(EPOCH FROM now())::BIGINT.

CREATE TABLE IF NOT EXISTS supply_update_events (
    id BIGSERIAL PRIMARY KEY,
    group_key BYTEA NOT NULL CHECK(octet_length(group_key) = 33),
    sub_tree_type TEXT NOT NULL
        CHECK(sub_tree_type IN ('mint_supply', 'burn', 'ignore')),
    leaf_key BYTEA NOT NULL CHECK(octet_length(leaf_key) = 32),
    event_data BYTEA NOT NULL,
    created_at BIGINT NOT NULL DEFAULT (EXTRACT(EPOCH FROM now())::BIGINT),
    UNIQUE(group_key, sub_tree_type, leaf_key)
);

CREATE INDEX IF NOT EXISTS supply_update_events_group_idx
    ON supply_update_events (group_key);

-- Key descriptors for keys the supply pipeline must be able to sign
-- with later: delegation keys (pre-commitment outputs, ignore tuples)
-- and supply commitment output internal keys.
CREATE TABLE IF NOT EXISTS supply_key_descs (
    pub_key BYTEA PRIMARY KEY CHECK(octet_length(pub_key) = 33),
    key_family BIGINT NOT NULL,
    key_index BIGINT NOT NULL
);

-- The delegation key of each asset group that opted into universe
-- supply commitments (from the group anchor's MetaReveal).
CREATE TABLE IF NOT EXISTS supply_delegation_keys (
    group_key BYTEA PRIMARY KEY CHECK(octet_length(group_key) = 33),
    delegation_key BYTEA NOT NULL CHECK(octet_length(delegation_key) = 33)
);

-- Asset ID -> tweaked group key mapping for assets minted into groups
-- with universe supply commitments (used to resolve the group of an
-- ignored asset outpoint).
CREATE TABLE IF NOT EXISTS supply_asset_groups (
    asset_id BYTEA PRIMARY KEY CHECK(octet_length(asset_id) = 32),
    group_key BYTEA NOT NULL CHECK(octet_length(group_key) = 33)
);

INSERT INTO schema_version (version) VALUES (11);
