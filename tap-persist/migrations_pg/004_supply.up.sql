-- PostgreSQL port of migrations/004_supply.up.sql.
--
-- MS-SMT sums (l_sum, r_sum, sum, root_sum, supply_root_sum) are u64
-- in Rust and are stored as BIGINT via a two's-complement `as i64`
-- cast, exactly like the SQLite backend stores them in its 64-bit
-- INTEGER storage class; values above i64::MAX round-trip unchanged
-- through the matching `as u64` cast on read.

-- Generic persistent MS-SMT node storage. Trees are partitioned by a
-- namespace string (mirroring Go's tapdb mssmt_nodes table).
CREATE TABLE IF NOT EXISTS mssmt_nodes (
    namespace TEXT NOT NULL,
    hash_key BYTEA NOT NULL CHECK(octet_length(hash_key) = 32),
    node_type TEXT NOT NULL CHECK(node_type IN ('branch', 'leaf', 'compacted')),
    l_hash BYTEA CHECK(l_hash IS NULL OR octet_length(l_hash) = 32),
    r_hash BYTEA CHECK(r_hash IS NULL OR octet_length(r_hash) = 32),
    l_sum BIGINT,
    r_sum BIGINT,
    node_key BYTEA CHECK(node_key IS NULL OR octet_length(node_key) = 32),
    node_value BYTEA,
    sum BIGINT NOT NULL,
    PRIMARY KEY (namespace, hash_key)
);

-- One root row per namespace (mirroring Go's mssmt_roots).
CREATE TABLE IF NOT EXISTS mssmt_roots (
    namespace TEXT PRIMARY KEY,
    root_hash BYTEA NOT NULL CHECK(octet_length(root_hash) = 32),
    root_sum BIGINT NOT NULL
);

-- Root supply tree per asset group (mirroring Go's
-- universe_supply_roots).
CREATE TABLE IF NOT EXISTS universe_supply_roots (
    id BIGSERIAL PRIMARY KEY,
    group_key BYTEA NOT NULL UNIQUE CHECK(octet_length(group_key) = 33),
    namespace_root TEXT NOT NULL UNIQUE
);

-- The (up to three) leaves of a root supply tree, one per sub-tree
-- type (mirroring Go's universe_supply_leaves).
CREATE TABLE IF NOT EXISTS universe_supply_leaves (
    id BIGSERIAL PRIMARY KEY,
    supply_root_id BIGINT NOT NULL
        REFERENCES universe_supply_roots(id) ON DELETE CASCADE,
    sub_tree_type TEXT NOT NULL
        CHECK(sub_tree_type IN ('mint_supply', 'burn', 'ignore')),
    leaf_node_key BYTEA NOT NULL CHECK(octet_length(leaf_node_key) = 32),
    leaf_node_namespace TEXT NOT NULL,
    UNIQUE(supply_root_id, sub_tree_type)
);

-- On-chain supply commitments (mirroring Go's supply_commitments).
CREATE TABLE IF NOT EXISTS supply_commitments (
    commit_id BIGSERIAL PRIMARY KEY,
    group_key BYTEA NOT NULL CHECK(octet_length(group_key) = 33),
    chain_txid BYTEA NOT NULL CHECK(octet_length(chain_txid) = 32),
    output_index BIGINT NOT NULL,
    raw_tx BYTEA NOT NULL,
    internal_key BYTEA NOT NULL CHECK(octet_length(internal_key) = 33),
    output_key BYTEA CHECK(output_key IS NULL OR octet_length(output_key) = 32),
    supply_root_hash BYTEA
        CHECK(supply_root_hash IS NULL OR octet_length(supply_root_hash) = 32),
    supply_root_sum BIGINT,
    block_height BIGINT,
    block_hash BYTEA CHECK(block_hash IS NULL OR octet_length(block_hash) = 32),
    block_header BYTEA
        CHECK(block_header IS NULL OR octet_length(block_header) = 80),
    tx_index BIGINT,
    merkle_proof BYTEA,
    chain_fees BIGINT NOT NULL DEFAULT 0,
    spent_commitment_txid BYTEA
        CHECK(spent_commitment_txid IS NULL
              OR octet_length(spent_commitment_txid) = 32),
    spent_commitment_vout BIGINT,
    UNIQUE(group_key, chain_txid, output_index)
);

CREATE INDEX IF NOT EXISTS supply_commitments_group_idx
    ON supply_commitments (group_key);

-- Pre-commitment outputs created by minting transactions (mirroring
-- Go's mint_anchor_uni_commitments plus its spent_by column).
CREATE TABLE IF NOT EXISTS supply_pre_commits (
    id BIGSERIAL PRIMARY KEY,
    group_key BYTEA NOT NULL CHECK(octet_length(group_key) = 33),
    txid BYTEA NOT NULL CHECK(octet_length(txid) = 32),
    out_idx BIGINT NOT NULL,
    raw_mint_tx BYTEA NOT NULL,
    internal_key BYTEA NOT NULL CHECK(octet_length(internal_key) = 33),
    block_height BIGINT NOT NULL,
    spent_by BIGINT REFERENCES supply_commitments(commit_id),
    UNIQUE(txid, out_idx)
);

CREATE INDEX IF NOT EXISTS supply_pre_commits_group_idx
    ON supply_pre_commits (group_key);

-- Signed ignore tuples per asset group. The prev_id_hash column stores
-- the ignore leaf's universe key (asset.PrevID.Hash) for fast
-- is_ignored lookups.
CREATE TABLE IF NOT EXISTS ignore_tuples (
    id BIGSERIAL PRIMARY KEY,
    group_key BYTEA NOT NULL CHECK(octet_length(group_key) = 33),
    txid BYTEA NOT NULL CHECK(octet_length(txid) = 32),
    vout BIGINT NOT NULL,
    asset_id BYTEA NOT NULL CHECK(octet_length(asset_id) = 32),
    script_key BYTEA NOT NULL CHECK(octet_length(script_key) = 33),
    amount BIGINT NOT NULL,
    block_height BIGINT NOT NULL,
    signed_tuple BYTEA NOT NULL,
    prev_id_hash BYTEA NOT NULL CHECK(octet_length(prev_id_hash) = 32),
    UNIQUE(group_key, prev_id_hash)
);

CREATE INDEX IF NOT EXISTS ignore_tuples_prev_id_idx
    ON ignore_tuples (prev_id_hash);

INSERT INTO schema_version (version) VALUES (4);
