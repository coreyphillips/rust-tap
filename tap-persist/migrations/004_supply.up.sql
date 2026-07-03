-- Universe supply commitments: persistent MS-SMT storage, supply trees,
-- on-chain supply commitments, pre-commitments, and ignore tuples.

-- Generic persistent MS-SMT node storage. Trees are partitioned by a
-- namespace string (mirroring Go's tapdb mssmt_nodes table). Branch
-- rows store the child hashes and sums so shallow branch nodes can be
-- reconstructed without recursion; compacted leaf rows store the leaf
-- key and value.
CREATE TABLE IF NOT EXISTS mssmt_nodes (
    namespace TEXT NOT NULL,
    hash_key BLOB NOT NULL CHECK(length(hash_key) = 32),
    node_type TEXT NOT NULL CHECK(node_type IN ('branch', 'leaf', 'compacted')),
    l_hash BLOB CHECK(l_hash IS NULL OR length(l_hash) = 32),
    r_hash BLOB CHECK(r_hash IS NULL OR length(r_hash) = 32),
    l_sum INTEGER,
    r_sum INTEGER,
    node_key BLOB CHECK(node_key IS NULL OR length(node_key) = 32),
    node_value BLOB,
    sum INTEGER NOT NULL,
    PRIMARY KEY (namespace, hash_key)
);

-- One root row per namespace (mirroring Go's mssmt_roots).
CREATE TABLE IF NOT EXISTS mssmt_roots (
    namespace TEXT PRIMARY KEY,
    root_hash BLOB NOT NULL CHECK(length(root_hash) = 32),
    root_sum INTEGER NOT NULL
);

-- Root supply tree per asset group (mirroring Go's
-- universe_supply_roots). The namespace_root points at the mssmt
-- namespace holding the root supply tree.
CREATE TABLE IF NOT EXISTS universe_supply_roots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_key BLOB NOT NULL UNIQUE CHECK(length(group_key) = 33),
    namespace_root TEXT NOT NULL UNIQUE
);

-- The (up to three) leaves of a root supply tree, one per sub-tree
-- type (mirroring Go's universe_supply_leaves).
CREATE TABLE IF NOT EXISTS universe_supply_leaves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    supply_root_id BIGINT NOT NULL
        REFERENCES universe_supply_roots(id) ON DELETE CASCADE,
    sub_tree_type TEXT NOT NULL
        CHECK(sub_tree_type IN ('mint_supply', 'burn', 'ignore')),
    leaf_node_key BLOB NOT NULL CHECK(length(leaf_node_key) = 32),
    leaf_node_namespace TEXT NOT NULL,
    UNIQUE(supply_root_id, sub_tree_type)
);

-- On-chain supply commitments (mirroring Go's supply_commitments).
CREATE TABLE IF NOT EXISTS supply_commitments (
    commit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_key BLOB NOT NULL CHECK(length(group_key) = 33),
    chain_txid BLOB NOT NULL CHECK(length(chain_txid) = 32),
    output_index INTEGER NOT NULL,
    raw_tx BLOB NOT NULL,
    internal_key BLOB NOT NULL CHECK(length(internal_key) = 33),
    output_key BLOB CHECK(output_key IS NULL OR length(output_key) = 32),
    supply_root_hash BLOB
        CHECK(supply_root_hash IS NULL OR length(supply_root_hash) = 32),
    supply_root_sum INTEGER,
    block_height INTEGER,
    block_hash BLOB CHECK(block_hash IS NULL OR length(block_hash) = 32),
    block_header BLOB
        CHECK(block_header IS NULL OR length(block_header) = 80),
    tx_index INTEGER,
    merkle_proof BLOB,
    chain_fees INTEGER NOT NULL DEFAULT 0,
    spent_commitment_txid BLOB
        CHECK(spent_commitment_txid IS NULL
              OR length(spent_commitment_txid) = 32),
    spent_commitment_vout INTEGER,
    UNIQUE(group_key, chain_txid, output_index)
);

CREATE INDEX IF NOT EXISTS supply_commitments_group_idx
    ON supply_commitments (group_key);

-- Pre-commitment outputs created by minting transactions (mirroring
-- Go's mint_anchor_uni_commitments plus its spent_by column).
CREATE TABLE IF NOT EXISTS supply_pre_commits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_key BLOB NOT NULL CHECK(length(group_key) = 33),
    txid BLOB NOT NULL CHECK(length(txid) = 32),
    out_idx INTEGER NOT NULL,
    raw_mint_tx BLOB NOT NULL,
    internal_key BLOB NOT NULL CHECK(length(internal_key) = 33),
    block_height INTEGER NOT NULL,
    spent_by BIGINT REFERENCES supply_commitments(commit_id),
    UNIQUE(txid, out_idx)
);

CREATE INDEX IF NOT EXISTS supply_pre_commits_group_idx
    ON supply_pre_commits (group_key);

-- Signed ignore tuples per asset group. The prev_id_hash column stores
-- the ignore leaf's universe key (asset.PrevID.Hash) for fast
-- is_ignored lookups.
CREATE TABLE IF NOT EXISTS ignore_tuples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_key BLOB NOT NULL CHECK(length(group_key) = 33),
    txid BLOB NOT NULL CHECK(length(txid) = 32),
    vout INTEGER NOT NULL,
    asset_id BLOB NOT NULL CHECK(length(asset_id) = 32),
    script_key BLOB NOT NULL CHECK(length(script_key) = 33),
    amount INTEGER NOT NULL,
    block_height INTEGER NOT NULL,
    signed_tuple BLOB NOT NULL,
    prev_id_hash BLOB NOT NULL CHECK(length(prev_id_hash) = 32),
    UNIQUE(group_key, prev_id_hash)
);

CREATE INDEX IF NOT EXISTS ignore_tuples_prev_id_idx
    ON ignore_tuples (prev_id_hash);

INSERT INTO schema_version (version) VALUES (4);
