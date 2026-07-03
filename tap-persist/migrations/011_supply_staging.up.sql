-- Supply commitment authoring: the staged supply update queue plus the
-- key/group metadata the authoring pipeline needs across restarts.

-- Staged supply update events per asset group (mirroring Go's
-- supply_update_events WAL table, simplified: rows are upserted keyed
-- by their universe leaf key and deleted once the commitment that
-- includes them is confirmed and persisted). The event blob uses the
-- per-type Go encoding (mint: raw issuance proof; burn: raw burn
-- proof; ignore: TLV signed ignore tuple).
CREATE TABLE IF NOT EXISTS supply_update_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_key BLOB NOT NULL CHECK(length(group_key) = 33),
    sub_tree_type TEXT NOT NULL
        CHECK(sub_tree_type IN ('mint_supply', 'burn', 'ignore')),
    leaf_key BLOB NOT NULL CHECK(length(leaf_key) = 32),
    event_data BLOB NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    UNIQUE(group_key, sub_tree_type, leaf_key)
);

CREATE INDEX IF NOT EXISTS supply_update_events_group_idx
    ON supply_update_events (group_key);

-- Key descriptors for keys the supply pipeline must be able to sign
-- with later: delegation keys (pre-commitment outputs, ignore tuples)
-- and supply commitment output internal keys.
CREATE TABLE IF NOT EXISTS supply_key_descs (
    pub_key BLOB PRIMARY KEY CHECK(length(pub_key) = 33),
    key_family INTEGER NOT NULL,
    key_index INTEGER NOT NULL
);

-- The delegation key of each asset group that opted into universe
-- supply commitments (from the group anchor's MetaReveal).
CREATE TABLE IF NOT EXISTS supply_delegation_keys (
    group_key BLOB PRIMARY KEY CHECK(length(group_key) = 33),
    delegation_key BLOB NOT NULL CHECK(length(delegation_key) = 33)
);

-- Asset ID -> tweaked group key mapping for assets minted into groups
-- with universe supply commitments (used to resolve the group of an
-- ignored asset outpoint).
CREATE TABLE IF NOT EXISTS supply_asset_groups (
    asset_id BLOB PRIMARY KEY CHECK(length(asset_id) = 32),
    group_key BLOB NOT NULL CHECK(length(group_key) = 33)
);

INSERT INTO schema_version (version) VALUES (11);
