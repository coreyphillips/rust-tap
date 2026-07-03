// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Postgres-backed supply tree, supply commitment, and supply staging
//! stores, mirroring the SQLite implementations in
//! [`crate::supply_store`].

use std::sync::Arc;

use postgres::Row;

use tap_onchain::chain::KeyDescriptor;
use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};
use tap_primitives::mssmt::{
    copy_tree_store, CompactedTree, DefaultStore, NodeHash,
};
use tap_primitives::proof::decode::decode_tx_merkle_proof;
use tap_primitives::proof::encode::encode_tx_merkle_proof;
use tap_primitives::proof::BlockHeader;
use tap_universe::supply::{
    CommitmentBlock, PreCommitment, RootCommitment, SupplySubTree,
    SupplyTree, SupplyTrees, SupplyUpdateEvent, ALL_SUPPLY_SUB_TREES,
};

use crate::postgres::mssmt::PostgresTreeStore;
use crate::postgres::{to_array, PostgresDb};
use crate::supply_store::{
    root_supply_namespace, sub_tree_namespace, SupplyCommitStore,
    SupplyStagingStore, SupplyTreeStore,
};

// ---------------------------------------------------------------------------
// PostgresSupplyTreeStore
// ---------------------------------------------------------------------------

/// Postgres-backed [`SupplyTreeStore`], persisting trees in the
/// namespaced `mssmt_nodes`/`mssmt_roots` tables plus the
/// `universe_supply_roots`/`universe_supply_leaves` linkage tables.
pub struct PostgresSupplyTreeStore {
    db: Arc<PostgresDb>,
}

impl PostgresSupplyTreeStore {
    pub fn new(db: Arc<PostgresDb>) -> Self {
        PostgresSupplyTreeStore { db }
    }

    /// Copies the persistent tree in `namespace` into a fresh
    /// in-memory tree.
    fn snapshot_tree(&self, namespace: &str) -> Result<SupplyTree, String> {
        let store = PostgresTreeStore::new(Arc::clone(&self.db), namespace);
        let mut memory = DefaultStore::new();
        copy_tree_store(&store, &mut memory).map_err(|e| e.to_string())?;
        Ok(CompactedTree::new(memory))
    }

    /// Finds or creates the `universe_supply_roots` row for the group,
    /// returning its id.
    fn find_or_create_root_row(
        &self,
        group_key: &SerializedKey,
    ) -> Result<i64, String> {
        let mut client = self.db.lock()?;
        let namespace = root_supply_namespace(group_key);
        client
            .execute(
                "INSERT INTO universe_supply_roots \
                 (group_key, namespace_root) VALUES ($1, $2) \
                 ON CONFLICT (group_key) DO NOTHING",
                &[&&group_key.as_bytes()[..], &namespace],
            )
            .map_err(|e| e.to_string())?;
        client
            .query_one(
                "SELECT id FROM universe_supply_roots WHERE group_key = $1",
                &[&&group_key.as_bytes()[..]],
            )
            .and_then(|row| row.try_get(0))
            .map_err(|e| e.to_string())
    }
}

impl SupplyTreeStore for PostgresSupplyTreeStore {
    fn fetch_sub_tree(
        &self,
        group_key: &SerializedKey,
        tree_type: SupplySubTree,
    ) -> Result<SupplyTree, String> {
        self.snapshot_tree(&sub_tree_namespace(group_key, tree_type))
    }

    fn fetch_sub_trees(
        &self,
        group_key: &SerializedKey,
    ) -> Result<SupplyTrees, String> {
        let mut trees = SupplyTrees::new();
        for tree_type in ALL_SUPPLY_SUB_TREES {
            trees.insert(
                tree_type,
                self.fetch_sub_tree(group_key, tree_type)?,
            );
        }
        Ok(trees)
    }

    fn fetch_root_supply_tree(
        &self,
        group_key: &SerializedKey,
    ) -> Result<SupplyTree, String> {
        self.snapshot_tree(&root_supply_namespace(group_key))
    }

    fn apply_supply_updates(
        &mut self,
        group_key: &SerializedKey,
        updates: &[SupplyUpdateEvent],
    ) -> Result<(NodeHash, u64), String> {
        let root_id = self.find_or_create_root_row(group_key)?;

        // Apply each update to its persistent sub-tree.
        let mut touched: Vec<SupplySubTree> = Vec::new();
        for update in updates {
            let tree_type = update.sub_tree_type();
            if !touched.contains(&tree_type) {
                touched.push(tree_type);
            }

            let namespace = sub_tree_namespace(group_key, tree_type);
            let mut tree = CompactedTree::new(PostgresTreeStore::new(
                Arc::clone(&self.db),
                namespace,
            ));

            let leaf =
                update.universe_leaf_node().map_err(|e| e.to_string())?;
            tree.insert(update.universe_leaf_key(), leaf)
                .map_err(|e| e.to_string())?;
            if let Some(err) = tree.store.take_error() {
                return Err(err.to_string());
            }
        }

        // Upsert the changed sub-tree roots into the root supply tree
        // (Go's upsertSupplyTreeLeaf).
        let root_namespace = root_supply_namespace(group_key);
        for tree_type in touched {
            let sub_namespace = sub_tree_namespace(group_key, tree_type);
            let sub_tree = CompactedTree::new(PostgresTreeStore::new(
                Arc::clone(&self.db),
                sub_namespace.clone(),
            ));
            let sub_root = sub_tree.root().map_err(|e| e.to_string())?;
            if sub_root.node_sum() == 0 {
                continue;
            }

            let mut root_tree = CompactedTree::new(PostgresTreeStore::new(
                Arc::clone(&self.db),
                root_namespace.clone(),
            ));
            root_tree
                .insert(
                    tree_type.universe_key(),
                    tap_primitives::mssmt::LeafNode::new(
                        sub_root.node_hash().0.to_vec(),
                        sub_root.node_sum(),
                    ),
                )
                .map_err(|e| e.to_string())?;
            if let Some(err) = root_tree.store.take_error() {
                return Err(err.to_string());
            }

            // Record the leaf linkage row.
            let mut client = self.db.lock()?;
            client
                .execute(
                    "INSERT INTO universe_supply_leaves \
                     (supply_root_id, sub_tree_type, leaf_node_key, \
                      leaf_node_namespace) VALUES ($1, $2, $3, $4) \
                     ON CONFLICT (supply_root_id, sub_tree_type) \
                     DO UPDATE SET \
                      leaf_node_key = EXCLUDED.leaf_node_key, \
                      leaf_node_namespace = EXCLUDED.leaf_node_namespace",
                    &[
                        &root_id,
                        &tree_type.as_str(),
                        &&tree_type.universe_key()[..],
                        &sub_namespace,
                    ],
                )
                .map_err(|e| e.to_string())?;
        }

        let root_tree = CompactedTree::new(PostgresTreeStore::new(
            Arc::clone(&self.db),
            root_namespace,
        ));
        let root = root_tree.root().map_err(|e| e.to_string())?;
        Ok((root.node_hash(), root.node_sum()))
    }
}

// ---------------------------------------------------------------------------
// PostgresSupplyCommitStore
// ---------------------------------------------------------------------------

/// Postgres-backed [`SupplyCommitStore`].
pub struct PostgresSupplyCommitStore {
    db: Arc<PostgresDb>,
}

impl PostgresSupplyCommitStore {
    pub fn new(db: Arc<PostgresDb>) -> Self {
        PostgresSupplyCommitStore { db }
    }
}

fn row_to_commitment(row: &Row) -> Result<RootCommitment, String> {
    let err = |e: postgres::Error| e.to_string();

    let raw_tx: Vec<u8> = row.try_get("raw_tx").map_err(err)?;
    let internal_key: Vec<u8> = row.try_get("internal_key").map_err(err)?;
    let output_key: Option<Vec<u8>> =
        row.try_get("output_key").map_err(err)?;
    let root_hash: Option<Vec<u8>> =
        row.try_get("supply_root_hash").map_err(err)?;
    let root_sum: Option<i64> =
        row.try_get("supply_root_sum").map_err(err)?;
    let output_index: i64 = row.try_get("output_index").map_err(err)?;
    let block_height: Option<i64> =
        row.try_get("block_height").map_err(err)?;
    let block_hash: Option<Vec<u8>> =
        row.try_get("block_hash").map_err(err)?;
    let block_header: Option<Vec<u8>> =
        row.try_get("block_header").map_err(err)?;
    let tx_index: Option<i64> = row.try_get("tx_index").map_err(err)?;
    let merkle_proof: Option<Vec<u8>> =
        row.try_get("merkle_proof").map_err(err)?;
    let chain_fees: i64 = row.try_get("chain_fees").map_err(err)?;
    let spent_txid: Option<Vec<u8>> =
        row.try_get("spent_commitment_txid").map_err(err)?;
    let spent_vout: Option<i64> =
        row.try_get("spent_commitment_vout").map_err(err)?;

    let txn: bitcoin::Transaction =
        bitcoin::consensus::encode::deserialize(&raw_tx)
            .map_err(|_| "invalid raw tx".to_string())?;

    let commitment_block = match block_height {
        Some(height) => {
            let hash: [u8; 32] = to_array(
                block_hash.ok_or_else(|| "missing block hash".to_string())?,
                "block_hash",
            )?;
            let header = match block_header {
                Some(bytes) => {
                    let arr: [u8; 80] = bytes
                        .try_into()
                        .map_err(|_| "invalid block header".to_string())?;
                    Some(BlockHeader(arr))
                }
                None => None,
            };
            let merkle_proof = match merkle_proof {
                Some(bytes) => Some(
                    decode_tx_merkle_proof(&bytes)
                        .map_err(|_| "invalid merkle proof".to_string())?,
                ),
                None => None,
            };
            Some(CommitmentBlock {
                height: height as u32,
                hash,
                tx_index: tx_index.map(|v| v as u32).unwrap_or(0),
                block_header: header,
                merkle_proof,
                chain_fees,
            })
        }
        None => None,
    };

    let spent_commitment = match (spent_txid, spent_vout) {
        (Some(txid), Some(vout)) => Some(OutPoint {
            txid: to_array(txid, "spent_commitment_txid")?,
            vout: vout as u32,
        }),
        _ => None,
    };

    Ok(RootCommitment {
        txn,
        tx_out_idx: output_index as u32,
        internal_key: SerializedKey(to_array(internal_key, "internal_key")?),
        output_key: match output_key {
            Some(bytes) => Some(to_array(bytes, "output_key")?),
            None => None,
        },
        supply_root_hash: NodeHash(to_array(
            root_hash
                .ok_or_else(|| "missing supply root hash".to_string())?,
            "supply_root_hash",
        )?),
        supply_root_sum: root_sum.unwrap_or(0) as u64,
        commitment_block,
        spent_commitment,
    })
}

const COMMITMENT_COLUMNS: &str = "raw_tx, output_index, internal_key, \
    output_key, supply_root_hash, supply_root_sum, block_height, \
    block_hash, block_header, tx_index, merkle_proof, chain_fees, \
    spent_commitment_txid, spent_commitment_vout";

impl SupplyCommitStore for PostgresSupplyCommitStore {
    fn insert_commitment(
        &mut self,
        group_key: &SerializedKey,
        commitment: &RootCommitment,
    ) -> Result<(), String> {
        let mut client = self.db.lock()?;

        let raw_tx = bitcoin::consensus::encode::serialize(&commitment.txn);
        let commit_point = commitment.commit_point();

        let (block_height, block_hash, block_header, tx_index, merkle_proof, chain_fees) =
            match &commitment.commitment_block {
                Some(block) => (
                    Some(i64::from(block.height)),
                    Some(block.hash.to_vec()),
                    block.block_header.as_ref().map(|h| h.0.to_vec()),
                    Some(i64::from(block.tx_index)),
                    block
                        .merkle_proof
                        .as_ref()
                        .map(encode_tx_merkle_proof),
                    block.chain_fees,
                ),
                None => (None, None, None, None, None, 0),
            };

        let (spent_txid, spent_vout) = match &commitment.spent_commitment {
            Some(op) => {
                (Some(op.txid.to_vec()), Some(i64::from(op.vout)))
            }
            None => (None, None),
        };

        client
            .execute(
                "INSERT INTO supply_commitments \
                 (group_key, chain_txid, output_index, raw_tx, internal_key, \
                  output_key, supply_root_hash, supply_root_sum, \
                  block_height, block_hash, block_header, tx_index, \
                  merkle_proof, chain_fees, spent_commitment_txid, \
                  spent_commitment_vout) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
                         $13, $14, $15, $16) \
                 ON CONFLICT (group_key, chain_txid, output_index) \
                 DO UPDATE SET \
                  raw_tx = EXCLUDED.raw_tx, \
                  internal_key = EXCLUDED.internal_key, \
                  output_key = EXCLUDED.output_key, \
                  supply_root_hash = EXCLUDED.supply_root_hash, \
                  supply_root_sum = EXCLUDED.supply_root_sum, \
                  block_height = EXCLUDED.block_height, \
                  block_hash = EXCLUDED.block_hash, \
                  block_header = EXCLUDED.block_header, \
                  tx_index = EXCLUDED.tx_index, \
                  merkle_proof = EXCLUDED.merkle_proof, \
                  chain_fees = EXCLUDED.chain_fees, \
                  spent_commitment_txid = EXCLUDED.spent_commitment_txid, \
                  spent_commitment_vout = EXCLUDED.spent_commitment_vout",
                &[
                    &&group_key.as_bytes()[..],
                    &&commit_point.txid[..],
                    &i64::from(commit_point.vout),
                    &&raw_tx[..],
                    &&commitment.internal_key.as_bytes()[..],
                    &commitment.output_key.as_ref().map(|k| k.to_vec()),
                    &&commitment.supply_root_hash.0[..],
                    &(commitment.supply_root_sum as i64),
                    &block_height,
                    &block_hash,
                    &block_header,
                    &tx_index,
                    &merkle_proof,
                    &chain_fees,
                    &spent_txid,
                    &spent_vout,
                ],
            )
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    fn latest_commitment(
        &self,
        group_key: &SerializedKey,
    ) -> Result<Option<RootCommitment>, String> {
        let mut client = self.db.lock()?;
        let query = format!(
            "SELECT {COMMITMENT_COLUMNS} FROM supply_commitments \
             WHERE group_key = $1 ORDER BY commit_id DESC LIMIT 1"
        );
        client
            .query_opt(query.as_str(), &[&&group_key.as_bytes()[..]])
            .map_err(|e| e.to_string())?
            .map(|row| row_to_commitment(&row))
            .transpose()
    }

    fn starting_commitment(
        &self,
        group_key: &SerializedKey,
    ) -> Result<Option<RootCommitment>, String> {
        let mut client = self.db.lock()?;
        let query = format!(
            "SELECT {COMMITMENT_COLUMNS} FROM supply_commitments \
             WHERE group_key = $1 ORDER BY commit_id ASC LIMIT 1"
        );
        client
            .query_opt(query.as_str(), &[&&group_key.as_bytes()[..]])
            .map_err(|e| e.to_string())?
            .map(|row| row_to_commitment(&row))
            .transpose()
    }

    fn commitment_by_outpoint(
        &self,
        group_key: &SerializedKey,
        outpoint: &OutPoint,
    ) -> Result<Option<RootCommitment>, String> {
        let mut client = self.db.lock()?;
        let query = format!(
            "SELECT {COMMITMENT_COLUMNS} FROM supply_commitments \
             WHERE group_key = $1 AND chain_txid = $2 AND output_index = $3"
        );
        client
            .query_opt(
                query.as_str(),
                &[
                    &&group_key.as_bytes()[..],
                    &&outpoint.txid[..],
                    &i64::from(outpoint.vout),
                ],
            )
            .map_err(|e| e.to_string())?
            .map(|row| row_to_commitment(&row))
            .transpose()
    }

    fn insert_pre_commit(
        &mut self,
        pre_commit: &PreCommitment,
    ) -> Result<(), String> {
        let mut client = self.db.lock()?;
        let raw_tx =
            bitcoin::consensus::encode::serialize(&pre_commit.minting_txn);
        let op = pre_commit.out_point();
        client
            .execute(
                "INSERT INTO supply_pre_commits \
                 (group_key, txid, out_idx, raw_mint_tx, internal_key, \
                  block_height, spent_by) \
                 VALUES ($1, $2, $3, $4, $5, $6, NULL) \
                 ON CONFLICT (txid, out_idx) DO UPDATE SET \
                  group_key = EXCLUDED.group_key, \
                  raw_mint_tx = EXCLUDED.raw_mint_tx, \
                  internal_key = EXCLUDED.internal_key, \
                  block_height = EXCLUDED.block_height, \
                  spent_by = NULL",
                &[
                    &&pre_commit.group_pub_key.as_bytes()[..],
                    &&op.txid[..],
                    &i64::from(op.vout),
                    &&raw_tx[..],
                    &&pre_commit.internal_key.as_bytes()[..],
                    &i64::from(pre_commit.block_height),
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn unspent_pre_commits(
        &self,
        group_key: &SerializedKey,
    ) -> Result<Vec<PreCommitment>, String> {
        let mut client = self.db.lock()?;
        let rows = client
            .query(
                "SELECT raw_mint_tx, out_idx, internal_key, block_height \
                 FROM supply_pre_commits \
                 WHERE group_key = $1 AND spent_by IS NULL \
                 ORDER BY id",
                &[&&group_key.as_bytes()[..]],
            )
            .map_err(|e| e.to_string())?;

        let group_key_bytes = *group_key.as_bytes();
        let mut result = Vec::new();
        for row in &rows {
            let err = |e: postgres::Error| e.to_string();
            let raw_tx: Vec<u8> = row.try_get(0).map_err(err)?;
            let out_idx: i64 = row.try_get(1).map_err(err)?;
            let internal_key: Vec<u8> = row.try_get(2).map_err(err)?;
            let block_height: i64 = row.try_get(3).map_err(err)?;

            let minting_txn: bitcoin::Transaction =
                bitcoin::consensus::encode::deserialize(&raw_tx)
                    .map_err(|e| e.to_string())?;
            let internal_key: [u8; 33] =
                to_array(internal_key, "internal_key")?;
            result.push(PreCommitment {
                block_height: block_height as u32,
                minting_txn,
                out_idx: out_idx as u32,
                internal_key: SerializedKey(internal_key),
                group_pub_key: SerializedKey(group_key_bytes),
            });
        }
        Ok(result)
    }

    fn mark_pre_commit_spent(
        &mut self,
        pre_commit_outpoint: &OutPoint,
        spent_by: &OutPoint,
    ) -> Result<(), String> {
        let mut client = self.db.lock()?;

        // Resolve the spending commitment's id, if stored.
        let commit_id: Option<i64> = client
            .query_opt(
                "SELECT commit_id FROM supply_commitments \
                 WHERE chain_txid = $1 AND output_index = $2",
                &[&&spent_by.txid[..], &i64::from(spent_by.vout)],
            )
            .map_err(|e| e.to_string())?
            .map(|row| row.try_get(0).map_err(|e| e.to_string()))
            .transpose()?;

        let commit_id = commit_id
            .ok_or_else(|| "spending commitment not found".to_string())?;

        let updated = client
            .execute(
                "UPDATE supply_pre_commits SET spent_by = $1 \
                 WHERE txid = $2 AND out_idx = $3",
                &[
                    &commit_id,
                    &&pre_commit_outpoint.txid[..],
                    &i64::from(pre_commit_outpoint.vout),
                ],
            )
            .map_err(|e| e.to_string())?;

        if updated == 0 {
            return Err("pre-commitment not found".into());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// PostgresSupplyStagingStore
// ---------------------------------------------------------------------------

/// Postgres-backed [`SupplyStagingStore`] over the migration-011
/// tables (`supply_update_events`, `supply_key_descs`,
/// `supply_delegation_keys`, `supply_asset_groups`).
pub struct PostgresSupplyStagingStore {
    db: Arc<PostgresDb>,
}

impl PostgresSupplyStagingStore {
    pub fn new(db: Arc<PostgresDb>) -> Self {
        PostgresSupplyStagingStore { db }
    }
}

impl SupplyStagingStore for PostgresSupplyStagingStore {
    fn stage_update(
        &mut self,
        group_key: &SerializedKey,
        update: &SupplyUpdateEvent,
    ) -> Result<(), String> {
        let mut client = self.db.lock()?;
        client
            .execute(
                "INSERT INTO supply_update_events \
                 (group_key, sub_tree_type, leaf_key, event_data) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (group_key, sub_tree_type, leaf_key) \
                 DO UPDATE SET event_data = EXCLUDED.event_data",
                &[
                    &&group_key.as_bytes()[..],
                    &update.sub_tree_type().as_str(),
                    &&update.universe_leaf_key()[..],
                    &&update.encode()[..],
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn staged_updates(
        &self,
        group_key: &SerializedKey,
    ) -> Result<Vec<SupplyUpdateEvent>, String> {
        let mut client = self.db.lock()?;
        let rows = client
            .query(
                "SELECT sub_tree_type, event_data \
                 FROM supply_update_events WHERE group_key = $1 \
                 ORDER BY id",
                &[&&group_key.as_bytes()[..]],
            )
            .map_err(|e| e.to_string())?;

        let mut updates = Vec::new();
        for row in &rows {
            let err = |e: postgres::Error| e.to_string();
            let tree_type: String = row.try_get(0).map_err(err)?;
            let data: Vec<u8> = row.try_get(1).map_err(err)?;
            let tree_type = SupplySubTree::from_str_name(&tree_type)
                .ok_or_else(|| {
                    format!("unknown sub-tree type: {}", tree_type)
                })?;
            updates.push(
                SupplyUpdateEvent::decode(tree_type, &data)
                    .map_err(|e| e.to_string())?,
            );
        }
        Ok(updates)
    }

    fn groups_with_staged_updates(
        &self,
    ) -> Result<Vec<SerializedKey>, String> {
        let mut client = self.db.lock()?;
        let rows = client
            .query(
                "SELECT group_key FROM supply_update_events \
                 GROUP BY group_key ORDER BY MIN(id)",
                &[],
            )
            .map_err(|e| e.to_string())?;

        let mut groups = Vec::new();
        for row in &rows {
            let bytes: Vec<u8> =
                row.try_get(0).map_err(|e| e.to_string())?;
            groups.push(SerializedKey(to_array(bytes, "group_key")?));
        }
        Ok(groups)
    }

    fn remove_staged_updates(
        &mut self,
        group_key: &SerializedKey,
        updates: &[SupplyUpdateEvent],
    ) -> Result<(), String> {
        let mut client = self.db.lock()?;
        for update in updates {
            client
                .execute(
                    "DELETE FROM supply_update_events \
                     WHERE group_key = $1 AND sub_tree_type = $2 \
                     AND leaf_key = $3",
                    &[
                        &&group_key.as_bytes()[..],
                        &update.sub_tree_type().as_str(),
                        &&update.universe_leaf_key()[..],
                    ],
                )
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn save_key_descriptor(
        &mut self,
        desc: &KeyDescriptor,
    ) -> Result<(), String> {
        let mut client = self.db.lock()?;
        client
            .execute(
                "INSERT INTO supply_key_descs \
                 (pub_key, key_family, key_index) VALUES ($1, $2, $3) \
                 ON CONFLICT (pub_key) DO UPDATE SET \
                  key_family = EXCLUDED.key_family, \
                  key_index = EXCLUDED.key_index",
                &[
                    &&desc.pub_key.as_bytes()[..],
                    &i64::from(desc.family),
                    &i64::from(desc.index),
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn key_descriptor(
        &self,
        pub_key: &SerializedKey,
    ) -> Result<Option<KeyDescriptor>, String> {
        let mut client = self.db.lock()?;
        let row = client
            .query_opt(
                "SELECT key_family, key_index FROM supply_key_descs \
                 WHERE pub_key = $1",
                &[&&pub_key.as_bytes()[..]],
            )
            .map_err(|e| e.to_string())?;
        match row {
            Some(row) => {
                let family: i64 =
                    row.try_get(0).map_err(|e| e.to_string())?;
                let index: i64 =
                    row.try_get(1).map_err(|e| e.to_string())?;
                Ok(Some(KeyDescriptor {
                    family: family as u16,
                    index: index as u32,
                    pub_key: *pub_key,
                }))
            }
            None => Ok(None),
        }
    }

    fn set_delegation_key(
        &mut self,
        group_key: &SerializedKey,
        delegation_key: &SerializedKey,
    ) -> Result<(), String> {
        let mut client = self.db.lock()?;
        client
            .execute(
                "INSERT INTO supply_delegation_keys \
                 (group_key, delegation_key) VALUES ($1, $2) \
                 ON CONFLICT (group_key) DO UPDATE SET \
                  delegation_key = EXCLUDED.delegation_key",
                &[
                    &&group_key.as_bytes()[..],
                    &&delegation_key.as_bytes()[..],
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn delegation_key(
        &self,
        group_key: &SerializedKey,
    ) -> Result<Option<SerializedKey>, String> {
        let mut client = self.db.lock()?;
        client
            .query_opt(
                "SELECT delegation_key FROM supply_delegation_keys \
                 WHERE group_key = $1",
                &[&&group_key.as_bytes()[..]],
            )
            .map_err(|e| e.to_string())?
            .map(|row| {
                let bytes: Vec<u8> =
                    row.try_get(0).map_err(|e| e.to_string())?;
                Ok(SerializedKey(to_array(bytes, "delegation_key")?))
            })
            .transpose()
    }

    fn map_asset_group(
        &mut self,
        asset_id: &AssetId,
        group_key: &SerializedKey,
    ) -> Result<(), String> {
        let mut client = self.db.lock()?;
        client
            .execute(
                "INSERT INTO supply_asset_groups \
                 (asset_id, group_key) VALUES ($1, $2) \
                 ON CONFLICT (asset_id) DO UPDATE SET \
                  group_key = EXCLUDED.group_key",
                &[
                    &&asset_id.as_bytes()[..],
                    &&group_key.as_bytes()[..],
                ],
            )
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    fn asset_group(
        &self,
        asset_id: &AssetId,
    ) -> Result<Option<SerializedKey>, String> {
        let mut client = self.db.lock()?;
        client
            .query_opt(
                "SELECT group_key FROM supply_asset_groups \
                 WHERE asset_id = $1",
                &[&&asset_id.as_bytes()[..]],
            )
            .map_err(|e| e.to_string())?
            .map(|row| {
                let bytes: Vec<u8> =
                    row.try_get(0).map_err(|e| e.to_string())?;
                Ok(SerializedKey(to_array(bytes, "group_key")?))
            })
            .transpose()
    }
}
