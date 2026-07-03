// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Persistence for universe supply trees and supply commitments,
//! mirroring Go's `tapdb/supply_tree.go` and the commitment portions of
//! `tapdb/supply_commit.go`.
//!
//! Two store traits are defined, each with an in-memory and (behind the
//! `sqlite` feature) a SQLite implementation:
//!
//! - [`SupplyTreeStore`]: fetch/apply the root supply tree and its
//!   mint/burn/ignore sub-trees per asset group. The SQLite
//!   implementation persists tree nodes in the namespaced
//!   `mssmt_nodes`/`mssmt_roots` tables via
//!   [`crate::mssmt_store::SqliteTreeStore`], using Go's namespace
//!   scheme (`supply-root-<group_key_hex>` and
//!   `supply-sub-<type>-<group_key_hex>`).
//! - [`SupplyCommitStore`]: verified on-chain supply commitments and
//!   pre-commitment outputs.
//!
//! The authoring state machine's WAL tables (pending transitions,
//! update events) are deferred together with the state machine itself.

use std::collections::HashMap;

use tap_primitives::asset::{OutPoint, SerializedKey};
use tap_primitives::mssmt::NodeHash;
use tap_universe::supply::{
    apply_tree_updates, new_supply_tree, update_root_supply_tree,
    PreCommitment, RootCommitment, SupplySubTree, SupplyTree, SupplyTrees,
    SupplyUpdateEvent, ALL_SUPPLY_SUB_TREES,
};

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Returns the MS-SMT namespace of the root supply tree for a group
/// key, mirroring Go's `rootSupplyNamespace` (tapdb/supply_tree.go).
pub fn root_supply_namespace(group_key: &SerializedKey) -> String {
    format!("supply-root-{}", hex_encode(group_key.as_bytes()))
}

/// Returns the MS-SMT namespace of a supply sub-tree for a group key,
/// mirroring Go's `subTreeNamespace` (tapdb/supply_tree.go).
pub fn sub_tree_namespace(
    group_key: &SerializedKey,
    tree_type: SupplySubTree,
) -> String {
    format!(
        "supply-sub-{}-{}",
        tree_type.as_str(),
        hex_encode(group_key.as_bytes())
    )
}

/// Storage of the supply trees (root tree + sub-trees) per asset
/// group.
pub trait SupplyTreeStore {
    /// Returns a copy of the sub-tree of the given type. Missing trees
    /// are returned empty.
    fn fetch_sub_tree(
        &self,
        group_key: &SerializedKey,
        tree_type: SupplySubTree,
    ) -> Result<SupplyTree, String>;

    /// Returns copies of all sub-trees.
    fn fetch_sub_trees(
        &self,
        group_key: &SerializedKey,
    ) -> Result<SupplyTrees, String>;

    /// Returns a copy of the root supply tree.
    fn fetch_root_supply_tree(
        &self,
        group_key: &SerializedKey,
    ) -> Result<SupplyTree, String>;

    /// Applies the given supply update events to the stored sub-trees
    /// and upserts the changed sub-tree roots into the root supply
    /// tree, mirroring Go's `applySupplyUpdatesInternal`
    /// (tapdb/supply_tree.go). Returns the new root supply tree root
    /// (hash, sum).
    fn apply_supply_updates(
        &mut self,
        group_key: &SerializedKey,
        updates: &[SupplyUpdateEvent],
    ) -> Result<(NodeHash, u64), String>;
}

/// Storage of verified on-chain supply commitments and pre-commitment
/// outputs per asset group.
pub trait SupplyCommitStore {
    /// Inserts a verified supply commitment. If the commitment spends
    /// a previous commitment or pre-commitments, the caller is
    /// expected to mark those spent separately.
    fn insert_commitment(
        &mut self,
        group_key: &SerializedKey,
        commitment: &RootCommitment,
    ) -> Result<(), String>;

    /// Returns the latest (most recently inserted) commitment.
    fn latest_commitment(
        &self,
        group_key: &SerializedKey,
    ) -> Result<Option<RootCommitment>, String>;

    /// Returns the very first commitment of the group.
    fn starting_commitment(
        &self,
        group_key: &SerializedKey,
    ) -> Result<Option<RootCommitment>, String>;

    /// Returns the commitment with the given outpoint, if known.
    fn commitment_by_outpoint(
        &self,
        group_key: &SerializedKey,
        outpoint: &OutPoint,
    ) -> Result<Option<RootCommitment>, String>;

    /// Inserts an unspent pre-commitment output.
    fn insert_pre_commit(
        &mut self,
        pre_commit: &PreCommitment,
    ) -> Result<(), String>;

    /// Returns all unspent pre-commitments of the group.
    fn unspent_pre_commits(
        &self,
        group_key: &SerializedKey,
    ) -> Result<Vec<PreCommitment>, String>;

    /// Marks the pre-commitment with the given outpoint as spent by the
    /// commitment with the given commit point.
    fn mark_pre_commit_spent(
        &mut self,
        pre_commit_outpoint: &OutPoint,
        spent_by: &OutPoint,
    ) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// In-memory implementations
// ---------------------------------------------------------------------------

/// In-memory [`SupplyTreeStore`].
#[derive(Default)]
pub struct MemorySupplyTreeStore {
    /// Per group key: (root supply tree, sub-trees).
    trees: HashMap<[u8; 33], (SupplyTree, SupplyTrees)>,
}

impl MemorySupplyTreeStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SupplyTreeStore for MemorySupplyTreeStore {
    fn fetch_sub_tree(
        &self,
        group_key: &SerializedKey,
        tree_type: SupplySubTree,
    ) -> Result<SupplyTree, String> {
        Ok(self
            .trees
            .get(group_key.as_bytes())
            .and_then(|(_, subs)| subs.get(tree_type).cloned())
            .unwrap_or_else(new_supply_tree))
    }

    fn fetch_sub_trees(
        &self,
        group_key: &SerializedKey,
    ) -> Result<SupplyTrees, String> {
        Ok(self
            .trees
            .get(group_key.as_bytes())
            .map(|(_, subs)| subs.clone())
            .unwrap_or_default())
    }

    fn fetch_root_supply_tree(
        &self,
        group_key: &SerializedKey,
    ) -> Result<SupplyTree, String> {
        Ok(self
            .trees
            .get(group_key.as_bytes())
            .map(|(root, _)| root.clone())
            .unwrap_or_else(new_supply_tree))
    }

    fn apply_supply_updates(
        &mut self,
        group_key: &SerializedKey,
        updates: &[SupplyUpdateEvent],
    ) -> Result<(NodeHash, u64), String> {
        let entry = self
            .trees
            .entry(*group_key.as_bytes())
            .or_insert_with(|| (new_supply_tree(), SupplyTrees::new()));

        let new_subs = apply_tree_updates(&entry.1, updates)
            .map_err(|e| e.to_string())?;
        update_root_supply_tree(&mut entry.0, &new_subs)
            .map_err(|e| e.to_string())?;
        entry.1 = new_subs;

        let root = entry.0.root().map_err(|e| e.to_string())?;
        Ok((root.node_hash(), root.node_sum()))
    }
}

/// In-memory [`SupplyCommitStore`].
#[derive(Default)]
pub struct MemorySupplyCommitStore {
    commitments: HashMap<[u8; 33], Vec<RootCommitment>>,
    /// (pre-commitment, spent_by commit point).
    pre_commits: HashMap<[u8; 33], Vec<(PreCommitment, Option<OutPoint>)>>,
}

impl MemorySupplyCommitStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SupplyCommitStore for MemorySupplyCommitStore {
    fn insert_commitment(
        &mut self,
        group_key: &SerializedKey,
        commitment: &RootCommitment,
    ) -> Result<(), String> {
        self.commitments
            .entry(*group_key.as_bytes())
            .or_default()
            .push(commitment.clone());
        Ok(())
    }

    fn latest_commitment(
        &self,
        group_key: &SerializedKey,
    ) -> Result<Option<RootCommitment>, String> {
        Ok(self
            .commitments
            .get(group_key.as_bytes())
            .and_then(|list| list.last().cloned()))
    }

    fn starting_commitment(
        &self,
        group_key: &SerializedKey,
    ) -> Result<Option<RootCommitment>, String> {
        Ok(self
            .commitments
            .get(group_key.as_bytes())
            .and_then(|list| list.first().cloned()))
    }

    fn commitment_by_outpoint(
        &self,
        group_key: &SerializedKey,
        outpoint: &OutPoint,
    ) -> Result<Option<RootCommitment>, String> {
        Ok(self.commitments.get(group_key.as_bytes()).and_then(|list| {
            list.iter().find(|c| c.commit_point() == *outpoint).cloned()
        }))
    }

    fn insert_pre_commit(
        &mut self,
        pre_commit: &PreCommitment,
    ) -> Result<(), String> {
        self.pre_commits
            .entry(*pre_commit.group_pub_key.as_bytes())
            .or_default()
            .push((pre_commit.clone(), None));
        Ok(())
    }

    fn unspent_pre_commits(
        &self,
        group_key: &SerializedKey,
    ) -> Result<Vec<PreCommitment>, String> {
        Ok(self
            .pre_commits
            .get(group_key.as_bytes())
            .map(|list| {
                list.iter()
                    .filter(|(_, spent_by)| spent_by.is_none())
                    .map(|(pc, _)| pc.clone())
                    .collect()
            })
            .unwrap_or_default())
    }

    fn mark_pre_commit_spent(
        &mut self,
        pre_commit_outpoint: &OutPoint,
        spent_by: &OutPoint,
    ) -> Result<(), String> {
        for list in self.pre_commits.values_mut() {
            for (pc, spent) in list.iter_mut() {
                if pc.out_point() == *pre_commit_outpoint {
                    *spent = Some(spent_by.clone());
                    return Ok(());
                }
            }
        }
        Err("pre-commitment not found".into())
    }
}

// ---------------------------------------------------------------------------
// SQLite implementations
// ---------------------------------------------------------------------------

#[cfg(feature = "sqlite")]
pub use sqlite_impl::{SqliteSupplyCommitStore, SqliteSupplyTreeStore};

#[cfg(feature = "sqlite")]
mod sqlite_impl {
    use super::*;

    use rusqlite::{params, OptionalExtension};

    use tap_primitives::mssmt::{copy_tree_store, CompactedTree, DefaultStore};
    use tap_primitives::proof::decode::decode_tx_merkle_proof;
    use tap_primitives::proof::encode::encode_tx_merkle_proof;
    use tap_primitives::proof::BlockHeader;
    use tap_universe::supply::CommitmentBlock;

    use crate::mssmt_store::SqliteTreeStore;
    use crate::sqlite::SqliteDb;

    /// SQLite-backed [`SupplyTreeStore`], persisting trees in the
    /// namespaced `mssmt_nodes`/`mssmt_roots` tables plus the
    /// `universe_supply_roots`/`universe_supply_leaves` linkage tables.
    pub struct SqliteSupplyTreeStore {
        db: std::sync::Arc<SqliteDb>,
    }

    impl SqliteSupplyTreeStore {
        pub fn new(db: std::sync::Arc<SqliteDb>) -> Self {
            SqliteSupplyTreeStore { db }
        }

        /// Copies the persistent tree in `namespace` into a fresh
        /// in-memory tree.
        fn snapshot_tree(&self, namespace: &str) -> Result<SupplyTree, String> {
            let store = SqliteTreeStore::new(std::sync::Arc::clone(&self.db), namespace);
            let mut memory = DefaultStore::new();
            copy_tree_store(&store, &mut memory).map_err(|e| e.to_string())?;
            Ok(CompactedTree::new(memory))
        }

        /// Finds or creates the `universe_supply_roots` row for the
        /// group, returning its id.
        fn find_or_create_root_row(
            &self,
            group_key: &SerializedKey,
        ) -> Result<i64, String> {
            let conn = self.db.conn.lock().map_err(|e| e.to_string())?;
            let namespace = root_supply_namespace(group_key);
            conn.execute(
                "INSERT OR IGNORE INTO universe_supply_roots \
                 (group_key, namespace_root) VALUES (?1, ?2)",
                params![&group_key.as_bytes()[..], &namespace],
            )
            .map_err(|e| e.to_string())?;
            conn.query_row(
                "SELECT id FROM universe_supply_roots WHERE group_key = ?1",
                params![&group_key.as_bytes()[..]],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|e| e.to_string())
        }
    }

    impl SupplyTreeStore for SqliteSupplyTreeStore {
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
                let mut tree = CompactedTree::new(SqliteTreeStore::new(
                    std::sync::Arc::clone(&self.db), namespace,
                ));

                let leaf =
                    update.universe_leaf_node().map_err(|e| e.to_string())?;
                tree.insert(update.universe_leaf_key(), leaf)
                    .map_err(|e| e.to_string())?;
                if let Some(err) = tree.store.take_error() {
                    return Err(err.to_string());
                }
            }

            // Upsert the changed sub-tree roots into the root supply
            // tree (Go's upsertSupplyTreeLeaf).
            let root_namespace = root_supply_namespace(group_key);
            for tree_type in touched {
                let sub_namespace = sub_tree_namespace(group_key, tree_type);
                let sub_tree = CompactedTree::new(SqliteTreeStore::new(
                    std::sync::Arc::clone(&self.db),
                    sub_namespace.clone(),
                ));
                let sub_root = sub_tree.root().map_err(|e| e.to_string())?;
                if sub_root.node_sum() == 0 {
                    continue;
                }

                let mut root_tree = CompactedTree::new(SqliteTreeStore::new(
                    std::sync::Arc::clone(&self.db),
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
                let conn = self.db.conn.lock().map_err(|e| e.to_string())?;
                conn.execute(
                    "INSERT OR REPLACE INTO universe_supply_leaves \
                     (supply_root_id, sub_tree_type, leaf_node_key, \
                      leaf_node_namespace) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        root_id,
                        tree_type.as_str(),
                        &tree_type.universe_key()[..],
                        &sub_namespace,
                    ],
                )
                .map_err(|e| e.to_string())?;
            }

            let root_tree = CompactedTree::new(SqliteTreeStore::new(
                std::sync::Arc::clone(&self.db),
                root_namespace,
            ));
            let root = root_tree.root().map_err(|e| e.to_string())?;
            Ok((root.node_hash(), root.node_sum()))
        }
    }

    /// SQLite-backed [`SupplyCommitStore`].
    pub struct SqliteSupplyCommitStore {
        db: std::sync::Arc<SqliteDb>,
    }

    impl SqliteSupplyCommitStore {
        pub fn new(db: std::sync::Arc<SqliteDb>) -> Self {
            SqliteSupplyCommitStore { db }
        }
    }

    fn row_to_commitment(
        row: &rusqlite::Row<'_>,
    ) -> Result<RootCommitment, rusqlite::Error> {
        let raw_tx: Vec<u8> = row.get("raw_tx")?;
        let internal_key: Vec<u8> = row.get("internal_key")?;
        let output_key: Option<Vec<u8>> = row.get("output_key")?;
        let root_hash: Option<Vec<u8>> = row.get("supply_root_hash")?;
        let root_sum: Option<i64> = row.get("supply_root_sum")?;
        let output_index: u32 = row.get("output_index")?;
        let block_height: Option<u32> = row.get("block_height")?;
        let block_hash: Option<Vec<u8>> = row.get("block_hash")?;
        let block_header: Option<Vec<u8>> = row.get("block_header")?;
        let tx_index: Option<u32> = row.get("tx_index")?;
        let merkle_proof: Option<Vec<u8>> = row.get("merkle_proof")?;
        let chain_fees: i64 = row.get("chain_fees")?;
        let spent_txid: Option<Vec<u8>> = row.get("spent_commitment_txid")?;
        let spent_vout: Option<u32> = row.get("spent_commitment_vout")?;

        let invalid = |msg: &str| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Blob,
                msg.to_string().into(),
            )
        };

        let txn: bitcoin::Transaction =
            bitcoin::consensus::encode::deserialize(&raw_tx)
                .map_err(|_| invalid("invalid raw tx"))?;

        let commitment_block = match block_height {
            Some(height) => {
                let hash: [u8; 32] = block_hash
                    .ok_or_else(|| invalid("missing block hash"))?
                    .try_into()
                    .map_err(|_| invalid("invalid block hash"))?;
                let header = match block_header {
                    Some(bytes) => {
                        let arr: [u8; 80] = bytes
                            .try_into()
                            .map_err(|_| invalid("invalid block header"))?;
                        Some(BlockHeader(arr))
                    }
                    None => None,
                };
                let merkle_proof = match merkle_proof {
                    Some(bytes) => Some(
                        decode_tx_merkle_proof(&bytes)
                            .map_err(|_| invalid("invalid merkle proof"))?,
                    ),
                    None => None,
                };
                Some(CommitmentBlock {
                    height,
                    hash,
                    tx_index: tx_index.unwrap_or(0),
                    block_header: header,
                    merkle_proof,
                    chain_fees,
                })
            }
            None => None,
        };

        let spent_commitment = match (spent_txid, spent_vout) {
            (Some(txid), Some(vout)) => Some(OutPoint {
                txid: txid
                    .try_into()
                    .map_err(|_| invalid("invalid spent txid"))?,
                vout,
            }),
            _ => None,
        };

        Ok(RootCommitment {
            txn,
            tx_out_idx: output_index,
            internal_key: SerializedKey(
                internal_key
                    .try_into()
                    .map_err(|_| invalid("invalid internal key"))?,
            ),
            output_key: match output_key {
                Some(bytes) => Some(
                    bytes
                        .try_into()
                        .map_err(|_| invalid("invalid output key"))?,
                ),
                None => None,
            },
            supply_root_hash: NodeHash(
                root_hash
                    .ok_or_else(|| invalid("missing supply root hash"))?
                    .try_into()
                    .map_err(|_| invalid("invalid supply root hash"))?,
            ),
            supply_root_sum: root_sum.unwrap_or(0) as u64,
            commitment_block,
            spent_commitment,
        })
    }

    const COMMITMENT_COLUMNS: &str = "raw_tx, output_index, internal_key, \
        output_key, supply_root_hash, supply_root_sum, block_height, \
        block_hash, block_header, tx_index, merkle_proof, chain_fees, \
        spent_commitment_txid, spent_commitment_vout";

    impl SupplyCommitStore for SqliteSupplyCommitStore {
        fn insert_commitment(
            &mut self,
            group_key: &SerializedKey,
            commitment: &RootCommitment,
        ) -> Result<(), String> {
            let conn = self.db.conn.lock().map_err(|e| e.to_string())?;

            let raw_tx =
                bitcoin::consensus::encode::serialize(&commitment.txn);
            let commit_point = commitment.commit_point();

            let (block_height, block_hash, block_header, tx_index, merkle_proof, chain_fees) =
                match &commitment.commitment_block {
                    Some(block) => (
                        Some(block.height),
                        Some(block.hash.to_vec()),
                        block.block_header.as_ref().map(|h| h.0.to_vec()),
                        Some(block.tx_index),
                        block
                            .merkle_proof
                            .as_ref()
                            .map(encode_tx_merkle_proof),
                        block.chain_fees,
                    ),
                    None => (None, None, None, None, None, 0),
                };

            let (spent_txid, spent_vout) = match &commitment.spent_commitment
            {
                Some(op) => (Some(op.txid.to_vec()), Some(op.vout)),
                None => (None, None),
            };

            conn.execute(
                "INSERT OR REPLACE INTO supply_commitments \
                 (group_key, chain_txid, output_index, raw_tx, internal_key, \
                  output_key, supply_root_hash, supply_root_sum, \
                  block_height, block_hash, block_header, tx_index, \
                  merkle_proof, chain_fees, spent_commitment_txid, \
                  spent_commitment_vout) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, \
                         ?13, ?14, ?15, ?16)",
                params![
                    &group_key.as_bytes()[..],
                    &commit_point.txid[..],
                    commit_point.vout,
                    &raw_tx[..],
                    &commitment.internal_key.as_bytes()[..],
                    commitment.output_key.as_ref().map(|k| k.to_vec()),
                    &commitment.supply_root_hash.0[..],
                    commitment.supply_root_sum as i64,
                    block_height,
                    block_hash,
                    block_header,
                    tx_index,
                    merkle_proof,
                    chain_fees,
                    spent_txid,
                    spent_vout,
                ],
            )
            .map_err(|e| e.to_string())?;

            Ok(())
        }

        fn latest_commitment(
            &self,
            group_key: &SerializedKey,
        ) -> Result<Option<RootCommitment>, String> {
            let conn = self.db.conn.lock().map_err(|e| e.to_string())?;
            conn.query_row(
                &format!(
                    "SELECT {} FROM supply_commitments WHERE group_key = ?1 \
                     ORDER BY commit_id DESC LIMIT 1",
                    COMMITMENT_COLUMNS
                ),
                params![&group_key.as_bytes()[..]],
                row_to_commitment,
            )
            .optional()
            .map_err(|e| e.to_string())
        }

        fn starting_commitment(
            &self,
            group_key: &SerializedKey,
        ) -> Result<Option<RootCommitment>, String> {
            let conn = self.db.conn.lock().map_err(|e| e.to_string())?;
            conn.query_row(
                &format!(
                    "SELECT {} FROM supply_commitments WHERE group_key = ?1 \
                     ORDER BY commit_id ASC LIMIT 1",
                    COMMITMENT_COLUMNS
                ),
                params![&group_key.as_bytes()[..]],
                row_to_commitment,
            )
            .optional()
            .map_err(|e| e.to_string())
        }

        fn commitment_by_outpoint(
            &self,
            group_key: &SerializedKey,
            outpoint: &OutPoint,
        ) -> Result<Option<RootCommitment>, String> {
            let conn = self.db.conn.lock().map_err(|e| e.to_string())?;
            conn.query_row(
                &format!(
                    "SELECT {} FROM supply_commitments WHERE group_key = ?1 \
                     AND chain_txid = ?2 AND output_index = ?3",
                    COMMITMENT_COLUMNS
                ),
                params![
                    &group_key.as_bytes()[..],
                    &outpoint.txid[..],
                    outpoint.vout
                ],
                row_to_commitment,
            )
            .optional()
            .map_err(|e| e.to_string())
        }

        fn insert_pre_commit(
            &mut self,
            pre_commit: &PreCommitment,
        ) -> Result<(), String> {
            let conn = self.db.conn.lock().map_err(|e| e.to_string())?;
            let raw_tx = bitcoin::consensus::encode::serialize(
                &pre_commit.minting_txn,
            );
            let op = pre_commit.out_point();
            conn.execute(
                "INSERT OR REPLACE INTO supply_pre_commits \
                 (group_key, txid, out_idx, raw_mint_tx, internal_key, \
                  block_height, spent_by) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)",
                params![
                    &pre_commit.group_pub_key.as_bytes()[..],
                    &op.txid[..],
                    op.vout,
                    &raw_tx[..],
                    &pre_commit.internal_key.as_bytes()[..],
                    pre_commit.block_height,
                ],
            )
            .map_err(|e| e.to_string())?;
            Ok(())
        }

        fn unspent_pre_commits(
            &self,
            group_key: &SerializedKey,
        ) -> Result<Vec<PreCommitment>, String> {
            let conn = self.db.conn.lock().map_err(|e| e.to_string())?;
            let mut stmt = conn
                .prepare(
                    "SELECT raw_mint_tx, out_idx, internal_key, block_height \
                     FROM supply_pre_commits \
                     WHERE group_key = ?1 AND spent_by IS NULL \
                     ORDER BY id",
                )
                .map_err(|e| e.to_string())?;

            let group_key_bytes = *group_key.as_bytes();
            let rows = stmt
                .query_map(params![&group_key_bytes[..]], |row| {
                    let raw_tx: Vec<u8> = row.get(0)?;
                    let out_idx: u32 = row.get(1)?;
                    let internal_key: Vec<u8> = row.get(2)?;
                    let block_height: u32 = row.get(3)?;
                    Ok((raw_tx, out_idx, internal_key, block_height))
                })
                .map_err(|e| e.to_string())?;

            let mut result = Vec::new();
            for row in rows {
                let (raw_tx, out_idx, internal_key, block_height) =
                    row.map_err(|e| e.to_string())?;
                let minting_txn: bitcoin::Transaction =
                    bitcoin::consensus::encode::deserialize(&raw_tx)
                        .map_err(|e| e.to_string())?;
                let internal_key: [u8; 33] = internal_key
                    .try_into()
                    .map_err(|_| "invalid internal key".to_string())?;
                result.push(PreCommitment {
                    block_height,
                    minting_txn,
                    out_idx,
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
            let conn = self.db.conn.lock().map_err(|e| e.to_string())?;

            // Resolve the spending commitment's id, if stored.
            let commit_id: Option<i64> = conn
                .query_row(
                    "SELECT commit_id FROM supply_commitments \
                     WHERE chain_txid = ?1 AND output_index = ?2",
                    params![&spent_by.txid[..], spent_by.vout],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| e.to_string())?;

            let commit_id = commit_id
                .ok_or_else(|| "spending commitment not found".to_string())?;

            let updated = conn
                .execute(
                    "UPDATE supply_pre_commits SET spent_by = ?1 \
                     WHERE txid = ?2 AND out_idx = ?3",
                    params![
                        commit_id,
                        &pre_commit_outpoint.txid[..],
                        pre_commit_outpoint.vout
                    ],
                )
                .map_err(|e| e.to_string())?;

            if updated == 0 {
                return Err("pre-commitment not found".into());
            }
            Ok(())
        }
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;
    use std::sync::Arc;

    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::sha256d;
    use bitcoin::hashes::Hash as BtcHash;
    use bitcoin::transaction::Version;
    use bitcoin::{
        Amount, OutPoint as BtcOutPoint, ScriptBuf, Sequence, Transaction,
        TxIn, TxOut, Txid, Witness,
    };

    use tap_primitives::asset::{AssetId, PrevId};
    use tap_primitives::proof::{BlockHeader, TxMerkleProof};
    use tap_universe::ignore::{IgnoreSig, IgnoreTuple, SignedIgnoreTuple};
    use tap_universe::supply::{CommitmentBlock, NewIgnoreEvent};

    use crate::sqlite::SqliteDb;

    fn group_key() -> SerializedKey {
        let mut k = [0x02u8; 33];
        k[32] = 0x77;
        SerializedKey(k)
    }

    fn valid_script_key() -> SerializedKey {
        // The secp256k1 generator point (a known-valid key).
        let mut k = [0u8; 33];
        k[0] = 0x02;
        k[1..].copy_from_slice(&[
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62,
            0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce,
            0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        ]);
        SerializedKey(k)
    }

    fn ignore_update(vout: u32, amount: u64) -> SupplyUpdateEvent {
        SupplyUpdateEvent::Ignore(NewIgnoreEvent {
            signed_tuple: SignedIgnoreTuple {
                tuple: IgnoreTuple {
                    prev_id: PrevId {
                        out_point: OutPoint {
                            txid: [0x33; 32],
                            vout,
                        },
                        id: AssetId([0x44; 32]),
                        script_key: valid_script_key(),
                    },
                    amount,
                    block_height: 100,
                },
                sig: IgnoreSig([0x01; 64]),
            },
        })
    }

    fn dummy_tx(seed: u8, value: u64, script: Vec<u8>) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: BtcOutPoint {
                    txid: Txid::from_raw_hash(sha256d::Hash::from_byte_array(
                        [seed; 32],
                    )),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::from_bytes(script),
            }],
        }
    }

    fn test_commitment(seed: u8, with_block: bool) -> RootCommitment {
        let txn = dummy_tx(seed, 1000, vec![0x51, 0x20, seed, 0x00]);
        let commitment_block = if with_block {
            let mut header_bytes = [0u8; 80];
            header_bytes[0] = seed;
            let header = BlockHeader(header_bytes);
            Some(CommitmentBlock {
                height: 123,
                hash: header.block_hash(),
                tx_index: 1,
                block_header: Some(header),
                merkle_proof: Some(TxMerkleProof {
                    nodes: vec![[seed; 32]],
                    bits: vec![true],
                }),
                chain_fees: 42,
            })
        } else {
            None
        };

        RootCommitment {
            txn,
            tx_out_idx: 0,
            internal_key: group_key(),
            output_key: Some([seed; 32]),
            supply_root_hash: NodeHash([seed; 32]),
            supply_root_sum: 500,
            commitment_block,
            spent_commitment: if seed % 2 == 0 {
                Some(OutPoint {
                    txid: [seed; 32],
                    vout: 1,
                })
            } else {
                None
            },
        }
    }

    /// Memory and SQLite tree stores produce identical supply roots.
    #[test]
    fn test_supply_tree_store_backends_agree() {
        let db = Arc::new(SqliteDb::open_in_memory().unwrap());
        let mut sqlite_store = SqliteSupplyTreeStore::new(Arc::clone(&db));
        let mut memory_store = MemorySupplyTreeStore::new();

        let updates =
            vec![ignore_update(0, 100), ignore_update(1, 250)];

        let (sqlite_root, sqlite_sum) = sqlite_store
            .apply_supply_updates(&group_key(), &updates)
            .expect("sqlite apply");
        let (memory_root, memory_sum) = memory_store
            .apply_supply_updates(&group_key(), &updates)
            .expect("memory apply");

        assert_eq!(sqlite_root, memory_root);
        assert_eq!(sqlite_sum, memory_sum);
        assert_eq!(sqlite_sum, 350);

        // Fetching the trees yields the same roots.
        let sq_root_tree =
            sqlite_store.fetch_root_supply_tree(&group_key()).unwrap();
        let mem_root_tree =
            memory_store.fetch_root_supply_tree(&group_key()).unwrap();
        assert_eq!(
            sq_root_tree.root().unwrap().node_hash(),
            mem_root_tree.root().unwrap().node_hash()
        );

        let sq_sub = sqlite_store
            .fetch_sub_tree(&group_key(), SupplySubTree::Ignore)
            .unwrap();
        let mem_sub = memory_store
            .fetch_sub_tree(&group_key(), SupplySubTree::Ignore)
            .unwrap();
        assert_eq!(
            sq_sub.root().unwrap().node_hash(),
            mem_sub.root().unwrap().node_hash()
        );
        assert_eq!(sq_sub.root().unwrap().node_sum(), 350);
    }

    /// Incremental updates accumulate across calls.
    #[test]
    fn test_supply_tree_store_incremental() {
        let db = Arc::new(SqliteDb::open_in_memory().unwrap());
        let mut store = SqliteSupplyTreeStore::new(Arc::clone(&db));

        let (_, sum1) = store
            .apply_supply_updates(&group_key(), &[ignore_update(0, 100)])
            .unwrap();
        assert_eq!(sum1, 100);

        let (_, sum2) = store
            .apply_supply_updates(&group_key(), &[ignore_update(1, 50)])
            .unwrap();
        assert_eq!(sum2, 150);

        // Replacing a leaf at the same key overwrites, not adds.
        let (_, sum3) = store
            .apply_supply_updates(&group_key(), &[ignore_update(1, 75)])
            .unwrap();
        assert_eq!(sum3, 175);
    }

    /// Commitments round-trip through both store backends.
    #[test]
    fn test_supply_commit_store_round_trip() {
        let db = Arc::new(SqliteDb::open_in_memory().unwrap());
        let mut sqlite_store = SqliteSupplyCommitStore::new(Arc::clone(&db));
        let mut memory_store = MemorySupplyCommitStore::new();

        let first = test_commitment(1, true);
        let second = test_commitment(2, false);

        for store in [
            &mut sqlite_store as &mut dyn SupplyCommitStore,
            &mut memory_store as &mut dyn SupplyCommitStore,
        ] {
            store.insert_commitment(&group_key(), &first).unwrap();
            store.insert_commitment(&group_key(), &second).unwrap();

            let starting =
                store.starting_commitment(&group_key()).unwrap().unwrap();
            assert_eq!(starting.commit_point(), first.commit_point());
            assert_eq!(starting.supply_root_hash, first.supply_root_hash);
            assert_eq!(starting.supply_root_sum, 500);

            let block = starting.commitment_block.as_ref().unwrap();
            assert_eq!(block.height, 123);
            assert_eq!(block.tx_index, 1);
            assert_eq!(block.chain_fees, 42);
            assert_eq!(
                block.merkle_proof.as_ref().unwrap().nodes,
                vec![[1u8; 32]]
            );
            assert_eq!(
                block.hash,
                block.block_header.as_ref().unwrap().block_hash()
            );

            let latest =
                store.latest_commitment(&group_key()).unwrap().unwrap();
            assert_eq!(latest.commit_point(), second.commit_point());
            assert!(latest.commitment_block.is_none());
            assert_eq!(
                latest.spent_commitment,
                Some(OutPoint {
                    txid: [2; 32],
                    vout: 1
                })
            );

            let by_op = store
                .commitment_by_outpoint(&group_key(), &first.commit_point())
                .unwrap()
                .unwrap();
            assert_eq!(by_op.commit_point(), first.commit_point());

            assert!(store
                .commitment_by_outpoint(
                    &group_key(),
                    &OutPoint {
                        txid: [0xEE; 32],
                        vout: 0
                    }
                )
                .unwrap()
                .is_none());
        }
    }

    /// Pre-commitments can be inserted, listed, and marked spent in
    /// both backends.
    #[test]
    fn test_pre_commit_round_trip() {
        let db = Arc::new(SqliteDb::open_in_memory().unwrap());
        let mut sqlite_store = SqliteSupplyCommitStore::new(Arc::clone(&db));
        let mut memory_store = MemorySupplyCommitStore::new();

        let pre_commit = PreCommitment {
            block_height: 90,
            minting_txn: dummy_tx(9, 1000, vec![0x51, 0x20, 0x09]),
            out_idx: 0,
            internal_key: group_key(),
            group_pub_key: group_key(),
        };

        let commitment = test_commitment(1, true);

        for store in [
            &mut sqlite_store as &mut dyn SupplyCommitStore,
            &mut memory_store as &mut dyn SupplyCommitStore,
        ] {
            store.insert_commitment(&group_key(), &commitment).unwrap();
            store.insert_pre_commit(&pre_commit).unwrap();

            let unspent = store.unspent_pre_commits(&group_key()).unwrap();
            assert_eq!(unspent.len(), 1);
            assert_eq!(unspent[0].out_point(), pre_commit.out_point());
            assert_eq!(unspent[0].block_height, 90);

            store
                .mark_pre_commit_spent(
                    &pre_commit.out_point(),
                    &commitment.commit_point(),
                )
                .unwrap();

            assert!(store
                .unspent_pre_commits(&group_key())
                .unwrap()
                .is_empty());
        }
    }
}
