// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Postgres-backed MS-SMT tree store, mirroring
//! [`crate::mssmt_store::SqliteTreeStore`]: a namespaced
//! [`TreeStoreViewTx`]/[`TreeStoreUpdateTx`] over the
//! `mssmt_nodes`/`mssmt_roots` tables.
//!
//! The update half of the trait is infallible by signature, so write
//! errors are latched internally and surfaced by the next fallible
//! (view) operation and by [`PostgresTreeStore::take_error`]. Callers
//! performing mutations should check `take_error` afterwards.

use std::cell::RefCell;
use std::sync::Arc;

use tap_primitives::mssmt::{
    empty_tree, BranchNode, CompactedLeafNode, ComputedNode, LeafNode, Node,
    NodeHash, StoreError, TreeStoreUpdateTx, TreeStoreViewTx,
};

use crate::postgres::PostgresDb;

/// A namespaced, Postgres-backed MS-SMT tree store.
pub struct PostgresTreeStore {
    db: Arc<PostgresDb>,
    namespace: String,
    /// Latched error from infallible update operations.
    err: RefCell<Option<StoreError>>,
}

/// A raw node row from `mssmt_nodes`.
struct NodeRow {
    node_type: String,
    l_hash: Option<Vec<u8>>,
    r_hash: Option<Vec<u8>>,
    l_sum: Option<i64>,
    r_sum: Option<i64>,
    node_key: Option<Vec<u8>>,
    node_value: Option<Vec<u8>>,
    sum: i64,
}

fn to_hash32(bytes: &[u8]) -> Result<[u8; 32], StoreError> {
    bytes
        .try_into()
        .map_err(|_| StoreError::Other("invalid 32-byte column".into()))
}

impl PostgresTreeStore {
    /// Creates a new tree store over the given namespace.
    pub fn new(db: Arc<PostgresDb>, namespace: impl Into<String>) -> Self {
        PostgresTreeStore {
            db,
            namespace: namespace.into(),
            err: RefCell::new(None),
        }
    }

    /// Returns the namespace of this store.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Takes (and clears) any latched write error.
    pub fn take_error(&self) -> Option<StoreError> {
        self.err.borrow_mut().take()
    }

    fn latch_err(&self, msg: String) {
        let mut slot = self.err.borrow_mut();
        if slot.is_none() {
            *slot = Some(StoreError::Other(msg));
        }
    }

    fn latch(&self, result: Result<(), postgres::Error>) {
        if let Err(e) = result {
            self.latch_err(e.to_string());
        }
    }

    fn check_latched(&self) -> Result<(), StoreError> {
        match &*self.err.borrow() {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }

    fn fetch_row(
        &self,
        hash: &NodeHash,
    ) -> Result<Option<NodeRow>, StoreError> {
        let mut client = self
            .db
            .lock()
            .map_err(StoreError::Other)?;
        let row = client
            .query_opt(
                "SELECT node_type, l_hash, r_hash, l_sum, r_sum, node_key, \
                 node_value, sum FROM mssmt_nodes \
                 WHERE namespace = $1 AND hash_key = $2",
                &[&self.namespace, &&hash.0[..]],
            )
            .map_err(|e| StoreError::Other(e.to_string()))?;

        match row {
            Some(row) => {
                let get = |i: usize| -> Result<_, StoreError> {
                    row.try_get(i)
                        .map_err(|e| StoreError::Other(e.to_string()))
                };
                Ok(Some(NodeRow {
                    node_type: row
                        .try_get(0)
                        .map_err(|e| StoreError::Other(e.to_string()))?,
                    l_hash: get(1)?,
                    r_hash: get(2)?,
                    l_sum: row
                        .try_get(3)
                        .map_err(|e| StoreError::Other(e.to_string()))?,
                    r_sum: row
                        .try_get(4)
                        .map_err(|e| StoreError::Other(e.to_string()))?,
                    node_key: get(5)?,
                    node_value: get(6)?,
                    sum: row
                        .try_get(7)
                        .map_err(|e| StoreError::Other(e.to_string()))?,
                }))
            }
            None => Ok(None),
        }
    }

    /// Materializes the node with the given hash at the given height.
    /// Branch nodes are returned shallow (with computed children),
    /// leaves and compacted leaves in full.
    fn fetch_node(
        &self,
        height: usize,
        hash: &NodeHash,
    ) -> Result<Node, StoreError> {
        let empty = empty_tree();
        if *hash == empty[height].node_hash() {
            return Ok(empty[height].clone());
        }

        let row = match self.fetch_row(hash)? {
            Some(row) => row,
            None => return Err(StoreError::NodeNotFound),
        };

        self.row_to_node(height, row)
    }

    fn row_to_node(
        &self,
        height: usize,
        row: NodeRow,
    ) -> Result<Node, StoreError> {
        match row.node_type.as_str() {
            "branch" => {
                let l_hash = to_hash32(&row.l_hash.ok_or_else(|| {
                    StoreError::Other("branch missing l_hash".into())
                })?)?;
                let r_hash = to_hash32(&row.r_hash.ok_or_else(|| {
                    StoreError::Other("branch missing r_hash".into())
                })?)?;
                let l_sum = row.l_sum.ok_or_else(|| {
                    StoreError::Other("branch missing l_sum".into())
                })? as u64;
                let r_sum = row.r_sum.ok_or_else(|| {
                    StoreError::Other("branch missing r_sum".into())
                })? as u64;
                Ok(Node::Branch(BranchNode::new(
                    Node::Computed(ComputedNode::new(NodeHash(l_hash), l_sum)),
                    Node::Computed(ComputedNode::new(NodeHash(r_hash), r_sum)),
                )))
            }
            "leaf" => {
                let value = row.node_value.unwrap_or_default();
                Ok(Node::Leaf(LeafNode::new(value, row.sum as u64)))
            }
            "compacted" => {
                let key = to_hash32(&row.node_key.ok_or_else(|| {
                    StoreError::Other("compacted leaf missing key".into())
                })?)?;
                let value = row.node_value.unwrap_or_default();
                let leaf = LeafNode::new(value, row.sum as u64);
                Ok(Node::Compacted(CompactedLeafNode::new(
                    height, &key, leaf,
                )))
            }
            other => Err(StoreError::Other(format!(
                "unknown node type: {}",
                other
            ))),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn upsert_node(
        &self,
        hash: &NodeHash,
        node_type: &str,
        l_hash: Option<&[u8]>,
        r_hash: Option<&[u8]>,
        l_sum: Option<i64>,
        r_sum: Option<i64>,
        node_key: Option<&[u8]>,
        node_value: Option<&[u8]>,
        sum: i64,
    ) {
        let mut client = match self.db.lock() {
            Ok(client) => client,
            Err(e) => {
                self.latch_err(e);
                return;
            }
        };
        let res = client
            .execute(
                "INSERT INTO mssmt_nodes \
                 (namespace, hash_key, node_type, l_hash, r_hash, l_sum, \
                  r_sum, node_key, node_value, sum) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
                 ON CONFLICT (namespace, hash_key) DO UPDATE SET \
                  node_type = EXCLUDED.node_type, \
                  l_hash = EXCLUDED.l_hash, \
                  r_hash = EXCLUDED.r_hash, \
                  l_sum = EXCLUDED.l_sum, \
                  r_sum = EXCLUDED.r_sum, \
                  node_key = EXCLUDED.node_key, \
                  node_value = EXCLUDED.node_value, \
                  sum = EXCLUDED.sum",
                &[
                    &self.namespace,
                    &&hash.0[..],
                    &node_type,
                    &l_hash,
                    &r_hash,
                    &l_sum,
                    &r_sum,
                    &node_key,
                    &node_value,
                    &sum,
                ],
            )
            .map(|_| ());
        self.latch(res);
    }

    fn delete_node(&self, hash: &NodeHash) {
        let mut client = match self.db.lock() {
            Ok(client) => client,
            Err(e) => {
                self.latch_err(e);
                return;
            }
        };
        let res = client
            .execute(
                "DELETE FROM mssmt_nodes \
                 WHERE namespace = $1 AND hash_key = $2",
                &[&self.namespace, &&hash.0[..]],
            )
            .map(|_| ());
        self.latch(res);
    }
}

impl TreeStoreViewTx for PostgresTreeStore {
    fn get_children(
        &self,
        height: usize,
        hash: &NodeHash,
    ) -> Result<(Node, Node), StoreError> {
        self.check_latched()?;

        let empty = empty_tree();
        if *hash == empty[height].node_hash() {
            let child = &empty[height + 1];
            return Ok((child.clone(), child.clone()));
        }

        let row = match self.fetch_row(hash)? {
            Some(row) => row,
            None => return Err(StoreError::NodeNotFound),
        };

        if row.node_type != "branch" {
            return Err(StoreError::NodeNotFound);
        }

        let l_hash = NodeHash(to_hash32(&row.l_hash.ok_or_else(|| {
            StoreError::Other("branch missing l_hash".into())
        })?)?);
        let r_hash = NodeHash(to_hash32(&row.r_hash.ok_or_else(|| {
            StoreError::Other("branch missing r_hash".into())
        })?)?);

        let left = self.fetch_node(height + 1, &l_hash)?;
        let right = self.fetch_node(height + 1, &r_hash)?;
        Ok((left, right))
    }

    fn root_node(&self) -> Result<Node, StoreError> {
        self.check_latched()?;

        let root_hash: Option<Vec<u8>> = {
            let mut client = self
                .db
                .lock()
                .map_err(StoreError::Other)?;
            let row = client
                .query_opt(
                    "SELECT root_hash FROM mssmt_roots WHERE namespace = $1",
                    &[&self.namespace],
                )
                .map_err(|e| StoreError::Other(e.to_string()))?;
            match row {
                Some(row) => Some(
                    row.try_get(0)
                        .map_err(|e| StoreError::Other(e.to_string()))?,
                ),
                None => None,
            }
        };

        match root_hash {
            Some(bytes) => {
                let hash = NodeHash(to_hash32(&bytes)?);
                self.fetch_node(0, &hash)
            }
            None => Ok(empty_tree()[0].clone()),
        }
    }
}

impl TreeStoreUpdateTx for PostgresTreeStore {
    fn update_root(&mut self, node: &BranchNode) {
        self.insert_branch(node);
        let hash = node.node_hash();
        let sum = node.node_sum();
        let mut client = match self.db.lock() {
            Ok(client) => client,
            Err(e) => {
                self.latch_err(e);
                return;
            }
        };
        let res = client
            .execute(
                "INSERT INTO mssmt_roots \
                 (namespace, root_hash, root_sum) VALUES ($1, $2, $3) \
                 ON CONFLICT (namespace) DO UPDATE SET \
                  root_hash = EXCLUDED.root_hash, \
                  root_sum = EXCLUDED.root_sum",
                &[&self.namespace, &&hash.0[..], &(sum as i64)],
            )
            .map(|_| ());
        self.latch(res);
    }

    fn insert_branch(&mut self, node: &BranchNode) {
        self.upsert_node(
            &node.node_hash(),
            "branch",
            Some(&node.left.node_hash().0[..]),
            Some(&node.right.node_hash().0[..]),
            Some(node.left.node_sum() as i64),
            Some(node.right.node_sum() as i64),
            None,
            None,
            node.node_sum() as i64,
        );
    }

    fn insert_leaf(&mut self, node: &LeafNode) {
        self.upsert_node(
            &node.node_hash(),
            "leaf",
            None,
            None,
            None,
            None,
            None,
            Some(&node.value[..]),
            node.node_sum() as i64,
        );
    }

    fn insert_compacted_leaf(&mut self, node: &CompactedLeafNode) {
        self.upsert_node(
            &node.node_hash(),
            "compacted",
            None,
            None,
            None,
            None,
            Some(&node.key()[..]),
            Some(&node.leaf.value[..]),
            node.node_sum() as i64,
        );
    }

    fn delete_branch(&mut self, hash: &NodeHash) {
        self.delete_node(hash);
    }

    fn delete_leaf(&mut self, hash: &NodeHash) {
        self.delete_node(hash);
    }

    fn delete_compacted_leaf(&mut self, hash: &NodeHash) {
        self.delete_node(hash);
    }

    fn delete_root(&mut self) {
        let mut client = match self.db.lock() {
            Ok(client) => client,
            Err(e) => {
                self.latch_err(e);
                return;
            }
        };
        let res = client
            .execute(
                "DELETE FROM mssmt_roots WHERE namespace = $1",
                &[&self.namespace],
            )
            .map(|_| ());
        self.latch(res);
    }

    fn delete_all_nodes(&mut self) {
        let mut client = match self.db.lock() {
            Ok(client) => client,
            Err(e) => {
                self.latch_err(e);
                return;
            }
        };
        let res = client
            .execute(
                "DELETE FROM mssmt_nodes WHERE namespace = $1",
                &[&self.namespace],
            )
            .and_then(|_| {
                client.execute(
                    "DELETE FROM mssmt_roots WHERE namespace = $1",
                    &[&self.namespace],
                )
            })
            .map(|_| ());
        self.latch(res);
    }
}
