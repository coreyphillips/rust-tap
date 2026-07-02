// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! SQLite-backed MS-SMT tree store.
//!
//! [`SqliteTreeStore`] implements the tap-primitives
//! [`TreeStoreViewTx`]/[`TreeStoreUpdateTx`] traits over the
//! `mssmt_nodes`/`mssmt_roots` tables (migration 004), partitioned by a
//! namespace string. This mirrors Go's tapdb MS-SMT store, which keys
//! nodes by `(hash_key, namespace)`.
//!
//! The update half of the trait is infallible by signature, so write
//! errors are latched internally and surfaced by the next fallible
//! (view) operation and by [`SqliteTreeStore::take_error`]. Callers
//! performing mutations should check `take_error` afterwards.

use std::cell::RefCell;

use rusqlite::{params, OptionalExtension};

use tap_primitives::mssmt::{
    empty_tree, BranchNode, CompactedLeafNode, ComputedNode, LeafNode, Node,
    NodeHash, StoreError, TreeStoreUpdateTx, TreeStoreViewTx,
};

use crate::sqlite::SqliteDb;

/// A namespaced, SQLite-backed MS-SMT tree store.
pub struct SqliteTreeStore {
    db: std::sync::Arc<SqliteDb>,
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

impl SqliteTreeStore {
    /// Creates a new tree store over the given namespace.
    pub fn new(db: std::sync::Arc<SqliteDb>, namespace: impl Into<String>) -> Self {
        SqliteTreeStore {
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

    fn latch(&self, result: Result<(), rusqlite::Error>) {
        if let Err(e) = result {
            let mut slot = self.err.borrow_mut();
            if slot.is_none() {
                *slot = Some(StoreError::Other(e.to_string()));
            }
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
        let conn = self
            .db
            .conn
            .lock()
            .map_err(|_| StoreError::Other("poisoned lock".into()))?;
        conn.query_row(
            "SELECT node_type, l_hash, r_hash, l_sum, r_sum, node_key, \
             node_value, sum FROM mssmt_nodes \
             WHERE namespace = ?1 AND hash_key = ?2",
            params![&self.namespace, &hash.0[..]],
            |row| {
                Ok(NodeRow {
                    node_type: row.get(0)?,
                    l_hash: row.get(1)?,
                    r_hash: row.get(2)?,
                    l_sum: row.get(3)?,
                    r_sum: row.get(4)?,
                    node_key: row.get(5)?,
                    node_value: row.get(6)?,
                    sum: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(|e| StoreError::Other(e.to_string()))
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
        let conn = match self.db.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                self.latch(Err(rusqlite::Error::InvalidQuery));
                return;
            }
        };
        let res = conn
            .execute(
                "INSERT OR REPLACE INTO mssmt_nodes \
                 (namespace, hash_key, node_type, l_hash, r_hash, l_sum, \
                  r_sum, node_key, node_value, sum) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    &self.namespace,
                    &hash.0[..],
                    node_type,
                    l_hash,
                    r_hash,
                    l_sum,
                    r_sum,
                    node_key,
                    node_value,
                    sum,
                ],
            )
            .map(|_| ());
        self.latch(res);
    }

    fn delete_node(&self, hash: &NodeHash) {
        let conn = match self.db.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                self.latch(Err(rusqlite::Error::InvalidQuery));
                return;
            }
        };
        let res = conn
            .execute(
                "DELETE FROM mssmt_nodes \
                 WHERE namespace = ?1 AND hash_key = ?2",
                params![&self.namespace, &hash.0[..]],
            )
            .map(|_| ());
        self.latch(res);
    }
}

impl TreeStoreViewTx for SqliteTreeStore {
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
            let conn = self
                .db
                .conn
                .lock()
                .map_err(|_| StoreError::Other("poisoned lock".into()))?;
            conn.query_row(
                "SELECT root_hash FROM mssmt_roots WHERE namespace = ?1",
                params![&self.namespace],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| StoreError::Other(e.to_string()))?
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

impl TreeStoreUpdateTx for SqliteTreeStore {
    fn update_root(&mut self, node: &BranchNode) {
        self.insert_branch(node);
        let hash = node.node_hash();
        let sum = node.node_sum();
        let conn = match self.db.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                self.latch(Err(rusqlite::Error::InvalidQuery));
                return;
            }
        };
        let res = conn
            .execute(
                "INSERT OR REPLACE INTO mssmt_roots \
                 (namespace, root_hash, root_sum) VALUES (?1, ?2, ?3)",
                params![&self.namespace, &hash.0[..], sum as i64],
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
        let conn = match self.db.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                self.latch(Err(rusqlite::Error::InvalidQuery));
                return;
            }
        };
        let res = conn
            .execute(
                "DELETE FROM mssmt_roots WHERE namespace = ?1",
                params![&self.namespace],
            )
            .map(|_| ());
        self.latch(res);
    }

    fn delete_all_nodes(&mut self) {
        let conn = match self.db.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                self.latch(Err(rusqlite::Error::InvalidQuery));
                return;
            }
        };
        let res = conn
            .execute(
                "DELETE FROM mssmt_nodes WHERE namespace = ?1",
                params![&self.namespace],
            )
            .and_then(|_| {
                conn.execute(
                    "DELETE FROM mssmt_roots WHERE namespace = ?1",
                    params![&self.namespace],
                )
            })
            .map(|_| ());
        self.latch(res);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tap_primitives::mssmt::{
        copy_tree_store, CompactedTree, DefaultStore,
    };

    fn make_key(byte: u8) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[0] = byte;
        key
    }

    /// Inserting the same leaves into an in-memory tree and a
    /// SQLite-backed tree must produce identical roots.
    #[test]
    fn test_sqlite_tree_matches_memory_tree() {
        let db = Arc::new(SqliteDb::open_in_memory().unwrap());
        let store = SqliteTreeStore::new(Arc::clone(&db), "test-ns");
        let mut sqlite_tree = CompactedTree::new(store);
        let mut memory_tree = CompactedTree::new(DefaultStore::new());

        for i in 0..10u8 {
            let key = make_key(i);
            let leaf =
                LeafNode::new(vec![i, i + 1, i + 2], (i as u64 + 1) * 10);
            sqlite_tree.insert(key, leaf.clone()).unwrap();
            memory_tree.insert(key, leaf).unwrap();
            assert!(sqlite_tree.store.take_error().is_none());
        }

        let sqlite_root = sqlite_tree.root().unwrap();
        let memory_root = memory_tree.root().unwrap();
        assert_eq!(sqlite_root.node_hash(), memory_root.node_hash());
        assert_eq!(sqlite_root.node_sum(), memory_root.node_sum());

        // Leaf lookup works through the persistent store.
        let leaf = sqlite_tree.get(make_key(3)).unwrap();
        assert_eq!(leaf.node_sum(), 40);
    }

    /// A tree persisted in one store instance is readable from a fresh
    /// instance over the same namespace.
    #[test]
    fn test_sqlite_tree_persistence() {
        let db = Arc::new(SqliteDb::open_in_memory().unwrap());

        {
            let store = SqliteTreeStore::new(Arc::clone(&db), "persist-ns");
            let mut tree = CompactedTree::new(store);
            tree.insert(make_key(1), LeafNode::new(vec![1], 100)).unwrap();
            tree.insert(make_key(2), LeafNode::new(vec![2], 200)).unwrap();
            assert!(tree.store.take_error().is_none());
        }

        let store = SqliteTreeStore::new(Arc::clone(&db), "persist-ns");
        let tree = CompactedTree::new(store);
        let root = tree.root().unwrap();
        assert_eq!(root.node_sum(), 300);
        assert_eq!(tree.get(make_key(2)).unwrap().node_sum(), 200);
    }

    /// Namespaces are isolated.
    #[test]
    fn test_sqlite_tree_namespaces_isolated() {
        let db = Arc::new(SqliteDb::open_in_memory().unwrap());

        let mut tree_a =
            CompactedTree::new(SqliteTreeStore::new(Arc::clone(&db), "ns-a"));
        tree_a.insert(make_key(1), LeafNode::new(vec![1], 100)).unwrap();

        let tree_b = CompactedTree::new(SqliteTreeStore::new(Arc::clone(&db), "ns-b"));
        assert_eq!(tree_b.root().unwrap().node_sum(), 0);
    }

    /// Copying a persistent tree into memory preserves the root.
    #[test]
    fn test_copy_tree_store_from_sqlite() {
        let db = Arc::new(SqliteDb::open_in_memory().unwrap());
        let mut tree =
            CompactedTree::new(SqliteTreeStore::new(Arc::clone(&db), "copy-ns"));
        for i in 0..5u8 {
            tree.insert(make_key(i), LeafNode::new(vec![i], 10)).unwrap();
        }

        let mut memory = DefaultStore::new();
        copy_tree_store(&tree.store, &mut memory).unwrap();
        let copied = CompactedTree::new(memory);
        assert_eq!(
            copied.root().unwrap().node_hash(),
            tree.root().unwrap().node_hash()
        );
        assert_eq!(copied.root().unwrap().node_sum(), 50);

        // The copy is a snapshot: mutating it does not affect the
        // original.
        let mut copied = copied;
        copied.insert(make_key(9), LeafNode::new(vec![9], 5)).unwrap();
        assert_eq!(tree.root().unwrap().node_sum(), 50);
    }

    /// Deleting a leaf updates the persistent root.
    #[test]
    fn test_sqlite_tree_delete() {
        let db = Arc::new(SqliteDb::open_in_memory().unwrap());
        let mut tree =
            CompactedTree::new(SqliteTreeStore::new(Arc::clone(&db), "del-ns"));
        tree.insert(make_key(1), LeafNode::new(vec![1], 100)).unwrap();
        tree.insert(make_key(2), LeafNode::new(vec![2], 200)).unwrap();
        tree.delete(make_key(1)).unwrap();
        assert_eq!(tree.root().unwrap().node_sum(), 200);
    }
}
