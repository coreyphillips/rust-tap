// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Storage backends for the MS-SMT.
//!
//! The [`TreeStore`] trait abstracts over storage, using a view/update
//! transaction model. [`DefaultStore`] provides an in-memory implementation
//! backed by `HashMap`s.

use std::collections::HashMap;

use super::node::*;

/// Errors that can occur during tree store operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// A node was not found in the store.
    NodeNotFound,
    /// Generic store error.
    Other(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::NodeNotFound => write!(f, "node not found in store"),
            StoreError::Other(msg) => write!(f, "store error: {}", msg),
        }
    }
}

impl std::error::Error for StoreError {}

/// Read-only view of the tree store.
pub trait TreeStoreViewTx {
    /// Returns the left and right children of the node at the given height
    /// with the given hash.
    fn get_children(
        &self,
        height: usize,
        hash: &NodeHash,
    ) -> Result<(Node, Node), StoreError>;

    /// Returns the root node of the tree.
    fn root_node(&self) -> Result<Node, StoreError>;
}

/// Read-write view of the tree store.
pub trait TreeStoreUpdateTx: TreeStoreViewTx {
    fn update_root(&mut self, node: &BranchNode);
    fn insert_branch(&mut self, node: &BranchNode);
    fn insert_leaf(&mut self, node: &LeafNode);
    fn insert_compacted_leaf(&mut self, node: &CompactedLeafNode);
    fn delete_branch(&mut self, hash: &NodeHash);
    fn delete_leaf(&mut self, hash: &NodeHash);
    fn delete_compacted_leaf(&mut self, hash: &NodeHash);
    fn delete_root(&mut self);
    fn delete_all_nodes(&mut self);
}

/// An in-memory tree store backed by `HashMap`s.
///
/// This mirrors the Go `DefaultStore` and is suitable for testing and
/// ephemeral use. For persistence, implement [`TreeStoreViewTx`] and
/// [`TreeStoreUpdateTx`] over a database.
#[derive(Clone, Debug)]
pub struct DefaultStore {
    branches: HashMap<NodeHash, BranchNode>,
    leaves: HashMap<NodeHash, LeafNode>,
    compacted_leaves: HashMap<NodeHash, CompactedLeafNode>,
    root: Option<BranchNode>,
}

impl DefaultStore {
    pub fn new() -> Self {
        DefaultStore {
            branches: HashMap::new(),
            leaves: HashMap::new(),
            compacted_leaves: HashMap::new(),
            root: None,
        }
    }
}

impl Default for DefaultStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DefaultStore {
    /// Look up a node by hash at the given height.
    fn get_node(&self, height: usize, hash: &NodeHash) -> Node {
        let empty = empty_tree();

        if *hash == empty[height].node_hash() {
            return empty[height].clone();
        }

        if let Some(branch) = self.branches.get(hash) {
            return Node::Branch(branch.clone());
        }

        if let Some(cl) = self.compacted_leaves.get(hash) {
            return Node::Compacted(cl.clone());
        }

        if let Some(leaf) = self.leaves.get(hash) {
            return Node::Leaf(leaf.clone());
        }

        empty[height].clone()
    }
}

impl TreeStoreViewTx for DefaultStore {
    fn get_children(
        &self,
        height: usize,
        hash: &NodeHash,
    ) -> Result<(Node, Node), StoreError> {
        let empty = empty_tree();

        // If the hash matches the empty tree node at this height, return
        // empty children at height+1.
        if *hash == empty[height].node_hash() {
            let child = &empty[height + 1];
            return Ok((child.clone(), child.clone()));
        }

        // Look up the node by its hash.
        let node = self.get_node(height, hash);

        // If we didn't find a real node (got empty back), error.
        if *hash != empty[height].node_hash()
            && node.node_hash() == empty[height].node_hash()
        {
            return Err(StoreError::NodeNotFound);
        }

        // Only branch nodes have children we can return.
        match &node {
            Node::Branch(branch) => {
                let left = self.get_node(height + 1, &branch.left.node_hash());
                let right =
                    self.get_node(height + 1, &branch.right.node_hash());
                Ok((left, right))
            }
            _ => Err(StoreError::NodeNotFound),
        }
    }

    fn root_node(&self) -> Result<Node, StoreError> {
        match &self.root {
            Some(root) => Ok(Node::Branch(root.clone())),
            None => Ok(empty_tree()[0].clone()),
        }
    }
}

impl TreeStoreUpdateTx for DefaultStore {
    fn update_root(&mut self, node: &BranchNode) {
        self.root = Some(node.clone());
    }

    fn insert_branch(&mut self, node: &BranchNode) {
        self.branches.insert(node.node_hash(), node.clone());
    }

    fn insert_leaf(&mut self, node: &LeafNode) {
        self.leaves.insert(node.node_hash(), node.clone());
    }

    fn insert_compacted_leaf(&mut self, node: &CompactedLeafNode) {
        self.compacted_leaves
            .insert(node.node_hash(), node.clone());
    }

    fn delete_branch(&mut self, hash: &NodeHash) {
        self.branches.remove(hash);
    }

    fn delete_leaf(&mut self, hash: &NodeHash) {
        self.leaves.remove(hash);
    }

    fn delete_compacted_leaf(&mut self, hash: &NodeHash) {
        self.compacted_leaves.remove(hash);
    }

    fn delete_root(&mut self) {
        self.root = None;
    }

    fn delete_all_nodes(&mut self) {
        self.branches.clear();
        self.leaves.clear();
        self.compacted_leaves.clear();
        self.root = None;
    }
}
