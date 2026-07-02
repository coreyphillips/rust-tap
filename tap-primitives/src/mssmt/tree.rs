// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Full (non-compacted) MS-SMT implementation.
//!
//! The [`FullTree`] stores every branch node explicitly. It is simpler than
//! [`super::compacted_tree::CompactedTree`] but uses more storage for sparse
//! trees.

use super::node::*;
use super::proof::Proof;
use super::store::*;

/// Errors that can occur during tree operations.
#[derive(Debug, Clone)]
pub enum TreeError {
    Store(StoreError),
    IntegerOverflow { root_sum: u64, leaf_sum: u64 },
}

impl std::fmt::Display for TreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TreeError::Store(e) => write!(f, "{}", e),
            TreeError::IntegerOverflow {
                root_sum,
                leaf_sum,
            } => write!(
                f,
                "integer overflow: root_sum={}, leaf_sum={}",
                root_sum, leaf_sum
            ),
        }
    }
}

impl std::error::Error for TreeError {}

impl From<StoreError> for TreeError {
    fn from(e: StoreError) -> Self {
        TreeError::Store(e)
    }
}

/// Checks if adding two u64 values would overflow.
pub fn check_sum_overflow_u64(a: u64, b: u64) -> Result<(), TreeError> {
    if a.checked_add(b).is_none() {
        Err(TreeError::IntegerOverflow {
            root_sum: a,
            leaf_sum: b,
        })
    } else {
        Ok(())
    }
}

/// Walks down the tree from root to the leaf at `key`, calling `iter` at each level.
///
/// Returns the leaf node found at the key position.
fn walk_down<S: TreeStoreViewTx, F>(
    store: &S,
    key: &[u8; HASH_SIZE],
    mut iter: F,
) -> Result<LeafNode, TreeError>
where
    F: FnMut(usize, &Node, &Node, &Node),
{
    let mut current = store.root_node()?;

    for i in 0..=LAST_BIT_INDEX {
        let (left, right) = store.get_children(i, &current.node_hash())?;

        let (next, sibling) = if bit_index(i as u8, key) == 0 {
            (left, right)
        } else {
            (right, left)
        };

        iter(i, &next, &sibling, &current);
        current = next;
    }

    match current {
        Node::Leaf(leaf) => Ok(leaf),
        // If the store returns a computed/branch at leaf level, treat as empty.
        _ => Ok(LeafNode::empty()),
    }
}

/// Walks up from a starting node to the root using the given siblings.
///
/// `siblings[0]` corresponds to level `LAST_BIT_INDEX`, `siblings[255]` to level 0.
fn walk_up<F>(
    key: &[u8; HASH_SIZE],
    start: Node,
    siblings: &[Node],
    mut iter: F,
) -> BranchNode
where
    F: FnMut(usize, &Node, &Node, &Node),
{
    let mut current = start;

    for i in (0..=LAST_BIT_INDEX).rev() {
        let sibling = &siblings[LAST_BIT_INDEX - i];
        let parent = if bit_index(i as u8, key) == 0 {
            BranchNode::new(current.clone(), sibling.clone())
        } else {
            BranchNode::new(sibling.clone(), current.clone())
        };
        let parent_node = Node::Branch(parent);
        iter(i, &current, sibling, &parent_node);
        current = parent_node;
    }

    match current {
        Node::Branch(branch) => branch,
        _ => unreachable!("walk_up always produces a branch at the root"),
    }
}

/// A full (non-compacted) Merkle-Sum Sparse Merkle Tree.
#[derive(Clone, Debug)]
pub struct FullTree<S: TreeStoreUpdateTx> {
    pub store: S,
}

impl<S: TreeStoreUpdateTx> FullTree<S> {
    /// Creates a new empty MS-SMT backed by the given store.
    pub fn new(store: S) -> Self {
        FullTree { store }
    }

    /// Returns the root node of the tree.
    pub fn root(&self) -> Result<BranchNode, TreeError> {
        let root = self.store.root_node()?;
        match root {
            Node::Branch(b) => Ok(b),
            _ => {
                // If the store returns an empty tree root, construct a branch.
                let empty = empty_tree();
                Ok(empty[0].as_branch().expect("empty tree root is a branch").clone())
            }
        }
    }

    /// Inserts a leaf node at the given key.
    ///
    /// Returns an error if the insertion would cause a sum overflow.
    pub fn insert(
        &mut self,
        key: [u8; HASH_SIZE],
        leaf: LeafNode,
    ) -> Result<(), TreeError> {
        // Check for sum overflow.
        let current_root = self.root()?;
        check_sum_overflow_u64(current_root.node_sum(), leaf.node_sum())?;

        let root = self.insert_inner(&key, &leaf)?;
        self.store.update_root(&root);

        // Store or delete the leaf.
        if leaf.is_empty() {
            // When deleting, we pass the key as a NodeHash for removal.
            // This matches Go behavior (minor: may be a no-op if keyed by hash).
            self.store.delete_leaf(&NodeHash(key));
        } else {
            self.store.insert_leaf(&leaf);
        }

        Ok(())
    }

    /// Deletes the leaf at the given key (inserts an empty leaf).
    pub fn delete(&mut self, key: [u8; HASH_SIZE]) -> Result<(), TreeError> {
        let root = self.insert_inner(&key, &LeafNode::empty())?;
        self.store.update_root(&root);
        self.store.delete_leaf(&NodeHash(key));
        Ok(())
    }

    /// Returns the leaf node at the given key, or an empty leaf if none exists.
    pub fn get(
        &self,
        key: [u8; HASH_SIZE],
    ) -> Result<LeafNode, TreeError> {
        walk_down(&self.store, &key, |_, _, _, _| {})
    }

    /// Generates a Merkle proof for the leaf at the given key.
    ///
    /// If no leaf exists at the key, the proof is a non-inclusion proof
    /// (the leaf in the proof will be empty).
    pub fn merkle_proof(
        &self,
        key: [u8; HASH_SIZE],
    ) -> Result<Proof, TreeError> {
        let mut proof_nodes = vec![Node::Leaf(LeafNode::empty()); MAX_TREE_LEVELS];
        walk_down(&self.store, &key, |i, _, sibling, _| {
            proof_nodes[MAX_TREE_LEVELS - 1 - i] = sibling.clone();
        })?;
        Ok(Proof::new(proof_nodes))
    }

    /// Internal insert: walks down collecting siblings, then walks up
    /// creating new branches.
    fn insert_inner(
        &mut self,
        key: &[u8; HASH_SIZE],
        leaf: &LeafNode,
    ) -> Result<BranchNode, TreeError> {
        let empty = empty_tree();

        // Walk down to collect siblings and previous parent hashes.
        let mut prev_parents = vec![NodeHash::EMPTY; MAX_TREE_LEVELS];
        let mut siblings = vec![Node::Leaf(LeafNode::empty()); MAX_TREE_LEVELS];

        walk_down(&self.store, key, |i, _, sibling, parent| {
            prev_parents[MAX_TREE_LEVELS - 1 - i] = parent.node_hash();
            siblings[MAX_TREE_LEVELS - 1 - i] = sibling.clone();
        })?;

        // Walk up, replacing old branches with new ones.
        let store = &mut self.store;
        let root = walk_up(
            key,
            Node::Leaf(leaf.clone()),
            &siblings,
            |i, _, _, parent| {
                let prev_parent = &prev_parents[MAX_TREE_LEVELS - 1 - i];
                if *prev_parent != empty[i].node_hash() {
                    store.delete_branch(prev_parent);
                }
                if parent.node_hash() != empty[i].node_hash() {
                    if let Some(branch) = parent.as_branch() {
                        store.insert_branch(branch);
                    }
                }
            },
        );

        Ok(root)
    }
}

/// Verifies that the given proof correctly maps the leaf at `key` to the
/// expected root.
pub fn verify_merkle_proof(
    key: [u8; HASH_SIZE],
    leaf: &LeafNode,
    proof: &Proof,
    root: &Node,
) -> bool {
    let computed_root = proof.root(&key, &Node::Leaf(leaf.clone()));
    is_equal_node(&Node::Branch(computed_root), root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(byte: u8) -> [u8; HASH_SIZE] {
        let mut key = [0u8; HASH_SIZE];
        key[0] = byte;
        key
    }

    #[test]
    fn test_empty_tree_root() {
        let store = DefaultStore::new();
        let tree = FullTree::new(store);
        let root = tree.root().unwrap();
        assert_eq!(root.node_hash(), empty_tree_root_hash());
        assert_eq!(root.node_sum(), 0);
    }

    #[test]
    fn test_insert_and_get() {
        let store = DefaultStore::new();
        let mut tree = FullTree::new(store);

        let key = make_key(0x01);
        let leaf = LeafNode::new(vec![42], 100);
        tree.insert(key, leaf.clone()).unwrap();

        let retrieved = tree.get(key).unwrap();
        assert_eq!(retrieved.node_hash(), leaf.node_hash());
        assert_eq!(retrieved.node_sum(), 100);

        // Root sum should reflect the inserted leaf.
        let root = tree.root().unwrap();
        assert_eq!(root.node_sum(), 100);
    }

    #[test]
    fn test_insert_multiple() {
        let store = DefaultStore::new();
        let mut tree = FullTree::new(store);

        let key1 = make_key(0x01);
        let key2 = make_key(0x02);
        tree.insert(key1, LeafNode::new(vec![1], 30)).unwrap();
        tree.insert(key2, LeafNode::new(vec![2], 70)).unwrap();

        let root = tree.root().unwrap();
        assert_eq!(root.node_sum(), 100);

        assert_eq!(tree.get(key1).unwrap().node_sum(), 30);
        assert_eq!(tree.get(key2).unwrap().node_sum(), 70);
    }

    #[test]
    fn test_delete() {
        let store = DefaultStore::new();
        let mut tree = FullTree::new(store);

        let key = make_key(0xAB);
        tree.insert(key, LeafNode::new(vec![1], 50)).unwrap();
        assert_eq!(tree.root().unwrap().node_sum(), 50);

        tree.delete(key).unwrap();
        assert_eq!(tree.root().unwrap().node_sum(), 0);
        assert_eq!(tree.root().unwrap().node_hash(), empty_tree_root_hash());
    }

    #[test]
    fn test_merkle_proof_inclusion() {
        let store = DefaultStore::new();
        let mut tree = FullTree::new(store);

        let key = make_key(0x42);
        let leaf = LeafNode::new(vec![1, 2, 3], 999);
        tree.insert(key, leaf.clone()).unwrap();

        let proof = tree.merkle_proof(key).unwrap();
        let root = tree.root().unwrap();
        assert!(verify_merkle_proof(
            key,
            &leaf,
            &proof,
            &Node::Branch(root)
        ));
    }

    #[test]
    fn test_merkle_proof_non_inclusion() {
        let store = DefaultStore::new();
        let mut tree = FullTree::new(store);

        let key1 = make_key(0x01);
        tree.insert(key1, LeafNode::new(vec![1], 50)).unwrap();

        // Proof for a key that was NOT inserted.
        let key2 = make_key(0x02);
        let proof = tree.merkle_proof(key2).unwrap();
        let root = tree.root().unwrap();
        // The proof should verify with an empty leaf.
        assert!(verify_merkle_proof(
            key2,
            &LeafNode::empty(),
            &proof,
            &Node::Branch(root)
        ));
    }

    #[test]
    fn test_insert_delete_insert() {
        let store = DefaultStore::new();
        let mut tree = FullTree::new(store);

        let key = make_key(0xFF);
        tree.insert(key, LeafNode::new(vec![1], 100)).unwrap();
        tree.delete(key).unwrap();
        tree.insert(key, LeafNode::new(vec![2], 200)).unwrap();

        assert_eq!(tree.get(key).unwrap().node_sum(), 200);
        assert_eq!(tree.root().unwrap().node_sum(), 200);
    }

    #[test]
    fn test_root_hash_deterministic() {
        // Two trees with the same insertions should have the same root.
        let mut tree1 = FullTree::new(DefaultStore::new());
        let mut tree2 = FullTree::new(DefaultStore::new());

        let keys: Vec<_> = (0..10u8).map(make_key).collect();
        for (i, key) in keys.iter().enumerate() {
            let leaf = LeafNode::new(vec![i as u8], (i as u64 + 1) * 10);
            tree1.insert(*key, leaf.clone()).unwrap();
            tree2.insert(*key, leaf).unwrap();
        }

        assert_eq!(
            tree1.root().unwrap().node_hash(),
            tree2.root().unwrap().node_hash()
        );
    }

    #[test]
    fn test_overflow_detection() {
        let store = DefaultStore::new();
        let mut tree = FullTree::new(store);

        let key1 = make_key(0x01);
        tree.insert(key1, LeafNode::new(vec![1], u64::MAX)).unwrap();

        let key2 = make_key(0x02);
        let result = tree.insert(key2, LeafNode::new(vec![2], 1));
        assert!(result.is_err());
    }
}
