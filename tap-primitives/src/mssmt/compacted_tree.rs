// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Compacted MS-SMT implementation.
//!
//! A [`CompactedTree`] produces identical root hashes and proofs as
//! [`super::tree::FullTree`] but stores sparse subtrees as single
//! [`CompactedLeafNode`]s instead of materializing the full branch path.
//! This reduces storage from O(256) branches per leaf to O(1) for
//! isolated leaves in sparse regions.

use super::node::*;
use super::proof::Proof;
use super::store::*;
use super::tree::{check_sum_overflow_u64, TreeError};

/// A compacted Merkle-Sum Sparse Merkle Tree.
///
/// Functionally identical to [`super::tree::FullTree`] but much more
/// storage-efficient for sparse trees.
#[derive(Clone, Debug)]
pub struct CompactedTree<S: TreeStoreUpdateTx> {
    pub store: S,
}

impl<S: TreeStoreUpdateTx> CompactedTree<S> {
    pub fn new(store: S) -> Self {
        CompactedTree { store }
    }

    pub fn root(&self) -> Result<BranchNode, TreeError> {
        let root = self.store.root_node()?;
        match root {
            Node::Branch(b) => Ok(b),
            _ => Ok(empty_tree()[0].as_branch().expect("empty tree root is a branch").clone()),
        }
    }

    /// Inserts a leaf at the given key.
    pub fn insert(
        &mut self,
        key: [u8; HASH_SIZE],
        leaf: LeafNode,
    ) -> Result<(), TreeError> {
        let current_root = self.root()?;
        check_sum_overflow_u64(current_root.node_sum(), leaf.node_sum())?;

        let new_root =
            self.insert_at(&key, 0, &current_root, &leaf)?;
        self.store.update_root(&new_root);
        Ok(())
    }

    /// Deletes the leaf at the given key.
    pub fn delete(
        &mut self,
        key: [u8; HASH_SIZE],
    ) -> Result<(), TreeError> {
        let current_root = self.root()?;
        let new_root =
            self.insert_at(&key, 0, &current_root, &LeafNode::empty())?;
        self.store.update_root(&new_root);
        Ok(())
    }

    /// Returns the leaf at the given key.
    pub fn get(
        &self,
        key: [u8; HASH_SIZE],
    ) -> Result<LeafNode, TreeError> {
        self.walk_down(&key, |_, _, _, _| {})
    }

    /// Generates a Merkle proof for the leaf at the given key.
    pub fn merkle_proof(
        &self,
        key: [u8; HASH_SIZE],
    ) -> Result<Proof, TreeError> {
        let mut proof_nodes =
            vec![Node::Leaf(LeafNode::empty()); MAX_TREE_LEVELS];
        self.walk_down(&key, |i, _, sibling, _| {
            proof_nodes[MAX_TREE_LEVELS - 1 - i] = sibling.clone();
        })?;
        Ok(Proof::new(proof_nodes))
    }

    /// Walks down the tree, expanding compacted leaves as encountered.
    fn walk_down<F>(
        &self,
        key: &[u8; HASH_SIZE],
        mut iter: F,
    ) -> Result<LeafNode, TreeError>
    where
        F: FnMut(usize, &Node, &Node, &Node),
    {
        let mut current = self.store.root_node()?;

        let mut i = 0;
        while i <= LAST_BIT_INDEX {
            let (left, right) =
                self.store.get_children(i, &current.node_hash())?;

            let (mut next, mut sibling) = step_order(i, key, left, right);

            match &next {
                Node::Compacted(compacted) => {
                    // Expand the compacted leaf into its virtual
                    // subtree rooted at level i + 1 and continue the
                    // walk in memory. The extracted subtree only
                    // materializes branches along the compacted leaf's
                    // own key path; every sibling in it is an empty
                    // tree node. If the query key diverges from the
                    // compacted key at some level, the walk continues
                    // through empty tree nodes down to the (empty)
                    // leaf, which yields a correct non-inclusion proof.
                    next = compacted.extract(i + 1);

                    if let Node::Compacted(cs) = &sibling {
                        sibling = cs.extract(i + 1);
                    }

                    // Call iter for level i (the outer loop level).
                    iter(i, &next, &sibling, &current);
                    current = next;

                    // Walk the in-memory subtree from level i+1 down
                    // to the leaf level.
                    for j in (i + 1)..=LAST_BIT_INDEX {
                        let (left, right) = in_memory_children(j, &current);
                        let (n, s) = step_order(j, key, left, right);
                        iter(j, &n, &s, &current);
                        current = n;
                    }

                    return match current {
                        Node::Leaf(leaf) => Ok(leaf),
                        _ => Ok(LeafNode::empty()),
                    };
                }
                _ => {
                    iter(i, &next, &sibling, &current);
                    current = next;
                }
            }
            i += 1;
        }

        match current {
            Node::Leaf(leaf) => Ok(leaf),
            _ => Ok(LeafNode::empty()),
        }
    }

    /// Recursive insert at a given height.
    fn insert_at(
        &mut self,
        key: &[u8; HASH_SIZE],
        height: usize,
        root: &BranchNode,
        leaf: &LeafNode,
    ) -> Result<BranchNode, TreeError> {
        let empty = empty_tree();
        let (left, right) =
            self.store.get_children(height, &root.node_hash())?;

        let is_left = bit_index(height as u8, key) == 0;
        let (next, sibling) = if is_left {
            (left, right)
        } else {
            (right, left)
        };

        let next_height = height + 1;
        let new_node: Node;

        match &next {
            Node::Branch(branch) => {
                if is_equal_node(&next, &empty[next_height]) {
                    // Empty subtree — insert a compacted leaf.
                    if leaf.is_empty() {
                        new_node = empty[next_height].clone();
                    } else {
                        let cl = CompactedLeafNode::new(
                            next_height, key, leaf.clone(),
                        );
                        self.store.insert_compacted_leaf(&cl);
                        new_node = Node::Compacted(cl);
                    }
                } else {
                    // Non-empty branch — recurse deeper.
                    let new_branch =
                        self.insert_at(key, next_height, branch, leaf)?;
                    new_node = Node::Branch(new_branch);
                }
            }
            Node::Compacted(compacted) => {
                // Delete the old compacted leaf.
                self.store
                    .delete_compacted_leaf(&compacted.node_hash());

                if *key == compacted.key {
                    // Replacing an existing leaf at the same key.
                    if leaf.is_empty() {
                        new_node = empty[next_height].clone();
                    } else {
                        let cl = CompactedLeafNode::new(
                            next_height, key, leaf.clone(),
                        );
                        self.store.insert_compacted_leaf(&cl);
                        new_node = Node::Compacted(cl);
                    }
                } else {
                    // Different key — merge both leaves into a subtree.
                    if leaf.is_empty() {
                        // Inserting empty over a different key means
                        // we just re-insert the existing compacted leaf.
                        let cl = CompactedLeafNode::new(
                            next_height,
                            compacted.key(),
                            compacted.leaf.clone(),
                        );
                        self.store.insert_compacted_leaf(&cl);
                        new_node = Node::Compacted(cl);
                    } else {
                        let merged = self.merge(
                            next_height,
                            *key,
                            leaf,
                            *compacted.key(),
                            &compacted.leaf,
                        )?;
                        new_node = Node::Branch(merged);
                    }
                }
            }
            _ => {
                // Shouldn't happen — leaf or computed at non-leaf level.
                if leaf.is_empty() {
                    new_node = empty[next_height].clone();
                } else {
                    let cl = CompactedLeafNode::new(
                        next_height, key, leaf.clone(),
                    );
                    self.store.insert_compacted_leaf(&cl);
                    new_node = Node::Compacted(cl);
                }
            }
        }

        // Delete old root branch if it's not an empty tree node.
        if !is_equal_node(&Node::Branch(root.clone()), &empty[height]) {
            self.store.delete_branch(&root.node_hash());
        }

        // Create the new branch.
        let branch = if is_left {
            BranchNode::new(new_node, sibling)
        } else {
            BranchNode::new(sibling, new_node)
        };

        if !is_equal_node(&Node::Branch(branch.clone()), &empty[height]) {
            self.store.insert_branch(&branch);
        }

        Ok(branch)
    }

    /// Merges two leaves that share a common prefix into a subtree.
    fn merge(
        &mut self,
        height: usize,
        key1: [u8; HASH_SIZE],
        leaf1: &LeafNode,
        key2: [u8; HASH_SIZE],
        leaf2: &LeafNode,
    ) -> Result<BranchNode, TreeError> {
        let empty = empty_tree();

        // Find common prefix length starting from `height`.
        let mut common_prefix_len = height;
        for i in height..=LAST_BIT_INDEX {
            if bit_index(i as u8, &key1) == bit_index(i as u8, &key2) {
                common_prefix_len = i + 1;
            } else {
                break;
            }
        }

        // Create compacted leaves at the divergence point.
        let cl1 =
            CompactedLeafNode::new(common_prefix_len + 1, &key1, leaf1.clone());
        let cl2 =
            CompactedLeafNode::new(common_prefix_len + 1, &key2, leaf2.clone());
        self.store.insert_compacted_leaf(&cl1);
        self.store.insert_compacted_leaf(&cl2);

        // Create the branch at the divergence point.
        let (left, right) = if bit_index(common_prefix_len as u8, &key1) == 0 {
            (Node::Compacted(cl1), Node::Compacted(cl2))
        } else {
            (Node::Compacted(cl2), Node::Compacted(cl1))
        };
        let mut parent = BranchNode::new(left, right);
        self.store.insert_branch(&parent);

        // Walk back up to `height`, creating branches with empty siblings.
        for i in (height..common_prefix_len).rev() {
            let (left, right) = if bit_index(i as u8, &key1) == 0 {
                (Node::Branch(parent), empty[i + 1].clone())
            } else {
                (empty[i + 1].clone(), Node::Branch(parent))
            };
            parent = BranchNode::new(left, right);
            self.store.insert_branch(&parent);
        }

        Ok(parent)
    }
}

/// Returns the children (living at `level + 1`) of an in-memory node at
/// `level` inside an extracted compacted subtree.
///
/// Branches yield their actual children. Any other node kind here is by
/// construction an empty tree node (extract uses empty tree nodes for
/// all siblings, and the empty tree stores its children as computed
/// nodes), so its children are the empty nodes one level deeper.
fn in_memory_children(level: usize, node: &Node) -> (Node, Node) {
    if let Node::Branch(branch) = node {
        (*branch.left.clone(), *branch.right.clone())
    } else {
        let child = empty_tree()[level + 1].clone();
        (child.clone(), child)
    }
}

/// Selects next/sibling based on the key bit at the given height.
fn step_order(
    height: usize,
    key: &[u8; HASH_SIZE],
    left: Node,
    right: Node,
) -> (Node, Node) {
    if bit_index(height as u8, key) == 0 {
        (left, right)
    } else {
        (right, left)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mssmt::tree::{verify_merkle_proof, FullTree};

    fn make_key(byte: u8) -> [u8; HASH_SIZE] {
        let mut key = [0u8; HASH_SIZE];
        key[0] = byte;
        key
    }

    #[test]
    fn test_empty_compacted_tree() {
        let store = DefaultStore::new();
        let tree = CompactedTree::new(store);
        let root = tree.root().unwrap();
        assert_eq!(root.node_hash(), empty_tree_root_hash());
    }

    #[test]
    fn test_insert_and_get() {
        let mut tree = CompactedTree::new(DefaultStore::new());
        let key = make_key(0x42);
        let leaf = LeafNode::new(vec![1, 2, 3], 100);
        tree.insert(key, leaf.clone()).unwrap();

        let retrieved = tree.get(key).unwrap();
        assert_eq!(retrieved.node_hash(), leaf.node_hash());
        assert_eq!(retrieved.node_sum(), 100);
    }

    #[test]
    fn test_insert_multiple() {
        let mut tree = CompactedTree::new(DefaultStore::new());
        tree.insert(make_key(0x01), LeafNode::new(vec![1], 30))
            .unwrap();
        tree.insert(make_key(0x02), LeafNode::new(vec![2], 70))
            .unwrap();

        let root = tree.root().unwrap();
        assert_eq!(root.node_sum(), 100);
        assert_eq!(tree.get(make_key(0x01)).unwrap().node_sum(), 30);
        assert_eq!(tree.get(make_key(0x02)).unwrap().node_sum(), 70);
    }

    #[test]
    fn test_delete() {
        let mut tree = CompactedTree::new(DefaultStore::new());
        let key = make_key(0xAB);
        tree.insert(key, LeafNode::new(vec![1], 50)).unwrap();
        tree.delete(key).unwrap();

        assert_eq!(tree.root().unwrap().node_hash(), empty_tree_root_hash());
    }

    #[test]
    fn test_merkle_proof() {
        let mut tree = CompactedTree::new(DefaultStore::new());
        let key = make_key(0x42);
        let leaf = LeafNode::new(vec![1, 2, 3], 999);
        tree.insert(key, leaf.clone()).unwrap();

        let proof = tree.merkle_proof(key).unwrap();
        let root = tree.root().unwrap();
        assert!(verify_merkle_proof(
            key,
            &leaf,
            &proof,
            &Node::Branch(root),
        ));
    }

    #[test]
    fn test_same_root_as_full_tree() {
        // The critical property: CompactedTree and FullTree produce
        // identical root hashes for the same set of insertions.
        let mut compact = CompactedTree::new(DefaultStore::new());
        let mut full = FullTree::new(DefaultStore::new());

        let keys = [
            make_key(0x01),
            make_key(0x42),
            make_key(0xAB),
            make_key(0xFF),
        ];
        let values = [10u64, 20, 30, 40];

        for (key, val) in keys.iter().zip(values.iter()) {
            let leaf = LeafNode::new(vec![*val as u8], *val);
            compact.insert(*key, leaf.clone()).unwrap();
            full.insert(*key, leaf).unwrap();
        }

        assert_eq!(
            compact.root().unwrap().node_hash(),
            full.root().unwrap().node_hash(),
            "CompactedTree and FullTree must produce the same root hash"
        );
        assert_eq!(
            compact.root().unwrap().node_sum(),
            full.root().unwrap().node_sum(),
        );
    }

    #[test]
    fn test_proof_compatible_with_full_tree() {
        let mut compact = CompactedTree::new(DefaultStore::new());
        let mut full = FullTree::new(DefaultStore::new());

        let key = make_key(0x42);
        let leaf = LeafNode::new(vec![1], 100);
        compact.insert(key, leaf.clone()).unwrap();
        full.insert(key, leaf.clone()).unwrap();

        // Proof from compacted tree should verify against full tree root.
        let compact_proof = compact.merkle_proof(key).unwrap();
        let full_root = full.root().unwrap();
        assert!(verify_merkle_proof(
            key,
            &leaf,
            &compact_proof,
            &Node::Branch(full_root),
        ));

        // And vice versa.
        let full_proof = full.merkle_proof(key).unwrap();
        let compact_root = compact.root().unwrap();
        assert!(verify_merkle_proof(
            key,
            &leaf,
            &full_proof,
            &Node::Branch(compact_root),
        ));
    }

    #[test]
    fn test_insert_delete_insert() {
        let mut tree = CompactedTree::new(DefaultStore::new());
        let key = make_key(0xFF);
        tree.insert(key, LeafNode::new(vec![1], 100)).unwrap();
        tree.delete(key).unwrap();
        tree.insert(key, LeafNode::new(vec![2], 200)).unwrap();

        assert_eq!(tree.get(key).unwrap().node_sum(), 200);
        assert_eq!(tree.root().unwrap().node_sum(), 200);
    }

    #[test]
    fn test_many_inserts_match_full_tree() {
        let mut compact = CompactedTree::new(DefaultStore::new());
        let mut full = FullTree::new(DefaultStore::new());

        for i in 0..50u8 {
            let key = make_key(i);
            let leaf = LeafNode::new(vec![i], (i as u64 + 1) * 10);
            compact.insert(key, leaf.clone()).unwrap();
            full.insert(key, leaf).unwrap();
        }

        assert_eq!(
            compact.root().unwrap().node_hash(),
            full.root().unwrap().node_hash(),
        );
    }

    #[test]
    fn test_delete_one_of_two() {
        let mut tree = CompactedTree::new(DefaultStore::new());
        tree.insert(make_key(0x01), LeafNode::new(vec![1], 50))
            .unwrap();
        tree.insert(make_key(0x02), LeafNode::new(vec![2], 50))
            .unwrap();

        tree.delete(make_key(0x01)).unwrap();
        assert_eq!(tree.root().unwrap().node_sum(), 50);
        assert_eq!(tree.get(make_key(0x02)).unwrap().node_sum(), 50);
        assert!(tree.get(make_key(0x01)).unwrap().is_empty());
    }

    #[test]
    fn test_overflow_detection() {
        let mut tree = CompactedTree::new(DefaultStore::new());
        tree.insert(make_key(0x01), LeafNode::new(vec![1], u64::MAX))
            .unwrap();
        let result =
            tree.insert(make_key(0x02), LeafNode::new(vec![2], 1));
        assert!(result.is_err());
    }

    #[test]
    fn test_non_inclusion_proof() {
        let mut tree = CompactedTree::new(DefaultStore::new());
        tree.insert(make_key(0x01), LeafNode::new(vec![1], 50))
            .unwrap();

        let key2 = make_key(0x02);
        let proof = tree.merkle_proof(key2).unwrap();
        let root = tree.root().unwrap();

        // Non-inclusion: the leaf at key2 should be empty.
        assert!(verify_merkle_proof(
            key2,
            &LeafNode::empty(),
            &proof,
            &Node::Branch(root),
        ));
    }
}
