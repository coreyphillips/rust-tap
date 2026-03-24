// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Node types for the Merkle-Sum Sparse Merkle Tree (MS-SMT).
//!
//! The MS-SMT uses four node types:
//! - [`LeafNode`]: stores a value and a sum at tree depth 256
//! - [`BranchNode`]: internal node with left/right children, hash = SHA256(left_hash || right_hash || sum)
//! - [`CompactedLeafNode`]: optimization for sparse regions — stores a leaf at a higher level
//! - [`ComputedNode`]: precomputed hash+sum (used in proofs and the empty tree)

use bitcoin_hashes::{sha256, Hash, HashEngine};
use std::sync::OnceLock;

/// Size of a SHA-256 hash in bytes.
pub const HASH_SIZE: usize = 32;

/// Maximum depth of the MS-SMT (256 levels for a 32-byte key).
pub const MAX_TREE_LEVELS: usize = HASH_SIZE * 8;

/// Index of the last bit (leaf level).
pub const LAST_BIT_INDEX: usize = MAX_TREE_LEVELS - 1;

/// A 32-byte hash used as a node identifier in the MS-SMT.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct NodeHash(pub [u8; HASH_SIZE]);

impl NodeHash {
    pub const EMPTY: NodeHash = NodeHash([0u8; HASH_SIZE]);

    pub fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }
}

impl std::fmt::Debug for NodeHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NodeHash({})", crate::hex::encode(&self.0))
    }
}

impl AsRef<[u8]> for NodeHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Returns the bit at position `idx` in `key`.
///
/// Bit 0 is the LSB of byte 0, bit 8 is the LSB of byte 1, etc.
/// This matches the Go implementation's `bitIndex` function.
pub fn bit_index(idx: u8, key: &[u8; HASH_SIZE]) -> u8 {
    let byte_val = key[(idx / 8) as usize];
    (byte_val >> (idx % 8)) & 1
}

/// A node in the MS-SMT. Each node carries a hash and a sum value.
#[derive(Clone, Debug)]
pub enum Node {
    Leaf(LeafNode),
    Branch(BranchNode),
    Compacted(CompactedLeafNode),
    Computed(ComputedNode),
}

impl Node {
    /// Returns the SHA-256 hash commitment for this node.
    pub fn node_hash(&self) -> NodeHash {
        match self {
            Node::Leaf(n) => n.node_hash(),
            Node::Branch(n) => n.node_hash(),
            Node::Compacted(n) => n.node_hash(),
            Node::Computed(n) => n.node_hash(),
        }
    }

    /// Returns the sum commitment for this node.
    pub fn node_sum(&self) -> u64 {
        match self {
            Node::Leaf(n) => n.node_sum(),
            Node::Branch(n) => n.node_sum(),
            Node::Compacted(n) => n.node_sum(),
            Node::Computed(n) => n.node_sum(),
        }
    }

    /// Returns true if this node is an empty leaf (no value, zero sum).
    pub fn is_empty_leaf(&self) -> bool {
        match self {
            Node::Leaf(n) => n.is_empty(),
            _ => false,
        }
    }

    /// Returns a reference to the inner `BranchNode`, or `None`.
    pub fn as_branch(&self) -> Option<&BranchNode> {
        match self {
            Node::Branch(n) => Some(n),
            _ => None,
        }
    }

    /// Returns a reference to the inner `LeafNode`, or `None`.
    pub fn as_leaf(&self) -> Option<&LeafNode> {
        match self {
            Node::Leaf(n) => Some(n),
            _ => None,
        }
    }
}

impl PartialEq for Node {
    fn eq(&self, other: &Self) -> bool {
        self.node_hash() == other.node_hash() && self.node_sum() == other.node_sum()
    }
}

impl Eq for Node {}

/// A leaf node at the bottom of the tree (depth 256).
///
/// Hash = SHA256(value || big_endian_u64(sum))
#[derive(Clone, Debug)]
pub struct LeafNode {
    cached_hash: OnceLock<NodeHash>,
    pub value: Vec<u8>,
    pub sum: u64,
}

impl LeafNode {
    /// Creates a new leaf node with the given value and sum.
    pub fn new(value: Vec<u8>, sum: u64) -> Self {
        LeafNode {
            cached_hash: OnceLock::new(),
            value,
            sum,
        }
    }

    /// Returns the empty leaf node (no value, zero sum).
    pub fn empty() -> Self {
        LeafNode::new(Vec::new(), 0)
    }

    /// Returns true if this leaf has no value and zero sum.
    pub fn is_empty(&self) -> bool {
        self.value.is_empty() && self.sum == 0
    }

    pub fn node_hash(&self) -> NodeHash {
        *self.cached_hash.get_or_init(|| {
            let mut engine = sha256::HashEngine::default();
            engine.input(&self.value);
            engine.input(&self.sum.to_be_bytes());
            let hash = sha256::Hash::from_engine(engine);
            NodeHash(hash.to_byte_array())
        })
    }

    pub fn node_sum(&self) -> u64 {
        self.sum
    }
}

/// An internal branch node with two children.
///
/// Hash = SHA256(left_hash || right_hash || big_endian_u64(sum))
/// Sum = left.sum + right.sum
#[derive(Clone, Debug)]
pub struct BranchNode {
    cached_hash: OnceLock<NodeHash>,
    cached_sum: OnceLock<u64>,
    pub left: Box<Node>,
    pub right: Box<Node>,
}

impl BranchNode {
    /// Creates a new branch node with the given children.
    pub fn new(left: Node, right: Node) -> Self {
        BranchNode {
            cached_hash: OnceLock::new(),
            cached_sum: OnceLock::new(),
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    pub fn node_hash(&self) -> NodeHash {
        *self.cached_hash.get_or_init(|| {
            let left_hash = self.left.node_hash();
            let right_hash = self.right.node_hash();
            let mut engine = sha256::HashEngine::default();
            engine.input(left_hash.as_bytes());
            engine.input(right_hash.as_bytes());
            engine.input(&self.node_sum().to_be_bytes());
            let hash = sha256::Hash::from_engine(engine);
            NodeHash(hash.to_byte_array())
        })
    }

    pub fn node_sum(&self) -> u64 {
        *self.cached_sum.get_or_init(|| {
            self.left.node_sum() + self.right.node_sum()
        })
    }
}

/// A precomputed node with known hash and sum. Used in proofs and the empty tree.
#[derive(Clone, Debug)]
pub struct ComputedNode {
    pub hash: NodeHash,
    pub sum: u64,
}

impl ComputedNode {
    pub fn new(hash: NodeHash, sum: u64) -> Self {
        ComputedNode { hash, sum }
    }

    pub fn node_hash(&self) -> NodeHash {
        self.hash
    }

    pub fn node_sum(&self) -> u64 {
        self.sum
    }
}

/// A compacted leaf node that represents a leaf stored at a higher tree level.
///
/// In sparse regions, instead of storing the full path of empty branches down
/// to a single leaf, we store the leaf with its key at the compaction point.
/// The `compacted_hash` is the hash of the subtree root that would exist if
/// the full branch path were materialized.
#[derive(Clone, Debug)]
pub struct CompactedLeafNode {
    pub leaf: LeafNode,
    pub key: [u8; HASH_SIZE],
    compacted_hash: NodeHash,
}

impl CompactedLeafNode {
    /// Creates a new compacted leaf node at the given height.
    ///
    /// `height` is the level where this compacted node sits (0 = root, 255 = just above leaves).
    /// The compacted hash is computed by reconstructing the subtree from the leaf
    /// up to `height`, using empty nodes for all siblings.
    pub fn new(height: usize, key: &[u8; HASH_SIZE], leaf: LeafNode) -> Self {
        // Build the subtree hash from the leaf level up to `height`.
        let compacted_hash = Self::compute_compacted_hash(height, key, &leaf);
        CompactedLeafNode {
            leaf,
            key: *key,
            compacted_hash,
        }
    }

    fn compute_compacted_hash(
        height: usize,
        key: &[u8; HASH_SIZE],
        leaf: &LeafNode,
    ) -> NodeHash {
        let empty_tree = empty_tree();
        let mut current_hash = leaf.node_hash();
        let mut current_sum = leaf.node_sum();

        // Walk from the leaf level (LAST_BIT_INDEX) up to `height`.
        // At each level, the sibling is the empty tree node at that level + 1.
        for i in (height..=(LAST_BIT_INDEX)).rev() {
            let sibling_hash = empty_tree[i + 1].node_hash();
            let sibling_sum = empty_tree[i + 1].node_sum();

            let (left_hash, right_hash, left_sum, right_sum) =
                if bit_index(i as u8, key) == 0 {
                    (current_hash, sibling_hash, current_sum, sibling_sum)
                } else {
                    (sibling_hash, current_hash, sibling_sum, current_sum)
                };

            let sum = left_sum + right_sum;
            let mut engine = sha256::HashEngine::default();
            engine.input(left_hash.as_bytes());
            engine.input(right_hash.as_bytes());
            engine.input(&sum.to_be_bytes());
            current_hash = NodeHash(sha256::Hash::from_engine(engine).to_byte_array());
            current_sum = sum;
        }

        current_hash
    }

    /// Returns the compacted hash (the hash of the virtual subtree root).
    pub fn node_hash(&self) -> NodeHash {
        self.compacted_hash
    }

    pub fn node_sum(&self) -> u64 {
        self.leaf.node_sum()
    }

    pub fn key(&self) -> &[u8; HASH_SIZE] {
        &self.key
    }

    /// Extracts the full subtree from this compacted leaf, reconstructing
    /// branch nodes down from `height` to the leaf level.
    pub fn extract(&self, height: usize) -> Node {
        let empty_tree = empty_tree();
        let mut current: Node = Node::Leaf(self.leaf.clone());

        // Walk from the leaf level up to `height`, building branches.
        for i in (height..=(LAST_BIT_INDEX)).rev() {
            let sibling = empty_tree[i + 1].clone();
            let branch = if bit_index(i as u8, &self.key) == 0 {
                BranchNode::new(current, sibling)
            } else {
                BranchNode::new(sibling, current)
            };
            current = Node::Branch(branch);
        }

        current
    }
}

/// Returns a reference to the precomputed empty tree.
///
/// The empty tree has 257 entries (indices 0..=256):
/// - Index 256 = empty leaf
/// - Index i (0..256) = branch with both children being empty_tree[i+1]
pub fn empty_tree() -> &'static [Node] {
    use std::sync::LazyLock;

    static EMPTY_TREE: LazyLock<Vec<Node>> = LazyLock::new(|| {
        let mut tree = vec![Node::Leaf(LeafNode::empty()); MAX_TREE_LEVELS + 1];

        // Force computation of the empty leaf hash.
        tree[MAX_TREE_LEVELS].node_hash();

        // Build from the bottom up.
        for i in (0..MAX_TREE_LEVELS).rev() {
            let child_hash = tree[i + 1].node_hash();
            let child_sum = tree[i + 1].node_sum();
            // Both children are the same empty node, so use ComputedNode to
            // avoid deep recursive cloning.
            let child_computed =
                Node::Computed(ComputedNode::new(child_hash, child_sum));
            let branch = BranchNode::new(child_computed.clone(), child_computed);
            // Force hash computation so it's cached.
            branch.node_hash();
            branch.node_sum();
            tree[i] = Node::Branch(branch);
        }

        tree
    });

    &EMPTY_TREE
}

/// Returns the root hash of a completely empty MS-SMT.
pub fn empty_tree_root_hash() -> NodeHash {
    empty_tree()[0].node_hash()
}

/// Returns true if two nodes have identical hash and sum.
pub fn is_equal_node(a: &Node, b: &Node) -> bool {
    a.node_hash() == b.node_hash() && a.node_sum() == b.node_sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_leaf_hash_is_deterministic() {
        let leaf1 = LeafNode::empty();
        let leaf2 = LeafNode::empty();
        assert_eq!(leaf1.node_hash(), leaf2.node_hash());
        assert_eq!(leaf1.node_sum(), 0);
    }

    #[test]
    fn test_leaf_hash_includes_value_and_sum() {
        let a = LeafNode::new(vec![1, 2, 3], 100);
        let b = LeafNode::new(vec![1, 2, 3], 200);
        let c = LeafNode::new(vec![4, 5, 6], 100);
        assert_ne!(a.node_hash(), b.node_hash());
        assert_ne!(a.node_hash(), c.node_hash());
    }

    #[test]
    fn test_branch_hash_is_deterministic() {
        let left = Node::Leaf(LeafNode::new(vec![1], 10));
        let right = Node::Leaf(LeafNode::new(vec![2], 20));
        let branch1 = BranchNode::new(left.clone(), right.clone());
        let branch2 = BranchNode::new(left, right);
        assert_eq!(branch1.node_hash(), branch2.node_hash());
        assert_eq!(branch1.node_sum(), 30);
    }

    #[test]
    fn test_branch_sum_is_children_sum() {
        let left = Node::Leaf(LeafNode::new(vec![], 42));
        let right = Node::Leaf(LeafNode::new(vec![], 58));
        let branch = BranchNode::new(left, right);
        assert_eq!(branch.node_sum(), 100);
    }

    #[test]
    fn test_empty_tree_structure() {
        let tree = empty_tree();
        assert_eq!(tree.len(), MAX_TREE_LEVELS + 1);

        // The bottom level should be an empty leaf.
        assert!(tree[MAX_TREE_LEVELS].is_empty_leaf());

        // All sums should be zero.
        for node in tree.iter() {
            assert_eq!(node.node_sum(), 0);
        }

        // Root hash should be consistent.
        assert_eq!(tree[0].node_hash(), empty_tree_root_hash());
    }

    #[test]
    fn test_bit_index() {
        let mut key = [0u8; HASH_SIZE];
        key[0] = 0b10101010;
        assert_eq!(bit_index(0, &key), 0); // bit 0 = LSB = 0
        assert_eq!(bit_index(1, &key), 1); // bit 1 = 1
        assert_eq!(bit_index(2, &key), 0); // bit 2 = 0
        assert_eq!(bit_index(3, &key), 1); // bit 3 = 1
        assert_eq!(bit_index(7, &key), 1); // bit 7 = MSB = 1
    }

    #[test]
    fn test_compacted_leaf_hash_matches_extracted() {
        let key = [0xABu8; HASH_SIZE];
        let leaf = LeafNode::new(vec![1, 2, 3], 42);
        let height = 200;
        let compacted = CompactedLeafNode::new(height, &key, leaf);

        // Extract the full subtree and verify the root hash matches.
        let extracted = compacted.extract(height);
        assert_eq!(compacted.node_hash(), extracted.node_hash());
        assert_eq!(compacted.node_sum(), extracted.node_sum());
    }
}
