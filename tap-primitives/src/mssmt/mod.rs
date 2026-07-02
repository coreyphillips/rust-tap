// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Merkle-Sum Sparse Merkle Tree (MS-SMT) implementation.
//!
//! An MS-SMT is a 256-level sparse Merkle tree where each node carries a sum
//! value in addition to a hash. The sum aggregates up the tree, enabling
//! efficient proofs of total supply (asset conservation).
//!
//! # Modules
//!
//! - [`node`]: Node types (`LeafNode`, `BranchNode`, `CompactedLeafNode`, `ComputedNode`)
//! - [`store`]: Storage abstraction (`TreeStoreViewTx`, `TreeStoreUpdateTx`, `DefaultStore`)
//! - [`tree`]: Full tree implementation (`FullTree`)
//! - [`proof`]: Merkle proofs (`Proof`, `CompressedProof`)

pub mod compacted_tree;
pub mod node;
pub mod proof;
pub mod store;
pub mod tree;

// Re-export key types for convenience.
pub use compacted_tree::CompactedTree;
pub use node::{
    bit_index, empty_tree, empty_tree_root_hash, is_equal_node, BranchNode,
    CompactedLeafNode, ComputedNode, LeafNode, Node, NodeHash, HASH_SIZE,
    LAST_BIT_INDEX, MAX_TREE_LEVELS,
};
pub use proof::{CompressedProof, Proof};
pub use store::{
    copy_tree_store, DefaultStore, StoreError, TreeStoreUpdateTx,
    TreeStoreViewTx,
};
pub use tree::{verify_merkle_proof, FullTree, TreeError};
