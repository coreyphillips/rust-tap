// Property-based tests for the MS-SMT implementation.

use proptest::prelude::*;
use tap_primitives::mssmt::*;

/// Generates a random 32-byte key.
fn arb_key() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>())
}

/// Generates a random leaf sum (non-zero to avoid empty-leaf semantics).
fn arb_sum() -> impl Strategy<Value = u64> {
    1..=10_000u64
}

proptest! {
    /// Root sum equals sum of all inserted leaf sums.
    #[test]
    fn root_sum_equals_leaf_sum(
        entries in prop::collection::vec((arb_key(), arb_sum()), 1..20)
    ) {
        let mut tree = FullTree::new(DefaultStore::new());

        for (key, sum) in &entries {
            let leaf = LeafNode::new(sum.to_be_bytes().to_vec(), *sum);
            tree.insert(*key, leaf).unwrap();
        }

        // Compute expected sum with last-write-wins semantics.
        let mut seen = std::collections::HashMap::new();
        for (key, sum) in &entries {
            seen.insert(*key, *sum);
        }
        let expected_sum: u64 = seen.values().sum();

        let root = tree.root().unwrap();
        prop_assert_eq!(root.node_sum(), expected_sum);
    }

    /// Inserting then deleting all leaves returns to empty root.
    #[test]
    fn insert_delete_returns_to_empty(
        entries in prop::collection::vec((arb_key(), arb_sum()), 1..20)
    ) {
        let mut tree = FullTree::new(DefaultStore::new());
        let empty_root = tree.root().unwrap().node_hash();

        // Insert all.
        let mut unique_keys = std::collections::HashSet::new();
        for (key, sum) in &entries {
            let leaf = LeafNode::new(sum.to_be_bytes().to_vec(), *sum);
            tree.insert(*key, leaf).unwrap();
            unique_keys.insert(*key);
        }

        // Delete all.
        for key in unique_keys {
            tree.delete(key).unwrap();
        }

        let final_root = tree.root().unwrap().node_hash();
        prop_assert_eq!(final_root, empty_root);
    }

    /// Merkle proof verifies for any inserted leaf.
    #[test]
    fn merkle_proof_verifies(
        entries in prop::collection::vec((arb_key(), arb_sum()), 1..20),
        target_idx in any::<prop::sample::Index>(),
    ) {
        let mut tree = FullTree::new(DefaultStore::new());
        let mut unique = std::collections::HashMap::new();

        for (key, sum) in &entries {
            let leaf = LeafNode::new(sum.to_be_bytes().to_vec(), *sum);
            tree.insert(*key, leaf.clone()).unwrap();
            unique.insert(*key, leaf);
        }

        if unique.is_empty() {
            return Ok(());
        }

        let keys: Vec<[u8; 32]> = unique.keys().cloned().collect();
        let target_key = keys[target_idx.index(keys.len())];
        let target_leaf = unique[&target_key].clone();

        let proof = tree.merkle_proof(target_key).unwrap();
        let root = tree.root().unwrap();
        let root_node = Node::Branch(root);

        prop_assert!(verify_merkle_proof(
            target_key,
            &target_leaf,
            &proof,
            &root_node,
        ));
    }

    /// Compacted tree produces the same root hash as the full tree.
    #[test]
    fn compacted_matches_full(
        entries in prop::collection::vec((arb_key(), arb_sum()), 1..30)
    ) {
        let mut full_tree = FullTree::new(DefaultStore::new());
        let mut compacted_tree = CompactedTree::new(DefaultStore::new());

        for (key, sum) in &entries {
            let leaf = LeafNode::new(sum.to_be_bytes().to_vec(), *sum);
            full_tree.insert(*key, leaf.clone()).unwrap();
            compacted_tree.insert(*key, leaf).unwrap();
        }

        let full_root = full_tree.root().unwrap();
        let compacted_root = compacted_tree.root().unwrap();

        prop_assert_eq!(full_root.node_hash(), compacted_root.node_hash());
        prop_assert_eq!(full_root.node_sum(), compacted_root.node_sum());
    }
}
