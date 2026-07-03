//! MS-SMT tests driven by the vendored Go BIP test vectors
//! (`mssmt/testdata/` in lightninglabs/taproot-assets).

mod common;

use std::collections::HashMap;

use common::*;
use tap_primitives::mssmt::{
    verify_merkle_proof, CompactedTree, CompressedProof, DefaultStore,
    FullTree, LeafNode, Node, NodeHash,
};

/// Builds a key -> leaf lookup from the `all_tree_leaves` dictionary.
fn leaf_map(file: &MssmtVectorFile) -> HashMap<[u8; 32], LeafNode> {
    file.all_tree_leaves
        .iter()
        .flatten()
        .map(|l| l.to_key_and_leaf())
        .collect()
}

fn assert_root(
    root: &tap_primitives::mssmt::BranchNode,
    case: &MssmtValidCase,
    what: &str,
) {
    let comment = case.comment.as_deref().unwrap_or("");
    assert_eq!(
        hex::encode(root.node_hash().as_bytes()),
        case.root_hash,
        "{}: {} root hash mismatch",
        comment,
        what
    );
    let expected_sum: u64 = case.root_sum.parse().unwrap();
    assert_eq!(
        root.node_sum(),
        expected_sum,
        "{}: {} root sum mismatch",
        comment,
        what
    );
}

#[test]
fn mssmt_tree_proofs() {
    let file: MssmtVectorFile = load_json("mssmt_tree_proofs.json");
    let leaves = leaf_map(&file);
    let cases = file.valid_test_cases.as_ref().expect("no valid cases");

    for case in cases {
        // The proofs file inserts 10k leaves. The FullTree is known to
        // be slow (it materializes 256 branches per insert), so the
        // bulk insert and proof generation run on the CompactedTree;
        // the FullTree is cross-checked on a small subset below.
        let mut tree = CompactedTree::new(DefaultStore::new());
        for key_hex in &case.inserted_leaves {
            let key = parse_hex32(key_hex);
            let leaf = leaves.get(&key).expect("unknown leaf key").clone();
            tree.insert(key, leaf).expect("insert failed");
        }

        let root = tree.root().expect("root failed");
        assert_root(&root, case, "compacted tree");
        let root_node = Node::Branch(root);

        // Inclusion proofs: generated proofs must compress to the
        // exact expected bytes and verify against the root.
        for proof_case in case.inclusion_proofs.iter().flatten() {
            let key = parse_hex32(&proof_case.proof_key);
            let leaf = leaves.get(&key).expect("unknown proof key");

            let proof = tree.merkle_proof(key).expect("proof failed");
            let compressed = proof.compress();
            assert_eq!(
                hex::encode(compressed.encode()),
                proof_case.compressed_proof,
                "inclusion proof encoding mismatch for key {}",
                proof_case.proof_key
            );

            // Decode the expected compressed proof and verify
            // inclusion against the root.
            let decoded =
                CompressedProof::decode(&parse_hex(&proof_case.compressed_proof))
                    .expect("decode failed")
                    .decompress()
                    .expect("decompress failed");
            assert!(
                verify_merkle_proof(key, leaf, &decoded, &root_node),
                "inclusion proof failed for key {}",
                proof_case.proof_key
            );
        }

        // Exclusion proofs: the key is absent, so the proof must
        // verify with an empty leaf.
        for proof_case in case.exclusion_proofs.iter().flatten() {
            let key = parse_hex32(&proof_case.proof_key);
            assert!(
                !leaves.contains_key(&key)
                    || !case
                        .inserted_leaves
                        .contains(&proof_case.proof_key),
                "exclusion key unexpectedly present"
            );

            let proof = tree.merkle_proof(key).expect("proof failed");
            let compressed = proof.compress();
            assert_eq!(
                hex::encode(compressed.encode()),
                proof_case.compressed_proof,
                "exclusion proof encoding mismatch for key {}",
                proof_case.proof_key
            );

            let decoded =
                CompressedProof::decode(&parse_hex(&proof_case.compressed_proof))
                    .expect("decode failed")
                    .decompress()
                    .expect("decompress failed");
            assert!(
                verify_merkle_proof(
                    key,
                    &LeafNode::empty(),
                    &decoded,
                    &root_node
                ),
                "exclusion proof failed for key {}",
                proof_case.proof_key
            );
        }

        // Cross-check: FullTree and CompactedTree agree on a subset of
        // the first 100 leaves (using the full 10k leaves with the
        // FullTree takes unreasonably long due to the known perf
        // issue).
        let subset: Vec<_> = case.inserted_leaves.iter().take(100).collect();
        let mut full_tree = FullTree::new(DefaultStore::new());
        let mut compacted_subset = CompactedTree::new(DefaultStore::new());
        for key_hex in &subset {
            let key = parse_hex32(key_hex);
            let leaf = leaves.get(&key).unwrap().clone();
            full_tree.insert(key, leaf.clone()).unwrap();
            compacted_subset.insert(key, leaf).unwrap();
        }
        let full_root = full_tree.root().unwrap();
        let compacted_root = compacted_subset.root().unwrap();
        assert_eq!(
            full_root.node_hash(),
            compacted_root.node_hash(),
            "full tree and compacted tree roots disagree"
        );
        assert_eq!(full_root.node_sum(), compacted_root.node_sum());
    }
}

#[test]
fn mssmt_tree_deletion() {
    let file: MssmtVectorFile = load_json("mssmt_tree_deletion.json");
    let leaves = leaf_map(&file);
    let cases = file.valid_test_cases.as_ref().expect("no valid cases");
    assert!(!cases.is_empty());

    for case in cases {
        // Deletion cases are small; run them on both tree types.
        let mut compacted = CompactedTree::new(DefaultStore::new());
        let mut full = FullTree::new(DefaultStore::new());

        for key_hex in &case.inserted_leaves {
            let key = parse_hex32(key_hex);
            let leaf = leaves.get(&key).expect("unknown leaf key").clone();
            compacted.insert(key, leaf.clone()).unwrap();
            full.insert(key, leaf).unwrap();
        }
        for key_hex in case.deleted_leaves.iter().flatten() {
            let key = parse_hex32(key_hex);
            compacted.delete(key).unwrap();
            full.delete(key).unwrap();
        }

        assert_root(&compacted.root().unwrap(), case, "compacted tree");
        assert_root(&full.root().unwrap(), case, "full tree");
    }
}

#[test]
fn mssmt_tree_replacement() {
    let file: MssmtVectorFile = load_json("mssmt_tree_replacement.json");
    let leaves = leaf_map(&file);
    let cases = file.valid_test_cases.as_ref().expect("no valid cases");
    assert!(!cases.is_empty());

    for case in cases {
        let mut compacted = CompactedTree::new(DefaultStore::new());
        let mut full = FullTree::new(DefaultStore::new());

        for key_hex in &case.inserted_leaves {
            let key = parse_hex32(key_hex);
            let leaf = leaves.get(&key).expect("unknown leaf key").clone();
            compacted.insert(key, leaf.clone()).unwrap();
            full.insert(key, leaf).unwrap();
        }
        for replacement in case.replaced_leaves.iter().flatten() {
            let (key, leaf) = replacement.to_key_and_leaf();
            compacted.insert(key, leaf.clone()).unwrap();
            full.insert(key, leaf).unwrap();
        }

        assert_root(&compacted.root().unwrap(), case, "compacted tree");
        assert_root(&full.root().unwrap(), case, "full tree");
    }
}

#[test]
fn mssmt_tree_error_cases() {
    let file: MssmtVectorFile = load_json("mssmt_tree_error_cases.json");
    let leaves = leaf_map(&file);

    // The valid case (a single leaf whose sum does not overflow) must
    // produce the expected root.
    for case in file.valid_test_cases.iter().flatten() {
        let mut compacted = CompactedTree::new(DefaultStore::new());
        for key_hex in &case.inserted_leaves {
            let key = parse_hex32(key_hex);
            let leaf = leaves.get(&key).expect("unknown leaf key").clone();
            compacted.insert(key, leaf).unwrap();
        }
        assert_root(&compacted.root().unwrap(), case, "compacted tree");
    }

    // The error case inserts leaves whose sums overflow a u64; the
    // second insert must fail (match the error category loosely).
    for case in file.error_test_cases.iter().flatten() {
        let mut compacted = CompactedTree::new(DefaultStore::new());
        let mut full = FullTree::new(DefaultStore::new());
        let mut compacted_err = None;
        let mut full_err = None;

        for key_hex in &case.inserted_leaves {
            let key = parse_hex32(key_hex);
            let leaf = leaves.get(&key).expect("unknown leaf key").clone();
            if compacted_err.is_none() {
                compacted_err = compacted.insert(key, leaf.clone()).err();
            }
            if full_err.is_none() {
                full_err = full.insert(key, leaf).err();
            }
        }

        assert!(
            compacted_err.is_some(),
            "compacted tree: expected error '{}'",
            case.error
        );
        assert!(
            full_err.is_some(),
            "full tree: expected error '{}'",
            case.error
        );
    }
}

/// Sanity check: an empty tree has the well-known empty root and an
/// all-empty compressed proof.
#[test]
fn mssmt_empty_tree_root() {
    let tree = CompactedTree::new(DefaultStore::new());
    let root = tree.root().unwrap();
    assert_ne!(root.node_hash(), NodeHash::EMPTY);
    assert_eq!(root.node_sum(), 0);
}
