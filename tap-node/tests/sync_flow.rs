// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Universe sync: a mock remote `DiffEngine` serving a real (vendored)
//! genesis proof; the node pulls, verifies, and persists the leaf.

mod common;

use common::*;

use tap_node::*;
use tap_primitives::proof::decode_proof;
use tap_primitives::proof::File;
use tap_universe::memory::MemoryUniverseBackend;
use tap_universe::traits::{DiffEngine, UniverseBackend};
use tap_universe::types::*;

/// A mock remote universe server wrapping an in-memory backend.
struct MockRemote {
    backend: MemoryUniverseBackend,
}

impl DiffEngine for MockRemote {
    fn root_node(
        &self,
        id: &UniverseId,
    ) -> Result<UniverseRoot, UniverseError> {
        self.backend.root_node(id)
    }

    fn root_nodes(
        &self,
        _query: &RootNodesQuery,
    ) -> Result<Vec<UniverseRoot>, UniverseError> {
        Ok(self.backend.all_roots())
    }

    fn universe_leaf_keys(
        &self,
        id: &UniverseId,
        query: &LeafKeysQuery,
    ) -> Result<Vec<LeafKey>, UniverseError> {
        self.backend.fetch_keys(id, query)
    }

    fn fetch_proof_leaf(
        &self,
        id: &UniverseId,
        key: &LeafKey,
    ) -> Result<Option<UniverseProof>, UniverseError> {
        self.backend.fetch_proof(id, key)
    }
}

/// Loads the vendored regtest proof file and builds a valid issuance
/// leaf from its genesis proof.
fn valid_leaf() -> (UniverseId, LeafKey, UniverseLeaf) {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tap-primitives/tests/testdata/proof-file.hex"
    );
    let hex = std::fs::read_to_string(path)
        .expect("vendored proof-file.hex must exist");
    let bytes: Vec<u8> = (0..hex.trim().len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex.trim()[i..i + 2], 16)
                .expect("valid hex")
        })
        .collect();
    let file = File::decode(&bytes).expect("valid proof file");
    let proof_bytes = file.proofs[0].proof_bytes.clone();
    let proof = decode_proof(&proof_bytes).expect("valid proof");

    let id = UniverseId {
        asset_id: proof.asset.id(),
        group_key: None,
        proof_type: ProofType::Issuance,
    };
    let key = LeafKey {
        outpoint: proof.out_point(),
        script_key: *proof.asset.script_key.serialized(),
    };
    let leaf = UniverseLeaf {
        asset_id: proof.asset.id(),
        amount: proof.asset.amount,
        proof: proof_bytes,
        key: key.clone(),
    };
    (id, key, leaf)
}

#[test]
fn test_sync_with_engine_persists_real_leaves() {
    let harness = default_harness();
    let node = &harness.node;

    // The remote serves one valid leaf and one garbage leaf.
    let (id, key, leaf) = valid_leaf();
    let bad_key = LeafKey {
        outpoint: tap_primitives::asset::OutPoint {
            txid: [0xBB; 32],
            vout: 9,
        },
        script_key: SerializedKey([0x02; 33]),
    };
    let bad_leaf = UniverseLeaf {
        asset_id: id.asset_id,
        amount: 5,
        proof: vec![0xDE, 0xAD],
        key: bad_key.clone(),
    };

    let mut backend = MemoryUniverseBackend::new();
    backend.upsert_proof_leaf(&id, &key, &leaf).expect("seed");
    backend
        .upsert_proof_leaf(&id, &bad_key, &bad_leaf)
        .expect("seed bad");
    let remote = MockRemote { backend };

    // Before the sync the node has no local root for this universe.
    assert!(node.universe_root(&id).is_err());

    let diffs = node.sync_with_engine(&remote).expect("sync");
    assert_eq!(diffs.len(), 1);
    assert_eq!(diffs[0].universe_id, id);
    // Only the verified leaf synced; the garbage one was rejected.
    assert_eq!(diffs[0].new_leaves.len(), 1);
    assert_eq!(diffs[0].new_leaves[0].asset_id, id.asset_id);

    // The leaf is persisted in the node's local universe store.
    let root = node.universe_root(&id).expect("local root");
    assert_eq!(root.root_sum, leaf.amount);

    // The sync completion event carries the real count.
    let events = harness.drain_events();
    assert!(events.iter().any(|e| matches!(
        e,
        TapEvent::UniverseSyncCompleted {
            new_assets_discovered: 1
        }
    )));

    // A second sync is a no-op (roots match).
    let diffs = node.sync_with_engine(&remote).expect("sync again");
    assert!(diffs.is_empty());
}

#[test]
fn test_sync_universe_no_servers_is_empty() {
    let harness = default_harness();
    let node = &harness.node;

    let diffs = node.sync_universe().expect("sync");
    assert!(diffs.is_empty());

    let events = harness.drain_events();
    assert!(events.iter().any(|e| matches!(
        e,
        TapEvent::UniverseSyncCompleted {
            new_assets_discovered: 0
        }
    )));
}

#[test]
fn test_universe_server_management() {
    let harness = default_harness();
    let node = &harness.node;

    assert!(node.list_universe_servers().expect("list").is_empty());
    node.add_universe_server("http://universe.test:8080")
        .expect("add");
    let servers = node.list_universe_servers().expect("list");
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].host, "http://universe.test:8080");
    node.remove_universe_server("http://universe.test:8080")
        .expect("remove");
    assert!(node.list_universe_servers().expect("list").is_empty());
}
