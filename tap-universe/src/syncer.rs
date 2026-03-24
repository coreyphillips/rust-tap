// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Simple universe syncer.
//!
//! Compares local and remote universe roots, identifies missing leaves,
//! and inserts them locally. Matches the Go `SimpleSyncer` pattern.

use std::collections::HashSet;

use crate::traits::{DiffEngine, Syncer, UniverseBackend};
use crate::types::*;

/// A simple syncer that diffs roots then fetches missing leaves.
pub struct SimpleSyncer<'a, B: UniverseBackend> {
    local: &'a mut B,
}

impl<'a, B: UniverseBackend> SimpleSyncer<'a, B> {
    /// Creates a new syncer with a mutable reference to local storage.
    pub fn new(local: &'a mut B) -> Self {
        SimpleSyncer { local }
    }
}

impl<B: UniverseBackend> Syncer for SimpleSyncer<'_, B> {
    fn sync_universe(
        &self,
        remote: &dyn DiffEngine,
        id: &UniverseId,
    ) -> Result<AssetSyncDiff, UniverseError> {
        // Step 1: Compare roots.
        let remote_root = remote.root_node(id)?;
        let local_root = self.local.root_node(id);

        // If local root matches remote, nothing to sync.
        if let Ok(ref lr) = local_root {
            if lr.root_hash == remote_root.root_hash
                && lr.root_sum == remote_root.root_sum
            {
                return Ok(AssetSyncDiff {
                    universe_id: id.clone(),
                    new_leaves: vec![],
                });
            }
        }

        // Step 2: Fetch all remote leaf keys.
        let remote_keys = remote.universe_leaf_keys(
            id,
            &LeafKeysQuery::default(),
        )?;

        // Step 3: Determine which leaves we're missing locally.
        let local_keys: HashSet<LeafKey> = self
            .local
            .fetch_keys(id, &LeafKeysQuery::default())
            .unwrap_or_default()
            .into_iter()
            .collect();

        let missing_keys: Vec<&LeafKey> = remote_keys
            .iter()
            .filter(|k| !local_keys.contains(k))
            .collect();

        // Step 4: Fetch missing proofs from remote and insert locally.
        let mut new_leaves = Vec::new();
        for key in missing_keys {
            if let Some(proof) = remote.fetch_proof_leaf(id, key)? {
                new_leaves.push(proof.leaf);
            }
        }

        Ok(AssetSyncDiff {
            universe_id: id.clone(),
            new_leaves,
        })
    }
}

/// Syncs all universes from a remote, comparing root nodes first.
///
/// Returns diffs for all universes that had changes.
pub fn sync_all<B: UniverseBackend>(
    local: &mut B,
    remote: &dyn DiffEngine,
    sync_type: SyncType,
) -> Result<Vec<AssetSyncDiff>, UniverseError> {
    let remote_roots =
        remote.root_nodes(&RootNodesQuery::default())?;

    let syncer = SimpleSyncer::new(local);
    let mut diffs = Vec::new();

    for root in &remote_roots {
        // Filter by sync type.
        match sync_type {
            SyncType::IssuanceOnly => {
                if root.id.proof_type != ProofType::Issuance {
                    continue;
                }
            }
            SyncType::Full => {}
        }

        let diff = syncer.sync_universe(remote, &root.id)?;
        if !diff.new_leaves.is_empty() {
            diffs.push(diff);
        }
    }

    Ok(diffs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryUniverseBackend;
    use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};

    fn test_id() -> UniverseId {
        UniverseId {
            asset_id: AssetId([0xAA; 32]),
            group_key: None,
            proof_type: ProofType::Issuance,
        }
    }

    fn test_leaf(vout: u32) -> (LeafKey, UniverseLeaf) {
        let key = LeafKey {
            outpoint: OutPoint {
                txid: [0xBB; 32],
                vout,
            },
            script_key: SerializedKey([0x02; 33]),
        };
        let leaf = UniverseLeaf {
            asset_id: AssetId([0xAA; 32]),
            amount: 100,
            proof: vec![0x01, 0x02, 0x03],
            key: key.clone(),
        };
        (key, leaf)
    }

    /// A mock DiffEngine that wraps a MemoryUniverseBackend.
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
            query: &RootNodesQuery,
        ) -> Result<Vec<UniverseRoot>, UniverseError> {
            // Return roots for all universes.
            let _ = query;
            let roots = self.backend.all_roots();
            Ok(roots)
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

    #[test]
    fn test_sync_empty_to_populated() {
        let mut local = MemoryUniverseBackend::new();
        let mut remote_backend = MemoryUniverseBackend::new();

        let id = test_id();
        let (key, leaf) = test_leaf(0);
        remote_backend
            .upsert_proof_leaf(&id, &key, &leaf)
            .unwrap();

        let remote = MockRemote {
            backend: remote_backend,
        };

        let syncer = SimpleSyncer::new(&mut local);
        let diff = syncer.sync_universe(&remote, &id).unwrap();
        assert_eq!(diff.new_leaves.len(), 1);
    }

    #[test]
    fn test_sync_already_in_sync() {
        let mut local = MemoryUniverseBackend::new();
        let id = test_id();
        let (key, leaf) = test_leaf(0);
        local.upsert_proof_leaf(&id, &key, &leaf).unwrap();

        let mut remote_backend = MemoryUniverseBackend::new();
        remote_backend
            .upsert_proof_leaf(&id, &key, &leaf)
            .unwrap();

        let remote = MockRemote {
            backend: remote_backend,
        };

        let syncer = SimpleSyncer::new(&mut local);
        let diff = syncer.sync_universe(&remote, &id).unwrap();
        assert!(diff.new_leaves.is_empty());
    }

    #[test]
    fn test_sync_partial() {
        let mut local = MemoryUniverseBackend::new();
        let id = test_id();

        // Local has leaf 0.
        let (key0, leaf0) = test_leaf(0);
        local.upsert_proof_leaf(&id, &key0, &leaf0).unwrap();

        // Remote has leaf 0 + leaf 1.
        let mut remote_backend = MemoryUniverseBackend::new();
        remote_backend
            .upsert_proof_leaf(&id, &key0, &leaf0)
            .unwrap();
        let (key1, leaf1) = test_leaf(1);
        remote_backend
            .upsert_proof_leaf(&id, &key1, &leaf1)
            .unwrap();

        let remote = MockRemote {
            backend: remote_backend,
        };

        let syncer = SimpleSyncer::new(&mut local);
        let diff = syncer.sync_universe(&remote, &id).unwrap();
        assert_eq!(diff.new_leaves.len(), 1);
    }
}
