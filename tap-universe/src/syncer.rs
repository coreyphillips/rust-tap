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
//! verifies their proofs, and inserts them locally. Matches the Go
//! `SimpleSyncer` pattern (universe/syncer.go): fetched leaves that fail
//! verification are rejected (skipped) without aborting the rest of the
//! sync, and per-universe errors during a full sync are collected
//! instead of aborting the remaining universes.

use std::collections::HashSet;

use tap_primitives::proof::{
    decode_proof, BlockHeader, DefaultMerkleVerifier,
    FixedHeightChainLookup, GroupVerifier, HeaderVerifier, ProofError,
    ProofVerificationOptions, VerifierCtx,
};
use tap_primitives::asset::SerializedKey;

use crate::traits::{DiffEngine, Syncer, UniverseBackend};
use crate::types::*;

// ---------------------------------------------------------------------------
// Leaf verification
// ---------------------------------------------------------------------------

/// Verifies a universe leaf proof before it is inserted locally.
///
/// This is the pluggable verification hook of [`SimpleSyncer`]. The Go
/// syncer first checks the leaf against the remote root and then runs
/// full issuance/transfer proof verification inside the local registrar
/// before persisting (universe/syncer.go, universe/archive.go).
pub trait LeafVerifier {
    /// Verifies the given leaf. Returning an error rejects the leaf:
    /// it will not be inserted into the local universe.
    fn verify_leaf(
        &self,
        id: &UniverseId,
        key: &LeafKey,
        leaf: &UniverseLeaf,
    ) -> Result<(), UniverseError>;
}

/// Accepts any block header. Without a chain backend the syncer anchors
/// verification to the header embedded in the proof itself: the real
/// check is the transaction merkle proof against that header's merkle
/// root, performed by [`DefaultMerkleVerifier`].
struct AcceptEmbeddedHeader;

impl HeaderVerifier for AcceptEmbeddedHeader {
    fn verify_header(
        &self,
        _header: &BlockHeader,
        _height: u32,
    ) -> Result<(), ProofError> {
        Ok(())
    }
}

/// Accepts any group key. The syncer has no group key database; callers
/// that track known groups can plug in a custom [`LeafVerifier`].
struct AcceptAllGroups;

impl GroupVerifier for AcceptAllGroups {
    fn verify_group_key(
        &self,
        _group_key: &SerializedKey,
    ) -> Result<(), ProofError> {
        Ok(())
    }
}

/// The default [`LeafVerifier`]: decodes the raw proof and runs
/// [`tap_primitives::proof::types::Proof::verify_integrity`] with chain
/// verification enabled (tx merkle proof against the embedded block
/// header via [`DefaultMerkleVerifier`]). Time lock validation is
/// skipped since the syncer has no chain access.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProofLeafVerifier;

impl LeafVerifier for ProofLeafVerifier {
    fn verify_leaf(
        &self,
        _id: &UniverseId,
        _key: &LeafKey,
        leaf: &UniverseLeaf,
    ) -> Result<(), UniverseError> {
        let proof = decode_proof(&leaf.proof).map_err(|e| {
            UniverseError::ProofInvalid(format!(
                "leaf proof decode failed: {}",
                e
            ))
        })?;

        // The leaf metadata must be consistent with the embedded proof.
        if proof.asset.id() != leaf.asset_id {
            return Err(UniverseError::ProofInvalid(
                "leaf asset id does not match proof asset".into(),
            ));
        }
        if proof.asset.amount != leaf.amount {
            return Err(UniverseError::ProofInvalid(
                "leaf amount does not match proof asset".into(),
            ));
        }

        let ctx = VerifierCtx::new(
            AcceptEmbeddedHeader,
            DefaultMerkleVerifier,
            AcceptAllGroups,
            FixedHeightChainLookup(proof.block_height),
        );
        let opts = ProofVerificationOptions {
            challenge_bytes: None,
            skip_chain_verification: false,
            skip_time_lock_validation: true,
        };

        proof.verify_integrity(&ctx, &opts).map_err(|e| {
            UniverseError::ProofInvalid(format!(
                "leaf proof verification failed: {}",
                e
            ))
        })?;

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SimpleSyncer
// ---------------------------------------------------------------------------

/// A simple syncer that diffs roots then fetches, verifies, and inserts
/// missing leaves. Stateless with respect to storage: the local backend
/// is passed to [`Syncer::sync_universe`], mirroring the Go
/// `SimpleSyncer` which only carries configuration.
pub struct SimpleSyncer {
    /// Whether fetched leaves are verified before insertion.
    verify_proofs: bool,
    /// The verifier applied to fetched leaves when `verify_proofs` is
    /// enabled.
    verifier: Box<dyn LeafVerifier + Send + Sync>,
}

impl Default for SimpleSyncer {
    fn default() -> Self {
        SimpleSyncer::new()
    }
}

impl SimpleSyncer {
    /// Creates a syncer with proof verification enabled (the default),
    /// using [`ProofLeafVerifier`].
    pub fn new() -> Self {
        SimpleSyncer {
            verify_proofs: true,
            verifier: Box::new(ProofLeafVerifier),
        }
    }

    /// Creates a syncer with proof verification toggled by
    /// `verify_proofs`. When disabled, fetched leaves are inserted
    /// without inspection (only for trusted remotes/tests).
    pub fn with_verification(verify_proofs: bool) -> Self {
        SimpleSyncer {
            verify_proofs,
            ..SimpleSyncer::new()
        }
    }

    /// Replaces the default [`ProofLeafVerifier`] with a custom hook
    /// (and enables verification).
    pub fn with_verifier(
        verifier: Box<dyn LeafVerifier + Send + Sync>,
    ) -> Self {
        SimpleSyncer {
            verify_proofs: true,
            verifier,
        }
    }
}

impl Syncer for SimpleSyncer {
    fn sync_universe(
        &self,
        local: &mut dyn UniverseBackend,
        remote: &dyn DiffEngine,
        id: &UniverseId,
    ) -> Result<AssetSyncDiff, UniverseError> {
        // Step 1: Compare roots.
        let remote_root = remote.root_node(id)?;
        let local_root = local.root_node(id);

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
        let remote_keys =
            remote.universe_leaf_keys(id, &LeafKeysQuery::default())?;

        // Step 3: Determine which leaves we're missing locally.
        let local_keys: HashSet<LeafKey> = local
            .fetch_keys(id, &LeafKeysQuery::default())
            .unwrap_or_default()
            .into_iter()
            .collect();

        let missing_keys: Vec<&LeafKey> = remote_keys
            .iter()
            .filter(|k| !local_keys.contains(k))
            .collect();

        // Step 4: Fetch missing proofs from the remote, verify them,
        // and insert them locally. A leaf that fails verification is
        // rejected and skipped; the remaining leaves still sync,
        // mirroring the Go syncer's collect-errors-and-continue
        // behavior for individual leaves.
        let mut new_leaves = Vec::new();
        for key in missing_keys {
            let proof = match remote.fetch_proof_leaf(id, key)? {
                Some(proof) => proof,
                None => continue,
            };

            if self.verify_proofs {
                if self
                    .verifier
                    .verify_leaf(id, key, &proof.leaf)
                    .is_err()
                {
                    continue;
                }
            }

            local.upsert_proof_leaf(id, key, &proof.leaf)?;
            new_leaves.push(proof.leaf);
        }

        Ok(AssetSyncDiff {
            universe_id: id.clone(),
            new_leaves,
        })
    }
}

// ---------------------------------------------------------------------------
// sync_all
// ---------------------------------------------------------------------------

/// The outcome of a full multi-universe sync: the diffs that produced
/// new leaves plus any per-universe errors that were skipped over.
#[derive(Debug, Default)]
pub struct SyncAllResult {
    /// Diffs for all universes that had changes.
    pub diffs: Vec<AssetSyncDiff>,
    /// Universes that failed to sync, with the error encountered.
    /// Mirrors the Go federation envoy, which logs per-target errors
    /// and keeps syncing the remaining universes.
    pub errors: Vec<(UniverseId, UniverseError)>,
}

/// Syncs all universes from a remote, comparing root nodes first.
///
/// A failure to sync one universe does not abort the others; such
/// errors are collected in [`SyncAllResult::errors`]. Only a failure to
/// list the remote roots aborts the whole operation.
pub fn sync_all(
    syncer: &dyn Syncer,
    local: &mut dyn UniverseBackend,
    remote: &dyn DiffEngine,
    sync_type: SyncType,
) -> Result<SyncAllResult, UniverseError> {
    let remote_roots = remote.root_nodes(&RootNodesQuery::default())?;

    let mut result = SyncAllResult::default();

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

        match syncer.sync_universe(local, remote, &root.id) {
            Ok(diff) => {
                if !diff.new_leaves.is_empty() {
                    result.diffs.push(diff);
                }
            }
            Err(e) => result.errors.push((root.id.clone(), e)),
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryUniverseBackend;
    use tap_primitives::asset::{AssetId, OutPoint, SerializedKey};
    use tap_primitives::proof::File;

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

    /// Loads the first (genesis) proof of the vendored regtest proof
    /// file and builds a valid universe leaf from it.
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
                u8::from_str_radix(&hex.trim()[i..i + 2], 16).unwrap()
            })
            .collect();
        let file = File::decode(&bytes).unwrap();
        let proof_bytes = file.proofs[0].proof_bytes.clone();
        let proof = decode_proof(&proof_bytes).unwrap();

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

    /// A mock DiffEngine that wraps a MemoryUniverseBackend.
    struct MockRemote {
        backend: MemoryUniverseBackend,
        /// Universes whose root_node calls fail (for error tests).
        broken: Vec<UniverseId>,
    }

    impl MockRemote {
        fn new(backend: MemoryUniverseBackend) -> Self {
            MockRemote {
                backend,
                broken: vec![],
            }
        }
    }

    impl DiffEngine for MockRemote {
        fn root_node(
            &self,
            id: &UniverseId,
        ) -> Result<UniverseRoot, UniverseError> {
            if self.broken.contains(id) {
                return Err(UniverseError::SyncError(
                    "simulated remote failure".into(),
                ));
            }
            self.backend.root_node(id)
        }

        fn root_nodes(
            &self,
            query: &RootNodesQuery,
        ) -> Result<Vec<UniverseRoot>, UniverseError> {
            // Return roots for all universes.
            let _ = query;
            let mut roots = self.backend.all_roots();
            // Broken universes still show up in the listing.
            for id in &self.broken {
                if !roots.iter().any(|r| r.id == *id) {
                    roots.push(UniverseRoot {
                        id: id.clone(),
                        root_hash:
                            tap_primitives::mssmt::NodeHash([0xFF; 32]),
                        root_sum: 1,
                    });
                }
            }
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
        remote_backend.upsert_proof_leaf(&id, &key, &leaf).unwrap();

        let remote = MockRemote::new(remote_backend);

        let syncer = SimpleSyncer::with_verification(false);
        let diff = syncer.sync_universe(&mut local, &remote, &id).unwrap();
        assert_eq!(diff.new_leaves.len(), 1);

        // The fetched leaf must actually be persisted locally.
        assert!(local.fetch_proof(&id, &key).unwrap().is_some());
        let local_root = local.root_node(&id).unwrap();
        let remote_root = remote.root_node(&id).unwrap();
        assert_eq!(local_root.root_hash, remote_root.root_hash);
        assert_eq!(local_root.root_sum, remote_root.root_sum);
    }

    #[test]
    fn test_sync_already_in_sync() {
        let mut local = MemoryUniverseBackend::new();
        let id = test_id();
        let (key, leaf) = test_leaf(0);
        local.upsert_proof_leaf(&id, &key, &leaf).unwrap();

        let mut remote_backend = MemoryUniverseBackend::new();
        remote_backend.upsert_proof_leaf(&id, &key, &leaf).unwrap();

        let remote = MockRemote::new(remote_backend);

        let syncer = SimpleSyncer::with_verification(false);
        let diff = syncer.sync_universe(&mut local, &remote, &id).unwrap();
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

        let remote = MockRemote::new(remote_backend);

        let syncer = SimpleSyncer::with_verification(false);
        let diff = syncer.sync_universe(&mut local, &remote, &id).unwrap();
        assert_eq!(diff.new_leaves.len(), 1);

        // Both leaves present locally after sync.
        assert!(local.fetch_proof(&id, &key0).unwrap().is_some());
        assert!(local.fetch_proof(&id, &key1).unwrap().is_some());
    }

    /// With verification enabled (the default), a valid regtest genesis
    /// proof passes verification and is persisted.
    #[test]
    fn test_sync_verified_leaf_persisted() {
        let (id, key, leaf) = valid_leaf();

        let mut remote_backend = MemoryUniverseBackend::new();
        remote_backend.upsert_proof_leaf(&id, &key, &leaf).unwrap();
        let remote = MockRemote::new(remote_backend);

        let mut local = MemoryUniverseBackend::new();
        let syncer = SimpleSyncer::new();
        let diff = syncer.sync_universe(&mut local, &remote, &id).unwrap();

        assert_eq!(diff.new_leaves.len(), 1);
        assert!(local.fetch_proof(&id, &key).unwrap().is_some());
    }

    /// With verification enabled, a leaf carrying an undecodable proof
    /// is rejected and not persisted; the sync itself still succeeds.
    #[test]
    fn test_sync_invalid_leaf_rejected() {
        let mut remote_backend = MemoryUniverseBackend::new();
        let id = test_id();
        let (key, leaf) = test_leaf(0);
        remote_backend.upsert_proof_leaf(&id, &key, &leaf).unwrap();
        let remote = MockRemote::new(remote_backend);

        let mut local = MemoryUniverseBackend::new();
        let syncer = SimpleSyncer::new();
        let diff = syncer.sync_universe(&mut local, &remote, &id).unwrap();

        assert!(diff.new_leaves.is_empty());
        assert!(local.fetch_proof(&id, &key).unwrap().is_none());
    }

    /// A mix of valid and invalid leaves: only the valid one lands.
    #[test]
    fn test_sync_mixed_leaves() {
        let (id, valid_key, valid) = valid_leaf();

        // An invalid leaf in the same universe.
        let bad_key = LeafKey {
            outpoint: OutPoint {
                txid: [0xBB; 32],
                vout: 7,
            },
            script_key: SerializedKey([0x02; 33]),
        };
        let bad = UniverseLeaf {
            asset_id: id.asset_id,
            amount: 5,
            proof: vec![0xDE, 0xAD],
            key: bad_key.clone(),
        };

        let mut remote_backend = MemoryUniverseBackend::new();
        remote_backend
            .upsert_proof_leaf(&id, &valid_key, &valid)
            .unwrap();
        remote_backend.upsert_proof_leaf(&id, &bad_key, &bad).unwrap();
        let remote = MockRemote::new(remote_backend);

        let mut local = MemoryUniverseBackend::new();
        let syncer = SimpleSyncer::new();
        let diff = syncer.sync_universe(&mut local, &remote, &id).unwrap();

        assert_eq!(diff.new_leaves.len(), 1);
        assert!(local.fetch_proof(&id, &valid_key).unwrap().is_some());
        assert!(local.fetch_proof(&id, &bad_key).unwrap().is_none());
    }

    /// A custom verifier hook is honored.
    #[test]
    fn test_sync_custom_verifier() {
        struct RejectAll;
        impl LeafVerifier for RejectAll {
            fn verify_leaf(
                &self,
                _id: &UniverseId,
                _key: &LeafKey,
                _leaf: &UniverseLeaf,
            ) -> Result<(), UniverseError> {
                Err(UniverseError::ProofInvalid("nope".into()))
            }
        }

        let mut remote_backend = MemoryUniverseBackend::new();
        let id = test_id();
        let (key, leaf) = test_leaf(0);
        remote_backend.upsert_proof_leaf(&id, &key, &leaf).unwrap();
        let remote = MockRemote::new(remote_backend);

        let mut local = MemoryUniverseBackend::new();
        let syncer = SimpleSyncer::with_verifier(Box::new(RejectAll));
        let diff = syncer.sync_universe(&mut local, &remote, &id).unwrap();
        assert!(diff.new_leaves.is_empty());
        assert!(local.fetch_proof(&id, &key).unwrap().is_none());
    }

    /// A failing universe does not abort sync_all; its error is
    /// collected and the remaining universes still sync.
    #[test]
    fn test_sync_all_continues_on_per_universe_error() {
        let mut remote_backend = MemoryUniverseBackend::new();
        let good_id = test_id();
        let (key, leaf) = test_leaf(0);
        remote_backend
            .upsert_proof_leaf(&good_id, &key, &leaf)
            .unwrap();

        let broken_id = UniverseId {
            asset_id: AssetId([0xCC; 32]),
            group_key: None,
            proof_type: ProofType::Issuance,
        };

        let mut remote = MockRemote::new(remote_backend);
        remote.broken.push(broken_id.clone());

        let mut local = MemoryUniverseBackend::new();
        let syncer = SimpleSyncer::with_verification(false);
        let result = sync_all(
            &syncer,
            &mut local,
            &remote,
            SyncType::Full,
        )
        .unwrap();

        // The good universe synced.
        assert_eq!(result.diffs.len(), 1);
        assert_eq!(result.diffs[0].universe_id, good_id);
        assert!(local.fetch_proof(&good_id, &key).unwrap().is_some());

        // The broken universe's error was collected.
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.errors[0].0, broken_id);
    }

    /// IssuanceOnly filtering still applies.
    #[test]
    fn test_sync_all_issuance_only_filter() {
        let mut remote_backend = MemoryUniverseBackend::new();

        let issuance_id = test_id();
        let (key, leaf) = test_leaf(0);
        remote_backend
            .upsert_proof_leaf(&issuance_id, &key, &leaf)
            .unwrap();

        let transfer_id = UniverseId {
            asset_id: AssetId([0xAA; 32]),
            group_key: None,
            proof_type: ProofType::Transfer,
        };
        let (tkey, tleaf) = test_leaf(1);
        remote_backend
            .upsert_proof_leaf(&transfer_id, &tkey, &tleaf)
            .unwrap();

        let remote = MockRemote::new(remote_backend);

        let mut local = MemoryUniverseBackend::new();
        let syncer = SimpleSyncer::with_verification(false);
        let result = sync_all(
            &syncer,
            &mut local,
            &remote,
            SyncType::IssuanceOnly,
        )
        .unwrap();

        assert_eq!(result.diffs.len(), 1);
        assert_eq!(result.diffs[0].universe_id, issuance_id);
        assert!(result.errors.is_empty());
    }
}
