// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Commitment proofs for the two-level MS-SMT structure.
//!
//! A full commitment proof consists of:
//! - An [`AssetProof`]: proves inclusion/exclusion in the inner
//!   `AssetCommitment` tree
//! - A [`TaprootAssetProof`]: proves inclusion/exclusion in the outer
//!   `TapCommitment` tree
//!
//! Together they link an individual asset to the tapscript leaf embedded in
//! a Bitcoin Taproot output.

use crate::asset::AssetVersion;
use crate::mssmt::{self, LeafNode, Node};
use std::collections::BTreeMap;

use super::asset_commitment::CommitmentError;
use super::tap_commitment::TapCommitmentVersion;

/// Proof of an asset's inclusion or exclusion in an `AssetCommitment`.
#[derive(Clone, Debug)]
pub struct AssetProof {
    /// MS-SMT proof for the inner tree.
    pub proof: mssmt::Proof,
    /// Maximum asset version in this commitment.
    pub version: AssetVersion,
    /// The tap key (commitment identifier) for this asset commitment.
    pub tap_key: [u8; 32],
    /// Unknown odd TLV types for forward compatibility.
    pub unknown_odd_types: BTreeMap<u64, Vec<u8>>,
}

/// Proof of an asset commitment's inclusion or exclusion in a `TapCommitment`.
#[derive(Clone, Debug)]
pub struct TaprootAssetProof {
    /// MS-SMT proof for the outer tree.
    pub proof: mssmt::Proof,
    /// TAP commitment version.
    pub version: TapCommitmentVersion,
    /// Unknown odd TLV types for forward compatibility.
    pub unknown_odd_types: BTreeMap<u64, Vec<u8>>,
}

/// A complete commitment proof linking an asset to a Bitcoin output.
#[derive(Clone, Debug)]
pub struct CommitmentProof {
    /// Proof within the inner `AssetCommitment` tree.
    /// `None` means the asset commitment itself is excluded (non-inclusion at
    /// the outer level).
    pub asset_proof: Option<AssetProof>,
    /// Proof within the outer `TapCommitment` tree.
    pub taproot_asset_proof: TaprootAssetProof,
    /// Unknown odd TLV types for forward compatibility.
    pub unknown_odd_types: BTreeMap<u64, Vec<u8>>,
}

impl CommitmentProof {
    /// Derives the TapCommitment root by proving asset INCLUSION.
    ///
    /// Given an asset's commitment key and leaf, reconstructs the inner tree
    /// root via the asset proof, then uses that to reconstruct the outer root
    /// via the taproot asset proof.
    pub fn derive_by_asset_inclusion(
        &self,
        asset_commitment_key: &[u8; 32],
        asset_leaf: &LeafNode,
        tap_key: &[u8; 32],
    ) -> Result<mssmt::BranchNode, CommitmentError> {
        let asset_proof = self.asset_proof.as_ref().ok_or_else(|| {
            CommitmentError::InvalidProof(
                "asset proof required for inclusion".into(),
            )
        })?;

        // Reconstruct the inner AssetCommitment root from the asset leaf.
        let inner_root = asset_proof
            .proof
            .root(asset_commitment_key, &Node::Leaf(asset_leaf.clone()));

        // Build the AssetCommitment's tap commitment leaf from the inner root.
        let ac_leaf = build_asset_commitment_leaf(
            asset_proof.version,
            tap_key,
            &inner_root,
        );

        // Reconstruct the outer TapCommitment root.
        let outer_root = self
            .taproot_asset_proof
            .proof
            .root(tap_key, &Node::Leaf(ac_leaf));

        Ok(outer_root)
    }

    /// Derives the TapCommitment root by proving asset EXCLUSION.
    ///
    /// Proves the asset is NOT present in the inner tree by using an empty
    /// leaf, then uses the resulting (non-matching) inner root to reconstruct
    /// the outer root.
    pub fn derive_by_asset_exclusion(
        &self,
        asset_commitment_key: &[u8; 32],
        tap_key: &[u8; 32],
    ) -> Result<mssmt::BranchNode, CommitmentError> {
        let asset_proof = self.asset_proof.as_ref().ok_or_else(|| {
            CommitmentError::InvalidProof(
                "asset proof required for exclusion".into(),
            )
        })?;

        // Prove exclusion: the leaf at the asset's key is empty.
        let inner_root = asset_proof
            .proof
            .root(asset_commitment_key, &Node::Leaf(LeafNode::empty()));

        let ac_leaf = build_asset_commitment_leaf(
            asset_proof.version,
            tap_key,
            &inner_root,
        );

        let outer_root = self
            .taproot_asset_proof
            .proof
            .root(tap_key, &Node::Leaf(ac_leaf));

        Ok(outer_root)
    }

    /// Derives the TapCommitment root by proving the entire
    /// AssetCommitment is EXCLUDED from the outer tree.
    ///
    /// The `asset_proof` must be `None` — we prove that no asset commitment
    /// exists at the given tap key.
    pub fn derive_by_commitment_exclusion(
        &self,
        tap_key: &[u8; 32],
    ) -> Result<mssmt::BranchNode, CommitmentError> {
        if self.asset_proof.is_some() {
            return Err(CommitmentError::InvalidProof(
                "asset proof must be None for commitment exclusion".into(),
            ));
        }

        // Empty leaf at the tap key position in the outer tree.
        let outer_root = self
            .taproot_asset_proof
            .proof
            .root(tap_key, &Node::Leaf(LeafNode::empty()));

        Ok(outer_root)
    }
}

/// Builds the leaf that an AssetCommitment inserts into the outer
/// TapCommitment tree.
///
/// Leaf value = `version(1) || root(32) || BE(sum)(8)` = 41 bytes.
fn build_asset_commitment_leaf(
    version: AssetVersion,
    tap_key: &[u8; 32],
    inner_root: &mssmt::BranchNode,
) -> LeafNode {
    use bitcoin_hashes::{sha256, Hash, HashEngine};

    // Compute the AssetCommitment.Root() hash:
    // SHA256(tap_key || left_hash || right_hash || BE(sum))
    let left_hash = inner_root.left.node_hash();
    let right_hash = inner_root.right.node_hash();
    let sum = inner_root.node_sum();

    let mut engine = sha256::HashEngine::default();
    engine.input(tap_key);
    engine.input(left_hash.as_bytes());
    engine.input(right_hash.as_bytes());
    engine.input(&sum.to_be_bytes());
    let root_hash = sha256::Hash::from_engine(engine).to_byte_array();

    // Build the 41-byte leaf value.
    let mut value = Vec::with_capacity(41);
    value.push(version as u8);
    value.extend_from_slice(&root_hash);
    value.extend_from_slice(&sum.to_be_bytes());

    LeafNode::new(value, sum)
}

/// TLV type numbers for commitment proof encoding.
pub mod tlv_types {
    // AssetProof TLV types.
    pub const ASSET_PROOF_VERSION: u64 = 0x00;
    pub const ASSET_PROOF_ASSET_ID: u64 = 0x02;
    pub const ASSET_PROOF_PROOF: u64 = 0x04;

    // TaprootAssetProof TLV types.
    pub const TAP_PROOF_VERSION: u64 = 0x00;
    pub const TAP_PROOF_PROOF: u64 = 0x02;

    // CommitmentProof TLV types.
    pub const PROOF_ASSET_PROOF: u64 = 0x01;
    pub const PROOF_TAP_PROOF: u64 = 0x02;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::*;
    use crate::commitment::asset_commitment::{
        asset_commitment_key, asset_leaf, AssetCommitment,
    };
    use crate::commitment::tap_commitment::TapCommitmentVersion;
    use crate::mssmt::{DefaultStore, FullTree};

    fn test_asset(amount: u64, key_byte: u8) -> Asset {
        let genesis = Genesis {
            first_prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            tag: "test".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        };
        let script_key = ScriptKey::from_pub_key(SerializedKey([key_byte; 33]));
        Asset::new_genesis(genesis, amount, script_key)
    }

    #[test]
    fn test_inclusion_proof_roundtrip() {
        // Build a tree with one asset.
        let asset = test_asset(100, 0x02);
        let asset_id = asset.genesis.id();
        let has_group = asset.group_key.is_some();
        let ack =
            asset_commitment_key(&asset_id, asset.script_key.serialized(), has_group);
        let tap_key = crate::commitment::asset_commitment::tap_commitment_key(
            &asset_id,
            None,
        );

        // Build inner tree and get proof.
        let leaf = asset_leaf(&asset);
        let mut inner_tree = FullTree::new(DefaultStore::new());
        inner_tree.insert(ack, leaf.clone()).unwrap();
        let inner_proof = inner_tree.merkle_proof(ack).unwrap();
        let inner_root = inner_tree.root().unwrap();

        // Build the AssetCommitment leaf for the outer tree.
        let ac = AssetCommitment::from_root(
            AssetVersion::V0,
            tap_key,
            AssetType::Normal,
            inner_root,
        );
        let ac_leaf = ac.tap_commitment_leaf();

        // Build outer tree and get proof.
        let mut outer_tree = FullTree::new(DefaultStore::new());
        outer_tree.insert(tap_key, ac_leaf).unwrap();
        let outer_proof = outer_tree.merkle_proof(tap_key).unwrap();
        let outer_root = outer_tree.root().unwrap();

        // Construct the CommitmentProof and verify inclusion.
        let commitment_proof = CommitmentProof {
            asset_proof: Some(AssetProof {
                proof: inner_proof,
                version: AssetVersion::V0,
                tap_key,
                unknown_odd_types: BTreeMap::new(),
            }),
            taproot_asset_proof: TaprootAssetProof {
                proof: outer_proof,
                version: TapCommitmentVersion::V0,
                unknown_odd_types: BTreeMap::new(),
            },
            unknown_odd_types: BTreeMap::new(),
        };

        let derived_root = commitment_proof
            .derive_by_asset_inclusion(&ack, &leaf, &tap_key)
            .unwrap();

        assert_eq!(derived_root.node_hash(), outer_root.node_hash());
    }
}
