// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Asset commitment — an inner MS-SMT holding assets of one type, keyed by
//! asset commitment key (derived from script key and optionally asset ID).

use bitcoin_hashes::{sha256, Hash, HashEngine};

use crate::asset::{Asset, AssetId, AssetType, AssetVersion, SerializedKey};
use crate::mssmt::{self, LeafNode};

/// Computes the key used to insert an asset into an AssetCommitment's MS-SMT.
///
/// - If the asset has no group key (issuance disabled):
///   `SHA256(schnorr_script_key)` (32 bytes input)
/// - If the asset has a group key:
///   `SHA256(asset_id || schnorr_script_key)` (64 bytes input)
pub fn asset_commitment_key(
    asset_id: &AssetId,
    script_key: &SerializedKey,
    has_group_key: bool,
) -> [u8; 32] {
    let mut engine = sha256::HashEngine::default();
    if has_group_key {
        engine.input(asset_id.as_bytes());
    }
    engine.input(script_key.schnorr_bytes());
    sha256::Hash::from_engine(engine).to_byte_array()
}

/// Computes the tap key (commitment identifier) for an asset.
///
/// - If the asset has a group key: `SHA256(schnorr_group_pub_key)`
/// - If the asset has no group key: `asset_id` directly
pub fn tap_commitment_key(
    asset_id: &AssetId,
    group_pub_key: Option<&SerializedKey>,
) -> [u8; 32] {
    match group_pub_key {
        Some(gpk) => {
            let mut engine = sha256::HashEngine::default();
            engine.input(gpk.schnorr_bytes());
            sha256::Hash::from_engine(engine).to_byte_array()
        }
        None => *asset_id.as_bytes(),
    }
}

/// An asset commitment — an inner MS-SMT containing assets of one type.
///
/// All assets in a single `AssetCommitment` share the same tap key (either
/// asset ID for ungrouped assets or a hash of the group public key for
/// grouped assets).
#[derive(Clone, Debug)]
pub struct AssetCommitment {
    /// Maximum version among committed assets.
    pub version: AssetVersion,
    /// The commitment identifier (derived from asset ID or group key).
    pub tap_key: [u8; 32],
    /// The type of all committed assets.
    pub asset_type: AssetType,
    /// Root of the inner MS-SMT.
    pub tree_root: mssmt::BranchNode,
}

impl AssetCommitment {
    /// Creates an `AssetCommitment` from a set of assets.
    ///
    /// All assets must share the same tap key and asset type.
    pub fn new(assets: &[&Asset]) -> Result<Self, CommitmentError> {
        if assets.is_empty() {
            return Err(CommitmentError::EmptyAssetList);
        }

        let first = assets[0];
        let tap_key = tap_commitment_key(
            &first.genesis.id(),
            first.group_key.as_ref().map(|gk| &gk.group_pub_key),
        );
        let asset_type = first.genesis.asset_type;

        let store = mssmt::DefaultStore::new();
        let mut tree = mssmt::FullTree::new(store);
        let mut version = first.version;

        for asset in assets {
            let key = asset_commitment_key(
                &asset.genesis.id(),
                asset.script_key.serialized(),
                asset.group_key.is_some(),
            );
            let leaf = asset_leaf(asset);
            tree.insert(key, leaf)
                .map_err(|e| CommitmentError::TreeError(format!("{}", e)))?;

            if asset.version.to_u8() > version.to_u8() {
                version = asset.version;
            }
        }

        let root = tree
            .root()
            .map_err(|e| CommitmentError::TreeError(format!("{}", e)))?;

        Ok(AssetCommitment {
            version,
            tap_key,
            asset_type,
            tree_root: root,
        })
    }

    /// Creates an `AssetCommitment` from a known root node (used when
    /// reconstructing from proofs).
    pub fn from_root(
        version: AssetVersion,
        tap_key: [u8; 32],
        asset_type: AssetType,
        tree_root: mssmt::BranchNode,
    ) -> Self {
        AssetCommitment {
            version,
            tap_key,
            asset_type,
            tree_root,
        }
    }

    /// Computes the commitment root hash.
    ///
    /// `SHA256(tap_key || left_hash || right_hash || BE(root_sum))`
    pub fn root(&self) -> [u8; 32] {
        let left_hash = self.tree_root.left.node_hash();
        let right_hash = self.tree_root.right.node_hash();

        let mut engine = sha256::HashEngine::default();
        engine.input(&self.tap_key);
        engine.input(left_hash.as_bytes());
        engine.input(right_hash.as_bytes());
        engine.input(&self.tree_root.node_sum().to_be_bytes());
        sha256::Hash::from_engine(engine).to_byte_array()
    }

    /// Produces the leaf node for insertion into the outer TapCommitment
    /// MS-SMT.
    ///
    /// Leaf value = `version(1) || root(32) || BE(sum)(8)` = 41 bytes.
    /// Leaf sum = tree root sum (total asset amount).
    pub fn tap_commitment_leaf(&self) -> LeafNode {
        let root = self.root();
        let sum = self.tree_root.node_sum();

        let mut value = Vec::with_capacity(41);
        value.push(self.version.to_u8());
        value.extend_from_slice(&root);
        value.extend_from_slice(&sum.to_be_bytes());

        LeafNode::new(value, sum)
    }
}

/// Creates an MS-SMT leaf node for an asset using proper TLV encoding.
///
/// The leaf value is the TLV-encoded asset bytes:
/// - V0 assets: full encoding including witnesses
/// - V1 assets: encoding without witnesses (segwit style)
///
/// The leaf sum is the asset's amount.
pub fn asset_leaf(asset: &Asset) -> LeafNode {
    crate::encoding::asset::asset_to_leaf(asset)
}

/// Errors from commitment operations.
#[derive(Debug, Clone)]
pub enum CommitmentError {
    EmptyAssetList,
    TreeError(String),
    MismatchedTapKey,
    MismatchedAssetType,
    InvalidProof(String),
    /// An asset is not a valid alt leaf (Go's `Asset.ValidateAltLeaf`).
    InvalidAltLeaf(String),
    /// An alt leaf collides with another new or already committed alt
    /// leaf (Go's `asset.ErrDuplicateAltLeafKey`).
    DuplicateAltLeafKey([u8; 32]),
}

impl std::fmt::Display for CommitmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CommitmentError::EmptyAssetList => {
                write!(f, "empty asset list")
            }
            CommitmentError::TreeError(e) => write!(f, "tree error: {}", e),
            CommitmentError::MismatchedTapKey => {
                write!(f, "mismatched tap key in assets")
            }
            CommitmentError::MismatchedAssetType => {
                write!(f, "mismatched asset type in assets")
            }
            CommitmentError::InvalidProof(msg) => {
                write!(f, "invalid proof: {}", msg)
            }
            CommitmentError::InvalidAltLeaf(msg) => {
                write!(f, "invalid alt leaf: {}", msg)
            }
            CommitmentError::DuplicateAltLeafKey(key) => {
                write!(
                    f,
                    "duplicate alt leaf key: {}",
                    crate::hex::encode(key)
                )
            }
        }
    }
}

impl std::error::Error for CommitmentError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::*;

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
    fn test_asset_commitment_single() {
        let asset = test_asset(100, 0x02);
        let commitment = AssetCommitment::new(&[&asset]).unwrap();
        assert_eq!(commitment.tree_root.node_sum(), 100);
        assert_eq!(commitment.version, AssetVersion::V0);
    }

    #[test]
    fn test_asset_commitment_multiple() {
        let a1 = test_asset(60, 0x02);
        let a2 = test_asset(40, 0x03);
        let commitment = AssetCommitment::new(&[&a1, &a2]).unwrap();
        assert_eq!(commitment.tree_root.node_sum(), 100);
    }

    #[test]
    fn test_tap_commitment_leaf_size() {
        let asset = test_asset(100, 0x02);
        let commitment = AssetCommitment::new(&[&asset]).unwrap();
        let leaf = commitment.tap_commitment_leaf();
        assert_eq!(leaf.value.len(), 41);
        assert_eq!(leaf.sum, 100);
    }

    #[test]
    fn test_tap_commitment_key_ungrouped() {
        let id = AssetId([0xAA; 32]);
        let key = tap_commitment_key(&id, None);
        assert_eq!(key, *id.as_bytes());
    }

    #[test]
    fn test_tap_commitment_key_grouped() {
        let id = AssetId([0xAA; 32]);
        let gpk = SerializedKey([0x02; 33]);
        let key = tap_commitment_key(&id, Some(&gpk));
        // Should be SHA256 of the schnorr (x-only) group key.
        assert_ne!(key, *id.as_bytes());
    }
}
