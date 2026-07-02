// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Prover-side, tree-retaining commitment types.
//!
//! [`AssetCommitment`] and [`TapCommitment`] only keep the MS-SMT roots,
//! which is all a verifier needs. A prover, however, must derive
//! inclusion and exclusion proofs from the full trees, so this module
//! mirrors Go's `commitment.AssetCommitment`/`commitment.TapCommitment`
//! (which retain their `tree` and `assetCommitments`/`assets` maps) with
//! [`AssetCommitmentTree`] and [`TapCommitmentTree`].
//!
//! [`TapCommitmentTree::proof`] mirrors Go's `TapCommitment.Proof`
//! (commitment/tap.go:471) and produces the [`CommitmentProof`] shapes
//! consumed by the proof verifier:
//!
//! - asset inclusion: asset-level inclusion proof + tap-level inclusion
//!   proof,
//! - asset exclusion: asset-level non-inclusion proof + tap-level
//!   inclusion proof,
//! - commitment exclusion: tap-level non-inclusion proof only (no asset
//!   proof).

use std::collections::BTreeMap;

use crate::asset::Asset;
use crate::mssmt;

use super::asset_commitment::{
    asset_commitment_key, asset_leaf, tap_commitment_key, AssetCommitment,
    CommitmentError,
};
use super::proof::{AssetProof, CommitmentProof, TaprootAssetProof};
use super::tap_commitment::{TapCommitment, TapCommitmentVersion};

/// An [`AssetCommitment`] that retains its MS-SMT and the committed
/// assets, so asset-level (inner tree) proofs can be derived. Mirrors
/// the prover-side capabilities of Go's `commitment.AssetCommitment`.
#[derive(Clone, Debug)]
pub struct AssetCommitmentTree {
    commitment: AssetCommitment,
    tree: mssmt::FullTree<mssmt::DefaultStore>,
    assets: BTreeMap<[u8; 32], Asset>,
}

impl AssetCommitmentTree {
    /// Creates an `AssetCommitmentTree` from a set of assets, mirroring
    /// Go's `NewAssetCommitment` (commitment/asset.go). All assets must
    /// share the same tap key and asset type.
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

        let mut tree = mssmt::FullTree::new(mssmt::DefaultStore::new());
        let mut asset_map = BTreeMap::new();
        let mut version = first.version;

        for asset in assets {
            let asset_tap_key = tap_commitment_key(
                &asset.genesis.id(),
                asset.group_key.as_ref().map(|gk| &gk.group_pub_key),
            );
            if asset_tap_key != tap_key {
                return Err(CommitmentError::MismatchedTapKey);
            }
            if asset.genesis.asset_type != asset_type {
                return Err(CommitmentError::MismatchedAssetType);
            }

            let key = asset_commitment_key(
                &asset.genesis.id(),
                asset.script_key.serialized(),
                asset.group_key.is_some(),
            );
            let leaf = asset_leaf(asset);
            tree.insert(key, leaf)
                .map_err(|e| CommitmentError::TreeError(format!("{}", e)))?;
            asset_map.insert(key, (*asset).clone());

            if asset.version.to_u8() > version.to_u8() {
                version = asset.version;
            }
        }

        let root = tree
            .root()
            .map_err(|e| CommitmentError::TreeError(format!("{}", e)))?;

        Ok(AssetCommitmentTree {
            commitment: AssetCommitment::from_root(
                version, tap_key, asset_type, root,
            ),
            tree,
            assets: asset_map,
        })
    }

    /// Returns the root-only commitment summary.
    pub fn commitment(&self) -> &AssetCommitment {
        &self.commitment
    }

    /// Returns the committed assets, keyed by asset commitment key.
    pub fn assets(&self) -> &BTreeMap<[u8; 32], Asset> {
        &self.assets
    }

    /// Computes the asset-level merkle proof for the asset leaf located
    /// at `key`, mirroring Go's `AssetCommitment.AssetProof`
    /// (commitment/asset.go:364). Returns the committed asset (if
    /// present; `None` yields a non-inclusion proof) and the proof.
    pub fn asset_proof(
        &self,
        key: &[u8; 32],
    ) -> Result<(Option<&Asset>, mssmt::Proof), CommitmentError> {
        let proof = self
            .tree
            .merkle_proof(*key)
            .map_err(|e| CommitmentError::TreeError(format!("{}", e)))?;
        Ok((self.assets.get(key), proof))
    }
}

/// A [`TapCommitment`] that retains its outer MS-SMT and asset
/// commitments, so full [`CommitmentProof`]s can be derived. Mirrors the
/// prover-side capabilities of Go's `commitment.TapCommitment`.
#[derive(Clone, Debug)]
pub struct TapCommitmentTree {
    commitment: TapCommitment,
    tree: mssmt::FullTree<mssmt::DefaultStore>,
    asset_commitments: BTreeMap<[u8; 32], AssetCommitmentTree>,
}

impl TapCommitmentTree {
    /// Creates a `TapCommitmentTree` from a set of asset commitment
    /// trees, mirroring Go's `NewTapCommitment` (commitment/tap.go).
    pub fn new(
        version: TapCommitmentVersion,
        commitments: Vec<AssetCommitmentTree>,
    ) -> Result<Self, CommitmentError> {
        let mut tree = mssmt::FullTree::new(mssmt::DefaultStore::new());
        let mut commitment_map = BTreeMap::new();

        for ac in commitments {
            let key = ac.commitment().tap_key;
            if commitment_map.contains_key(&key) {
                return Err(CommitmentError::TreeError(format!(
                    "duplicate asset commitment for tap key {}",
                    crate::hex::encode(&key)
                )));
            }
            let leaf = ac.commitment().tap_commitment_leaf();
            tree.insert(key, leaf)
                .map_err(|e| CommitmentError::TreeError(format!("{}", e)))?;
            commitment_map.insert(key, ac);
        }

        let root = tree
            .root()
            .map_err(|e| CommitmentError::TreeError(format!("{}", e)))?;

        Ok(TapCommitmentTree {
            commitment: TapCommitment::from_root(version, root),
            tree,
            asset_commitments: commitment_map,
        })
    }

    /// Creates a `TapCommitmentTree` with an optional explicit version;
    /// when `None`, the version is derived from the maximum asset
    /// version among the commitments, matching
    /// [`TapCommitment::from_asset_commitments`].
    pub fn from_asset_commitment_trees(
        version: Option<TapCommitmentVersion>,
        commitments: Vec<AssetCommitmentTree>,
    ) -> Result<Self, CommitmentError> {
        let version = match version {
            Some(v) => v,
            None => {
                let max_version = commitments
                    .iter()
                    .map(|ac| ac.commitment().version.to_u8())
                    .max()
                    .unwrap_or(0);
                TapCommitmentVersion::from_u8(max_version)?
            }
        };
        Self::new(version, commitments)
    }

    /// Returns the root-only commitment summary.
    pub fn commitment(&self) -> &TapCommitment {
        &self.commitment
    }

    /// Returns the committed asset commitments, keyed by tap key.
    pub fn asset_commitments(
        &self,
    ) -> &BTreeMap<[u8; 32], AssetCommitmentTree> {
        &self.asset_commitments
    }

    /// Computes the tap-level (outer tree) merkle proof for the asset
    /// commitment located at `tap_commitment_key`. If no asset
    /// commitment exists at the key, the proof is a non-inclusion
    /// proof.
    pub fn merkle_proof(
        &self,
        tap_commitment_key: &[u8; 32],
    ) -> Result<mssmt::Proof, CommitmentError> {
        self.tree
            .merkle_proof(*tap_commitment_key)
            .map_err(|e| CommitmentError::TreeError(format!("{}", e)))
    }

    /// Computes the full commitment proof for the asset leaf located at
    /// `asset_commitment_key` within the asset commitment located at
    /// `tap_commitment_key`, mirroring Go's `TapCommitment.Proof`
    /// (commitment/tap.go:471).
    ///
    /// The returned asset is `Some` only if the asset is committed to
    /// (inclusion proof); otherwise the proof is an exclusion proof:
    /// either an asset-level non-inclusion proof (when the asset
    /// commitment exists) or a tap-level non-inclusion proof with no
    /// asset proof at all (when it does not).
    pub fn proof(
        &self,
        tap_commitment_key: &[u8; 32],
        asset_commitment_key: &[u8; 32],
    ) -> Result<(Option<&Asset>, CommitmentProof), CommitmentError> {
        let outer_proof = self.merkle_proof(tap_commitment_key)?;
        let taproot_asset_proof = TaprootAssetProof {
            proof: outer_proof,
            version: self.commitment.version,
            unknown_odd_types: BTreeMap::new(),
        };

        // If the corresponding asset commitment does not exist, return
        // the tap-level non-inclusion proof as is.
        let Some(asset_commitment) =
            self.asset_commitments.get(tap_commitment_key)
        else {
            return Ok((
                None,
                CommitmentProof {
                    asset_proof: None,
                    taproot_asset_proof,
                    tap_sibling_preimage: None,
                    stxo_proofs: BTreeMap::new(),
                    unknown_odd_types: BTreeMap::new(),
                },
            ));
        };

        // Otherwise, compute the asset-level proof and include it. The
        // asset may not be found, yielding a non-inclusion proof.
        let (asset, inner_proof) =
            asset_commitment.asset_proof(asset_commitment_key)?;

        Ok((
            asset,
            CommitmentProof {
                asset_proof: Some(AssetProof {
                    proof: inner_proof,
                    version: asset_commitment.commitment().version,
                    tap_key: asset_commitment.commitment().tap_key,
                    unknown_odd_types: BTreeMap::new(),
                }),
                taproot_asset_proof,
                tap_sibling_preimage: None,
                stxo_proofs: BTreeMap::new(),
                unknown_odd_types: BTreeMap::new(),
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::*;
    use crate::mssmt::Node;

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

    fn keys_of(asset: &Asset) -> ([u8; 32], [u8; 32]) {
        let ack = asset_commitment_key(
            &asset.genesis.id(),
            asset.script_key.serialized(),
            asset.group_key.is_some(),
        );
        let tck = tap_commitment_key(
            &asset.genesis.id(),
            asset.group_key.as_ref().map(|gk| &gk.group_pub_key),
        );
        (ack, tck)
    }

    #[test]
    fn tree_root_matches_root_only_commitment() {
        let asset = test_asset(100, 0x02);
        let act = AssetCommitmentTree::new(&[&asset]).unwrap();
        let ac = AssetCommitment::new(&[&asset]).unwrap();
        assert_eq!(act.commitment().root(), ac.root());

        let tct = TapCommitmentTree::new(
            TapCommitmentVersion::V2,
            vec![act.clone()],
        )
        .unwrap();
        let tc = TapCommitment::new(TapCommitmentVersion::V2, &[&ac]).unwrap();
        assert_eq!(
            tct.commitment().root_hash(),
            tc.root_hash(),
        );
    }

    #[test]
    fn inclusion_proof_derives_commitment_root() {
        let asset = test_asset(100, 0x02);
        let (ack, tck) = keys_of(&asset);

        let act = AssetCommitmentTree::new(&[&asset]).unwrap();
        let tct =
            TapCommitmentTree::new(TapCommitmentVersion::V0, vec![act])
                .unwrap();

        let (found, proof) = tct.proof(&tck, &ack).unwrap();
        assert!(found.is_some());

        let leaf = asset_leaf(&asset);
        let derived = proof
            .derive_by_asset_inclusion(&ack, &leaf, &tck)
            .unwrap();
        assert_eq!(derived.node_hash(), tct.commitment().root_hash());
    }

    #[test]
    fn asset_exclusion_proof_derives_commitment_root() {
        let committed = test_asset(100, 0x02);
        let other = test_asset(50, 0x03);
        let (other_ack, tck) = keys_of(&other);

        let act = AssetCommitmentTree::new(&[&committed]).unwrap();
        let tct =
            TapCommitmentTree::new(TapCommitmentVersion::V0, vec![act])
                .unwrap();

        // Same asset ID (same tap key), different script key: the asset
        // commitment exists, the asset does not.
        let (found, proof) = tct.proof(&tck, &other_ack).unwrap();
        assert!(found.is_none());
        assert!(proof.asset_proof.is_some());

        let derived = proof
            .derive_by_asset_exclusion(&other_ack, &tck)
            .unwrap();
        assert_eq!(derived.node_hash(), tct.commitment().root_hash());
    }

    #[test]
    fn commitment_exclusion_proof_derives_commitment_root() {
        let committed = test_asset(100, 0x02);
        let act = AssetCommitmentTree::new(&[&committed]).unwrap();
        let tct =
            TapCommitmentTree::new(TapCommitmentVersion::V0, vec![act])
                .unwrap();

        // A completely unrelated tap key: no asset commitment there.
        let missing_tck = [0xEE; 32];
        let (found, proof) = tct.proof(&missing_tck, &[0xDD; 32]).unwrap();
        assert!(found.is_none());
        assert!(proof.asset_proof.is_none());

        let derived = proof
            .derive_by_commitment_exclusion(&missing_tck)
            .unwrap();
        assert_eq!(derived.node_hash(), tct.commitment().root_hash());
    }

    #[test]
    fn asset_proof_non_inclusion_leaf_is_empty() {
        let committed = test_asset(100, 0x02);
        let act = AssetCommitmentTree::new(&[&committed]).unwrap();
        let (asset, proof) = act.asset_proof(&[0xAB; 32]).unwrap();
        assert!(asset.is_none());
        // Non-inclusion: an empty leaf at the key reconstructs the root.
        let root = proof.root(
            &[0xAB; 32],
            &Node::Leaf(crate::mssmt::LeafNode::empty()),
        );
        assert_eq!(
            root.node_hash(),
            act.commitment().tree_root.node_hash()
        );
    }

    #[test]
    fn mismatched_tap_key_rejected() {
        let a = test_asset(1, 0x02);
        let mut b = test_asset(1, 0x03);
        b.genesis.tag = "other".to_string();
        assert!(matches!(
            AssetCommitmentTree::new(&[&a, &b]),
            Err(CommitmentError::MismatchedTapKey)
        ));
    }
}
