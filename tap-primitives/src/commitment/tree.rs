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

use crate::asset::{self, Asset};
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

    /// Inserts (or updates) an asset in this commitment, mirroring Go's
    /// `AssetCommitment.Upsert` (commitment/asset.go): the asset must
    /// share this commitment's tap key and asset type; the inner tree,
    /// asset map, root, and version are updated.
    pub fn upsert(&mut self, asset: Asset) -> Result<(), CommitmentError> {
        if asset.genesis.asset_type != self.commitment.asset_type {
            return Err(CommitmentError::MismatchedAssetType);
        }

        let asset_tap_key = tap_commitment_key(
            &asset.genesis.id(),
            asset.group_key.as_ref().map(|gk| &gk.group_pub_key),
        );
        if asset_tap_key != self.commitment.tap_key {
            return Err(CommitmentError::MismatchedTapKey);
        }

        let key = asset_commitment_key(
            &asset.genesis.id(),
            asset.script_key.serialized(),
            asset.group_key.is_some(),
        );
        let leaf = asset_leaf(&asset);
        self.tree
            .insert(key, leaf)
            .map_err(|e| CommitmentError::TreeError(format!("{}", e)))?;

        let root = self
            .tree
            .root()
            .map_err(|e| CommitmentError::TreeError(format!("{}", e)))?;

        let mut version = self.commitment.version;
        if asset.version.to_u8() > version.to_u8() {
            version = asset.version;
        }

        self.commitment = AssetCommitment::from_root(
            version,
            self.commitment.tap_key,
            self.commitment.asset_type,
            root,
        );
        self.assets.insert(key, asset);

        Ok(())
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

    /// Inserts (or updates) an asset commitment in the outer tree,
    /// mirroring Go's `TapCommitment.Upsert` (commitment/tap.go). An
    /// asset commitment whose inner tree is empty is pruned from the
    /// outer tree instead. The commitment version is re-derived from
    /// the remaining asset commitments unless it is V2 (which is
    /// explicitly selected, not derived).
    pub fn upsert(
        &mut self,
        ac: AssetCommitmentTree,
    ) -> Result<(), CommitmentError> {
        let key = ac.commitment().tap_key;

        if ac.commitment().tree_root.node_hash()
            == mssmt::empty_tree_root_hash()
        {
            self.tree
                .delete(key)
                .map_err(|e| CommitmentError::TreeError(format!("{}", e)))?;
            self.asset_commitments.remove(&key);
        } else {
            let leaf = ac.commitment().tap_commitment_leaf();
            self.tree
                .insert(key, leaf)
                .map_err(|e| CommitmentError::TreeError(format!("{}", e)))?;
            self.asset_commitments.insert(key, ac);
        }

        let root = self
            .tree
            .root()
            .map_err(|e| CommitmentError::TreeError(format!("{}", e)))?;

        let version = match self.commitment.version {
            TapCommitmentVersion::V2 => TapCommitmentVersion::V2,
            _ => {
                let max_version = self
                    .asset_commitments
                    .values()
                    .map(|ac| ac.commitment().version.to_u8())
                    .max()
                    .unwrap_or(0);
                TapCommitmentVersion::from_u8(max_version)?
            }
        };

        self.commitment = TapCommitment::from_root(version, root);
        Ok(())
    }

    /// Merges a set of alt leaves into the asset commitment at
    /// [`asset::EMPTY_GENESIS_ID`], mirroring Go's
    /// `TapCommitment.MergeAltLeaves` (commitment/tap.go:694). All alt
    /// leaves must be valid and must not collide with each other or
    /// with any alt leaf already committed to.
    pub fn merge_alt_leaves(
        &mut self,
        alt_leaves: &[Asset],
    ) -> Result<(), CommitmentError> {
        if alt_leaves.is_empty() {
            return Ok(());
        }

        // First, check that the given alt leaves are valid and have
        // unique asset commitment keys.
        let mut new_leaf_keys = std::collections::BTreeSet::new();
        asset::add_leaf_keys_verify_unique(&mut new_leaf_keys, alt_leaves)
            .map_err(|e| match e {
                asset::AssetError::DuplicateAltLeafKey(key) => {
                    CommitmentError::DuplicateAltLeafKey(key)
                }
                other => CommitmentError::InvalidAltLeaf(other.to_string()),
            })?;

        let alt_key = *asset::EMPTY_GENESIS_ID.as_bytes();

        // If any alt leaves are already committed, the new alt leaves
        // must not collide with them.
        let mut alt_commitment = match self.asset_commitments.get(&alt_key) {
            Some(existing) => {
                for leaf_key in existing.assets().keys() {
                    if new_leaf_keys.contains(leaf_key) {
                        return Err(CommitmentError::DuplicateAltLeafKey(
                            *leaf_key,
                        ));
                    }
                }
                existing.clone()
            }
            None => AssetCommitmentTree::new(&[&alt_leaves[0]])?,
        };

        // None of the new or existing alt leaves collide; update the
        // alt commitment and the outer tree.
        for leaf in alt_leaves {
            alt_commitment.upsert(leaf.clone())?;
        }

        self.upsert(alt_commitment)
    }

    /// Returns a copy of the alt leaves committed to at
    /// [`asset::EMPTY_GENESIS_ID`], mirroring Go's
    /// `TapCommitment.FetchAltLeaves` (commitment/tap.go:679). The
    /// leaves are ordered by asset commitment key.
    pub fn fetch_alt_leaves(&self) -> Vec<Asset> {
        self.asset_commitments
            .get(asset::EMPTY_GENESIS_ID.as_bytes())
            .map(|ac| ac.assets().values().cloned().collect())
            .unwrap_or_default()
    }

    /// Returns a copy of this commitment with any alt leaves removed,
    /// along with the removed leaves, mirroring Go's
    /// `commitment.TrimAltLeaves` (commitment/tap.go:658).
    pub fn trim_alt_leaves(
        &self,
    ) -> Result<(TapCommitmentTree, Vec<Asset>), CommitmentError> {
        let alt_leaves = self.fetch_alt_leaves();

        let remaining: Vec<AssetCommitmentTree> = self
            .asset_commitments
            .iter()
            .filter(|(key, _)| **key != *asset::EMPTY_GENESIS_ID.as_bytes())
            .map(|(_, ac)| ac.clone())
            .collect();

        let trimmed =
            TapCommitmentTree::new(self.commitment.version, remaining)?;
        Ok((trimmed, alt_leaves))
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

    fn alt_leaf(key_byte: u8) -> Asset {
        Asset::new_alt_leaf(
            ScriptKey::from_pub_key(SerializedKey([key_byte; 33])),
            ScriptVersion::V0,
        )
    }

    fn tap_tree_with(asset: &Asset) -> TapCommitmentTree {
        let act = AssetCommitmentTree::new(&[asset]).unwrap();
        TapCommitmentTree::new(TapCommitmentVersion::V2, vec![act]).unwrap()
    }

    #[test]
    fn merge_fetch_trim_alt_leaves_round_trip() {
        let regular = test_asset(100, 0x02);
        let mut tct = tap_tree_with(&regular);
        let root_before = tct.commitment().root_hash();
        let sum_before = tct.commitment().root_sum();

        // No alt leaves yet.
        assert!(tct.fetch_alt_leaves().is_empty());

        // Merging changes the root; the sum is unchanged (alt leaves
        // carry no amount).
        let leaves = vec![alt_leaf(0x04), alt_leaf(0x05)];
        tct.merge_alt_leaves(&leaves).unwrap();
        assert_ne!(tct.commitment().root_hash(), root_before);
        assert_eq!(tct.commitment().root_sum(), sum_before);

        let mut fetched = tct.fetch_alt_leaves();
        assert_eq!(fetched.len(), 2);
        fetched.sort_by_key(|l| *l.script_key.serialized().as_bytes());
        let mut expected = leaves.clone();
        expected.sort_by_key(|l| *l.script_key.serialized().as_bytes());
        assert_eq!(fetched, expected);

        // Merging more leaves accumulates.
        tct.merge_alt_leaves(&[alt_leaf(0x06)]).unwrap();
        assert_eq!(tct.fetch_alt_leaves().len(), 3);

        // Trimming restores the original commitment root and returns
        // the removed leaves.
        let (trimmed, removed) = tct.trim_alt_leaves().unwrap();
        assert_eq!(trimmed.commitment().root_hash(), root_before);
        assert_eq!(removed.len(), 3);
        assert!(trimmed.fetch_alt_leaves().is_empty());
    }

    #[test]
    fn merge_alt_leaves_rejects_collisions() {
        let regular = test_asset(100, 0x02);
        let mut tct = tap_tree_with(&regular);

        // Duplicate keys within the new set.
        let dup = vec![alt_leaf(0x04), alt_leaf(0x04)];
        assert!(matches!(
            tct.merge_alt_leaves(&dup),
            Err(CommitmentError::DuplicateAltLeafKey(_))
        ));

        // Collision with an already committed alt leaf.
        tct.merge_alt_leaves(&[alt_leaf(0x04)]).unwrap();
        assert!(matches!(
            tct.merge_alt_leaves(&[alt_leaf(0x04)]),
            Err(CommitmentError::DuplicateAltLeafKey(_))
        ));

        // Invalid alt leaves are rejected.
        let mut invalid = alt_leaf(0x05);
        invalid.amount = 1;
        assert!(matches!(
            tct.merge_alt_leaves(&[invalid]),
            Err(CommitmentError::InvalidAltLeaf(_))
        ));
    }

    #[test]
    fn merged_alt_leaf_inclusion_proof_derives_root() {
        let regular = test_asset(100, 0x02);
        let mut tct = tap_tree_with(&regular);

        let leaf = alt_leaf(0x04);
        tct.merge_alt_leaves(std::slice::from_ref(&leaf)).unwrap();

        // An STXO-style inclusion proof: tap key EMPTY_GENESIS_ID,
        // asset key from the alt leaf's script key.
        let tck = *crate::asset::EMPTY_GENESIS_ID.as_bytes();
        let ack = leaf.asset_commitment_key();
        let (found, proof) = tct.proof(&tck, &ack).unwrap();
        assert_eq!(found, Some(&leaf));
        assert!(proof.asset_proof.is_some());

        let derived = proof
            .derive_by_asset_inclusion(&ack, &asset_leaf(&leaf), &tck)
            .unwrap();
        assert_eq!(derived.node_hash(), tct.commitment().root_hash());

        // Exclusion of a different (not committed) alt leaf.
        let other = alt_leaf(0x05);
        let other_ack = other.asset_commitment_key();
        let (found, proof) = tct.proof(&tck, &other_ack).unwrap();
        assert!(found.is_none());
        let derived = proof
            .derive_by_asset_exclusion(&other_ack, &tck)
            .unwrap();
        assert_eq!(derived.node_hash(), tct.commitment().root_hash());
    }

    #[test]
    fn upsert_empty_asset_commitment_prunes_leaf() {
        // Merging then trimming via upsert of an empty commitment is
        // the Go Upsert pruning path: build an alt commitment, merge
        // it, then upsert a version of it whose inner tree is empty.
        let regular = test_asset(100, 0x02);
        let mut tct = tap_tree_with(&regular);
        let root_before = tct.commitment().root_hash();

        let leaf = alt_leaf(0x04);
        tct.merge_alt_leaves(std::slice::from_ref(&leaf)).unwrap();
        assert_ne!(tct.commitment().root_hash(), root_before);

        // Build an empty asset commitment at the same key by removing
        // the leaf from a copy of the alt commitment tree.
        let tck = *crate::asset::EMPTY_GENESIS_ID.as_bytes();
        let mut alt_ct =
            tct.asset_commitments().get(&tck).cloned().unwrap();
        alt_ct.tree.delete(leaf.asset_commitment_key()).unwrap();
        let empty_root = alt_ct.tree.root().unwrap();
        alt_ct.commitment = AssetCommitment::from_root(
            alt_ct.commitment.version,
            tck,
            alt_ct.commitment.asset_type,
            empty_root,
        );
        alt_ct.assets.clear();

        tct.upsert(alt_ct).unwrap();
        assert_eq!(tct.commitment().root_hash(), root_before);
        assert!(tct.fetch_alt_leaves().is_empty());
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
