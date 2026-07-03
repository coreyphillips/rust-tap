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

use crate::asset::{AssetVersion, SerializedKey};
use crate::mssmt::{self, LeafNode, Node};
use std::collections::BTreeMap;

use super::asset_commitment::CommitmentError;
use super::tap_commitment::TapCommitmentVersion;

/// A preimage of a tapscript tree node, used to compute a sibling hash
/// next to a Taproot Asset commitment leaf.
///
/// Wire format (Go's `TapscriptPreimageEncoder` in
/// `commitment/encoding.go`): 1 byte sibling type (0 = leaf, 1 =
/// branch) followed by the raw preimage bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TapscriptPreimage {
    /// The type of the sibling preimage (0 = leaf, 1 = branch).
    pub sibling_type: u8,
    /// The raw preimage bytes.
    pub sibling_preimage: Vec<u8>,
}

impl TapscriptPreimage {
    /// Returns true if the preimage is empty, matching Go's
    /// `TapscriptPreimage.IsEmpty`.
    pub fn is_empty(&self) -> bool {
        self.sibling_preimage.is_empty()
    }

    /// Encodes to wire format: `type(1) || preimage`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(1 + self.sibling_preimage.len());
        buf.push(self.sibling_type);
        buf.extend_from_slice(&self.sibling_preimage);
        buf
    }

    /// Decodes from wire format. A zero-length input is rejected,
    /// matching Go's `TapscriptPreimageDecoder`
    /// (`ErrInvalidTapscriptPreimageLen`).
    pub fn decode(data: &[u8]) -> Result<Self, CommitmentError> {
        if data.is_empty() {
            return Err(CommitmentError::InvalidProof(
                "empty tapscript preimage".into(),
            ));
        }
        Ok(TapscriptPreimage {
            sibling_type: data[0],
            sibling_preimage: data[1..].to_vec(),
        })
    }

    /// Computes the tap hash of this preimage according to its type,
    /// mirroring Go's `TapscriptPreimage.TapHash`
    /// (commitment/taproot.go:241).
    ///
    /// - Leaf preimages (type 0) carry `leaf_version(1) ||
    ///   varbytes(script)` (Go's `NewLeafFromPreimage`); the script must
    ///   not itself be a Taproot Asset commitment script.
    /// - Branch preimages (type 1) carry the two 32-byte child hashes.
    pub fn tap_hash(&self) -> Result<[u8; 32], CommitmentError> {
        if self.is_empty() {
            return Err(CommitmentError::InvalidProof(
                "empty tapscript preimage".into(),
            ));
        }

        match self.sibling_type {
            // Leaf preimage: version byte + varbyte-prefixed script,
            // Go's NewLeafFromPreimage (commitment/taproot.go).
            0 => {
                let raw = &self.sibling_preimage;
                if raw.len() < 2 {
                    return Err(CommitmentError::InvalidProof(
                        "invalid tapscript preimage length".into(),
                    ));
                }
                let version = raw[0];
                let (script, consumed) = read_var_bytes(&raw[1..])?;
                if 1 + consumed != raw.len() {
                    return Err(CommitmentError::InvalidProof(
                        "trailing bytes in leaf preimage".into(),
                    ));
                }
                if super::tap_commitment::TapCommitment::is_tap_commitment_script(
                    script,
                ) {
                    return Err(CommitmentError::InvalidProof(
                        "preimage is a Taproot Asset commitment".into(),
                    ));
                }
                Ok(crate::crypto::tapscript::tap_leaf_hash(version, script))
            }

            // Branch preimage: left(32) || right(32), hashed via
            // asset.NewTapBranchHash (which sorts the two children).
            1 => {
                if self.sibling_preimage.len() != 64 {
                    return Err(CommitmentError::InvalidProof(
                        "invalid tapscript preimage length".into(),
                    ));
                }
                let left: [u8; 32] =
                    self.sibling_preimage[..32].try_into().expect("32 bytes");
                let right: [u8; 32] =
                    self.sibling_preimage[32..].try_into().expect("32 bytes");
                Ok(crate::crypto::tapscript::tap_branch_hash(&left, &right))
            }

            other => Err(CommitmentError::InvalidProof(format!(
                "invalid tapscript preimage type: {}",
                other
            ))),
        }
    }
}

/// Reads a Bitcoin var-bytes (compact size length prefix + data) from
/// `data`, returning the payload and the total bytes consumed.
fn read_var_bytes(data: &[u8]) -> Result<(&[u8], usize), CommitmentError> {
    let err = || CommitmentError::InvalidProof("invalid var bytes".into());
    if data.is_empty() {
        return Err(err());
    }
    let (len, prefix) = match data[0] {
        n if n < 253 => (n as usize, 1usize),
        253 => {
            if data.len() < 3 {
                return Err(err());
            }
            (
                u16::from_le_bytes(data[1..3].try_into().expect("2")) as usize,
                3,
            )
        }
        254 => {
            if data.len() < 5 {
                return Err(err());
            }
            (
                u32::from_le_bytes(data[1..5].try_into().expect("4")) as usize,
                5,
            )
        }
        _ => {
            if data.len() < 9 {
                return Err(err());
            }
            (
                u64::from_le_bytes(data[1..9].try_into().expect("8")) as usize,
                9,
            )
        }
    };
    if data.len() < prefix + len {
        return Err(err());
    }
    Ok((&data[prefix..prefix + len], prefix + len))
}

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
///
/// This corresponds to Go's `proof.CommitmentProof` (which embeds
/// `commitment.Proof` and adds the sibling preimage and STXO proofs).
/// When used as an STXO map entry only `asset_proof` and
/// `taproot_asset_proof` are populated, matching Go's bare
/// `commitment.Proof`.
#[derive(Clone, Debug)]
pub struct CommitmentProof {
    /// Proof within the inner `AssetCommitment` tree.
    /// `None` means the asset commitment itself is excluded (non-inclusion at
    /// the outer level).
    pub asset_proof: Option<AssetProof>,
    /// Proof within the outer `TapCommitment` tree.
    pub taproot_asset_proof: TaprootAssetProof,
    /// Optional preimage of a tap node hashed together with the Taproot
    /// Asset commitment leaf to arrive at the tapscript root of the
    /// output (TLV type 5, Go's
    /// `CommitmentProofTapSiblingPreimageType`).
    pub tap_sibling_preimage: Option<TapscriptPreimage>,
    /// STXO proofs proving spend (inclusion) or non-spend (exclusion) of
    /// the inputs referenced by the asset's previous witnesses (TLV type
    /// 7, Go's `CommitmentProofSTXOProofsType`). Encode/decode only;
    /// verification is implemented separately.
    pub stxo_proofs: BTreeMap<SerializedKey, CommitmentProof>,
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
    value.push(version.to_u8());
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
    // Proof-level extensions (Go proof/records.go): the tap sibling
    // preimage and STXO proofs continue the numbering.
    pub const PROOF_TAP_SIBLING_PREIMAGE: u64 = 0x05;
    pub const PROOF_STXO_PROOFS: u64 = 0x07;
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
        let leaf = asset_leaf(&asset).unwrap();
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
            tap_sibling_preimage: None,
            stxo_proofs: BTreeMap::new(),
            unknown_odd_types: BTreeMap::new(),
        };

        let derived_root = commitment_proof
            .derive_by_asset_inclusion(&ack, &leaf, &tap_key)
            .unwrap();

        assert_eq!(derived_root.node_hash(), outer_root.node_hash());
    }
}
