// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tap commitment — the outer MS-SMT that holds all asset commitments,
//! anchored into a Bitcoin tapscript leaf.

use bitcoin_hashes::{sha256, Hash};
use std::sync::LazyLock;

use super::asset_commitment::{AssetCommitment, CommitmentError};
use crate::mssmt::{self};

/// Version of the TAP commitment encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TapCommitmentVersion {
    /// V0: only V0 assets, legacy leaf format.
    V0 = 0,
    /// V1: V0/V1 assets, legacy leaf format.
    V1 = 1,
    /// V2: V0/V1 assets, new leaf format (tagged).
    V2 = 2,
}

impl TapCommitmentVersion {
    pub fn from_u8(v: u8) -> Result<Self, CommitmentError> {
        match v {
            0 => Ok(TapCommitmentVersion::V0),
            1 => Ok(TapCommitmentVersion::V1),
            2 => Ok(TapCommitmentVersion::V2),
            _ => Err(CommitmentError::InvalidProof(format!(
                "unknown tap commitment version: {}",
                v
            ))),
        }
    }
}

/// SHA256("taproot-assets") — the marker embedded in V0/V1 tap leaves.
pub static TAPROOT_ASSETS_MARKER: LazyLock<[u8; 32]> = LazyLock::new(|| {
    sha256::Hash::hash(b"taproot-assets").to_byte_array()
});

/// SHA256("taproot-assets:194243") — the tag for V2 tap leaves.
pub static TAPROOT_ASSETS_V2_TAG: LazyLock<[u8; 32]> = LazyLock::new(|| {
    sha256::Hash::hash(b"taproot-assets:194243").to_byte_array()
});

/// The outer TAP commitment — an MS-SMT holding asset commitments, whose
/// root is embedded in a Bitcoin tapscript leaf.
#[derive(Clone, Debug)]
pub struct TapCommitment {
    /// Encoding version.
    pub version: TapCommitmentVersion,
    /// Root of the outer MS-SMT.
    pub tree_root: mssmt::BranchNode,
}

impl TapCommitment {
    /// Creates a `TapCommitment` from a set of asset commitments.
    pub fn new(
        version: TapCommitmentVersion,
        commitments: &[&AssetCommitment],
    ) -> Result<Self, CommitmentError> {
        let store = mssmt::DefaultStore::new();
        let mut tree = mssmt::FullTree::new(store);

        for ac in commitments {
            let key = ac.tap_key;
            let leaf = ac.tap_commitment_leaf();
            tree.insert(key, leaf)
                .map_err(|e| CommitmentError::TreeError(format!("{}", e)))?;
        }

        let root = tree
            .root()
            .map_err(|e| CommitmentError::TreeError(format!("{}", e)))?;

        Ok(TapCommitment {
            version,
            tree_root: root,
        })
    }

    /// Creates a `TapCommitment` with an optional explicit version.
    ///
    /// When `version` is `None`, the commitment version is derived from
    /// the maximum asset version among the commitments (V0 assets give
    /// a V0 commitment, V1 assets a V1 commitment), matching Go's
    /// `NewTapCommitment` (commitment/tap.go:106).
    pub fn from_asset_commitments(
        version: Option<TapCommitmentVersion>,
        commitments: &[&AssetCommitment],
    ) -> Result<Self, CommitmentError> {
        let version = match version {
            Some(v) => v,
            None => {
                let max_version = commitments
                    .iter()
                    .map(|ac| ac.version.to_u8())
                    .max()
                    .unwrap_or(0);
                TapCommitmentVersion::from_u8(max_version)?
            }
        };
        Self::new(version, commitments)
    }

    /// Creates a `TapCommitment` from a known root (used when
    /// reconstructing from proofs).
    pub fn from_root(
        version: TapCommitmentVersion,
        tree_root: mssmt::BranchNode,
    ) -> Self {
        TapCommitment { version, tree_root }
    }

    /// Produces the tapscript leaf bytes for embedding in a Bitcoin
    /// Taproot output.
    ///
    /// **V0/V1 format (73 bytes):**
    /// `version(1) || marker(32) || root_hash(32) || BE(root_sum)(8)`
    ///
    /// **V2 format (73 bytes):**
    /// `tag(32) || version(1) || root_hash(32) || BE(root_sum)(8)`
    pub fn tap_leaf(&self) -> Vec<u8> {
        let root_hash = self.tree_root.node_hash();
        let root_sum = self.tree_root.node_sum();

        let mut leaf = Vec::with_capacity(73);

        match self.version {
            TapCommitmentVersion::V0 | TapCommitmentVersion::V1 => {
                leaf.push(self.version as u8);
                leaf.extend_from_slice(&*TAPROOT_ASSETS_MARKER);
                leaf.extend_from_slice(root_hash.as_bytes());
                leaf.extend_from_slice(&root_sum.to_be_bytes());
            }
            TapCommitmentVersion::V2 => {
                leaf.extend_from_slice(&*TAPROOT_ASSETS_V2_TAG);
                leaf.push(self.version as u8);
                leaf.extend_from_slice(root_hash.as_bytes());
                leaf.extend_from_slice(&root_sum.to_be_bytes());
            }
        }

        leaf
    }

    /// Returns the root hash of the outer MS-SMT.
    pub fn root_hash(&self) -> mssmt::NodeHash {
        self.tree_root.node_hash()
    }

    /// Returns the total sum of all committed assets.
    pub fn root_sum(&self) -> u64 {
        self.tree_root.node_sum()
    }

    /// Returns the tapscript root for this commitment, matching Go's
    /// `TapCommitment.TapscriptRoot` (commitment/tap.go:457).
    ///
    /// If `sibling` is `Some`, the commitment leaf hash is combined
    /// with the sibling hash into a tap branch (sorted); otherwise the
    /// commitment leaf hash itself is the tapscript root.
    pub fn tapscript_root(&self, sibling: Option<&[u8; 32]>) -> [u8; 32] {
        // The commitment tap leaf always uses the base tapscript leaf
        // version (0xc0).
        let leaf_hash =
            crate::crypto::tapscript::tap_leaf_hash(0xc0, &self.tap_leaf());
        match sibling {
            None => leaf_hash,
            Some(s) => {
                crate::crypto::tapscript::tap_branch_hash(&leaf_hash, s)
            }
        }
    }

    /// Returns a copy of this commitment with the version downgraded to
    /// V0, mirroring Go's `TapCommitment.Downgrade` (commitment/tap.go:408)
    /// for root-only commitments (the only case reachable from
    /// proof-derived commitments).
    pub fn downgrade(&self) -> TapCommitment {
        TapCommitment {
            version: TapCommitmentVersion::V0,
            tree_root: self.tree_root.clone(),
        }
    }

    /// Checks if the given bytes look like a TAP commitment script.
    ///
    /// The script must be exactly 73 bytes. Mirrors Go's
    /// `IsTaprootAssetCommitmentScript` (commitment/tap.go:432) exactly:
    /// the check switches on the leading version byte first, so a script
    /// whose first byte is neither `TapCommitmentV0` nor `TapCommitmentV1`
    /// is only accepted if it starts with the V2 tag, and a script whose
    /// first byte IS a V0/V1 version byte is only accepted if the V0/V1
    /// marker follows it. Checking marker and tag independent of the
    /// version byte would falsely accept crafted 73-byte scripts.
    pub fn is_tap_commitment_script(script: &[u8]) -> bool {
        if script.len() != 73 {
            return false;
        }

        match script[0] {
            // V0 and V1 commitment scripts use the legacy TapLeaf
            // format: version(1) || marker(32) || ...
            0 | 1 => script[1..33] == *TAPROOT_ASSETS_MARKER,

            // Everything else must use the V2 format: tag(32) || ...
            _ => script[0..32] == *TAPROOT_ASSETS_V2_TAG,
        }
    }
}

/// Returns true if both versions are nil, equal, or map to the same
/// effective commitment version. Mirrors Go's
/// `IsSimilarTapCommitmentVersion` (commitment/tap.go:280).
pub fn is_similar_tap_commitment_version(
    a: Option<&TapCommitmentVersion>,
    b: Option<&TapCommitmentVersion>,
) -> bool {
    match (a, b) {
        (None, None) => true,
        (None, Some(v)) | (Some(v), None) => {
            matches!(v, TapCommitmentVersion::V0 | TapCommitmentVersion::V1)
        }
        (Some(a), Some(b)) => {
            if *a == TapCommitmentVersion::V2 {
                return *b == TapCommitmentVersion::V2;
            }
            matches!(a, TapCommitmentVersion::V0 | TapCommitmentVersion::V1)
                && matches!(
                    b,
                    TapCommitmentVersion::V0 | TapCommitmentVersion::V1
                )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::*;
    use crate::commitment::asset_commitment::AssetCommitment;

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
    fn test_tap_leaf_v0_size() {
        let asset = test_asset(100, 0x02);
        let ac = AssetCommitment::new(&[&asset]).unwrap();
        let tc = TapCommitment::new(TapCommitmentVersion::V0, &[&ac]).unwrap();
        let leaf = tc.tap_leaf();
        assert_eq!(leaf.len(), 73);
        assert_eq!(leaf[0], 0x00); // V0
    }

    #[test]
    fn test_tap_leaf_v1_size() {
        let asset = test_asset(200, 0x03);
        let ac = AssetCommitment::new(&[&asset]).unwrap();
        let tc = TapCommitment::new(TapCommitmentVersion::V1, &[&ac]).unwrap();
        let leaf = tc.tap_leaf();
        assert_eq!(leaf.len(), 73);
        assert_eq!(leaf[0], 0x01); // V1
    }

    #[test]
    fn test_tap_leaf_v2_size() {
        let asset = test_asset(300, 0x04);
        let ac = AssetCommitment::new(&[&asset]).unwrap();
        let tc = TapCommitment::new(TapCommitmentVersion::V2, &[&ac]).unwrap();
        let leaf = tc.tap_leaf();
        assert_eq!(leaf.len(), 73);
        assert_eq!(leaf[0..32], *TAPROOT_ASSETS_V2_TAG);
    }

    #[test]
    fn test_tap_commitment_sum() {
        let a1 = test_asset(60, 0x02);
        let a2 = test_asset(40, 0x03);
        // Two separate asset commitments with the same genesis → same tap key.
        let ac = AssetCommitment::new(&[&a1, &a2]).unwrap();
        let tc = TapCommitment::new(TapCommitmentVersion::V0, &[&ac]).unwrap();
        assert_eq!(tc.root_sum(), 100);
    }

    #[test]
    fn test_is_tap_commitment_script_v0() {
        let asset = test_asset(50, 0x02);
        let ac = AssetCommitment::new(&[&asset]).unwrap();
        let tc = TapCommitment::new(TapCommitmentVersion::V0, &[&ac]).unwrap();
        let leaf = tc.tap_leaf();
        assert!(TapCommitment::is_tap_commitment_script(&leaf));
    }

    #[test]
    fn test_is_tap_commitment_script_v2() {
        let asset = test_asset(50, 0x02);
        let ac = AssetCommitment::new(&[&asset]).unwrap();
        let tc = TapCommitment::new(TapCommitmentVersion::V2, &[&ac]).unwrap();
        let leaf = tc.tap_leaf();
        assert!(TapCommitment::is_tap_commitment_script(&leaf));
    }

    #[test]
    fn test_not_tap_commitment_script() {
        assert!(!TapCommitment::is_tap_commitment_script(&[0u8; 73]));
        assert!(!TapCommitment::is_tap_commitment_script(&[0u8; 10]));
    }

    #[test]
    fn test_crafted_script_marker_with_bad_version_byte() {
        // A crafted 73-byte script that carries the V0/V1 marker at
        // offset 1 but has a version byte that is neither 0 nor 1. Go
        // falls through to the V2 branch (which requires the tag at
        // offset 0) and rejects it; so must we.
        let mut script = [0u8; 73];
        script[0] = 0x05;
        script[1..33].copy_from_slice(&*TAPROOT_ASSETS_MARKER);
        assert!(!TapCommitment::is_tap_commitment_script(&script));

        // The same script with a valid V0/V1 version byte is accepted.
        script[0] = 0x00;
        assert!(TapCommitment::is_tap_commitment_script(&script));
        script[0] = 0x01;
        assert!(TapCommitment::is_tap_commitment_script(&script));
    }

    #[test]
    fn test_crafted_script_v0_version_byte_requires_marker() {
        // A script starting with a V0/V1 version byte must carry the
        // marker at offset 1; the V2 tag branch is not consulted for
        // these version bytes (mirrors Go's switch semantics).
        let mut script = [0u8; 73];
        script[0] = 0x00;
        script[1..32].copy_from_slice(&TAPROOT_ASSETS_V2_TAG[1..32]);
        assert!(!TapCommitment::is_tap_commitment_script(&script));
    }
}
