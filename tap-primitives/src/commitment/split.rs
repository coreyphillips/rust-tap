// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Split commitment structures for partial asset transfers.
//!
//! When an asset is split across multiple outputs, a split commitment tree
//! (MS-SMT) is constructed. The root of this tree is stored in the root
//! asset's `split_commitment_root` field, and each split output carries a
//! proof of inclusion in this tree.

use bitcoin_hashes::{sha256, Hash, HashEngine};
use std::collections::HashMap;

use crate::asset::{Asset, AssetId, AssetType, SerializedKey};
use crate::mssmt;

use super::asset_commitment::CommitmentError;

/// Identifies a split output by its position and destination.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SplitLocator {
    /// Output index in the on-chain transaction.
    pub output_index: u32,
    /// Asset ID of the split asset.
    pub asset_id: AssetId,
    /// Script key of the recipient.
    pub script_key: SerializedKey,
    /// Amount allocated to this split.
    pub amount: u64,
}

impl SplitLocator {
    /// Computes the MS-SMT key for this split locator.
    ///
    /// `SHA256(BE(output_index) || asset_id || schnorr_script_key)`
    /// Total input: 4 + 32 + 32 = 68 bytes.
    pub fn hash(&self) -> [u8; 32] {
        let mut engine = sha256::HashEngine::default();
        engine.input(&self.output_index.to_be_bytes());
        engine.input(self.asset_id.as_bytes());
        engine.input(self.script_key.schnorr_bytes());
        sha256::Hash::from_engine(engine).to_byte_array()
    }
}

/// An asset with its output index — one piece of a split.
#[derive(Clone, Debug)]
pub struct SplitAsset {
    /// The split asset (with updated amount and script key).
    pub asset: Asset,
    /// The output index in the transaction.
    pub output_index: u32,
}

/// The result of constructing a split commitment.
#[derive(Clone, Debug)]
pub struct SplitCommitment {
    /// The root asset containing the split commitment tree root and witnesses.
    pub root_asset: Asset,
    /// The split outputs keyed by their locator.
    pub split_assets: HashMap<SplitLocator, SplitAsset>,
    /// The MS-SMT root node of the split tree.
    pub tree_root: mssmt::BranchNode,
}

/// Input assets being split, keyed by their PrevId.
pub type InputSet = HashMap<crate::asset::PrevId, Asset>;

/// Validates the locators for a split commitment.
pub fn validate_split_locators(
    root_locator: &SplitLocator,
    external_locators: &[&SplitLocator],
    asset_type: AssetType,
) -> Result<(), CommitmentError> {
    // Root locator validation.
    if root_locator.amount == 0
        && root_locator.script_key != crate::asset::NUMS_KEY
    {
        return Err(CommitmentError::InvalidProof(
            "zero-amount root must use NUMS key".into(),
        ));
    }
    if root_locator.amount != 0
        && root_locator.script_key == crate::asset::NUMS_KEY
    {
        return Err(CommitmentError::InvalidProof(
            "non-zero root must not use NUMS key".into(),
        ));
    }

    // External locators must have non-zero amounts.
    for loc in external_locators {
        if loc.amount == 0 {
            return Err(CommitmentError::InvalidProof(
                "external split locator has zero amount".into(),
            ));
        }
    }

    // Collectible-specific validation.
    if asset_type == AssetType::Collectible {
        if root_locator.amount != 0 {
            return Err(CommitmentError::InvalidProof(
                "collectible root must have zero amount".into(),
            ));
        }
        if external_locators.len() != 1 {
            return Err(CommitmentError::InvalidProof(
                "collectible must have exactly one external locator".into(),
            ));
        }
    }

    if external_locators.is_empty() {
        return Err(CommitmentError::InvalidProof(
            "at least one external locator required".into(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::*;

    #[test]
    fn test_split_locator_hash_deterministic() {
        let loc = SplitLocator {
            output_index: 1,
            asset_id: AssetId([0xAA; 32]),
            script_key: SerializedKey([0x02; 33]),
            amount: 100,
        };

        let h1 = loc.hash();
        let h2 = loc.hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn test_split_locator_hash_differs_by_index() {
        let mut loc = SplitLocator {
            output_index: 0,
            asset_id: AssetId([0xAA; 32]),
            script_key: SerializedKey([0x02; 33]),
            amount: 100,
        };
        let h1 = loc.hash();
        loc.output_index = 1;
        let h2 = loc.hash();
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_validate_valid_split() {
        let root = SplitLocator {
            output_index: 0,
            asset_id: AssetId([0xAA; 32]),
            script_key: NUMS_KEY,
            amount: 0,
        };
        let external = SplitLocator {
            output_index: 1,
            asset_id: AssetId([0xAA; 32]),
            script_key: SerializedKey([0x02; 33]),
            amount: 100,
        };
        assert!(validate_split_locators(
            &root,
            &[&external],
            AssetType::Normal
        )
        .is_ok());
    }

    #[test]
    fn test_validate_root_zero_amount_wrong_key() {
        let root = SplitLocator {
            output_index: 0,
            asset_id: AssetId([0xAA; 32]),
            script_key: SerializedKey([0x02; 33]), // not NUMS
            amount: 0,
        };
        let external = SplitLocator {
            output_index: 1,
            asset_id: AssetId([0xAA; 32]),
            script_key: SerializedKey([0x03; 33]),
            amount: 100,
        };
        assert!(validate_split_locators(
            &root,
            &[&external],
            AssetType::Normal
        )
        .is_err());
    }

    #[test]
    fn test_validate_no_external_locators() {
        let root = SplitLocator {
            output_index: 0,
            asset_id: AssetId([0xAA; 32]),
            script_key: NUMS_KEY,
            amount: 0,
        };
        assert!(
            validate_split_locators(&root, &[], AssetType::Normal).is_err()
        );
    }
}
