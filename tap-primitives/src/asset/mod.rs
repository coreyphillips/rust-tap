// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Core Taproot Asset data structures.
//!
//! This module defines the fundamental types for the Taproot Assets Protocol:
//! - [`Asset`]: The central type representing a Taproot Asset
//! - [`Genesis`] / [`AssetId`]: Asset identity derived from minting metadata
//! - [`ScriptKey`]: The key that authorizes spending an asset
//! - [`GroupKey`]: Links multiple issuances into a fungible group
//! - [`Witness`] / [`PrevId`]: State transition proofs

pub mod burn;
pub mod genesis;
pub mod group_key;
pub mod script_key;
pub mod types;
pub mod witness;

use std::collections::BTreeMap;

pub use burn::{derive_burn_key, is_burn_key};
pub use genesis::{AssetId, Genesis, OutPoint};
pub use group_key::{
    GroupKey, GroupKeyReveal, GroupKeyRevealV0, GroupKeyRevealV1,
    GroupKeyRevealTapscript,
};
pub use types::GroupKeyVersion;
pub use script_key::{
    ScriptKey, TweakedScriptKey, NUMS_BYTES, NUMS_KEY,
};
pub use types::*;
pub use witness::{PrevId, SplitCommitmentWitness, Witness};

use crate::mssmt;

/// A Taproot Asset — the central data structure of the protocol.
///
/// Each asset is identified by its genesis and anchored to a Bitcoin UTXO
/// via a Taproot commitment. The script key controls who can spend the asset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asset {
    /// Protocol version.
    pub version: AssetVersion,
    /// Genesis metadata that uniquely identifies this asset type.
    pub genesis: Genesis,
    /// Number of asset units. Always 1 for collectibles.
    pub amount: u64,
    /// Absolute lock time (block height). 0 means no lock.
    pub lock_time: u64,
    /// Relative lock time (block count). 0 means no lock.
    pub relative_lock_time: u64,
    /// Witnesses proving valid state transitions from previous owners.
    pub prev_witnesses: Vec<Witness>,
    /// Root of the split commitment tree, if this asset was split.
    /// Stored as (hash, sum) from the MS-SMT root node.
    pub split_commitment_root: Option<(mssmt::NodeHash, u64)>,
    /// Script version.
    pub script_version: ScriptVersion,
    /// The key that authorizes spending this asset.
    pub script_key: ScriptKey,
    /// Optional group key linking this to other issuances.
    pub group_key: Option<GroupKey>,
    /// Unknown odd TLV types preserved for forward compatibility.
    pub unknown_odd_types: BTreeMap<u64, Vec<u8>>,
}

impl Asset {
    /// Returns the asset ID derived from the genesis.
    pub fn id(&self) -> AssetId {
        self.genesis.id()
    }

    /// Returns true if this is a genesis asset (first issuance).
    pub fn is_genesis_asset(&self) -> bool {
        self.has_genesis_witness() || self.has_genesis_witness_for_group()
    }

    /// Returns true if this asset has a simple genesis witness (no group).
    pub fn has_genesis_witness(&self) -> bool {
        self.prev_witnesses.len() == 1
            && self.prev_witnesses[0].is_genesis()
    }

    /// Returns true if this asset has a genesis witness with group
    /// authorization.
    pub fn has_genesis_witness_for_group(&self) -> bool {
        self.prev_witnesses.len() == 1
            && self.prev_witnesses[0].is_genesis_for_group()
            && self.group_key.is_some()
    }

    /// Returns true if this is a grouped genesis asset whose group
    /// witness has not been attached yet. Matches Go's
    /// `Asset.NeedsGenesisWitnessForGroup`.
    pub fn needs_genesis_witness_for_group(&self) -> bool {
        self.has_genesis_witness() && self.group_key.is_some()
    }

    /// Returns true if this asset has a split commitment witness.
    pub fn has_split_commitment_witness(&self) -> bool {
        self.prev_witnesses.len() == 1
            && self.prev_witnesses[0].is_split_commitment()
    }

    /// Returns true if this is a transfer root (not genesis, not split output).
    pub fn is_transfer_root(&self) -> bool {
        !self.is_genesis_asset() && !self.has_split_commitment_witness()
    }

    /// Returns true if this asset is un-spendable (NUMS key + zero amount).
    pub fn is_unspendable(&self) -> bool {
        self.script_key.is_nums() && self.amount == 0
    }

    /// Returns true if this is a tombstone output (zero-value, NUMS key).
    pub fn is_tombstone(&self) -> bool {
        self.amount == 0 && self.script_key.is_nums()
    }

    /// Returns the primary PrevId — the prev ID of the first witness.
    /// For split commitment witnesses, follows through to the root asset's
    /// first witness.
    pub fn primary_prev_id(&self) -> Option<&PrevId> {
        self.prev_witnesses.first()?.prev_id.as_ref()
    }

    /// Creates a new genesis asset with default fields.
    pub fn new_genesis(
        genesis: Genesis,
        amount: u64,
        script_key: ScriptKey,
    ) -> Self {
        Asset {
            version: AssetVersion::V0,
            genesis,
            amount,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![Witness {
                prev_id: Some(PrevId::ZERO),
                tx_witness: vec![],
                split_commitment: None,
            }],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key,
            group_key: None,
            unknown_odd_types: BTreeMap::new(),
        }
    }

    /// Creates a minimal alt-leaf asset, mirroring Go's
    /// `asset.NewAltLeaf` (asset/asset.go:2325): version V0, empty
    /// genesis, zero amount, no witnesses, no group key.
    pub fn new_alt_leaf(
        script_key: ScriptKey,
        script_version: ScriptVersion,
    ) -> Self {
        Asset {
            version: AssetVersion::V0,
            genesis: Genesis::empty(),
            amount: 0,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![],
            split_commitment_root: None,
            script_version,
            script_key,
            group_key: None,
            unknown_odd_types: BTreeMap::new(),
        }
    }

    /// Copies this asset for spending in a dependent transaction,
    /// mirroring Go's `Asset.CopySpendTemplate` (asset/asset.go:1949):
    /// the split commitment root and both lock time fields are cleared.
    pub fn copy_spend_template(&self) -> Asset {
        let mut copy = self.clone();
        copy.split_commitment_root = None;
        copy.relative_lock_time = 0;
        copy.lock_time = 0;
        copy
    }
}

/// Creates a minimal spent-asset marker from a witness' `PrevId`,
/// mirroring Go's `asset.MakeSpentAsset` (asset/asset.go:2523). The
/// marker is an alt leaf whose script key is the burn key derived from
/// the prev ID.
pub fn make_spent_asset(witness: &Witness) -> Result<Asset, AssetError> {
    let prev_id = witness.prev_id.as_ref().ok_or_else(|| {
        AssetError::EncodingError("witness has no prevID".into())
    })?;

    let prev_id_key = derive_burn_key(prev_id);
    let script_key = ScriptKey::from_pub_key(prev_id_key);

    Ok(Asset::new_alt_leaf(script_key, ScriptVersion::V0))
}

/// Returns the assets spent by the given output asset in the form of
/// minimal spent-asset markers usable for STXO commitments, mirroring
/// Go's `asset.CollectSTXO` (asset/asset.go:2492).
///
/// Genesis assets and split leaves have an empty STXO set.
pub fn collect_stxo(out_asset: &Asset) -> Result<Vec<Asset>, AssetError> {
    if !out_asset.is_transfer_root() {
        return Ok(vec![]);
    }

    if out_asset.prev_witnesses.is_empty() {
        return Err(AssetError::EncodingError(
            "asset has no witnesses".into(),
        ));
    }

    out_asset
        .prev_witnesses
        .iter()
        .map(make_spent_asset)
        .collect()
}

/// TLV type numbers for asset encoding (must match Go implementation).
pub mod tlv_types {
    pub const LEAF_VERSION: u64 = 0;
    pub const LEAF_GENESIS: u64 = 2;
    pub const LEAF_TYPE: u64 = 4;
    pub const LEAF_AMOUNT: u64 = 6;
    pub const LEAF_LOCK_TIME: u64 = 7;
    pub const LEAF_RELATIVE_LOCK_TIME: u64 = 9;
    pub const LEAF_PREV_WITNESS: u64 = 11;
    pub const LEAF_SPLIT_COMMITMENT_ROOT: u64 = 13;
    pub const LEAF_SCRIPT_VERSION: u64 = 14;
    pub const LEAF_SCRIPT_KEY: u64 = 16;
    pub const LEAF_GROUP_KEY: u64 = 17;

    // Witness sub-record types.
    pub const WITNESS_PREV_ID: u64 = 1;
    pub const WITNESS_TX_WITNESS: u64 = 3;
    pub const WITNESS_SPLIT_COMMITMENT: u64 = 5;

    // Group key reveal types (V1).
    pub const GKR_VERSION: u64 = 0;
    pub const GKR_INTERNAL_KEY: u64 = 2;
    pub const GKR_TAPSCRIPT_ROOT: u64 = 4;
    pub const GKR_CUSTOM_SUBTREE_ROOT: u64 = 7;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_genesis() -> Genesis {
        Genesis {
            first_prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            tag: "test-asset".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        }
    }

    #[test]
    fn test_new_genesis_asset() {
        let genesis = test_genesis();
        let key = ScriptKey::from_pub_key(SerializedKey([0x02; 33]));
        let asset = Asset::new_genesis(genesis.clone(), 1000, key);

        assert_eq!(asset.amount, 1000);
        assert!(asset.is_genesis_asset());
        assert!(asset.has_genesis_witness());
        assert!(!asset.has_genesis_witness_for_group());
        assert!(!asset.has_split_commitment_witness());
        assert!(!asset.is_transfer_root());
        assert_eq!(asset.id(), genesis.id());
    }

    #[test]
    fn test_tombstone_asset() {
        let genesis = test_genesis();
        let asset = Asset::new_genesis(genesis, 0, ScriptKey::from_pub_key(NUMS_KEY));
        assert!(asset.is_tombstone());
        assert!(asset.is_unspendable());
    }

    #[test]
    fn test_non_tombstone() {
        let genesis = test_genesis();
        let key = ScriptKey::from_pub_key(SerializedKey([0x02; 33]));
        let asset = Asset::new_genesis(genesis, 100, key);
        assert!(!asset.is_tombstone());
        assert!(!asset.is_unspendable());
    }
}
