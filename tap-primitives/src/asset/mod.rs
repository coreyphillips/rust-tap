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
pub use genesis::{AssetId, Genesis, OutPoint, EMPTY_GENESIS_ID};
pub use group_key::{
    group_pub_key_v1, new_group_key_tapscript_root,
    new_group_key_v1_from_external, new_non_spendable_script_leaf,
    ExternalKey, GroupKey, GroupKeyReveal, GroupKeyRevealV0,
    GroupKeyRevealV1, GroupKeyRevealTapscript, OP_RETURN_VERSION,
    PEDERSEN_VERSION, TAPSCRIPT_LEAF_VERSION,
};
pub use types::GroupKeyVersion;
pub use script_key::{
    derive_unique_script_key, ScriptKey, ScriptKeyDerivationMethod,
    TweakedScriptKey, NUMS_BYTES, NUMS_KEY,
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

    /// Returns the MS-SMT key of this asset within its
    /// `AssetCommitment`, mirroring Go's `Asset.AssetCommitmentKey`
    /// (asset/asset.go):
    ///
    /// - no group key: `SHA256(schnorr_script_key)`
    /// - group key present: `SHA256(asset_id || schnorr_script_key)`
    pub fn asset_commitment_key(&self) -> [u8; 32] {
        use bitcoin_hashes::{sha256, Hash, HashEngine};

        let mut engine = sha256::HashEngine::default();
        if self.group_key.is_some() {
            engine.input(self.id().as_bytes());
        }
        engine.input(self.script_key.serialized().schnorr_bytes());
        sha256::Hash::from_engine(engine).to_byte_array()
    }

    /// Checks that this asset is a valid alt leaf, mirroring Go's
    /// `Asset.ValidateAltLeaf` (asset/asset.go:2360). An alt leaf must
    /// have version V0, the empty genesis, zero amount and lock times,
    /// no split commitment root, and no group key.
    pub fn validate_alt_leaf(&self) -> Result<(), AssetError> {
        let invalid =
            |msg: &str| Err(AssetError::InvalidAltLeaf(msg.to_string()));

        if self.version != AssetVersion::V0 {
            return invalid("alt leaf version must be 0");
        }
        if !self.genesis.is_empty() {
            return invalid("alt leaf genesis must be the empty genesis");
        }
        if self.amount != 0 {
            return invalid("alt leaf amount must be 0");
        }
        if self.lock_time != 0 {
            return invalid("alt leaf lock time must be 0");
        }
        if self.relative_lock_time != 0 {
            return invalid("alt leaf relative lock time must be 0");
        }
        if self.split_commitment_root.is_some() {
            return invalid("alt leaf split commitment root must be empty");
        }
        if self.group_key.is_some() {
            return invalid("alt leaf group key must be empty");
        }
        // The script key is always set in the Rust representation
        // (Go additionally checks for a nil pubkey here).

        Ok(())
    }

    /// Returns true if this asset would be stored in the alt commitment
    /// (under [`EMPTY_GENESIS_ID`]) of a TapCommitment, mirroring Go's
    /// `Asset.IsAltLeaf` (asset/asset.go:2432). Does not check that the
    /// asset is a valid alt leaf.
    pub fn is_alt_leaf(&self) -> bool {
        self.group_key.is_none() && self.genesis.is_empty()
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

/// Checks that a set of assets are valid alt leaves with unique asset
/// commitment keys, mirroring Go's `asset.ValidAltLeaves`
/// (asset/asset.go:2400).
pub fn valid_alt_leaves(leaves: &[Asset]) -> Result<(), AssetError> {
    let mut leaf_keys = std::collections::BTreeSet::new();
    add_leaf_keys_verify_unique(&mut leaf_keys, leaves)
}

/// Validates each alt leaf and checks that its asset commitment key is
/// unique both among `leaves` and against `existing_keys`, mirroring
/// Go's `asset.AddLeafKeysVerifyUnique`. Valid keys are added to
/// `existing_keys`.
pub fn add_leaf_keys_verify_unique(
    existing_keys: &mut std::collections::BTreeSet<[u8; 32]>,
    leaves: &[Asset],
) -> Result<(), AssetError> {
    for leaf in leaves {
        leaf.validate_alt_leaf()?;

        let leaf_key = leaf.asset_commitment_key();
        if !existing_keys.insert(leaf_key) {
            return Err(AssetError::DuplicateAltLeafKey(leaf_key));
        }
    }

    Ok(())
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

    fn test_alt_leaf(key_byte: u8) -> Asset {
        Asset::new_alt_leaf(
            ScriptKey::from_pub_key(SerializedKey([key_byte; 33])),
            ScriptVersion::V0,
        )
    }

    #[test]
    fn test_validate_alt_leaf_accepts_new_alt_leaf() {
        let leaf = test_alt_leaf(0x02);
        assert!(leaf.validate_alt_leaf().is_ok());
        assert!(leaf.is_alt_leaf());
    }

    #[test]
    fn test_validate_alt_leaf_rejects_invalid_fields() {
        // Every constraint from Go's Asset.ValidateAltLeaf, violated
        // one at a time.
        let cases: Vec<(&str, Box<dyn Fn(&mut Asset)>)> = vec![
            ("version", Box::new(|a| a.version = AssetVersion::V1)),
            ("genesis", Box::new(|a| a.genesis = test_genesis())),
            ("amount", Box::new(|a| a.amount = 1)),
            ("lock time", Box::new(|a| a.lock_time = 1)),
            (
                "relative lock time",
                Box::new(|a| a.relative_lock_time = 1),
            ),
            (
                "split root",
                Box::new(|a| {
                    a.split_commitment_root =
                        Some((crate::mssmt::NodeHash([0u8; 32]), 0))
                }),
            ),
            (
                "group key",
                Box::new(|a| {
                    a.group_key = Some(GroupKey {
                        version: GroupKeyVersion::V0,
                        raw_key: SerializedKey([0x02; 33]),
                        group_pub_key: SerializedKey([0x02; 33]),
                        tapscript_root: vec![],
                        witness: vec![],
                    })
                }),
            ),
        ];

        for (name, mutate) in cases {
            let mut leaf = test_alt_leaf(0x02);
            mutate(&mut leaf);
            assert!(
                leaf.validate_alt_leaf().is_err(),
                "constraint not enforced: {}",
                name
            );
        }
    }

    #[test]
    fn test_is_alt_leaf_ignores_other_fields() {
        // IsAltLeaf only checks the group key and genesis, matching Go.
        let mut leaf = test_alt_leaf(0x02);
        leaf.amount = 5;
        assert!(leaf.is_alt_leaf());
        assert!(leaf.validate_alt_leaf().is_err());
    }

    #[test]
    fn test_valid_alt_leaves_rejects_duplicate_keys() {
        let a = test_alt_leaf(0x02);
        let b = test_alt_leaf(0x03);
        assert!(valid_alt_leaves(&[a.clone(), b.clone()]).is_ok());

        let result = valid_alt_leaves(&[a.clone(), b, a.clone()]);
        assert!(matches!(
            result,
            Err(AssetError::DuplicateAltLeafKey(key))
                if key == a.asset_commitment_key()
        ));
    }

    #[test]
    fn test_collect_stxo_transfer_root() {
        let genesis = test_genesis();
        let prev_id = PrevId {
            out_point: OutPoint {
                txid: [0xAB; 32],
                vout: 1,
            },
            id: genesis.id(),
            script_key: SerializedKey([0x02; 33]),
        };
        let mut asset = Asset::new_genesis(
            genesis,
            50,
            ScriptKey::from_pub_key(SerializedKey({ let mut k = [0x22; 33]; k[0] = 0x03; k })),
        );
        asset.prev_witnesses = vec![Witness {
            prev_id: Some(prev_id.clone()),
            tx_witness: vec![vec![0u8; 64]],
            split_commitment: None,
        }];
        assert!(asset.is_transfer_root());

        let stxos = collect_stxo(&asset).unwrap();
        assert_eq!(stxos.len(), 1);
        let stxo = &stxos[0];
        assert!(stxo.validate_alt_leaf().is_ok());
        assert_eq!(
            stxo.script_key.serialized(),
            &derive_burn_key(&prev_id)
        );

        // Genesis assets and split leaves produce no STXO markers.
        let genesis_asset = Asset::new_genesis(
            test_genesis(),
            10,
            ScriptKey::from_pub_key(SerializedKey({ let mut k = [0x22; 33]; k[0] = 0x03; k })),
        );
        assert!(collect_stxo(&genesis_asset).unwrap().is_empty());
    }

    #[test]
    fn test_alt_leaf_encode_decode_round_trip() {
        use crate::encoding::asset::{decode_asset, encode_alt_leaf};

        // A plain STXO-style alt leaf, and one carrying witnesses (as
        // used by asset channels). The script keys must be valid curve
        // points, since decode validates them like Go.
        let plain = test_alt_leaf(0x02);
        let mut with_witness = Asset::new_alt_leaf(
            ScriptKey::from_pub_key(SerializedKey({
                let mut k = [0x22; 33];
                k[0] = 0x03;
                k
            })),
            ScriptVersion::V0,
        );
        with_witness.prev_witnesses = vec![Witness {
            prev_id: Some(PrevId::ZERO),
            tx_witness: vec![vec![0x01, 0x02], vec![0x03]],
            split_commitment: None,
        }];

        for leaf in [plain, with_witness] {
            let encoded = encode_alt_leaf(&leaf);
            let decoded = decode_asset(&encoded).expect("decode alt leaf");
            assert_eq!(decoded, leaf);
            assert!(decoded.validate_alt_leaf().is_ok());
        }
    }
}
