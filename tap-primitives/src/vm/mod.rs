// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Taproot Asset virtual machine for validating state transitions.
//!
//! The [`Engine`] validates that an asset state transition is correct by
//! checking:
//! - Genesis assets have proper structure (no inputs, no splits)
//! - Split commitments are provably included in the split root
//! - Amount conservation: sum of inputs equals sum of outputs
//! - Asset parameters (type, genesis) are preserved across transfers
//!
//! Witness validation (actual signature verification) requires integration
//! with a Bitcoin script engine and is stubbed as a trait for external
//! implementation.

use std::collections::HashMap;

use crate::asset::{
    Asset, AssetType, PrevId, ScriptVersion, Witness,
};
use crate::commitment::{SplitAsset, SplitLocator};
use crate::mssmt;

/// Errors from VM execution.
#[derive(Debug, Clone)]
pub enum VmError {
    InvalidGenesisStateTransition,
    NoInputs,
    AmountMismatch { expected: u64, got: u64 },
    InvalidSplitAssetType,
    NoSplitCommitment,
    InvalidSplitCommitmentWitness,
    InvalidSplitCommitmentProof,
    InvalidRootAsset,
    InvalidTransferWitness(String),
    ScriptKeyMismatch,
    IdMismatch,
    TypeMismatch,
    InvalidScriptVersion,
    WitnessValidationFailed(String),
}

impl std::fmt::Display for VmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmError::InvalidGenesisStateTransition => {
                write!(f, "invalid genesis state transition")
            }
            VmError::NoInputs => write!(f, "no inputs"),
            VmError::AmountMismatch { expected, got } => {
                write!(f, "amount mismatch: expected {}, got {}", expected, got)
            }
            VmError::InvalidSplitAssetType => {
                write!(f, "split asset type mismatch")
            }
            VmError::NoSplitCommitment => {
                write!(f, "no split commitment root")
            }
            VmError::InvalidSplitCommitmentWitness => {
                write!(f, "invalid split commitment witness")
            }
            VmError::InvalidSplitCommitmentProof => {
                write!(f, "split commitment proof verification failed")
            }
            VmError::InvalidRootAsset => {
                write!(f, "invalid root asset in split")
            }
            VmError::InvalidTransferWitness(msg) => {
                write!(f, "invalid transfer witness: {}", msg)
            }
            VmError::ScriptKeyMismatch => {
                write!(f, "script key mismatch")
            }
            VmError::IdMismatch => write!(f, "asset ID mismatch"),
            VmError::TypeMismatch => write!(f, "asset type mismatch"),
            VmError::InvalidScriptVersion => {
                write!(f, "invalid script version")
            }
            VmError::WitnessValidationFailed(msg) => {
                write!(f, "witness validation failed: {}", msg)
            }
        }
    }
}

impl std::error::Error for VmError {}

/// Input assets keyed by their PrevId.
pub type InputSet = HashMap<PrevId, Asset>;

/// Checks the new asset's previous ID against the previous asset's
/// genesis, mirroring Go's `matchesPrevGenesis` (vm/vm.go:113): either
/// the IDs match directly, or (for grouped assets) the group keys and
/// genesis tags match.
fn matches_prev_genesis(
    prev_id: &PrevId,
    group_key: Option<&crate::asset::GroupKey>,
    tag: &str,
    prev_asset: &Asset,
) -> bool {
    if prev_id.id == prev_asset.genesis.id() {
        return true;
    }

    match (group_key, prev_asset.group_key.as_ref()) {
        (Some(gk), Some(prev_gk)) => {
            gk.group_pub_key == prev_gk.group_pub_key
                && tag == prev_asset.genesis.tag
        }
        _ => false,
    }
}

/// Ensures a new asset continues to adhere to the static parameters of
/// its predecessor, mirroring Go's `matchesAssetParams` (vm/vm.go:148).
fn matches_asset_params(
    new_asset: &Asset,
    prev_asset: &Asset,
    prev_id: &PrevId,
) -> Result<(), VmError> {
    if prev_id.script_key != *prev_asset.script_key.serialized() {
        return Err(VmError::ScriptKeyMismatch);
    }

    if !matches_prev_genesis(
        prev_id,
        new_asset.group_key.as_ref(),
        &new_asset.genesis.tag,
        prev_asset,
    ) {
        return Err(VmError::IdMismatch);
    }

    if new_asset.genesis.asset_type != prev_asset.genesis.asset_type {
        return Err(VmError::TypeMismatch);
    }

    Ok(())
}

/// Trait for external witness validation (signature verification).
///
/// The actual script execution requires a Bitcoin script engine (e.g.,
/// `rust-bitcoin`'s consensus verification). This trait abstracts it away
/// so the VM can be tested independently.
///
/// The `sighash` parameter is the BIP-341 taproot key-spend sighash
/// computed from the virtual transaction. The VM engine builds the virtual
/// tx and computes the sighash before calling this method.
pub trait WitnessValidator {
    /// Validates the witness for a single input.
    ///
    /// `sighash` is the 32-byte BIP-341 sighash from the virtual tx.
    /// `witness` is the witness data.
    /// `prev_asset` is the previous asset being spent.
    fn validate_witness(
        &self,
        sighash: &[u8; 32],
        witness: &Witness,
        prev_asset: &Asset,
    ) -> Result<(), VmError>;

    /// Validates a script-path (tapscript) spend by executing the full
    /// input spend of the virtual transaction, mirroring Go running the
    /// btcd txscript engine on the virtual tx (vm/vm.go:340,
    /// `validateWitnessV0` -> `txscript.NewEngine(...).Execute()`).
    ///
    /// `virtual_tx` is the per-input virtual transaction copy
    /// (`VirtualTxWithInput`) with the input witness already attached at
    /// input 0, and `prev_out` is the synthetic prevout being spent
    /// (`OP_1 <32-byte script key>`, value = input amount).
    fn validate_script_spend(
        &self,
        virtual_tx: &bitcoin::Transaction,
        prev_out: &bitcoin::TxOut,
        witness: &Witness,
        prev_asset: &Asset,
    ) -> Result<(), VmError>;
}

/// A no-op witness validator that skips signature verification.
/// Only available in tests or when the `test-utils` feature is enabled.
#[cfg(any(test, feature = "test-utils"))]
pub struct SkipWitnessValidator;

#[cfg(any(test, feature = "test-utils"))]
impl WitnessValidator for SkipWitnessValidator {
    fn validate_witness(
        &self,
        _sighash: &[u8; 32],
        _witness: &Witness,
        _prev_asset: &Asset,
    ) -> Result<(), VmError> {
        Ok(())
    }

    fn validate_script_spend(
        &self,
        _virtual_tx: &bitcoin::Transaction,
        _prev_out: &bitcoin::TxOut,
        _witness: &Witness,
        _prev_asset: &Asset,
    ) -> Result<(), VmError> {
        Ok(())
    }
}

/// The Taproot Asset virtual machine.
pub struct Engine<'a, W: WitnessValidator> {
    /// The new asset after the state transition.
    pub new_asset: &'a Asset,
    /// Split outputs (if this is a split transaction).
    pub split_assets: &'a [SplitAsset],
    /// Previous assets being spent, keyed by PrevId.
    pub prev_assets: &'a InputSet,
    /// Witness validator for signature verification.
    pub witness_validator: &'a W,
}

impl<'a, W: WitnessValidator> Engine<'a, W> {
    /// Creates a new VM engine.
    pub fn new(
        new_asset: &'a Asset,
        split_assets: &'a [SplitAsset],
        prev_assets: &'a InputSet,
        witness_validator: &'a W,
    ) -> Self {
        Engine {
            new_asset,
            split_assets,
            prev_assets,
            witness_validator,
        }
    }

    /// Executes the state transition validation.
    pub fn execute(&self) -> Result<(), VmError> {
        // Genesis asset: single witness with zero PrevId, no splits, no
        // inputs.
        if self.new_asset.has_genesis_witness() {
            if !self.split_assets.is_empty() || !self.prev_assets.is_empty() {
                return Err(VmError::InvalidGenesisStateTransition);
            }
            // A genesis asset with a group key must have a group witness
            // (handled by has_genesis_witness_for_group).
            if self.new_asset.group_key.is_some() {
                return Err(VmError::InvalidGenesisStateTransition);
            }
            return Ok(());
        }

        // Genesis asset in a group: the group membership witness must
        // be verified against the tweaked group key (Go vm/vm.go
        // Execute + validateWitnessV0 with GenesisPrevOutFetcher).
        if self.new_asset.has_genesis_witness_for_group() {
            if !self.split_assets.is_empty() || !self.prev_assets.is_empty() {
                return Err(VmError::InvalidGenesisStateTransition);
            }
            return self.validate_group_genesis_witness();
        }

        // Validate each split asset.
        for split_asset in self.split_assets {
            self.validate_split(split_asset)?;
        }

        // Validate the full state transition.
        self.validate_state_transition()
    }

    /// Validates the group membership witness of a grouped genesis
    /// asset. The signature commits to the grouped-genesis virtual
    /// transaction and is validated against the tweaked GROUP key, not
    /// the script key (Go's validateWitnessV0 with
    /// `asset.GenesisPrevOutFetcher`).
    ///
    /// Script-path group witnesses (custom group tapscript trees) are
    /// not yet supported.
    fn validate_group_genesis_witness(&self) -> Result<(), VmError> {
        let witness = &self.new_asset.prev_witnesses[0];
        let group_key = self
            .new_asset
            .group_key
            .as_ref()
            .ok_or(VmError::InvalidGenesisStateTransition)?;

        if crate::crypto::tapscript::is_script_path_witness(
            &witness.tx_witness,
        ) {
            return Err(VmError::WitnessValidationFailed(
                "script-path group witnesses are not supported".into(),
            ));
        }

        // The grouped-genesis virtual tx commits to only the
        // (witnessless) genesis asset itself.
        let empty = InputSet::new();
        let (base_tx, _, _) =
            crate::crypto::virtual_tx::virtual_tx(self.new_asset, &empty)
                .map_err(|e| {
                    VmError::InvalidTransferWitness(e.to_string())
                })?;

        // Honor an explicit sighash byte on the signature, as btcd's
        // engine does (see validate_state_transition).
        let sig_hash_type = witness
            .tx_witness
            .first()
            .and_then(|sig| {
                crate::crypto::schnorr::taproot_witness_sig_hash_type(sig)
                    .ok()
            })
            .unwrap_or(bitcoin::sighash::TapSighashType::Default);

        let sighash =
            crate::crypto::virtual_tx::input_group_genesis_key_spend_sighash(
                &base_tx,
                self.new_asset,
                sig_hash_type,
            )
            .map_err(|e| VmError::WitnessValidationFailed(e.to_string()))?;

        // The validation key is the tweaked group key; hand the
        // validator a copy of the asset whose script key is the group
        // key so the signature is checked against it.
        let mut group_prev = self.new_asset.clone();
        group_prev.script_key =
            crate::asset::ScriptKey::from_pub_key(group_key.group_pub_key);

        self.witness_validator
            .validate_witness(&sighash, witness, &group_prev)
    }

    /// Validates a split output against the split commitment root,
    /// mirroring Go's `Engine.validateSplit` (vm/vm.go:243).
    fn validate_split(&self, split_asset: &SplitAsset) -> Result<(), VmError> {
        // Asset type must match.
        if self.new_asset.genesis.asset_type != split_asset.asset.genesis.asset_type {
            return Err(VmError::InvalidSplitAssetType);
        }

        // The root asset must have a split commitment root.
        let Some((root_hash, root_sum)) =
            self.new_asset.split_commitment_root.as_ref()
        else {
            return Err(VmError::NoSplitCommitment);
        };

        // Split assets must have a single witness with a split commitment.
        if !split_asset.asset.has_split_commitment_witness() {
            return Err(VmError::InvalidSplitCommitmentWitness);
        }

        // We use the input of the new (root) asset here, as splits
        // inherit the prev ID from the root asset.
        let root_witness = self
            .new_asset
            .prev_witnesses
            .first()
            .ok_or(VmError::NoInputs)?;
        let root_prev_id =
            root_witness.prev_id.as_ref().ok_or(VmError::NoInputs)?;

        // The prevID of the split commitment should be the ID of the
        // asset generating the split in the transaction.
        let prev_asset = self
            .prev_assets
            .get(root_prev_id)
            .ok_or(VmError::NoInputs)?;
        matches_asset_params(&split_asset.asset, prev_asset, root_prev_id)?;

        // Zero-amount root must be unspendable.
        if self.new_asset.amount == 0 && !self.new_asset.is_unspendable() {
            return Err(VmError::InvalidRootAsset);
        }

        // Zero-amount split must be unspendable.
        if split_asset.asset.amount == 0 && !split_asset.asset.is_unspendable()
        {
            return Err(VmError::InvalidRootAsset);
        }

        // Verify the split commitment proof.
        let locator = SplitLocator {
            output_index: split_asset.output_index,
            asset_id: split_asset.asset.genesis.id(),
            script_key: *split_asset.asset.script_key.serialized(),
            amount: split_asset.asset.amount,
        };

        let split_witness = &split_asset.asset.prev_witnesses[0];
        let split_commitment = split_witness
            .split_commitment
            .as_ref()
            .ok_or(VmError::InvalidSplitCommitmentWitness)?;

        // Build the leaf for the split asset: the split commitment
        // itself is stripped, and lock times are inherited from the
        // root asset (Go vm/vm.go:317-326).
        let mut split_no_witness = split_asset.asset.clone();
        split_no_witness.prev_witnesses[0].split_commitment = None;
        split_no_witness.lock_time = self.new_asset.lock_time;
        split_no_witness.relative_lock_time =
            self.new_asset.relative_lock_time;
        let split_leaf = crate::commitment::asset_leaf(&split_no_witness)
            .map_err(|e| {
                VmError::InvalidTransferWitness(e.to_string())
            })?;

        // Verify the merkle proof against the split commitment root.
        let root_node = mssmt::Node::Computed(mssmt::ComputedNode::new(
            *root_hash, *root_sum,
        ));

        if !mssmt::verify_merkle_proof(
            locator.hash(),
            &split_leaf,
            &split_commitment.proof,
            &root_node,
        ) {
            return Err(VmError::InvalidSplitCommitmentProof);
        }

        Ok(())
    }

    /// Validates the full state transition (non-genesis, non-split-only).
    ///
    /// Builds the virtual transaction and computes BIP-341 sighashes for
    /// each input before delegating signature verification to the
    /// [`WitnessValidator`].
    fn validate_state_transition(&self) -> Result<(), VmError> {
        if self.new_asset.prev_witnesses.is_empty() {
            return Err(VmError::NoInputs);
        }

        // Collectibles can only have one input.
        if self.new_asset.genesis.asset_type == AssetType::Collectible
            && self.new_asset.prev_witnesses.len() > 1
        {
            return Err(VmError::InvalidTransferWitness(
                "collectible has more than one prev input".into(),
            ));
        }

        // Build the virtual transaction for the non-inflation check and
        // sighash computation.
        let (base_tx, _, input_root_sum) =
            crate::crypto::virtual_tx::virtual_tx(self.new_asset, self.prev_assets)
                .map_err(|e| VmError::InvalidTransferWitness(e.to_string()))?;

        // Enforce that assets aren't being inflated: the input MS-SMT
        // root sum must match the virtual output value (which is the
        // split commitment root sum for splits, or the asset amount
        // otherwise). Mirrors Go's vm/vm.go validateStateTransition.
        let output_value = base_tx.output[0].value.to_sat();
        if input_root_sum != output_value {
            return Err(VmError::AmountMismatch {
                expected: input_root_sum,
                got: output_value,
            });
        }

        // Validate each witness.
        for (idx, witness) in
            self.new_asset.prev_witnesses.iter().enumerate()
        {
            let prev_id = witness
                .prev_id
                .as_ref()
                .ok_or(VmError::NoInputs)?;

            let prev_asset = self
                .prev_assets
                .get(prev_id)
                .ok_or(VmError::NoInputs)?;

            // The parameters of the new and old asset must match
            // exactly (Go's matchesAssetParams in validateWitnessV0).
            matches_asset_params(self.new_asset, prev_asset, prev_id)?;

            if prev_asset.script_version != ScriptVersion::V0 {
                return Err(VmError::InvalidScriptVersion);
            }

            // Determine if this is a script-path or key-path spend.
            if crate::crypto::tapscript::is_script_path_witness(
                &witness.tx_witness,
            ) {
                // Script-path: execute the full input spend against the
                // synthetic prevout, exactly like Go running the
                // txscript engine over the virtual transaction
                // (vm/vm.go:340 validateWitnessV0).
                let mut btc_witness = bitcoin::Witness::new();
                for elem in &witness.tx_witness {
                    btc_witness.push(elem);
                }
                let tx = crate::crypto::virtual_tx::virtual_tx_with_input(
                    &base_tx,
                    self.new_asset.lock_time,
                    self.new_asset.relative_lock_time,
                    idx as u32,
                    btc_witness,
                );
                let prev_out =
                    crate::crypto::virtual_tx::input_prev_out(prev_asset)
                        .map_err(|e| {
                            VmError::WitnessValidationFailed(e.to_string())
                        })?;
                self.witness_validator.validate_script_spend(
                    &tx, &prev_out, witness, prev_asset,
                )?;
            } else {
                // Key-path: compute a BIP-341 key-spend sighash with
                // the sighash type carried by the signature's trailing
                // byte (btcd's parseTaprootSigAndPubKey semantics: 64
                // bytes = default, 65 bytes = explicit non-zero type).
                // A missing or malformed signature falls back to the
                // default type here; the witness validator re-checks
                // the signature shape and rejects it with a precise
                // error (mirroring btcd, where parse and verify happen
                // together inside the engine).
                let sig_hash_type = witness
                    .tx_witness
                    .first()
                    .and_then(|sig| {
                        crate::crypto::schnorr::taproot_witness_sig_hash_type(
                            sig,
                        )
                        .ok()
                    })
                    .unwrap_or(bitcoin::sighash::TapSighashType::Default);
                let sighash =
                    crate::crypto::virtual_tx::input_key_spend_sighash(
                        &base_tx,
                        prev_asset,
                        self.new_asset,
                        idx as u32,
                        sig_hash_type,
                    )
                    .map_err(|e| {
                        VmError::WitnessValidationFailed(e.to_string())
                    })?;

                // Delegate to the external witness validator with the
                // computed sighash.
                self.witness_validator.validate_witness(
                    &sighash,
                    witness,
                    prev_asset,
                )?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::*;

    fn test_genesis() -> Genesis {
        Genesis {
            first_prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            tag: "test".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        }
    }

    fn genesis_asset(amount: u64) -> Asset {
        let key = ScriptKey::from_pub_key(SerializedKey([0x02; 33]));
        Asset::new_genesis(test_genesis(), amount, key)
    }

    #[test]
    fn test_genesis_execution() {
        let asset = genesis_asset(100);
        let validator = SkipWitnessValidator;
        let prev_assets = InputSet::new();
        let engine = Engine::new(&asset, &[], &prev_assets, &validator);
        assert!(engine.execute().is_ok());
    }

    #[test]
    fn test_genesis_with_prev_assets_fails() {
        let asset = genesis_asset(100);
        let validator = SkipWitnessValidator;
        let mut prev_assets = InputSet::new();
        prev_assets.insert(PrevId::ZERO, genesis_asset(50));

        let engine = Engine::new(&asset, &[], &prev_assets, &validator);
        assert!(matches!(
            engine.execute(),
            Err(VmError::InvalidGenesisStateTransition)
        ));
    }

    #[test]
    fn test_transfer_amount_conservation() {
        let genesis = test_genesis();
        let prev_key = SerializedKey([0x02; 33]);
        let prev_asset = Asset {
            version: AssetVersion::V0,
            genesis: genesis.clone(),
            amount: 100,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![Witness {
                prev_id: Some(PrevId::ZERO),
                tx_witness: vec![],
                split_commitment: None,
            }],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(prev_key),
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };

        let prev_id = PrevId {
            out_point: OutPoint {
                txid: [0xAA; 32],
                vout: 0,
            },
            id: genesis.id(),
            script_key: prev_key,
        };

        let new_asset = Asset {
            version: AssetVersion::V0,
            genesis: genesis.clone(),
            amount: 100,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![Witness {
                prev_id: Some(prev_id.clone()),
                tx_witness: vec![vec![0x01]],
                split_commitment: None,
            }],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(SerializedKey([0x03; 33])),
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };

        let mut prev_assets = InputSet::new();
        prev_assets.insert(prev_id, prev_asset);

        let validator = SkipWitnessValidator;
        let engine = Engine::new(&new_asset, &[], &prev_assets, &validator);
        assert!(engine.execute().is_ok());
    }

    #[test]
    fn test_transfer_amount_mismatch() {
        let genesis = test_genesis();
        let prev_key = SerializedKey([0x02; 33]);
        let prev_asset = Asset {
            version: AssetVersion::V0,
            genesis: genesis.clone(),
            amount: 100,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![Witness {
                prev_id: Some(PrevId::ZERO),
                tx_witness: vec![],
                split_commitment: None,
            }],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(prev_key),
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };

        let prev_id = PrevId {
            out_point: OutPoint {
                txid: [0xAA; 32],
                vout: 0,
            },
            id: genesis.id(),
            script_key: prev_key,
        };

        // Output has 200 units but input only has 100 — should fail.
        let new_asset = Asset {
            version: AssetVersion::V0,
            genesis: genesis.clone(),
            amount: 200,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![Witness {
                prev_id: Some(prev_id.clone()),
                tx_witness: vec![vec![0x01]],
                split_commitment: None,
            }],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(SerializedKey([0x03; 33])),
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };

        let mut prev_assets = InputSet::new();
        prev_assets.insert(prev_id, prev_asset);

        let validator = SkipWitnessValidator;
        let engine = Engine::new(&new_asset, &[], &prev_assets, &validator);
        assert!(matches!(
            engine.execute(),
            Err(VmError::AmountMismatch { .. })
        ));
    }

    #[test]
    fn test_no_inputs_fails() {
        let genesis = test_genesis();
        let new_asset = Asset {
            version: AssetVersion::V0,
            genesis,
            amount: 100,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: vec![],
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: ScriptKey::from_pub_key(SerializedKey([0x02; 33])),
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };

        let prev_assets = InputSet::new();
        let validator = SkipWitnessValidator;
        let engine = Engine::new(&new_asset, &[], &prev_assets, &validator);
        assert!(matches!(engine.execute(), Err(VmError::NoInputs)));
    }
}
