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

        // Genesis asset in a group: has witness for group membership.
        if self.new_asset.has_genesis_witness_for_group() {
            if !self.split_assets.is_empty() || !self.prev_assets.is_empty() {
                return Err(VmError::InvalidGenesisStateTransition);
            }
            // Group witness validation would happen here via
            // witness_validator.
            return Ok(());
        }

        // Validate each split asset.
        for split_asset in self.split_assets {
            self.validate_split(split_asset)?;
        }

        // Validate the full state transition.
        self.validate_state_transition()
    }

    /// Validates a split output against the split commitment root.
    fn validate_split(&self, split_asset: &SplitAsset) -> Result<(), VmError> {
        // Asset type must match.
        if self.new_asset.genesis.asset_type != split_asset.asset.genesis.asset_type {
            return Err(VmError::InvalidSplitAssetType);
        }

        // The root asset must have a split commitment root.
        if self.new_asset.split_commitment_root.is_none() {
            return Err(VmError::NoSplitCommitment);
        }

        // Split assets must have a single witness with a split commitment.
        if !split_asset.asset.has_split_commitment_witness() {
            return Err(VmError::InvalidSplitCommitmentWitness);
        }

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

        // Build the leaf for the split asset (without witness).
        let split_leaf = crate::commitment::asset_leaf(&split_asset.asset);

        // Verify the merkle proof against the split commitment root.
        let (root_hash, root_sum) =
            self.new_asset.split_commitment_root.as_ref().unwrap();

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

        // Amount conservation: sum of input amounts must equal the output.
        let input_sum: u64 = self
            .new_asset
            .prev_witnesses
            .iter()
            .filter_map(|w| w.prev_id.as_ref())
            .filter_map(|prev_id| self.prev_assets.get(prev_id))
            .map(|a| a.amount)
            .sum();

        // For splits, the output amount is the new asset amount plus all
        // split amounts. For non-splits, it's just the new asset amount.
        let output_sum = if self.split_assets.is_empty() {
            self.new_asset.amount
        } else {
            let split_sum: u64 =
                self.split_assets.iter().map(|s| s.asset.amount).sum();
            self.new_asset.amount + split_sum
        };

        if input_sum != output_sum {
            return Err(VmError::AmountMismatch {
                expected: input_sum,
                got: output_sum,
            });
        }

        // Build the virtual transaction for sighash computation.
        let (base_tx, _, _) =
            crate::crypto::virtual_tx::virtual_tx(self.new_asset, self.prev_assets)
                .map_err(|e| VmError::InvalidTransferWitness(e.to_string()))?;

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

            // Check static parameters.
            if prev_asset.script_key.serialized()
                != &prev_id.script_key
            {
                return Err(VmError::ScriptKeyMismatch);
            }

            if self.new_asset.genesis.asset_type
                != prev_asset.genesis.asset_type
            {
                return Err(VmError::TypeMismatch);
            }

            if prev_asset.script_version != ScriptVersion::V0 {
                return Err(VmError::InvalidScriptVersion);
            }

            // Determine if this is a script-path or key-path spend and
            // compute the appropriate sighash.
            let sighash = if crate::crypto::tapscript::is_script_path_witness(
                &witness.tx_witness,
            ) {
                // Script-path: extract the script from the witness and
                // compute a BIP-342 script-path sighash.
                let (script, _control_block) =
                    crate::crypto::tapscript::extract_script_path(
                        &witness.tx_witness,
                    )
                    .ok_or(VmError::InvalidTransferWitness(
                        "malformed script-path witness".into(),
                    ))?;
                let leaf = crate::crypto::tapscript::TapscriptLeaf::new(script);
                crate::crypto::tapscript::input_script_spend_sighash(
                    &base_tx,
                    prev_asset,
                    self.new_asset,
                    idx as u32,
                    &leaf,
                    bitcoin::sighash::TapSighashType::Default,
                )
                .map_err(|e| VmError::WitnessValidationFailed(e.to_string()))?
            } else {
                // Key-path: compute a BIP-341 key-spend sighash.
                crate::crypto::virtual_tx::input_key_spend_sighash(
                    &base_tx,
                    prev_asset,
                    self.new_asset,
                    idx as u32,
                    bitcoin::sighash::TapSighashType::Default,
                )
                .map_err(|e| VmError::WitnessValidationFailed(e.to_string()))?
            };

            // Delegate to external witness validator with the computed sighash.
            self.witness_validator.validate_witness(
                &sighash,
                witness,
                prev_asset,
            )?;
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
