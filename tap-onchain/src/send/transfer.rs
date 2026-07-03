// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Transfer construction and state machine.


use tap_primitives::asset::{
    collect_stxo, derive_burn_key, Asset, AssetVersion, Genesis, PrevId,
    ScriptKey, ScriptVersion, Witness, NUMS_KEY,
};
use tap_primitives::commitment::{
    asset_leaf, AssetCommitmentTree, SplitAsset, SplitLocator,
    TapCommitmentTree, TapCommitmentVersion,
};
use tap_primitives::mssmt;

use super::allocation::{SelectedInput, TransferOutput};
use crate::chain::ChainError;

/// Errors from the transfer pipeline.
#[derive(Debug, Clone)]
pub enum SendError {
    /// Not enough asset balance.
    InsufficientFunds { available: u64, needed: u64 },
    /// Collectible transfer validation failed.
    InvalidCollectibleTransfer,
    /// Zero-amount output (not a tombstone).
    ZeroAmountOutput,
    /// No outputs specified.
    NoOutputs,
    /// No inputs available.
    NoInputs,
    /// Chain error.
    Chain(ChainError),
    /// Commitment error.
    CommitmentError(String),
    /// Split commitment error.
    SplitError(String),
    /// Invalid state transition.
    InvalidState(String),
    /// Burn preparation or validation error.
    BurnError(String),
    /// The signer does not know the key behind an input's script key
    /// (no stored key descriptor for it).
    UnknownScriptKey(tap_primitives::asset::SerializedKey),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::InsufficientFunds {
                available,
                needed,
            } => write!(
                f,
                "insufficient funds: available={}, needed={}",
                available, needed
            ),
            SendError::InvalidCollectibleTransfer => {
                write!(f, "invalid collectible transfer")
            }
            SendError::ZeroAmountOutput => {
                write!(f, "zero-amount output")
            }
            SendError::NoOutputs => write!(f, "no outputs specified"),
            SendError::NoInputs => write!(f, "no inputs available"),
            SendError::Chain(e) => write!(f, "chain error: {}", e),
            SendError::CommitmentError(msg) => {
                write!(f, "commitment error: {}", msg)
            }
            SendError::SplitError(msg) => {
                write!(f, "split error: {}", msg)
            }
            SendError::InvalidState(msg) => {
                write!(f, "invalid state: {}", msg)
            }
            SendError::BurnError(msg) => {
                write!(f, "burn error: {}", msg)
            }
            SendError::UnknownScriptKey(key) => {
                write!(
                    f,
                    "unknown script key: no key descriptor stored for {:02x?}",
                    &key.0[..4]
                )
            }
        }
    }
}

impl std::error::Error for SendError {}

impl From<ChainError> for SendError {
    fn from(e: ChainError) -> Self {
        SendError::Chain(e)
    }
}

/// State of a transfer in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SendState {
    /// Select inputs (coin selection).
    VirtualCommitmentSelect = 0,
    /// Sign virtual transactions.
    VirtualSign = 1,
    /// Create and fund anchor PSBT.
    AnchorSign = 2,
    /// Verify before broadcast.
    VerifyPreBroadcast = 3,
    /// Store state to database.
    StorePreBroadcast = 4,
    /// Broadcast anchor transaction.
    Broadcast = 5,
    /// Wait for confirmation.
    WaitForConfirmation = 6,
    /// Store confirmation info.
    StorePostConfirmation = 7,
    /// Transfer proofs to receiver.
    TransferProofs = 8,
    /// Terminal state.
    Complete = 9,
}

/// The result of preparing outputs — the assets and commitments ready
/// for anchoring in a Bitcoin transaction.
///
/// The commitments retain their MS-SMT trees ([`TapCommitmentTree`]) so
/// inclusion and exclusion proofs can be derived after the anchor
/// transaction is built, without hand-assembling proof parts.
#[derive(Clone, Debug)]
pub struct PreparedTransfer {
    /// The root asset for the change/tombstone output.
    pub root_asset: Asset,
    /// Recipient outputs (each becomes a split asset).
    pub recipient_assets: Vec<SplitAsset>,
    /// The TAP commitment for the change output.
    pub change_commitment: TapCommitmentTree,
    /// Per-output TAP commitments for recipient outputs.
    pub output_commitments: Vec<TapCommitmentTree>,
    /// Whether a split was required (partial send).
    pub is_split: bool,
}

impl PreparedTransfer {
    /// Rebuilds the change output commitment from the current root
    /// asset. Must be called after signing: the root asset's leaf
    /// changes once its witnesses are populated, so the commitment
    /// created at preparation time no longer matches. For full-value
    /// sends the single output commitment is refreshed as well.
    ///
    /// STXO alt leaves for the spent inputs are merged into the
    /// commitment, mirroring Go's default behavior in
    /// `tapsend.CreateOutputCommitments`. Use
    /// [`Self::rebuild_root_commitment_with_options`] to opt out (Go's
    /// `tapsend.WithNoSTXOProofs`, used for asset channels).
    pub fn rebuild_root_commitment(&mut self) -> Result<(), SendError> {
        self.rebuild_root_commitment_with_options(false)
    }

    /// Rebuilds the change output commitment, optionally skipping the
    /// STXO alt leaf merge (`no_stxo_proofs`, mirroring Go's
    /// `tapsend.WithNoSTXOProofs`).
    ///
    /// When STXO proofs are enabled and the root asset is a transfer
    /// root, the spent inputs are collected into minimal spent-asset
    /// markers ([`tap_primitives::asset::collect_stxo`]) and merged
    /// into the commitment at `EMPTY_GENESIS_ID` BEFORE the anchor
    /// output script is computed, mirroring Go's
    /// `tapsend.CreateOutputCommitments` (tapsend/send.go:1038).
    pub fn rebuild_root_commitment_with_options(
        &mut self,
        no_stxo_proofs: bool,
    ) -> Result<(), SendError> {
        let version = self.change_commitment.commitment().version;
        let ac = AssetCommitmentTree::new(&[&self.root_asset])
            .map_err(|e| SendError::CommitmentError(e.to_string()))?;
        let mut tc = TapCommitmentTree::new(version, vec![ac])
            .map_err(|e| SendError::CommitmentError(e.to_string()))?;

        // Merge the STXO spent-asset markers into the commitment of
        // the output carrying the transfer root asset. Genesis assets
        // and split leaves produce no markers.
        if !no_stxo_proofs {
            let stxo_leaves = collect_stxo(&self.root_asset)
                .map_err(|e| SendError::CommitmentError(e.to_string()))?;
            tc.merge_alt_leaves(&stxo_leaves)
                .map_err(|e| SendError::CommitmentError(e.to_string()))?;
        }

        if !self.is_split {
            // Full send: the transfer asset itself is the root asset,
            // and the single output commitment mirrors the change
            // commitment.
            if let Some(first) = self.output_commitments.first_mut() {
                *first = tc.clone();
            }
        }
        self.change_commitment = tc;
        Ok(())
    }
}

/// Builds asset transfers from inputs and output allocations.
pub struct TransferBuilder;

impl TransferBuilder {
    /// Prepares output assets for a transfer.
    ///
    /// Handles two cases:
    /// 1. **Full send** (input amount == output amount): direct transfer,
    ///    no split commitment needed.
    /// 2. **Partial send** (input amount > output amount): creates a split
    ///    commitment with a tombstone root and recipient splits.
    pub fn prepare_outputs(
        inputs: &[SelectedInput],
        outputs: &[TransferOutput],
        genesis: &Genesis,
    ) -> Result<PreparedTransfer, SendError> {
        Self::prepare_outputs_with_version(inputs, outputs, genesis, None)
    }

    /// Prepares output assets for a transfer with an explicit commitment
    /// version.
    ///
    /// The commitment version comes from the destination: V1 and V2
    /// addresses (and V1 virtual packets) require V2 Taproot Asset
    /// commitments, while `None` derives the version from the asset
    /// versions like Go's `NewTapCommitment` (see
    /// `TapAddress::commitment_version` and Go tappsbt
    /// `CommitmentVersion`).
    pub fn prepare_outputs_with_version(
        inputs: &[SelectedInput],
        outputs: &[TransferOutput],
        genesis: &Genesis,
        commitment_version: Option<TapCommitmentVersion>,
    ) -> Result<PreparedTransfer, SendError> {
        // Burn keys can only be funded through `prepare_burn`; a normal
        // transfer must never pay to a key that provably burns the assets.
        // Mirrors Go, which only derives burn script keys inside FundBurn.
        for output in outputs {
            let is_burn = inputs.iter().any(|input| {
                output.script_key.serialized().schnorr_bytes()
                    == derive_burn_key(&input.prev_id).schnorr_bytes()
            });
            if is_burn {
                return Err(SendError::BurnError(
                    "cannot send to a burn key; use prepare_burn instead"
                        .into(),
                ));
            }
        }

        Self::prepare_outputs_inner(inputs, outputs, genesis, commitment_version)
    }

    /// Prepares output assets without the burn-key guard. Used by both
    /// [`Self::prepare_outputs`] and the burn path, which intentionally
    /// pays to a burn key.
    pub(crate) fn prepare_outputs_inner(
        inputs: &[SelectedInput],
        outputs: &[TransferOutput],
        genesis: &Genesis,
        commitment_version: Option<TapCommitmentVersion>,
    ) -> Result<PreparedTransfer, SendError> {
        if inputs.is_empty() {
            return Err(SendError::NoInputs);
        }
        if outputs.is_empty() {
            return Err(SendError::NoOutputs);
        }

        let input_sum: u64 = inputs.iter().map(|i| i.amount).sum();
        let output_sum: u64 = outputs.iter().map(|o| o.amount).sum();

        if output_sum > input_sum {
            return Err(SendError::InsufficientFunds {
                available: input_sum,
                needed: output_sum,
            });
        }

        let change_amount = input_sum - output_sum;
        let is_split = change_amount > 0 || outputs.len() > 1;

        if is_split {
            Self::prepare_split_outputs(
                inputs,
                outputs,
                genesis,
                change_amount,
                commitment_version,
            )
        } else {
            Self::prepare_full_send(
                inputs,
                outputs,
                genesis,
                commitment_version,
            )
        }
    }

    /// Prepares a full-value send (no split needed).
    fn prepare_full_send(
        inputs: &[SelectedInput],
        outputs: &[TransferOutput],
        genesis: &Genesis,
        commitment_version: Option<TapCommitmentVersion>,
    ) -> Result<PreparedTransfer, SendError> {
        let output = &outputs[0];

        // Create the new asset with the recipient's script key.
        let new_asset = Asset {
            version: output.asset_version,
            genesis: genesis.clone(),
            amount: output.amount,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: inputs
                .iter()
                .map(|input| Witness {
                    prev_id: Some(input.prev_id.clone()),
                    tx_witness: vec![], // Filled during signing.
                    split_commitment: None,
                })
                .collect(),
            split_commitment_root: None,
            script_version: ScriptVersion::V0,
            script_key: output.script_key.clone(),
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };

        // Build the output commitment.
        let ac = AssetCommitmentTree::new(&[&new_asset])
            .map_err(|e| SendError::CommitmentError(e.to_string()))?;
        let tc = TapCommitmentTree::from_asset_commitment_trees(
            commitment_version,
            vec![ac],
        )
        .map_err(|e| SendError::CommitmentError(e.to_string()))?;

        Ok(PreparedTransfer {
            root_asset: new_asset,
            recipient_assets: vec![],
            change_commitment: tc.clone(),
            output_commitments: vec![tc],
            is_split: false,
        })
    }

    /// Prepares a split transfer (partial send with change).
    fn prepare_split_outputs(
        inputs: &[SelectedInput],
        outputs: &[TransferOutput],
        genesis: &Genesis,
        change_amount: u64,
        commitment_version: Option<TapCommitmentVersion>,
    ) -> Result<PreparedTransfer, SendError> {
        let asset_id = genesis.id();

        // Create the root (change) asset.
        // If change_amount is 0, it's a tombstone with NUMS key.
        let root_script_key = if change_amount == 0 {
            ScriptKey::from_pub_key(NUMS_KEY)
        } else {
            // Change goes back to the sender using the first input's script key.
            // The caller is responsible for providing a properly derived key
            // via the input's script_key field.
            inputs[0].script_key.clone()
        };

        let root_asset = Asset {
            version: AssetVersion::V0,
            genesis: genesis.clone(),
            amount: change_amount,
            lock_time: 0,
            relative_lock_time: 0,
            prev_witnesses: inputs
                .iter()
                .map(|input| Witness {
                    prev_id: Some(input.prev_id.clone()),
                    tx_witness: vec![],
                    split_commitment: None,
                })
                .collect(),
            split_commitment_root: None, // Set after building split tree.
            script_version: ScriptVersion::V0,
            script_key: root_script_key,
            group_key: None,
            unknown_odd_types: std::collections::BTreeMap::new(),
        };

        // Create split assets for each recipient output.
        let mut split_assets = Vec::new();
        for output in outputs {
            let split_asset = Asset {
                version: output.asset_version,
                genesis: genesis.clone(),
                amount: output.amount,
                lock_time: 0,
                relative_lock_time: 0,
                prev_witnesses: vec![Witness {
                    prev_id: Some(PrevId::ZERO),
                    tx_witness: vec![],
                    split_commitment: None, // Set after proof generation.
                }],
                split_commitment_root: None,
                script_version: ScriptVersion::V0,
                script_key: output.script_key.clone(),
                group_key: None,
                unknown_odd_types: std::collections::BTreeMap::new(),
            };

            split_assets.push(SplitAsset {
                asset: split_asset,
                output_index: output.output_index,
            });
        }

        // Build the split commitment tree.
        let mut split_tree = mssmt::FullTree::new(mssmt::DefaultStore::new());

        // Insert root locator.
        let root_locator = SplitLocator {
            output_index: 0,
            asset_id,
            script_key: *root_asset.script_key.serialized(),
            amount: change_amount,
        };
        let root_leaf = asset_leaf(&root_asset);
        split_tree
            .insert(root_locator.hash(), root_leaf)
            .map_err(|e| SendError::SplitError(e.to_string()))?;

        // Insert each split output.
        for split in &split_assets {
            let locator = SplitLocator {
                output_index: split.output_index,
                asset_id,
                script_key: *split.asset.script_key.serialized(),
                amount: split.asset.amount,
            };
            let leaf = asset_leaf(&split.asset);
            split_tree
                .insert(locator.hash(), leaf)
                .map_err(|e| SendError::SplitError(e.to_string()))?;
        }

        let tree_root = split_tree
            .root()
            .map_err(|e| SendError::SplitError(e.to_string()))?;

        // Set the split commitment root on the root asset.
        let mut root_asset = root_asset;
        root_asset.split_commitment_root =
            Some((tree_root.node_hash(), tree_root.node_sum()));

        // Build output commitments.
        let root_ac = AssetCommitmentTree::new(&[&root_asset])
            .map_err(|e| SendError::CommitmentError(e.to_string()))?;
        let change_tc = TapCommitmentTree::from_asset_commitment_trees(
            commitment_version,
            vec![root_ac],
        )
        .map_err(|e| SendError::CommitmentError(e.to_string()))?;

        let mut output_commitments = Vec::new();
        for split in &split_assets {
            let ac = AssetCommitmentTree::new(&[&split.asset])
                .map_err(|e| SendError::CommitmentError(e.to_string()))?;
            let tc = TapCommitmentTree::from_asset_commitment_trees(
                commitment_version,
                vec![ac],
            )
            .map_err(|e| SendError::CommitmentError(e.to_string()))?;
            output_commitments.push(tc);
        }

        Ok(PreparedTransfer {
            root_asset,
            recipient_assets: split_assets,
            change_commitment: change_tc,
            output_commitments,
            is_split: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tap_primitives::asset::*;

    fn test_genesis() -> Genesis {
        Genesis {
            first_prev_out: OutPoint {
                txid: [0x01; 32],
                vout: 0,
            },
            tag: "test-token".to_string(),
            meta_hash: [0u8; 32],
            output_index: 0,
            asset_type: AssetType::Normal,
        }
    }

    fn test_input(amount: u64) -> SelectedInput {
        SelectedInput {
            prev_id: PrevId {
                out_point: OutPoint {
                    txid: [0xAA; 32],
                    vout: 0,
                },
                id: test_genesis().id(),
                script_key: SerializedKey([0x02; 33]),
            },
            anchor_point: OutPoint {
                txid: [0xAA; 32],
                vout: 0,
            },
            amount,
            asset_type: AssetType::Normal,
            script_key: ScriptKey::from_pub_key(SerializedKey([0x02; 33])),
        }
    }

    fn test_output(amount: u64, index: u32) -> TransferOutput {
        TransferOutput {
            output_index: index,
            amount,
            script_key: ScriptKey::from_pub_key(SerializedKey([0x03; 33])),
            asset_version: AssetVersion::V0,
            interactive: true,
        }
    }

    #[test]
    fn test_full_send() {
        let genesis = test_genesis();
        let inputs = vec![test_input(100)];
        let outputs = vec![test_output(100, 0)];

        let result =
            TransferBuilder::prepare_outputs(&inputs, &outputs, &genesis)
                .unwrap();

        assert!(!result.is_split);
        assert_eq!(result.root_asset.amount, 100);
        assert!(result.recipient_assets.is_empty());
    }

    #[test]
    fn test_commitment_version_from_destination() {
        let genesis = test_genesis();
        let inputs = vec![test_input(100)];
        let outputs = vec![test_output(100, 0)];

        // An explicit V2 version (V1/V2 addresses, V1 vPackets) makes
        // every output commitment V2, visible in the tagged leaf format.
        let v2 = TransferBuilder::prepare_outputs_with_version(
            &inputs,
            &outputs,
            &genesis,
            Some(TapCommitmentVersion::V2),
        )
        .unwrap();
        for tc in &v2.output_commitments {
            assert_eq!(tc.commitment().version, TapCommitmentVersion::V2);
            let leaf = tc.commitment().tap_leaf();
            // V2 leaves start with the 32-byte tag, not the version byte.
            assert_ne!(leaf[0], 2u8);
        }

        // With no explicit version, the version derives from the asset
        // versions, like Go's NewTapCommitment: V0 assets give a V0
        // commitment.
        let derived = TransferBuilder::prepare_outputs_with_version(
            &inputs,
            &outputs,
            &genesis,
            None,
        )
        .unwrap();
        for tc in &derived.output_commitments {
            assert_eq!(tc.commitment().version, TapCommitmentVersion::V0);
            assert_eq!(tc.commitment().tap_leaf()[0], 0u8);
        }
    }

    #[test]
    fn test_partial_send_with_change() {
        let genesis = test_genesis();
        let inputs = vec![test_input(100)];
        let outputs = vec![test_output(60, 1)];

        let result =
            TransferBuilder::prepare_outputs(&inputs, &outputs, &genesis)
                .unwrap();

        assert!(result.is_split);
        assert_eq!(result.root_asset.amount, 40); // change
        assert_eq!(result.recipient_assets.len(), 1);
        assert_eq!(result.recipient_assets[0].asset.amount, 60);
        assert!(result.root_asset.split_commitment_root.is_some());
    }

    #[test]
    fn test_full_send_two_recipients() {
        let genesis = test_genesis();
        let inputs = vec![test_input(100)];
        let outputs = vec![test_output(60, 0), test_output(40, 1)];

        let result =
            TransferBuilder::prepare_outputs(&inputs, &outputs, &genesis)
                .unwrap();

        assert!(result.is_split);
        assert_eq!(result.root_asset.amount, 0); // tombstone
        assert!(result.root_asset.is_tombstone());
        assert_eq!(result.recipient_assets.len(), 2);
    }

    #[test]
    fn test_insufficient_funds() {
        let genesis = test_genesis();
        let inputs = vec![test_input(50)];
        let outputs = vec![test_output(100, 0)];

        let result =
            TransferBuilder::prepare_outputs(&inputs, &outputs, &genesis);
        assert!(matches!(
            result,
            Err(SendError::InsufficientFunds { .. })
        ));
    }

    #[test]
    fn test_no_inputs() {
        let genesis = test_genesis();
        let outputs = vec![test_output(100, 0)];
        let result =
            TransferBuilder::prepare_outputs(&[], &outputs, &genesis);
        assert!(matches!(result, Err(SendError::NoInputs)));
    }

    #[test]
    fn test_no_outputs() {
        let genesis = test_genesis();
        let inputs = vec![test_input(100)];
        let result =
            TransferBuilder::prepare_outputs(&inputs, &[], &genesis);
        assert!(matches!(result, Err(SendError::NoOutputs)));
    }

    #[test]
    fn test_split_commitment_root_sum() {
        let genesis = test_genesis();
        let inputs = vec![test_input(100)];
        let outputs = vec![test_output(60, 1)];

        let result =
            TransferBuilder::prepare_outputs(&inputs, &outputs, &genesis)
                .unwrap();

        // The split tree root sum should equal the total input.
        let (_, root_sum) =
            result.root_asset.split_commitment_root.unwrap();
        assert_eq!(root_sum, 100); // 40 change + 60 recipient
    }
}
