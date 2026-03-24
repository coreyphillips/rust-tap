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
    Asset, AssetVersion, Genesis, PrevId, ScriptKey,
    ScriptVersion, Witness, NUMS_KEY,
};
use tap_primitives::commitment::{
    asset_leaf, AssetCommitment, SplitAsset, SplitLocator, TapCommitment,
    TapCommitmentVersion,
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
#[derive(Clone, Debug)]
pub struct PreparedTransfer {
    /// The root asset for the change/tombstone output.
    pub root_asset: Asset,
    /// Recipient outputs (each becomes a split asset).
    pub recipient_assets: Vec<SplitAsset>,
    /// The TAP commitment for the change output.
    pub change_commitment: TapCommitment,
    /// Per-output TAP commitments for recipient outputs.
    pub output_commitments: Vec<TapCommitment>,
    /// Whether a split was required (partial send).
    pub is_split: bool,
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
                inputs, outputs, genesis, change_amount,
            )
        } else {
            Self::prepare_full_send(inputs, outputs, genesis)
        }
    }

    /// Prepares a full-value send (no split needed).
    fn prepare_full_send(
        inputs: &[SelectedInput],
        outputs: &[TransferOutput],
        genesis: &Genesis,
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
        let ac = AssetCommitment::new(&[&new_asset])
            .map_err(|e| SendError::CommitmentError(e.to_string()))?;
        let tc = TapCommitment::new(TapCommitmentVersion::V2, &[&ac])
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
        let root_ac = AssetCommitment::new(&[&root_asset])
            .map_err(|e| SendError::CommitmentError(e.to_string()))?;
        let change_tc =
            TapCommitment::new(TapCommitmentVersion::V2, &[&root_ac])
                .map_err(|e| SendError::CommitmentError(e.to_string()))?;

        let mut output_commitments = Vec::new();
        for split in &split_assets {
            let ac = AssetCommitment::new(&[&split.asset])
                .map_err(|e| SendError::CommitmentError(e.to_string()))?;
            let tc = TapCommitment::new(TapCommitmentVersion::V2, &[&ac])
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
